"""ASGI upload boundary tests using synthetic in-memory PDFs."""
import asyncio
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from audit_contract import IntakeError, parse_pdf
from test_audit_contract import pdf
from upload_api import create_app


class UploadAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.storage = Path(self.temp.name) / 'private_uploads'
        self.job_counter = 0

        def authenticate(scope):
            headers = dict(scope.get('headers', []))
            credential = headers.get(b'authorization', b'')
            return {
                b'Bearer alice-token': 'alice',
                b'Bearer bob-token': 'bob',
            }.get(credential)

        self.app = create_app(authenticate, self.storage)

    def tearDown(self):
        self.app.close()
        self.temp.cleanup()

    def stored_files(self):
        return list(self.app._root.iterdir())

    def call(self, method, path, *, owner='alice', body=b'', chunks=None,
             headers=None, include_length=True):
        return asyncio.run(self.call_async(
            method, path, owner=owner, body=body, chunks=chunks,
            headers=headers, include_length=include_length,
        ))

    async def call_async(self, method, path, *, owner='alice', body=b'', chunks=None,
                         headers=None, include_length=True, before_receive=None):
        request_headers = [(b'authorization', f'Bearer {owner}-token'.encode())]
        for name, value in (headers or {}).items():
            request_headers.append((name.lower().encode(), value.encode()
                                    if isinstance(value, str) else value))
        payload = body if chunks is None else b''.join(chunks)
        if include_length and not any(name == b'content-length'
                                      for name, _ in request_headers):
            request_headers.append((b'content-length', str(len(payload)).encode()))
        parts = [payload] if chunks is None else list(chunks)
        if not parts:
            parts = [b'']
        events = [
            {'type': 'http.request', 'body': part,
             'more_body': index < len(parts) - 1}
            for index, part in enumerate(parts)
        ]
        consumed = []
        sent = []

        async def receive():
            consumed.append(True)
            if before_receive is not None:
                await before_receive(len(consumed))
            if events:
                return events.pop(0)
            return {'type': 'http.disconnect'}

        async def send(message):
            sent.append(message)

        async def run():
            path_only, _, query = path.partition('?')
            scope = {
                'type': 'http', 'asgi': {'version': '3.0'},
                'http_version': '1.1', 'method': method, 'scheme': 'http',
                'path': path_only, 'raw_path': path_only.encode(),
                'query_string': query.encode(), 'headers': request_headers,
                'client': ('test', 1234), 'server': ('test', 80),
            }
            await self.app(scope, receive, send)

        await run()
        start = next(message for message in sent
                     if message['type'] == 'http.response.start')
        raw_body = next(message['body'] for message in sent
                        if message['type'] == 'http.response.body')
        return start['status'], json.loads(raw_body), len(consumed)

    def create_job(self, owner='alice'):
        self.job_counter += 1
        status, payload, _ = self.call(
            'POST', '/v1/jobs', owner=owner,
            headers={'idempotency-key': f'create-{self.job_counter}'},
        )
        self.assertEqual(status, 201)
        return payload['job_id']

    def test_job_creation_is_idempotent_and_scoped_to_owner(self):
        first = self.call('POST', '/v1/jobs',
                          headers={'idempotency-key': 'job-request-1'})
        retry = self.call('POST', '/v1/jobs',
                          headers={'idempotency-key': 'job-request-1'})
        other_owner = self.call('POST', '/v1/jobs', owner='bob',
                                headers={'idempotency-key': 'job-request-1'})
        self.assertEqual(first[0], 201)
        self.assertEqual(retry[0], 200)
        self.assertEqual(first[1]['job_id'], retry[1]['job_id'])
        self.assertEqual(other_owner[0], 201)
        self.assertNotEqual(first[1]['job_id'], other_owner[1]['job_id'])

    def upload(self, job_id, *, owner='alice', filename='paper.pdf',
               content=None, key='upload-1', headers=None, chunks=None,
               include_length=True):
        request_headers = {
            'x-file-name': filename,
            'idempotency-key': key,
        }
        request_headers.update(headers or {})
        return self.call(
            'POST', f'/v1/jobs/{job_id}/documents?role=thesis', owner=owner,
            body=content or b'', chunks=chunks, headers=request_headers,
            include_length=include_length,
        )

    def test_pdf_upload_is_streamed_and_metadata_omits_filename(self):
        job_id = self.create_job()
        content = pdf(text='A private synthetic sentence')
        status, payload, _ = self.upload(
            job_id, filename='private-name.pdf', content=content,
            headers={'content-type': 'application/pdf'},
            chunks=[content[:17], content[17:]],
        )
        self.assertEqual(status, 201)
        self.assertEqual(payload['page_count'], 1)
        self.assertEqual(payload['coverage_summary']['text_extracted'], 1)
        self.assertEqual(payload['coverage_summary']['blank'], 0)
        self.assertEqual(payload['page_coverage'], [{
            'physical_page': 1,
            'coverage_status': 'text_extracted',
            'printed_label': None,
            'text_start_offset': 0,
            'text_end_offset': len('A private synthetic sentence'),
        }])
        self.assertEqual(payload['size_bytes'], len(content))
        self.assertNotIn('private-name.pdf', json.dumps(payload))
        files = self.stored_files()
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].suffix, '.pdf')
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.app._root.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.storage.stat().st_mode & 0o777, 0o700)

    def test_blank_page_upload_reports_coverage_without_rejecting_document(self):
        job_id = self.create_job()
        status, payload, _ = self.upload(
            job_id, content=pdf(text=''), key='blank-page',
        )
        self.assertEqual(status, 201)
        self.assertEqual(payload['page_count'], 1)
        self.assertEqual(payload['coverage_summary']['blank'], 1)
        self.assertEqual(payload['coverage_summary']['text_extracted'], 0)
        self.assertEqual(payload['page_coverage'][0]['physical_page'], 1)
        self.assertEqual(payload['page_coverage'][0]['coverage_status'], 'blank')
        self.assertIsNone(payload['page_coverage'][0]['printed_label'])

    def test_docx_is_rejected_even_when_body_is_a_valid_pdf(self):
        job_id = self.create_job()
        status, payload, _ = self.upload(job_id, filename='paper.docx', content=pdf())
        self.assertEqual((status, payload['error']), (415, 'PDF_REQUIRED'))
        self.assertEqual(self.stored_files(), [])

    def test_renamed_non_pdf_is_rejected_even_with_pdf_mime_type(self):
        job_id = self.create_job()
        status, payload, _ = self.upload(
            job_id, filename='renamed.pdf', content=b'PK\x03\x04not-a-pdf',
            headers={'content-type': 'application/pdf'},
        )
        self.assertEqual((status, payload['error']), (422, 'INVALID_PDF'))
        self.assertEqual(self.stored_files(), [])

    def test_empty_upload_has_stable_error(self):
        job_id = self.create_job()
        status, payload, _ = self.upload(job_id, content=b'')
        self.assertEqual((status, payload['error']), (400, 'EMPTY_FILE'))
        self.assertEqual(self.stored_files(), [])

    def test_parser_timeout_and_resource_failures_are_safe_and_remove_staging(self):
        job_id = self.create_job()
        for code in ('PDF_TIMEOUT', 'PDF_RESOURCE_LIMIT'):
            with self.subTest(code=code):
                with patch('upload_api.parse_pdf', side_effect=IntakeError(code)):
                    status, payload, _ = self.upload(
                        job_id, filename='private-manuscript-name.pdf',
                        content=b'private manuscript bytes', key=f'failure-{code}',
                    )
                self.assertEqual((status, payload), (422, {'error': code}))
                self.assertNotIn('private', json.dumps(payload))
                self.assertEqual(self.stored_files(), [])

    def test_declared_oversize_is_rejected_before_body_read(self):
        job_id = self.create_job()
        with patch('upload_api.MAX_BYTES', 32):
            status, payload, consumed = self.upload(
                job_id, content=b'x' * 33, include_length=True,
            )
        self.assertEqual((status, payload['error']), (413, 'FILE_TOO_LARGE'))
        self.assertEqual(consumed, 0)
        self.assertEqual(self.stored_files(), [])

    def test_streamed_oversize_is_rejected_and_partial_file_removed(self):
        job_id = self.create_job()
        with patch('upload_api.MAX_BYTES', 32):
            status, payload, _ = self.upload(
                job_id, chunks=[b'x' * 20, b'y' * 20], include_length=False,
            )
        self.assertEqual((status, payload['error']), (413, 'FILE_TOO_LARGE'))
        self.assertEqual(self.stored_files(), [])

    def test_content_length_mismatch_is_rejected(self):
        job_id = self.create_job()
        content = pdf()
        status, payload, _ = self.upload(
            job_id, content=content,
            headers={'content-length': str(len(content) + 1)},
        )
        self.assertEqual((status, payload['error']), (400, 'CONTENT_LENGTH_MISMATCH'))
        self.assertEqual(self.stored_files(), [])

    def test_idempotent_retry_returns_same_document_without_duplicate_file(self):
        job_id = self.create_job()
        content = pdf()
        first = self.upload(job_id, content=content, key='same-request')
        second = self.upload(job_id, content=content, key='same-request')
        self.assertEqual(first[0], 201)
        self.assertEqual(second[0], 200)
        self.assertEqual(first[1]['document_id'], second[1]['document_id'])
        self.assertEqual(len(self.stored_files()), 1)

    def test_idempotency_key_cannot_be_reused_for_different_content(self):
        job_id = self.create_job()
        self.assertEqual(self.upload(job_id, content=pdf(), key='same-request')[0], 201)
        status, payload, _ = self.upload(
            job_id, content=pdf(text='Different synthetic evidence'), key='same-request',
        )
        self.assertEqual((status, payload['error']), (409, 'IDEMPOTENCY_CONFLICT'))
        self.assertEqual(len(self.stored_files()), 1)

    def test_other_owner_cannot_read_upload_to_or_cancel_job(self):
        job_id = self.create_job()
        status, payload, _ = self.upload(job_id, owner='bob', content=pdf())
        self.assertEqual((status, payload['error']), (404, 'JOB_NOT_FOUND'))
        status, payload, _ = self.call('GET', f'/v1/jobs/{job_id}', owner='bob')
        self.assertEqual((status, payload['error']), (404, 'JOB_NOT_FOUND'))
        status, payload, _ = self.call('DELETE', f'/v1/jobs/{job_id}', owner='bob')
        self.assertEqual((status, payload['error']), (404, 'JOB_NOT_FOUND'))
        self.assertEqual(self.stored_files(), [])

    def test_cancel_removes_private_pdf_and_blocks_future_uploads(self):
        job_id = self.create_job()
        self.assertEqual(self.upload(job_id, content=pdf())[0], 201)
        self.assertEqual(len(list(self.app._root.glob('*.pdf'))), 1)
        status, payload, _ = self.call('DELETE', f'/v1/jobs/{job_id}')
        self.assertEqual(status, 200)
        self.assertEqual(payload['state'], 'cancelled')
        self.assertEqual(payload['removed_documents'], 1)
        self.assertEqual(self.stored_files(), [])
        status, payload, _ = self.upload(job_id, content=pdf(), key='after-cancel')
        self.assertEqual((status, payload['error']), (409, 'JOB_CANCELLED'))

    def test_cancel_during_stream_discards_partial_upload(self):
        job_id = self.create_job()
        content = pdf()
        cancel_result = []

        async def cancel_after_first_chunk(receive_count):
            if receive_count == 2:
                cancel_result.append(await self.call_async(
                    'DELETE', f'/v1/jobs/{job_id}',
                ))

        status, payload, _ = asyncio.run(self.call_async(
            'POST', f'/v1/jobs/{job_id}/documents?role=thesis',
            headers={'x-file-name': 'paper.pdf', 'idempotency-key': 'cancel-race'},
            chunks=[content[:20], content[20:]], before_receive=cancel_after_first_chunk,
        ))
        self.assertEqual((status, payload['error']), (409, 'JOB_CANCELLED'))
        self.assertEqual(cancel_result[0][0], 200)
        self.assertEqual(self.stored_files(), [])

    def test_cancel_during_parse_keeps_asgi_event_loop_responsive(self):
        job_id = self.create_job()
        content = pdf()
        parse_started = threading.Event()
        release_parse = threading.Event()

        def delayed_parse(filename, data):
            parse_started.set()
            release_parse.wait(timeout=2)
            return parse_pdf(filename, data)

        async def run():
            with patch('upload_api.parse_pdf', side_effect=delayed_parse):
                upload_task = asyncio.create_task(self.call_async(
                    'POST', f'/v1/jobs/{job_id}/documents?role=thesis',
                    headers={'x-file-name': 'paper.pdf',
                             'idempotency-key': 'cancel-during-parse'},
                    body=content,
                ))
                started = await asyncio.to_thread(parse_started.wait, 1)
                if not started:
                    release_parse.set()
                    await upload_task
                    self.fail('parser worker did not start')
                cancelled = await self.call_async('DELETE', f'/v1/jobs/{job_id}')
                release_parse.set()
                uploaded = await upload_task
                return cancelled, uploaded

        cancelled, uploaded = asyncio.run(run())
        self.assertEqual(cancelled[0], 200)
        self.assertEqual((uploaded[0], uploaded[1]['error']), (409, 'JOB_CANCELLED'))
        self.assertEqual(self.stored_files(), [])

    def test_asgi_shutdown_removes_instance_private_workspace(self):
        private_workspace = self.app._root

        async def run_shutdown():
            events = iter([
                {'type': 'lifespan.startup'},
                {'type': 'lifespan.shutdown'},
            ])
            responses = []

            async def receive():
                return next(events)

            async def send(message):
                responses.append(message)

            await self.app({'type': 'lifespan'}, receive, send)
            return responses

        responses = asyncio.run(run_shutdown())
        self.assertEqual(responses, [
            {'type': 'lifespan.startup.complete'},
            {'type': 'lifespan.shutdown.complete'},
        ])
        self.assertFalse(private_workspace.exists())

    def test_missing_authentication_fails_closed(self):
        status, payload, _ = self.call('POST', '/v1/jobs', owner='invalid')
        self.assertEqual((status, payload['error']), (401, 'AUTHENTICATION_REQUIRED'))

    def test_job_status_never_returns_filename_or_pdf_text(self):
        job_id = self.create_job()
        self.upload(job_id, filename='sensitive-title.pdf',
                    content=pdf(text='Secret manuscript wording'))
        status, payload, _ = self.call('GET', f'/v1/jobs/{job_id}')
        self.assertEqual(status, 200)
        serialized = json.dumps(payload)
        self.assertNotIn('sensitive-title.pdf', serialized)
        self.assertNotIn('Secret manuscript wording', serialized)
        self.assertEqual(payload['documents'][0]['page_coverage'][0]['physical_page'], 1)


if __name__ == '__main__':
    unittest.main()
