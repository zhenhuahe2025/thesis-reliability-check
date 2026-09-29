"""Minimal PDF-only ASGI intake API.

This prototype streams request bodies to private temporary files before parsing.
Authentication is injected by the host application; there is no default or
development credential. Jobs live in memory and the PDF parser is not isolated,
so do not expose this app to public traffic until the worker and persistence
issues are implemented.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Any, Awaitable, Callable, Mapping
from uuid import UUID, uuid4

from audit_contract import MAX_BYTES, IntakeError, parse_pdf

MAX_IDEMPOTENCY_KEY = 200
Authenticator = Callable[[Mapping[str, Any]], str | None | Awaitable[str | None]]


class RequestError(Exception):
    def __init__(self, status: int, code: str):
        self.status = status
        self.code = code
        super().__init__(code)


@dataclass
class DocumentRecord:
    document_id: str
    role: str
    sha256: str
    size_bytes: int
    page_count: int
    path: Path


@dataclass
class JobRecord:
    job_id: str
    owner_id: str
    state: str = 'created'
    documents: dict[str, DocumentRecord] = field(default_factory=dict)
    idempotency: dict[tuple[str, str], str] = field(default_factory=dict)


def _headers(scope: Mapping[str, Any]) -> dict[bytes, list[bytes]]:
    result: dict[bytes, list[bytes]] = {}
    for name, value in scope.get('headers', []):
        result.setdefault(name.lower(), []).append(value)
    return result


def _single_header(headers: dict[bytes, list[bytes]], name: bytes,
                   *, required: bool = False) -> bytes | None:
    values = headers.get(name, [])
    if len(values) > 1:
        raise RequestError(400, 'DUPLICATE_HEADER')
    if not values:
        if required:
            raise RequestError(400, 'MISSING_HEADER')
        return None
    return values[0]


def _content_length(headers: dict[bytes, list[bytes]]) -> int | None:
    raw = _single_header(headers, b'content-length')
    if raw is None:
        return None
    try:
        value = int(raw.decode('ascii'))
    except (UnicodeDecodeError, ValueError):
        raise RequestError(400, 'INVALID_CONTENT_LENGTH') from None
    if value < 0:
        raise RequestError(400, 'INVALID_CONTENT_LENGTH')
    return value


def _idempotency_key(headers: dict[bytes, list[bytes]]) -> str:
    raw = _single_header(headers, b'idempotency-key', required=True)
    try:
        key = raw.decode('ascii')
    except UnicodeDecodeError:
        raise RequestError(400, 'INVALID_IDEMPOTENCY_KEY') from None
    if (not key or len(key) > MAX_IDEMPOTENCY_KEY
            or any(ord(char) < 33 or ord(char) > 126 for char in key)):
        raise RequestError(400, 'INVALID_IDEMPOTENCY_KEY')
    return key


def _filename(headers: dict[bytes, list[bytes]]) -> str:
    raw = _single_header(headers, b'x-file-name', required=True)
    try:
        name = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise RequestError(400, 'INVALID_FILENAME') from None
    if (not name or name in {'.', '..'} or PurePath(name).name != name
            or '/' in name or '\\' in name or '\x00' in name
            or any(ord(char) < 32 for char in name)):
        raise RequestError(400, 'INVALID_FILENAME')
    if PurePath(name).suffix.lower() != '.pdf':
        raise RequestError(415, 'PDF_REQUIRED')
    return name


def _job_id(raw: str) -> str:
    try:
        return str(UUID(raw))
    except (ValueError, AttributeError):
        raise RequestError(404, 'JOB_NOT_FOUND') from None


async def _receive_to_private_file(receive, root: Path,
                                   declared_length: int | None,
                                   is_cancelled) -> tuple[Path, int, str]:
    if declared_length is not None and declared_length > MAX_BYTES:
        raise RequestError(413, 'FILE_TOO_LARGE')

    fd, raw_path = tempfile.mkstemp(prefix='.upload-', dir=root)
    path = Path(raw_path)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, 'wb') as stream:
            while True:
                if await is_cancelled():
                    raise RequestError(409, 'JOB_CANCELLED')
                event = await receive()
                if await is_cancelled():
                    raise RequestError(409, 'JOB_CANCELLED')
                event_type = event.get('type')
                if event_type == 'http.disconnect':
                    raise RequestError(400, 'UPLOAD_DISCONNECTED')
                if event_type != 'http.request':
                    continue
                chunk = event.get('body', b'')
                next_size = size + len(chunk)
                if next_size > MAX_BYTES:
                    raise RequestError(413, 'FILE_TOO_LARGE')
                if chunk:
                    stream.write(chunk)
                    digest.update(chunk)
                    size = next_size
                if not event.get('more_body', False):
                    break
            stream.flush()
        if declared_length is not None and declared_length != size:
            raise RequestError(400, 'CONTENT_LENGTH_MISMATCH')
        if size == 0:
            raise RequestError(400, 'EMPTY_FILE')
        return path, size, digest.hexdigest()
    except BaseException:
        path.unlink(missing_ok=True)
        raise


class PDFUploadApp:
    def __init__(self, authenticate: Authenticator, storage_root: str | Path):
        if not callable(authenticate):
            raise ValueError('authenticate must be supplied by the host application')
        root = Path(storage_root)
        if root.is_symlink():
            raise ValueError('storage_root must not be a symlink')
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not root.is_dir():
            raise ValueError('storage_root must be a directory')
        os.chmod(root, 0o700)
        self._storage_parent = root.resolve()
        self._workspace = tempfile.TemporaryDirectory(
            prefix='thesis-upload-', dir=self._storage_parent,
        )
        self._root = Path(self._workspace.name)
        os.chmod(self._root, 0o700)
        self._authenticate = authenticate
        self._jobs: dict[str, JobRecord] = {}
        self._job_idempotency: dict[tuple[str, str], str] = {}
        self._lock = asyncio.Lock()

    async def __call__(self, scope, receive, send):
        if scope.get('type') == 'lifespan':
            await self._lifespan(receive, send)
            return
        if scope.get('type') != 'http':
            return
        try:
            principal = self._authenticate(scope)
            if inspect.isawaitable(principal):
                principal = await principal
            if not isinstance(principal, str) or not principal.strip():
                raise RequestError(401, 'AUTHENTICATION_REQUIRED')
            await self._dispatch(scope, receive, send, principal.strip())
        except RequestError as exc:
            await self._respond(send, exc.status, {'error': exc.code})
        except Exception:
            # Deliberately do not include exception text, paths or request data.
            await self._respond(send, 500, {'error': 'INTERNAL_ERROR'})

    async def _lifespan(self, receive, send):
        while True:
            event = await receive()
            if event.get('type') == 'lifespan.startup':
                await send({'type': 'lifespan.startup.complete'})
            elif event.get('type') == 'lifespan.shutdown':
                self.close()
                await send({'type': 'lifespan.shutdown.complete'})
                return

    def close(self):
        """Remove this process-local private workspace on orderly shutdown."""
        self._workspace.cleanup()

    async def _dispatch(self, scope, receive, send, owner_id: str):
        method = scope.get('method', '').upper()
        path = scope.get('path', '')
        headers = _headers(scope)

        if path == '/v1/jobs' and method == 'POST':
            await self._create_job(headers, receive, send, owner_id)
            return

        match = re.fullmatch(r'/v1/jobs/([^/]+)(/documents)?', path)
        if not match:
            raise RequestError(404, 'NOT_FOUND')
        job_id = _job_id(match.group(1))
        suffix = match.group(2)

        if suffix == '/documents' and method == 'POST':
            await self._upload_document(scope, headers, receive, send, owner_id, job_id)
            return
        if suffix is None and method == 'GET':
            await self._get_job(send, owner_id, job_id)
            return
        if suffix is None and method == 'DELETE':
            await self._cancel_job(send, owner_id, job_id)
            return
        raise RequestError(405, 'METHOD_NOT_ALLOWED')

    async def _create_job(self, headers, receive, send, owner_id: str):
        idem = _idempotency_key(headers)
        declared_length = _content_length(headers)
        if declared_length not in (None, 0):
            raise RequestError(400, 'BODY_NOT_ALLOWED')
        # Read at most one ASGI event. Job creation does not accept a body.
        event = await receive()
        if event.get('type') == 'http.disconnect':
            raise RequestError(400, 'REQUEST_DISCONNECTED')
        if (event.get('type') != 'http.request' or event.get('body', b'')
                or event.get('more_body', False)):
            raise RequestError(400, 'BODY_NOT_ALLOWED')
        async with self._lock:
            previous_id = self._job_idempotency.get((owner_id, idem))
            if previous_id is not None:
                previous = self._jobs[previous_id]
                await self._respond(send, 200, {
                    'job_id': previous.job_id, 'state': previous.state,
                })
                return
            job = JobRecord(job_id=str(uuid4()), owner_id=owner_id)
            self._jobs[job.job_id] = job
            self._job_idempotency[(owner_id, idem)] = job.job_id
        await self._respond(send, 201, {'job_id': job.job_id, 'state': job.state})

    async def _upload_document(self, scope, headers, receive, send,
                               owner_id: str, job_id: str):
        filename = _filename(headers)
        idem = _idempotency_key(headers)
        query = scope.get('query_string', b'').decode('ascii', errors='ignore')
        role_values = [item.partition('=')[2] for item in query.split('&')
                       if item.partition('=')[0] == 'role']
        if len(role_values) > 1:
            raise RequestError(400, 'INVALID_DOCUMENT_ROLE')
        role = role_values[0] if role_values else 'thesis'
        if role not in {'thesis', 'source'}:
            raise RequestError(400, 'INVALID_DOCUMENT_ROLE')

        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.owner_id != owner_id:
                raise RequestError(404, 'JOB_NOT_FOUND')
            if job.state == 'cancelled':
                raise RequestError(409, 'JOB_CANCELLED')

        async def is_cancelled():
            async with self._lock:
                job = self._jobs.get(job_id)
                return job is None or job.owner_id != owner_id or job.state == 'cancelled'

        staged_path, size, digest = await _receive_to_private_file(
            receive, self._root, _content_length(headers), is_cancelled)
        try:
            data = staged_path.read_bytes()
            try:
                pages = parse_pdf(filename, data)
            except IntakeError as exc:
                status = 413 if str(exc) == 'FILE_TOO_LARGE' else 422
                if str(exc) == 'EMPTY_FILE':
                    status = 400
                raise RequestError(status, str(exc)) from None

            async with self._lock:
                job = self._jobs.get(job_id)
                if job is None or job.owner_id != owner_id:
                    raise RequestError(404, 'JOB_NOT_FOUND')
                if job.state == 'cancelled':
                    raise RequestError(409, 'JOB_CANCELLED')
                idempotency_key = (role, idem)
                existing_id = job.idempotency.get(idempotency_key)
                if existing_id is not None:
                    existing = job.documents[existing_id]
                    if existing.sha256 != digest:
                        raise RequestError(409, 'IDEMPOTENCY_CONFLICT')
                    await self._respond(send, 200, self._document_json(existing))
                    return

                document_id = str(uuid4())
                document_path = self._root / f'{document_id}.pdf'
                staged_path.replace(document_path)
                os.chmod(document_path, 0o600)
                record = DocumentRecord(document_id, role, digest, size,
                                        len(pages), document_path)
                job.documents[document_id] = record
                job.idempotency[idempotency_key] = document_id
            await self._respond(send, 201, self._document_json(record))
        finally:
            staged_path.unlink(missing_ok=True)

    async def _get_job(self, send, owner_id: str, job_id: str):
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.owner_id != owner_id:
                raise RequestError(404, 'JOB_NOT_FOUND')
            payload = {
                'job_id': job.job_id,
                'state': job.state,
                'documents': [self._document_json(item)
                              for item in job.documents.values()],
            }
        await self._respond(send, 200, payload)

    async def _cancel_job(self, send, owner_id: str, job_id: str):
        async with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.owner_id != owner_id:
                raise RequestError(404, 'JOB_NOT_FOUND')
            job.state = 'cancelled'
            paths = [item.path for item in job.documents.values()]
            removed_count = len(paths)
            job.documents.clear()
            job.idempotency.clear()
        for path in paths:
            path.unlink(missing_ok=True)
        await self._respond(send, 200, {
            'job_id': job_id, 'state': 'cancelled', 'removed_documents': removed_count,
        })

    @staticmethod
    def _document_json(record: DocumentRecord) -> dict[str, Any]:
        return {
            'document_id': record.document_id,
            'role': record.role,
            'size_bytes': record.size_bytes,
            'page_count': record.page_count,
        }

    @staticmethod
    async def _respond(send, status: int, payload: dict[str, Any]):
        body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        await send({
            'type': 'http.response.start',
            'status': status,
            'headers': [
                (b'content-type', b'application/json; charset=utf-8'),
                (b'content-length', str(len(body)).encode('ascii')),
                (b'cache-control', b'no-store'),
                (b'x-content-type-options', b'nosniff'),
            ],
        })
        await send({'type': 'http.response.body', 'body': body})


def create_app(authenticate: Authenticator, storage_root: str | Path) -> PDFUploadApp:
    """Create the PDF intake ASGI app with a host-provided identity function."""
    return PDFUploadApp(authenticate=authenticate, storage_root=storage_root)
