"""Synthetic page-coverage, offset, and parser-worker boundary tests."""
from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfWriter
from pypdf.generic import (
    ArrayObject, DecodedStreamObject, DictionaryObject, NameObject,
    NumberObject, TextStringObject,
)

import pdf_worker
from audit_contract import IntakeError, parse_pdf
from test_support import require_pdf_sandbox


def writer_bytes(writer: PdfWriter) -> bytes:
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


def add_helvetica_text(writer: PdfWriter, page, text: str, *, y: int = 220,
                       x: int = 20, font_name: str = '/F1'):
    font = DictionaryObject({
        NameObject('/Type'): NameObject('/Font'),
        NameObject('/Subtype'): NameObject('/Type1'),
        NameObject('/BaseFont'): NameObject('/Helvetica'),
    })
    font_ref = writer._add_object(font)
    resources = page.get('/Resources') or DictionaryObject()
    resources[NameObject('/Font')] = DictionaryObject({
        NameObject(font_name): font_ref,
    })
    page[NameObject('/Resources')] = resources
    stream = DecodedStreamObject()
    stream.set_data(
        f'BT {font_name} 12 Tf {x} {y} Td ({text}) Tj ET'.encode('ascii')
    )
    previous = page.get('/Contents')
    if previous is None:
        page[NameObject('/Contents')] = writer._add_object(stream)
    else:
        previous_ref = previous if hasattr(previous, 'idnum') else writer._add_object(previous)
        page[NameObject('/Contents')] = ArrayObject([previous_ref, writer._add_object(stream)])


def add_image(writer: PdfWriter, page):
    image = DecodedStreamObject()
    image.set_data(b'\xff\x00\x00')
    image.update({
        NameObject('/Type'): NameObject('/XObject'),
        NameObject('/Subtype'): NameObject('/Image'),
        NameObject('/Width'): NumberObject(1),
        NameObject('/Height'): NumberObject(1),
        NameObject('/ColorSpace'): NameObject('/DeviceRGB'),
        NameObject('/BitsPerComponent'): NumberObject(8),
    })
    image_ref = writer._add_object(image)
    resources = page.get('/Resources') or DictionaryObject()
    resources[NameObject('/XObject')] = DictionaryObject({
        NameObject('/Im1'): image_ref,
    })
    page[NameObject('/Resources')] = resources
    stream = DecodedStreamObject()
    stream.set_data(b'q 100 0 0 100 20 20 cm /Im1 Do Q')
    previous = page.get('/Contents')
    stream_ref = writer._add_object(stream)
    if previous is None:
        page[NameObject('/Contents')] = stream_ref
    else:
        page[NameObject('/Contents')] = ArrayObject([previous, stream_ref])


def unicode_pdf(text: str) -> bytes:
    """Build a tiny Type0 font fixture with an explicit ToUnicode mapping."""
    codepoints = [ord(char) for char in text]
    cmap = (
        '/CIDInit /ProcSet findresource begin\n'
        '12 dict begin\nbegincmap\n'
        '/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) '
        '/Supplement 0 >> def\n'
        '/CMapName /Synthetic-UCS def\n/CMapType 2 def\n'
        '1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n'
        f'{len(codepoints)} beginbfchar\n'
        + ''.join(f'<{index + 1:04X}> <{code:04X}>\n'
                  for index, code in enumerate(codepoints))
        + 'endbfchar\nendcmap\n'
        'CMapName currentdict /CMap defineresource pop\nend\nend'
    )
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    to_unicode = DecodedStreamObject()
    to_unicode.set_data(cmap.encode('ascii'))
    to_unicode_ref = writer._add_object(to_unicode)
    cid_font = DictionaryObject({
        NameObject('/Type'): NameObject('/Font'),
        NameObject('/Subtype'): NameObject('/CIDFontType2'),
        NameObject('/BaseFont'): NameObject('/SyntheticUnicode'),
        NameObject('/CIDSystemInfo'): DictionaryObject({
            NameObject('/Registry'): TextStringObject('Adobe'),
            NameObject('/Ordering'): TextStringObject('Identity'),
            NameObject('/Supplement'): NumberObject(0),
        }),
        NameObject('/DW'): NumberObject(1000),
        NameObject('/CIDToGIDMap'): NameObject('/Identity'),
    })
    cid_ref = writer._add_object(cid_font)
    type0_font = DictionaryObject({
        NameObject('/Type'): NameObject('/Font'),
        NameObject('/Subtype'): NameObject('/Type0'),
        NameObject('/BaseFont'): NameObject('/SyntheticUnicode'),
        NameObject('/Encoding'): NameObject('/Identity-H'),
        NameObject('/DescendantFonts'): ArrayObject([cid_ref]),
        NameObject('/ToUnicode'): to_unicode_ref,
    })
    font_ref = writer._add_object(type0_font)
    page[NameObject('/Resources')] = DictionaryObject({
        NameObject('/Font'): DictionaryObject({NameObject('/F0'): font_ref}),
    })
    codes = ''.join(f'{index + 1:04X}' for index in range(len(codepoints)))
    content = DecodedStreamObject()
    content.set_data(f'BT /F0 12 Tf 20 220 Td <{codes}> Tj ET'.encode('ascii'))
    page[NameObject('/Contents')] = writer._add_object(content)
    return writer_bytes(writer)


def image_pdf(*, include_text: bool = False) -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    add_image(writer, page)
    if include_text:
        add_helvetica_text(writer, page, 'Text beside scanned figure')
    return writer_bytes(writer)


class PageCoverageTests(unittest.TestCase):
    def setUp(self):
        require_pdf_sandbox(self)

    def test_physical_page_status_and_joined_text_offsets(self):
        writer = PdfWriter()
        first = writer.add_blank_page(width=300, height=300)
        add_helvetica_text(writer, first, 'First physical page')
        blank = writer.add_blank_page(width=300, height=300)
        empty = DecodedStreamObject()
        empty.set_data(b'')
        blank[NameObject('/Contents')] = writer._add_object(empty)
        third = writer.add_blank_page(width=300, height=300)
        add_helvetica_text(writer, third, 'Third physical page')

        pages = parse_pdf('mixed-pages.pdf', writer_bytes(writer))
        self.assertEqual([page.number for page in pages], [1, 2, 3])
        self.assertEqual([page.coverage_status for page in pages], [
            'text_extracted', 'blank', 'text_extracted',
        ])
        self.assertTrue(all(page.printed_label is None for page in pages))
        joined = '\n'.join(page.text for page in pages)
        for page in pages:
            self.assertEqual(joined[page.text_start_offset:page.text_end_offset],
                             page.text)
        self.assertEqual(pages[0].text_start_offset, 0)
        self.assertEqual(pages[1].text_start_offset, pages[0].text_end_offset + 1)
        self.assertEqual(pages[2].text_start_offset, pages[1].text_end_offset + 1)

    def test_scanned_and_mixed_pages_are_not_discarded(self):
        scanned, = parse_pdf('scan.pdf', image_pdf())
        mixed, = parse_pdf('mixed.pdf', image_pdf(include_text=True))
        self.assertEqual(scanned.coverage_status, 'image_only')
        self.assertEqual(mixed.coverage_status, 'mixed')
        self.assertIn('Text beside scanned figure', mixed.text)

    def test_non_text_vector_content_is_explicitly_unclassified(self):
        writer = PdfWriter()
        page = writer.add_blank_page(width=300, height=300)
        vector = DecodedStreamObject()
        vector.set_data(b'20 20 m 100 100 l S')
        page[NameObject('/Contents')] = writer._add_object(vector)
        parsed, = parse_pdf('vector.pdf', writer_bytes(writer))
        self.assertEqual(parsed.coverage_status, 'unclassified_content')

    def test_chinese_text_and_rotated_page_are_preserved(self):
        chinese, = parse_pdf('chinese.pdf', unicode_pdf('中文论文'))
        self.assertEqual(chinese.text, '中文论文')
        self.assertEqual(chinese.coverage_status, 'text_extracted')

        writer = PdfWriter()
        page = writer.add_blank_page(width=300, height=300)
        page[NameObject('/Rotate')] = NumberObject(90)
        add_helvetica_text(writer, page, 'Rotated page text')
        rotated, = parse_pdf('rotated.pdf', writer_bytes(writer))
        self.assertEqual(rotated.number, 1)
        self.assertEqual(rotated.text, 'Rotated page text')
        self.assertEqual(rotated.coverage_status, 'text_extracted')

    def test_garbled_extraction_has_a_separate_state(self):
        page, = parse_pdf('garbled.pdf', unicode_pdf('\ufffd'))
        self.assertEqual(page.text, '\ufffd')
        self.assertEqual(page.coverage_status, 'garbled')

    def test_multicolumn_text_is_covered_without_claiming_reading_order(self):
        writer = PdfWriter()
        page = writer.add_blank_page(width=400, height=400)
        font = DictionaryObject({
            NameObject('/Type'): NameObject('/Font'),
            NameObject('/Subtype'): NameObject('/Type1'),
            NameObject('/BaseFont'): NameObject('/Helvetica'),
        })
        font_ref = writer._add_object(font)
        page[NameObject('/Resources')] = DictionaryObject({
            NameObject('/Font'): DictionaryObject({NameObject('/F1'): font_ref}),
        })
        columns = DecodedStreamObject()
        columns.set_data(
            b'BT /F1 12 Tf 20 300 Td (Left column claim) Tj '
            b'ET BT /F1 12 Tf 220 300 Td (Right column evidence) Tj ET'
        )
        page[NameObject('/Contents')] = writer._add_object(columns)
        parsed, = parse_pdf('columns.pdf', writer_bytes(writer))
        self.assertEqual(parsed.coverage_status, 'text_extracted')
        self.assertIn('Left column claim', parsed.text)
        self.assertIn('Right column evidence', parsed.text)

    def test_corrupt_and_encrypted_pdfs_fail_with_stable_codes(self):
        for payload, expected in [
            (b'%PDF-1.7\nnot a PDF', 'PDF_PARSE_FAILED'),
        ]:
            with self.subTest(expected=expected):
                with self.assertRaises(IntakeError) as caught:
                    parse_pdf('bad.pdf', payload)
                self.assertEqual(str(caught.exception), expected)

        writer = PdfWriter()
        writer.add_blank_page(width=300, height=300)
        writer.encrypt('private-secret')
        with self.assertRaises(IntakeError) as caught:
            parse_pdf('locked.pdf', writer_bytes(writer))
        self.assertEqual(str(caught.exception), 'ENCRYPTED_PDF')

    def test_text_limit_does_not_return_partial_offsets(self):
        writer = PdfWriter()
        page = writer.add_blank_page(width=300, height=300)
        add_helvetica_text(writer, page, 'a' * (pdf_worker.MAX_EXTRACTED_CHARS + 1))
        with self.assertRaises(IntakeError) as caught:
            parse_pdf('large-text.pdf', writer_bytes(writer))
        self.assertEqual(str(caught.exception), 'PDF_TEXT_LIMIT')


class WorkerBoundaryTests(unittest.TestCase):
    def test_sandbox_command_is_fail_closed_and_has_no_host_writable_bind(self):
        command = pdf_worker._worker_command()
        self.assertIn("--unshare-user", command)
        self.assertIn("--unshare-pid", command)
        self.assertIn("--unshare-ipc", command)
        self.assertIn("--unshare-uts", command)
        self.assertIn("--die-with-parent", command)
        self.assertIn("--as-pid-1", command)
        self.assertIn("--cap-drop", command)
        self.assertIn("ALL", command)
        self.assertIn("--remount-ro", command)
        self.assertIn("--tmpfs", command)
        self.assertNotIn("--bind", command)
        self.assertNotIn("--share-net", command)

        mounts = pdf_worker._sandbox_mounts()
        private_paths = {
            str(Path(__file__).resolve().parent),
            str(Path.home().resolve()),
            str(Path(tempfile.gettempdir()).resolve()),
        }
        for private_path in private_paths:
            for source, _ in mounts:
                self.assertFalse(
                    pdf_worker._path_contains(private_path, source)
                    or pdf_worker._path_contains(source, private_path),
                )

    def test_linux_worker_blocks_network_and_sets_resource_limits(self):
        require_pdf_sandbox(self)
        result = pdf_worker.check_worker_isolation()
        self.assertTrue(result['network_blocked'])
        self.assertEqual(result['namespaces_isolated'], {
            'user': True, 'mnt': True, 'pid': True,
        })
        self.assertTrue(result['host_tmp_hidden'])
        self.assertTrue(result['host_workspace_hidden'])
        self.assertTrue(result['host_home_hidden'])
        self.assertTrue(result['pid_isolated'])
        self.assertTrue(result['capabilities_dropped'])
        self.assertTrue(result['root_readonly'])
        self.assertTrue(result['tmp_writable'])
        self.assertLessEqual(result['tmpfs_bytes'], pdf_worker.SANDBOX_TMPFS_BYTES)
        self.assertEqual(result['limits']['cpu'], [8, 10])
        self.assertEqual(result['limits']['address_space'], [
            512 * 1024 * 1024, 512 * 1024 * 1024,
        ])
        self.assertEqual(result['limits']['open_files'], [32, 32])
        self.assertEqual(result['limits']['core'], [0, 0])

    def test_missing_bubblewrap_fails_closed(self):
        with patch('pdf_worker.shutil.which', return_value=None):
            with self.assertRaises(IntakeError) as caught:
                pdf_worker._run_worker(b'synthetic')
        self.assertEqual(str(caught.exception), 'PDF_WORKER_ISOLATION_UNAVAILABLE')

    def test_private_storage_overlap_with_runtime_fails_closed(self):
        with self.assertRaises(IntakeError) as caught:
            pdf_worker._sandbox_mounts((sys.prefix,))
        self.assertEqual(str(caught.exception), 'PDF_WORKER_ISOLATION_UNAVAILABLE')

    def test_private_storage_under_system_library_root_fails_closed(self):
        roots = [path for path in ('/lib', '/lib64', '/usr/lib', '/usr/lib64')
                 if os.path.isdir(path)]
        if not roots:
            self.skipTest('No system library mount roots are present')
        private_storage = str(Path(roots[0]) / 'trc-private-storage')
        with self.assertRaises(IntakeError) as caught:
            pdf_worker._sandbox_mounts((private_storage,))
        self.assertEqual(str(caught.exception), 'PDF_WORKER_ISOLATION_UNAVAILABLE')

    def test_bubblewrap_setup_failure_has_a_stable_code(self):
        failed = subprocess.CompletedProcess(['bwrap'], 1, stdout=b'', stderr=None)
        with patch('pdf_worker.subprocess.run', return_value=failed):
            with self.assertRaises(IntakeError) as caught:
                pdf_worker._run_worker(b'synthetic')
        self.assertEqual(str(caught.exception), 'PDF_WORKER_ISOLATION_UNAVAILABLE')

    def test_timeout_is_stable_and_does_not_echo_input(self):
        private = b'private manuscript wording'
        timeout = subprocess.TimeoutExpired(['python'], 12, output=private, stderr=private)
        with patch('pdf_worker.subprocess.run', side_effect=timeout):
            with self.assertRaises(IntakeError) as caught:
                pdf_worker._run_worker(private)
        self.assertEqual(str(caught.exception), 'PDF_TIMEOUT')
        self.assertNotIn(private.decode(), str(caught.exception))

    def test_cpu_limit_termination_is_stable_and_does_not_echo_input(self):
        private = b'private manuscript wording'
        result = subprocess.CompletedProcess(['python'], -signal.SIGXCPU,
                                             stdout=private, stderr=None)
        with patch('pdf_worker.subprocess.run', return_value=result):
            with self.assertRaises(IntakeError) as caught:
                pdf_worker._run_worker(private)
        self.assertEqual(str(caught.exception), 'PDF_CPU_LIMIT')
        self.assertNotIn(private.decode(), str(caught.exception))

    def test_killed_and_crashed_workers_have_separate_stable_codes(self):
        for signum, expected in [
            (signal.SIGKILL, 'PDF_WORKER_KILLED'),
            (signal.SIGSEGV, 'PDF_WORKER_CRASHED'),
        ]:
            result = subprocess.CompletedProcess(['python'], -signum,
                                                 stdout=b'', stderr=None)
            with self.subTest(expected=expected):
                with patch('pdf_worker.subprocess.run', return_value=result):
                    with self.assertRaises(IntakeError) as caught:
                        pdf_worker._run_worker(b'synthetic')
                self.assertEqual(str(caught.exception), expected)

    def test_unexpected_worker_exit_has_stable_failure(self):
        with patch('pdf_worker.subprocess.run', return_value=
                   subprocess.CompletedProcess(['python'], 2, stdout=b'', stderr=None)):
            with self.assertRaises(IntakeError) as caught:
                pdf_worker._run_worker(b'synthetic')
        self.assertEqual(str(caught.exception), 'PDF_WORKER_FAILED')


if __name__ == '__main__':
    unittest.main()
