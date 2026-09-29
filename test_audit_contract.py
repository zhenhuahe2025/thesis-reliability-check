"""Offline synthetic tests; no private manuscripts or external APIs."""
import unittest
from io import BytesIO
from unittest.mock import patch

from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject
from audit_contract import (Evidence, Finding, IntakeError, Page,
                            evidence_exists, parse_pdf)
from test_support import requires_pdf_sandbox


def pdf(text='Synthetic research evidence', encrypted=False):
    writer = PdfWriter()
    page = writer.add_blank_page(width=300, height=300)
    if text:
        font = DictionaryObject({NameObject('/Type'): NameObject('/Font'),
                                 NameObject('/Subtype'): NameObject('/Type1'),
                                 NameObject('/BaseFont'): NameObject('/Helvetica')})
        page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'):
            DictionaryObject({NameObject('/F1'): writer._add_object(font)})})
        stream = DecodedStreamObject()
        stream.set_data(f'BT /F1 12 Tf 20 100 Td ({text}) Tj ET'.encode())
        page[NameObject('/Contents')] = writer._add_object(stream)
    if encrypted:
        writer.encrypt('synthetic-password')
    result = BytesIO()
    writer.write(result)
    return result.getvalue()


class IntakeTests(unittest.TestCase):
    def assert_error(self, code, filename, data):
        with self.assertRaises(IntakeError) as caught:
            parse_pdf(filename, data)
        self.assertEqual(str(caught.exception), code)

    @requires_pdf_sandbox
    def test_text_pdf_and_physical_page(self):
        pages = parse_pdf('paper.PDF', pdf())
        self.assertEqual(pages[0].number, 1)
        self.assertIn('Synthetic research evidence', pages[0].text)

    def test_non_pdf_extension(self):
        self.assert_error('PDF_REQUIRED', 'paper.docx', pdf())

    def test_renamed_file(self):
        self.assert_error('INVALID_PDF', 'paper.pdf', b'PK fake word document')

    @requires_pdf_sandbox
    def test_signature_is_insufficient(self):
        self.assert_error('PDF_PARSE_FAILED', 'paper.pdf', b'%PDF-1.7\nnot a PDF')

    def test_empty(self):
        self.assert_error('EMPTY_FILE', 'paper.pdf', b'')

    def test_byte_limit(self):
        with patch('audit_contract.MAX_BYTES', 10):
            self.assert_error('FILE_TOO_LARGE', 'paper.pdf', pdf())

    @requires_pdf_sandbox
    def test_page_limit(self):
        with patch('audit_contract.MAX_PAGES', 0):
            self.assert_error('PAGE_LIMIT', 'paper.pdf', pdf())

    @requires_pdf_sandbox
    def test_encrypted(self):
        self.assert_error('ENCRYPTED_PDF', 'paper.pdf', pdf(encrypted=True))

    @requires_pdf_sandbox
    def test_textless(self):
        page, = parse_pdf('paper.pdf', pdf(text=''))
        self.assertEqual(page.coverage_status, 'blank')
        self.assertIsNone(page.printed_label)
        self.assertEqual((page.text_start_offset, page.text_end_offset), (0, 0))


class EvidenceTests(unittest.TestCase):
    def test_unknown_without_evidence_is_allowed(self):
        self.assertEqual(Finding('unable_to_verify', 'Source unavailable').status,
                         'unable_to_verify')

    def test_risk_requires_evidence(self):
        with self.assertRaises(ValueError):
            Finding('needs_review', 'Possible mismatch')

    def test_unapproved_status_is_rejected(self):
        with self.assertRaises(ValueError):
            Finding('fabricated', 'Database did not find this reference')

    def test_grounding_checks_source_page_and_quote(self):
        evidence = Evidence('source-a', 'exact evidence', 2)
        self.assertTrue(evidence_exists(evidence, {'source-a': (Page(2, 'The exact evidence.'),)}))
        for sources in ({}, {'source-b': (Page(2, 'exact evidence'),)},
                        {'source-a': (Page(1, 'exact evidence'),)},
                        {'source-a': (Page(2, 'different text'),)}):
            self.assertFalse(evidence_exists(evidence, sources))

    def test_invalid_evidence(self):
        for values in [('', 'quote', 1), ('source', '', 1), ('source', 'quote', 0),
                       ('source', 'quote', True)]:
            with self.assertRaises(ValueError):
                Evidence(*values)


if __name__ == '__main__':
    unittest.main()
