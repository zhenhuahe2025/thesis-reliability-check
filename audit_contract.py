"""PDF-only intake and evidence contracts; no automated audit is implemented."""
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePath
from typing import Literal

from pypdf import PdfReader

MAX_BYTES = 20 * 1024 * 1024
MAX_PAGES = 300


class IntakeError(ValueError):
    """Stable error code safe to show without document contents."""


@dataclass(frozen=True)
class Page:
    number: int  # one-based physical PDF page, never a printed label
    text: str


def parse_pdf(filename: str, data: bytes) -> tuple[Page, ...]:
    """Parse in-memory bytes. Run in a resource-limited worker before web use.

    Textless pages fail closed in this first slice: OCR is not implemented.
    No file is written and no document content is included in exceptions.
    """
    if PurePath(filename).suffix.lower() != '.pdf':
        raise IntakeError('PDF_REQUIRED')
    if not data:
        raise IntakeError('EMPTY_FILE')
    if len(data) > MAX_BYTES:
        raise IntakeError('FILE_TOO_LARGE')
    if not data.startswith(b'%PDF-'):
        raise IntakeError('INVALID_PDF')
    try:
        reader = PdfReader(BytesIO(data), strict=True)
        if reader.is_encrypted:
            raise IntakeError('ENCRYPTED_PDF')
        if not 1 <= len(reader.pages) <= MAX_PAGES:
            raise IntakeError('PAGE_LIMIT')
        pages = tuple(Page(i + 1, page.extract_text() or '')
                      for i, page in enumerate(reader.pages))
        if any(not page.text.strip() for page in pages):
            raise IntakeError('TEXTLESS_PAGE_REQUIRES_REVIEW')
        return pages
    except IntakeError:
        raise
    except Exception:
        raise IntakeError('PDF_PARSE_FAILED') from None


@dataclass(frozen=True)
class Evidence:
    source_id: str
    quote: str
    page: int

    def __post_init__(self):
        if not self.source_id.strip() or not self.quote.strip():
            raise ValueError('Evidence needs a source and exact quote')
        if type(self.page) is not int or self.page < 1:
            raise ValueError('Evidence page must be a positive integer')


@dataclass(frozen=True)
class Finding:
    status: Literal['needs_review', 'unable_to_verify']
    reason: str
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self):
        if self.status not in ('needs_review', 'unable_to_verify'):
            raise ValueError('Unsupported assessment status')
        if not self.reason.strip():
            raise ValueError('Reason is required')
        if not isinstance(self.evidence, tuple) or any(
                not isinstance(item, Evidence) for item in self.evidence):
            raise ValueError('Evidence must be a tuple of Evidence objects')
        if self.status == 'needs_review' and not self.evidence:
            raise ValueError('Risk findings require evidence')


def evidence_exists(evidence: Evidence, sources: dict[str, tuple[Page, ...]]) -> bool:
    """Exact quote grounding only; this does NOT establish claim support."""
    return any(page.number == evidence.page and evidence.quote in page.text
               for page in sources.get(evidence.source_id, ()))
