"""PDF-only intake and evidence contracts; no automated audit is implemented."""
from dataclasses import dataclass
from pathlib import PurePath
from typing import Literal

MAX_BYTES = 20 * 1024 * 1024
MAX_PAGES = 300
PAGE_COVERAGE_STATUSES = (
    'text_extracted', 'mixed', 'image_only', 'blank',
    'unclassified_content', 'garbled',
)


class IntakeError(ValueError):
    """Stable error code safe to show without document contents."""


@dataclass(frozen=True)
class Page:
    number: int
    text: str
    coverage_status: Literal[
        'text_extracted', 'mixed', 'image_only', 'blank',
        'unclassified_content', 'garbled',
    ] = 'text_extracted'
    printed_label: str | None = None
    text_start_offset: int = 0
    text_end_offset: int = 0


def parse_pdf(filename: str, data: bytes, *,
              sandbox_exclusions: tuple[str, ...] = ()) -> tuple[Page, ...]:
    """Parse in a restricted worker and retain explicit page coverage.

    Host paths that may contain uploaded documents must be supplied in
    ``sandbox_exclusions`` so they cannot be exposed by a runtime mount.
    Offsets are end-exclusive code-point indexes into ``'\\n'.join(page.text
    for page in result)``. The inserted one-character separators are the only
    normalization; each page's extracted text is otherwise preserved exactly.
    Printed page labels stay unknown unless a later parser can read them.
    """
    if PurePath(filename).suffix.lower() != '.pdf':
        raise IntakeError('PDF_REQUIRED')
    if not data:
        raise IntakeError('EMPTY_FILE')
    if len(data) > MAX_BYTES:
        raise IntakeError('FILE_TOO_LARGE')
    if not data.startswith(b'%PDF-'):
        raise IntakeError('INVALID_PDF')
    from pdf_worker import parse_pdf_isolated

    worker_pages = parse_pdf_isolated(data, excluded_paths=sandbox_exclusions)
    if not 1 <= len(worker_pages) <= MAX_PAGES:
        raise IntakeError('PAGE_LIMIT')
    pages = []
    offset = 0
    for index, record in enumerate(worker_pages):
        if index:
            offset += 1  # the documented LF separator in joined extraction
        text = record['text']
        start = offset
        end = start + len(text)
        pages.append(Page(
            number=record['number'],
            text=text,
            coverage_status=record['coverage_status'],
            printed_label=None,
            text_start_offset=start,
            text_end_offset=end,
        ))
        offset = end
    return tuple(pages)


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
