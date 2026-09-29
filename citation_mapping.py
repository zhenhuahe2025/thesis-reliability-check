"""Conservative citation anchors over extracted PDF page text.

This module preserves source spans and ambiguity. It does not judge whether a
reference supports a claim, verify bibliographic metadata, or rewrite text.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Literal, Sequence

from audit_contract import Page

CitationStyle = Literal["numeric", "author_year"]
CitationStatus = Literal["matched", "partial", "ambiguous", "unmapped"]

_NUMBERED_ENTRY = re.compile(
    r"^\s*(?:\[(\d{1,4})\]|\((\d{1,4})\)|（(\d{1,4})）|(\d{1,4})[.．、)])\s*"
)
_REFERENCE_HEADING = re.compile(
    r"^(?:references?|bibliography|works\s+cited|"
    r"参考文献(?:\s*[（(]references?[）)])?|引用文献|参考资料)\s*[:：]?$",
    re.IGNORECASE,
)
_SECTION_END = re.compile(
    r"^(?:appendix(?:\s+[a-z0-9]+)?|acknowledg(?:e?ments?)?|"
    r"致谢|附录(?:\s*[a-z0-9一二三四五六七八九十]+)?)$",
    re.IGNORECASE,
)
_NUMERIC_CITATION = re.compile(r"\[(?P<body>\s*\d[\d\s,，;；\-–—]{0,80})\]")
_AUTHOR_TOKEN = r"(?:[A-Za-z][A-Za-z'’\-]{1,39}|[\u3400-\u9fff]{2,4})"
_YEAR_TOKEN = r"(?P<year>(?:19|20)\d{2})(?P<suffix>[a-z]?)"
_AUTHOR_YEAR_PAREN = re.compile(
    rf"[（(]\s*(?P<author>{_AUTHOR_TOKEN})"
    rf"(?:\s+(?:et\s+al\.?|等))?\s*[,，]\s*{_YEAR_TOKEN}\s*[）)]"
)
_AUTHOR_YEAR_NARRATIVE = re.compile(
    rf"(?P<author>{_AUTHOR_TOKEN})(?:\s+(?:et\s+al\.?|等))?"
    rf"\s*[（(]\s*{_YEAR_TOKEN}\s*[）)]"
)
_YEAR_IN_REFERENCE = re.compile(r"(?<!\d)((?:19|20)\d{2})([a-z]?)(?!\d)", re.IGNORECASE)
_NUMBER_IN_BODY = re.compile(r"^\s*(?:\[(?:\d{1,4})\]|\((?:\d{1,4})\)|（(?:\d{1,4})）|(?:\d{1,4})[.．、)])\s*")


@dataclass(frozen=True)
class ReferenceEntry:
    """One conservatively delimited bibliography entry."""

    index: int
    label: int | None
    text: str
    start_page: int
    end_page: int
    start_offset: int
    end_offset: int
    author_key: str | None = None
    year: str | None = None


@dataclass(frozen=True)
class CitationAnchor:
    """A possible citation with an exact span in joined extracted page text."""

    style: CitationStyle
    text: str
    page: int
    start_offset: int
    end_offset: int
    reference_numbers: tuple[int, ...] = ()
    candidate_entry_indexes: tuple[int, ...] = ()
    unmatched_numbers: tuple[int, ...] = ()
    status: CitationStatus = "unmapped"


@dataclass(frozen=True)
class ReferenceAnalysis:
    """Citation-to-bibliography candidates; no semantic support verdict."""

    reference_section_found: bool
    references: tuple[ReferenceEntry, ...]
    citations: tuple[CitationAnchor, ...]
    uncited_entry_indexes: tuple[int, ...]
    missing_reference_numbers: tuple[int, ...]


@dataclass(frozen=True)
class _Line:
    text: str
    page: int
    start: int
    end: int


def _joined_text(pages: Sequence[Page]) -> str:
    return "\n".join(page.text for page in pages)


def _page_lines(pages: Sequence[Page]) -> tuple[_Line, ...]:
    """Split only on LF, retaining offsets into the documented joined text."""
    lines: list[_Line] = []
    page_start = 0
    for page_index, page in enumerate(pages):
        text = page.text
        pos = 0
        while pos <= len(text):
            newline = text.find("\n", pos)
            line_end = len(text) if newline < 0 else newline
            raw = text[pos:line_end]
            visible = raw[:-1] if raw.endswith("\r") else raw
            lines.append(_Line(visible, page.number, page_start + pos,
                               page_start + pos + len(visible)))
            if newline < 0:
                break
            pos = newline + 1
        page_start += len(text)
        if page_index + 1 < len(pages):
            page_start += 1
    return tuple(lines)


def _section_bounds(lines: Sequence[_Line], document_length: int) -> tuple[int, int, bool]:
    heading_index = next((i for i, line in enumerate(lines)
                          if _REFERENCE_HEADING.fullmatch(line.text.strip())), None)
    if heading_index is None:
        return document_length, document_length, False
    start = lines[heading_index].start
    end = document_length
    for line in lines[heading_index + 1:]:
        if _SECTION_END.fullmatch(line.text.strip()):
            end = line.start
            break
    return start, end, True


def _normalize_author(value: str) -> str:
    value = re.sub(r"\s+et\s+al\.?$", "", value.strip(), flags=re.IGNORECASE)
    value = re.sub(r"等$", "", value.strip())
    return "".join(char.casefold() for char in value
                   if char.isalnum() or "\u3400" <= char <= "\u9fff")


def _reference_author_year(text: str) -> tuple[str | None, str | None]:
    remainder = _NUMBER_IN_BODY.sub("", text, count=1).strip()
    year_match = _YEAR_IN_REFERENCE.search(remainder)
    if year_match is None:
        return None, None
    author_text = remainder[:year_match.start()].strip()
    author_text = re.split(r"[,，、.;；。:：]", author_text, maxsplit=1)[0].strip()
    author_key = _normalize_author(author_text)
    year = year_match.group(1) + year_match.group(2).lower()
    return (author_key or None), year


def _extract_references(lines: Sequence[_Line], joined: str,
                        heading_start: int, section_end: int) -> tuple[ReferenceEntry, ...]:
    section_lines = [line for line in lines
                     if heading_start < line.start < section_end]
    entries: list[ReferenceEntry] = []
    start: int | None = None
    label: int | None = None
    start_page = 0
    end_page = 0
    end = 0
    previous_blank = False

    def flush() -> None:
        nonlocal start, label, start_page, end_page, end
        if start is None or end <= start:
            start = None
            label = None
            return
        raw = joined[start:end]
        author_key, year = _reference_author_year(raw)
        entries.append(ReferenceEntry(
            index=len(entries) + 1,
            label=label,
            text=raw,
            start_page=start_page,
            end_page=end_page,
            start_offset=start,
            end_offset=end,
            author_key=author_key,
            year=year,
        ))
        start = None
        label = None

    for line in section_lines:
        if _SECTION_END.fullmatch(line.text.strip()):
            flush()
            break
        stripped = line.text.strip()
        if not stripped:
            previous_blank = True
            continue
        numbered = _NUMBERED_ENTRY.match(line.text)
        if numbered:
            flush()
            label = int(next(group for group in numbered.groups() if group is not None))
            start = line.start
            start_page = end_page = line.page
            end = line.end
        else:
            if start is None or (previous_blank and label is None):
                flush()
                start = line.start
                label = None
                start_page = line.page
            end_page = line.page
            end = line.end
        previous_blank = False
    flush()
    return tuple(entries)


def _expand_numeric_body(body: str) -> tuple[int, ...] | None:
    numbers: list[int] = []
    pieces = re.split(r"[,，;；]", body)
    if not pieces:
        return None
    for piece in pieces:
        piece = piece.strip()
        single = re.fullmatch(r"(\d{1,4})", piece)
        if single:
            numbers.append(int(single.group(1)))
            continue
        span = re.fullmatch(r"(\d{1,4})\s*[-–—]\s*(\d{1,4})", piece)
        if span is None:
            return None
        first, last = (int(value) for value in span.groups())
        if last < first or last - first > 99:
            return None
        numbers.extend(range(first, last + 1))
        if len(numbers) > 100:
            return None
    return tuple(dict.fromkeys(numbers)) if numbers else None


def _citation_matches(page_text: str):
    matches: dict[tuple[int, int], tuple[str, re.Match[str]]] = {}
    for match in _NUMERIC_CITATION.finditer(page_text):
        matches[(match.start(), match.end())] = ("numeric", match)
    for pattern in (_AUTHOR_YEAR_PAREN, _AUTHOR_YEAR_NARRATIVE):
        for match in pattern.finditer(page_text):
            matches.setdefault((match.start(), match.end()), ("author_year", match))
    return sorted(((start, end, style, match)
                   for (start, end), (style, match) in matches.items()),
                  key=lambda item: (item[0], item[1]))


def analyze_references(pages: Sequence[Page]) -> ReferenceAnalysis:
    """Map likely citations to exact bibliography candidates.

    Offsets refer to ``'\\n'.join(page.text for page in pages)`` and are
    end-exclusive Unicode code-point offsets. Numeric ranges are expanded only
    up to 100 labels. Repeated labels and author/year collisions remain
    ambiguous; missing labels are reported separately. Text after an appendix,
    acknowledgements, 致谢, or 附录 heading is not treated as bibliography.
    """
    pages = tuple(pages)
    joined = _joined_text(pages)
    lines = _page_lines(pages)
    heading_start, section_end, section_found = _section_bounds(lines, len(joined))
    references = (_extract_references(lines, joined, heading_start, section_end)
                  if section_found else ())

    by_number: dict[int, list[ReferenceEntry]] = {}
    by_author_year: dict[tuple[str, str], list[ReferenceEntry]] = {}
    for entry in references:
        if entry.label is not None:
            by_number.setdefault(entry.label, []).append(entry)
        if entry.author_key and entry.year:
            by_author_year.setdefault((entry.author_key, entry.year), []).append(entry)

    page_starts: list[int] = []
    offset = 0
    for index, page in enumerate(pages):
        page_starts.append(offset)
        offset += len(page.text) + (1 if index + 1 < len(pages) else 0)

    anchors: list[CitationAnchor] = []
    missing_numbers: set[int] = set()
    referenced_entries: set[int] = set()
    for index, page in enumerate(pages):
        page_start = page_starts[index]
        if page_start >= heading_start:
            break
        available = min(len(page.text), heading_start - page_start)
        body = page.text[:max(0, available)]
        for local_start, local_end, style, match in _citation_matches(body):
            start, end = page_start + local_start, page_start + local_end
            raw = joined[start:end]
            if style == "numeric":
                numbers = _expand_numeric_body(match.group("body"))
                requested = numbers or ()
                candidates: list[ReferenceEntry] = []
                unmatched: list[int] = []
                duplicate = False
                for number in requested:
                    matches = by_number.get(number, [])
                    if not matches:
                        unmatched.append(number)
                    else:
                        candidates.extend(matches)
                        duplicate = duplicate or len(matches) > 1
                candidates = list({entry.index: entry for entry in candidates}.values())
                if not candidates:
                    status: CitationStatus = "unmapped"
                elif duplicate:
                    status = "ambiguous"
                elif unmatched:
                    status = "partial"
                else:
                    status = "matched"
                missing_numbers.update(unmatched)
                candidate_indexes = tuple(entry.index for entry in candidates)
                anchors.append(CitationAnchor(
                    style="numeric", text=raw, page=page.number,
                    start_offset=start, end_offset=end,
                    reference_numbers=requested,
                    candidate_entry_indexes=candidate_indexes,
                    unmatched_numbers=tuple(unmatched), status=status,
                ))
                referenced_entries.update(candidate_indexes)
                continue

            author = _normalize_author(match.group("author"))
            year = match.group("year") + match.group("suffix").lower()
            candidates = by_author_year.get((author, year), [])
            if not match.group("suffix"):
                candidates = [entry for entry in references
                              if entry.author_key == author and entry.year
                              and entry.year.startswith(year)]
            candidate_indexes = tuple(entry.index for entry in candidates)
            status = ("unmapped" if not candidates else
                      "ambiguous" if len(candidates) > 1 else "matched")
            anchors.append(CitationAnchor(
                style="author_year", text=raw, page=page.number,
                start_offset=start, end_offset=end,
                candidate_entry_indexes=candidate_indexes, status=status,
            ))
            referenced_entries.update(candidate_indexes)

    anchors.sort(key=lambda item: (item.start_offset, item.end_offset))
    uncited = tuple(entry.index for entry in references
                    if entry.index not in referenced_entries)
    return ReferenceAnalysis(
        reference_section_found=section_found,
        references=references,
        citations=tuple(anchors),
        uncited_entry_indexes=uncited,
        missing_reference_numbers=tuple(sorted(missing_numbers)),
    )
