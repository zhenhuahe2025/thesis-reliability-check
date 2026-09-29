"""Synthetic citation mapping tests; no real papers or network access."""
import unittest

from audit_contract import Page
from citation_mapping import analyze_references


class CitationMappingTests(unittest.TestCase):
    def test_numeric_citations_ranges_wrapped_entry_and_uncited_reference(self):
        page = Page(1, (
            "正文引用 [1] 和 [2–3]，另有 [5]。\n"
            "参考文献\n"
            "[1] Smith, J. First title. 2020.\ncontinued title and venue\n"
            "[2] 张三, 李四. 第二篇. 2021.\n"
            "[3] Wang, Z. Third title. 2022.\n"
            "[4] Lonely, A. Uncited title. 2023."
        ))
        joined = page.text
        result = analyze_references((page,))

        self.assertTrue(result.reference_section_found)
        self.assertEqual(len(result.references), 4)
        self.assertIn("continued title and venue", result.references[0].text)
        self.assertEqual(
            joined[result.references[0].start_offset:result.references[0].end_offset],
            result.references[0].text,
        )
        self.assertEqual([anchor.text for anchor in result.citations],
                         ["[1]", "[2–3]", "[5]"])
        self.assertEqual(result.citations[0].candidate_entry_indexes, (1,))
        self.assertEqual(result.citations[1].reference_numbers, (2, 3))
        self.assertEqual(result.citations[1].candidate_entry_indexes, (2, 3))
        self.assertEqual(result.citations[1].status, "matched")
        self.assertEqual(result.citations[2].status, "unmapped")
        self.assertEqual(result.missing_reference_numbers, (5,))
        self.assertEqual(result.uncited_entry_indexes, (4,))

    def test_duplicate_numbers_and_partial_range_remain_explicit(self):
        page = Page(1, (
            "See [1] and [2–4].\nReferences\n"
            "[1] First duplicate.\n[1] Second duplicate.\n[3] Existing."
        ))
        result = analyze_references((page,))

        self.assertEqual(result.citations[0].status, "ambiguous")
        self.assertEqual(result.citations[0].candidate_entry_indexes, (1, 2))
        self.assertEqual(result.citations[1].status, "partial")
        self.assertEqual(result.citations[1].candidate_entry_indexes, (3,))
        self.assertEqual(result.citations[1].unmatched_numbers, (2, 4))
        self.assertEqual(result.missing_reference_numbers, (2, 4))
        self.assertEqual(result.uncited_entry_indexes, ())

    def test_author_year_candidates_preserve_collisions_and_chinese_names(self):
        page = Page(1, (
            "Prior results (Smith et al., 2020) and (张三，2021); see Wang (2022).\n"
            "References\n"
            "[1] Smith, J. First. 2020.\n"
            "[2] Smith, S. Second. 2020.\n"
            "[3] 张三, 李四. 中文标题. 2021.\n"
            "[4] Wang, Z. Third. 2022."
        ))
        result = analyze_references((page,))
        author_year = [anchor for anchor in result.citations
                       if anchor.style == "author_year"]

        self.assertEqual([anchor.text for anchor in author_year],
                         ["(Smith et al., 2020)", "(张三，2021)", "Wang (2022)"])
        self.assertEqual(author_year[0].status, "ambiguous")
        self.assertEqual(author_year[0].candidate_entry_indexes, (1, 2))
        self.assertEqual(author_year[1].status, "matched")
        self.assertEqual(author_year[1].candidate_entry_indexes, (3,))
        self.assertEqual(author_year[2].candidate_entry_indexes, (4,))

    def test_offsets_and_pages_use_joined_original_extraction(self):
        pages = (
            Page(1, "First page [1]\n"),
            Page(2, "Second page [2].\nReferences\n[1] Alpha. 2020\n[2] Beta. 2021"),
        )
        joined = "\n".join(page.text for page in pages)
        result = analyze_references(pages)

        self.assertEqual([anchor.page for anchor in result.citations], [1, 2])
        for anchor in result.citations:
            self.assertEqual(joined[anchor.start_offset:anchor.end_offset], anchor.text)
        self.assertEqual(result.references[0].start_page, 2)
        self.assertEqual(result.references[0].end_page, 2)

    def test_reference_entry_can_continue_across_physical_pages(self):
        pages = (
            Page(1, "See [1].\nReferences\n[1] Smith, J. Article title"),
            Page(2, " continued on next page. 2020."),
        )
        joined = "\n".join(page.text for page in pages)
        result = analyze_references(pages)
        entry = result.references[0]

        self.assertEqual((entry.start_page, entry.end_page), (1, 2))
        self.assertEqual(joined[entry.start_offset:entry.end_offset], entry.text)
        self.assertIn("continued on next page", entry.text)

    def test_stops_reference_section_at_appendix_heading(self):
        result = analyze_references((Page(1, (
            "See [1].\nReferences\n[1] Source.\nAppendix A\n[2] Not a reference."
        )),))
        self.assertEqual([entry.label for entry in result.references], [1])

    def test_no_reference_heading_does_not_invent_entries(self):
        result = analyze_references((Page(1, "Citation [7] without a bibliography."),))
        self.assertFalse(result.reference_section_found)
        self.assertEqual(result.references, ())
        self.assertEqual(result.citations[0].status, "unmapped")
        self.assertEqual(result.missing_reference_numbers, (7,))

    def test_large_numeric_range_is_not_expanded(self):
        result = analyze_references((Page(1, "See [1–200].\nReferences\n[1] Source."),))
        self.assertEqual(result.citations[0].text, "[1–200]")
        self.assertEqual(result.citations[0].status, "unmapped")
        self.assertEqual(result.citations[0].reference_numbers, ())
        self.assertEqual(result.missing_reference_numbers, ())


if __name__ == "__main__":
    unittest.main()
