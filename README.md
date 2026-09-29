# Thesis Reliability Check

Evidence-first thesis review for graduate students. **PDF uploads only.**

论文可信度体检：帮助研究生发现前后矛盾、参考文献信息异常、引用支持不足和格式问题，提供可定位、可解释、可复核的证据。AI 发现异常，人做最终判断。

## Status

Foundation only, not a completed audit service. This first slice provides in-memory PDF intake and evidence contracts with offline synthetic tests. No web server, external scholarly API or LLM is called. No manuscript is stored. Reports, user accounts and deletion workflows are planned, not implemented.

## Local development

Use Python 3.11 or 3.12 in a virtual environment:

```sh
python -m venv .venv
# Activate the virtual environment for your operating system.
python -m pip install -r requirements.txt
python -m unittest -v
```

`audit_contract.parse_pdf(filename, data)` accepts a PDF of at most 20 MiB and 300 pages. It rejects other extensions, invalid signatures, corrupt/encrypted files and any textless page. This conservative first version also rejects legitimate blank pages; better partial-coverage handling is tracked separately. OCR, tables, formula interpretation and reading-order guarantees are not implemented. Text presence alone is not proof of correct extraction.

Never expose this parser directly to untrusted internet traffic: isolated workers with CPU/memory/time limits and bounded request streaming are release prerequisites. The byte check happens after bytes are supplied to this library function.

## Core roadmap

1. Foundation and reproducible tests.
2. PDF-only upload, isolated parsing and structure/citation extraction.
3. Reference metadata matching with explicit uncertainty.
4. Claim → citation → source → exact evidence → assessment.
5. Cross-section consistency and configurable reference style checks.
6. Coverage-aware report UI, privacy lifecycle and human evaluation.

Read [MVP product and technical plan](MVP_PLAN.md) for architecture, API contracts, acceptance gates, license proposal and detailed task breakdown.

## Evidence and privacy

- A database miss is **unable to verify**, not evidence of fabrication.
- A quote match only establishes grounding, not that a source supports a claim.
- Report physical PDF pages separately from optional printed page labels.
- No AI-generation percentage, automated misconduct verdict or auto-rewriting.
- Never commit user manuscripts, real reports, API keys or credentials.
- Synthetic fixtures are generated in memory by tests; no private PDFs are included.

## Contributing

Issue → feature branch → tests → self-review → pull request → owner approval → merge. Do not push directly to main. PRs must explain What, Why, Changes, Tests, Screenshots (when relevant), Risks, Security/Privacy, Evidence and Rollback. Do not include manuscript excerpts in public bug reports.

## License

The repository currently contains MIT, chosen during repository creation. This PR preserves it. Alternative licensing is a proposal only and requires the owner's explicit decision.

## Demo, citation and contact

No live demo or publication exists yet. Use repository Issues for non-sensitive feedback. A release citation file and screenshots will be added when a release exists; do not cite this scaffold as a validated detection system.
