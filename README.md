# ADA Title II & PDF/UA-1 Auditor (GitHub Action)

Zero-dependency Python 3 GitHub Action that scans `**/*.pdf` in your repository for **ISO 14289-1 (PDF/UA-1)** and **WCAG 2.1 AA** accessibility conformance, writes a crisp Markdown audit table to `$GITHUB_STEP_SUMMARY`, emits pull-request file annotations, and optionally fails CI on non-compliant PDFs.

- **Zero external dependencies**: pure Python 3 standard library only (no `pip install`, no Docker build wait, executes in under 1 second).
- **Handles modern PDFs**: parses uncompressed objects as well as PDF 1.5+ `/ObjStm` compressed object streams and `/FlateDecode` XMP/content streams.
- **Built for ADA Title II & Section 508 teams**: municipalities, transit agencies, housing authorities, universities, SaaS docs portals, and federal contractors.

---

## Quick Start

Add this workflow to `.github/workflows/pdf-accessibility.yml`:

```yaml
name: ADA Title II & PDF/UA-1 Audit

on:
  push:
    paths:
      - "**/*.pdf"
  pull_request:
    paths:
      - "**/*.pdf"

jobs:
  pdf-ua-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Audit repository PDFs for PDF/UA-1 & WCAG 2.1 AA
        uses: oneandroid-max/pdf-ua-audit-action@v1
        with:
          path: "."
          glob: "**/*.pdf"
          fail-on-error: "true"
          min-score: "90"
          fail-severity: "CRITICAL"
          write-summary: "true"
```

---

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Root directory or single PDF path to scan. |
| `glob` | `**/*.pdf` | Recursive glob pattern under `path`. |
| `fail-on-error` | `false` | Set to `true` to fail the CI job if any PDF violates `min-score` or `fail-severity`. |
| `min-score` | `90` | Minimum passing `passScore` (0–100) when `fail-on-error` is `true`. |
| `fail-severity` | `CRITICAL` | Minimum severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) that triggers CI failure. |
| `write-summary` | `true` | Append Markdown audit table to `$GITHUB_STEP_SUMMARY`. |
| `output-json` | `""` | Optional file path to save the full JSON audit payload. |

## Outputs

| Output | Description |
| --- | --- |
| `total-pdfs` | Total number of PDFs scanned. |
| `passed-pdfs` | Count of PDFs scoring `PASS`. |
| `failed-pdfs` | Count of PDFs with conformance issues. |
| `average-score` | Average ISO 14289-1 / WCAG 2.1 AA score (0–100). |
| `estimated-remediation-usd` | Total estimated remediation cost in USD using Second Foreman LLC unit rates. |
| `report-json` | Path to the JSON report if `output-json` was provided. |

---

## Checks Performed

Every discovered PDF is audited for:

1. **`structTreeRoot`** — Tagged logical structure tree (`/StructTreeRoot`, ISO 14289-1 §7.1 / WCAG 1.3.1)
2. **`marked`** — `/MarkInfo << /Marked true >>` indicator (ISO 14289-1 §7.1)
3. **`lang`** — Primary BCP-47 document language (`/Lang`, WCAG 3.1.1 / ISO 14289-1 §7.2)
4. **`title`** — Meaningful document title (`dc:title` / Info `/Title`, WCAG 2.4.2; flags raw Word/filename prefixes)
5. **`displayDocTitle`** — `/ViewerPreferences << /DisplayDocTitle true >>` (ISO 14289-1 §7.1)
6. **`pdfUaXmp`** — XMP `pdfuaid:part=1` conformance identifier (ISO 14289-1 §5)
7. **`scannedImagePages`** — Image-only pages lacking OCR text (WCAG 1.4.5)
8. **`missingAltFigures`** — `/Figure` nodes missing `/Alt`/`/ActualText` or untagged raster images (WCAG 1.1.1)
9. **`tableCount` / `tableHeaderCount`** — `/Table` structures missing `/TH` header cells (WCAG 1.3.1)
10. **`formFieldCount` / `missingTooltips`** — Interactive AcroForm/Widget fields missing `/TU` tooltips (WCAG 4.1.2)

---

## Sample Job Summary Output

```markdown
## ADA Title II & PDF/UA-1 Accessibility Audit

- **PDFs Scanned:** 2 | **Passed:** 1 | **Failed:** 1 | **Avg Score:** 52.5/100 | **Est. Remediation:** $9.00

| File | Score | Severity | Pages | Tagged | Marked | Lang | Display Title | PDF/UA XMP | Scanned | Missing Alt | Forms (No /TU) | Est. Fix |
| --- | ---: | :---: | ---: | :---: | :---: | :---: | :---: | :---: | ---: | ---: | :---: | ---: |
| `docs/ada-guide.pdf` | 5/100 | **CRITICAL** | 6 | No | No | — | No | No | 0 | 13 | 0 | $9.00 |
| `docs/notice-remediated.pdf` | 100/100 | **PASS** | 1 | Yes | Yes | en-US | Yes | Yes | 0 | 0 | 0 | $0.00 |
```

---

## Local Usage & Unit Tests

```bash
# Audit all PDFs in the current directory
python3 audit_pdfs.py --path . --glob "**/*.pdf"

# Run the unit test suite
python3 -m unittest test_audit.py -v
```

---

## Need Failing PDFs Remediated?

Every failing PDF in your CI summary links directly to **[Second Foreman LLC PDF/UA-1 Remediation](https://secondforeman.com/pdf-remediation/)**:

- **Free Page-1 Proof**: Send any failing PDF or URL and receive Page 1 tagged to ISO 14289-1 with a 0-failed-rules **veraPDF 1.30.4** report in 24 hours at zero cost.
- **Fixed-Fee Unit Schedule**: `$1.50/pg` standard text, `$3.00/pg` scanned OCR rebuild, `$4.50/pg` complex tables, `$25–$60` fillable AcroForms, or `$2,500` prepaid 1,650-page Government P-Card / PO block (SAM.gov UEI `U4BYU2ELNVW1`).

## The Foreman's Guarantee & AI Disclosure

> *"You're on the job. I got the floor covered. Guaranteed. If not, you don't pay."*

If any remediated PDF delivered by Second Foreman LLC fails veraPDF 1.30.4 PDF/UA-1 validation, we remediate it at zero cost—or refund/waive the fee.

**Built and operated by an AI agent (Google Gemini) with Paul Lewis human sign-off, guaranteed by Second Foreman LLC.**
