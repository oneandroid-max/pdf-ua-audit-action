#!/usr/bin/env python3
"""Unit tests for the zero-dependency ADA Title II & PDF/UA-1 GitHub Action."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import zlib
from pathlib import Path

import audit_pdfs


def _build_pdf(objects: dict[int, bytes], root_num: int, info_num: int | None = None) -> bytes:
    """Assemble a valid minimal PDF 1.7 file from an object map."""
    chunks = [b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"]
    offsets: dict[int, int] = {}
    for obj_num in sorted(objects):
        offsets[obj_num] = sum(len(c) for c in chunks)
        chunks.append(f"{obj_num} 0 obj\n".encode("ascii") + objects[obj_num] + b"\nendobj\n")

    xref_pos = sum(len(c) for c in chunks)
    max_obj = max(objects) if objects else 0
    xref_lines = [f"xref\n0 {max_obj + 1}\n0000000000 65535 f \n".encode("ascii")]
    for i in range(1, max_obj + 1):
        if i in offsets:
            xref_lines.append(f"{offsets[i]:010d} 00000 n \n".encode("ascii"))
        else:
            xref_lines.append(b"0000000000 65535 f \n")
    chunks.extend(xref_lines)

    info_entry = f" /Info {info_num} 0 R" if info_num is not None else ""
    trailer = (
        f"trailer\n<< /Size {max_obj + 1} /Root {root_num} 0 R{info_entry} >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode("ascii")
    chunks.append(trailer)
    return b"".join(chunks)


def _make_failing_untagged_pdf() -> bytes:
    """Untagged PDF missing StructTreeRoot, MarkInfo, Lang, DisplayDocTitle, XMP pdfuaid, and Alt text."""
    content = b"BT /F1 12 Tf 72 720 Td (Public Meeting Agenda - Untagged) Tj ET"
    img_data = b"\x00" * 16
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>",
        4: f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream",
        5: (
            f"<< /Type /XObject /Subtype /Image /Width 320 /Height 240 /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length {len(img_data)} >>\nstream\n".encode("ascii")
            + img_data
            + b"\nendstream"
        ),
        6: b"<< /Title (Microsoft Word - City_Council_Agenda.docx) >>",
    }
    return _build_pdf(objects, root_num=1, info_num=6)


def _make_passing_pdfua_pdf() -> bytes:
    """Fully compliant ISO 14289-1 (PDF/UA-1) tagged PDF."""
    content = b"BT /F1 12 Tf 72 720 Td (Notice of Public Hearing for 2027 Annual Plan) Tj ET"
    xmp = (
        '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
        '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
        '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
        '<rdf:Description rdf:about="" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" '
        'xmlns:pdfuaid="http://www.aiim.org/pdfua/ns/id/">'
        '<dc:title><rdf:Alt><rdf:li xml:lang="x-default">2027 Annual Plan Notice of Public Hearing</rdf:li></rdf:Alt></dc:title>'
        "<pdfuaid:part>1</pdfuaid:part>"
        "</rdf:Description></rdf:RDF></x:xmpmeta>"
        '<?xpacket end="w"?>'
    ).encode("utf-8")

    objects = {
        1: (
            b"<< /Type /Catalog /Pages 2 0 R /Lang (en-US) "
            b"/MarkInfo << /Marked true >> "
            b"/ViewerPreferences << /DisplayDocTitle true >> "
            b"/StructTreeRoot 5 0 R "
            b"/Metadata 8 0 R >>"
        ),
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        4: f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream",
        5: b"<< /Type /StructTreeRoot /K [6 0 R] >>",
        6: b"<< /Type /StructElem /S /Document /P 5 0 R /K [7 0 R] >>",
        7: b"<< /Type /StructElem /S /Figure /P 6 0 R /Alt (Official agency seal) >>",
        8: f"<< /Type /Metadata /Subtype /XML /Length {len(xmp)} >>\nstream\n".encode("ascii") + xmp + b"\nendstream",
        9: b"<< /Title (2027 Annual Plan Notice of Public Hearing) >>",
    }
    return _build_pdf(objects, root_num=1, info_num=9)


def _make_objstm_and_forms_pdf() -> bytes:
    """PDF using compressed /ObjStm (PDF 1.5+) plus a headerless Table and form field missing /TU."""
    # Pack objects 5 (StructTreeRoot) and 6 (Table) and 7 (Form Field) into an /ObjStm
    obj5 = b"<< /Type /StructTreeRoot /K [6 0 R] >>"
    obj6 = b"<< /Type /StructElem /S /Table /P 5 0 R >>"
    obj7 = b"<< /FT /Tx /T (ApplicantName) /Subtype /Widget >>"
    off5 = 0
    off6 = len(obj5) + 1
    off7 = off6 + len(obj6) + 1
    header = f"5 {off5} 6 {off6} 7 {off7}\n".encode("ascii")
    payload = header + obj5 + b"\n" + obj6 + b"\n" + obj7
    compressed = zlib.compress(payload)

    content = b"BT /F1 12 Tf 72 720 Td (Permit Application Form with Data Table) Tj ET"
    objects = {
        1: (
            b"<< /Type /Catalog /Pages 2 0 R /Lang (en-US) "
            b"/MarkInfo << /Marked true >> "
            b"/ViewerPreferences << /DisplayDocTitle true >> "
            b"/StructTreeRoot 5 0 R "
            b"/AcroForm << /Fields [7 0 R] >> >>"
        ),
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
        4: f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream",
        8: (
            f"<< /Type /ObjStm /N 3 /First {len(header)} /Filter /FlateDecode /Length {len(compressed)} >>\nstream\n".encode("ascii")
            + compressed
            + b"\nendstream"
        ),
        9: b"<< /Title (Permit Application Form) >>",
    }
    return _build_pdf(objects, root_num=1, info_num=9)


def _make_scanned_image_only_pdf() -> bytes:
    """Scanned image-only PDF with large raster page image and zero text operators."""
    content = b"q 612 0 0 792 0 0 cm /Im1 Do Q"
    img_data = b"\xff" * 32
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im1 5 0 R >> >> /Contents 4 0 R >>",
        4: f"<< /Length {len(content)} >>\nstream\n".encode("ascii") + content + b"\nendstream",
        5: (
            f"<< /Type /XObject /Subtype /Image /Width 1700 /Height 2200 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length {len(img_data)} >>\nstream\n".encode("ascii")
            + img_data
            + b"\nendstream"
        ),
    }
    return _build_pdf(objects, root_num=1)


class TestPdfUaAuditAction(unittest.TestCase):
    def test_failing_untagged_pdf_scores_critical(self) -> None:
        result = audit_pdfs.audit_pdf_bytes(_make_failing_untagged_pdf(), file_path="docs/failing.pdf")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertLess(result["passScore"], 30)
        self.assertFalse(result["structTreeRoot"])
        self.assertFalse(result["marked"])
        self.assertIsNone(result["lang"])
        self.assertFalse(result["displayDocTitle"])
        self.assertFalse(result["pdfUaXmp"])
        self.assertEqual(result["pageCount"], 1)
        self.assertEqual(result["missingAltFigures"], 1)
        self.assertGreater(result["remediationEstimateUsd"], 0.0)

    def test_passing_pdfua_pdf_scores_100_pass(self) -> None:
        result = audit_pdfs.audit_pdf_bytes(_make_passing_pdfua_pdf(), file_path="docs/passing.pdf")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["severity"], "PASS")
        self.assertEqual(result["passScore"], 100)
        self.assertTrue(result["structTreeRoot"])
        self.assertTrue(result["marked"])
        self.assertEqual(result["lang"], "en-US")
        self.assertEqual(result["title"], "2027 Annual Plan Notice of Public Hearing")
        self.assertTrue(result["displayDocTitle"])
        self.assertTrue(result["pdfUaXmp"])
        self.assertEqual(result["missingAltFigures"], 0)
        self.assertEqual(result["remediationEstimateUsd"], 0.0)
        self.assertEqual(result["issues"], [])

    def test_objstm_decompression_tables_and_form_tooltips(self) -> None:
        result = audit_pdfs.audit_pdf_bytes(_make_objstm_and_forms_pdf(), file_path="forms/permit.pdf")
        self.assertTrue(result["structTreeRoot"])
        self.assertEqual(result["tableCount"], 1)
        self.assertEqual(result["tableHeaderCount"], 0)
        self.assertEqual(result["formFieldCount"], 1)
        self.assertEqual(result["missingTooltips"], 1)
        self.assertEqual(result["status"], "FAIL")
        # 1 table page ($4.50) + 1 form field ($25.00) = $29.50
        self.assertEqual(result["remediationEstimateUsd"], 29.50)

    def test_scanned_image_only_pdf_detected(self) -> None:
        result = audit_pdfs.audit_pdf_bytes(_make_scanned_image_only_pdf(), file_path="scans/minutes.pdf")
        self.assertEqual(result["pageCount"], 1)
        self.assertEqual(result["scannedImagePages"], 1)
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertEqual(result["remediationEstimateUsd"], 3.00)

    def test_cli_scans_glob_writes_summary_outputs_and_enforces_ci_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "public" / "notices").mkdir(parents=True)
            (root / "public" / "notices" / "failing.pdf").write_bytes(_make_failing_untagged_pdf())
            (root / "public" / "passing.pdf").write_bytes(_make_passing_pdfua_pdf())

            summary_file = root / "step_summary.md"
            output_file = root / "github_output.txt"
            json_report = root / "report.json"

            old_summary = os.environ.get("GITHUB_STEP_SUMMARY")
            old_output = os.environ.get("GITHUB_OUTPUT")
            try:
                os.environ["GITHUB_STEP_SUMMARY"] = str(summary_file)
                os.environ["GITHUB_OUTPUT"] = str(output_file)

                # Non-blocking mode exits 0
                rc_soft = audit_pdfs.main(
                    [
                        "--path",
                        str(root),
                        "--glob",
                        "**/*.pdf",
                        "--fail-on-error",
                        "false",
                        "--output-json",
                        str(json_report),
                    ]
                )
                self.assertEqual(rc_soft, 0)

                summary_text = summary_file.read_text(encoding="utf-8")
                self.assertIn("| File | Score | Severity |", summary_text)
                self.assertIn("public/notices/failing.pdf", summary_text)
                self.assertIn("public/passing.pdf", summary_text)
                self.assertIn("https://secondforeman.com/pdf-remediation/", summary_text)
                self.assertIn(
                    "Built and operated by an AI agent (Google Gemini) with Paul Lewis human sign-off, guaranteed by Second Foreman LLC.",
                    summary_text,
                )

                gh_outputs = output_file.read_text(encoding="utf-8")
                self.assertIn("total-pdfs=2", gh_outputs)
                self.assertIn("passed-pdfs=1", gh_outputs)
                self.assertIn("failed-pdfs=1", gh_outputs)

                payload = json.loads(json_report.read_text(encoding="utf-8"))
                self.assertEqual(payload["summary"]["totalPdfs"], 2)
                self.assertEqual(payload["summary"]["passedPdfs"], 1)
                self.assertEqual(payload["summary"]["failedPdfs"], 1)

                # Blocking mode exits 1 when failing PDF is present
                rc_fail = audit_pdfs.main(
                    [
                        "--path",
                        str(root),
                        "--glob",
                        "**/*.pdf",
                        "--fail-on-error",
                        "true",
                        "--min-score",
                        "90",
                    ]
                )
                self.assertEqual(rc_fail, 1)

                # Blocking mode exits 0 when only passing PDF is scanned
                rc_pass = audit_pdfs.main(
                    [
                        "--path",
                        str(root / "public" / "passing.pdf"),
                        "--fail-on-error",
                        "true",
                        "--min-score",
                        "90",
                    ]
                )
                self.assertEqual(rc_pass, 0)
            finally:
                if old_summary is None:
                    os.environ.pop("GITHUB_STEP_SUMMARY", None)
                else:
                    os.environ["GITHUB_STEP_SUMMARY"] = old_summary
                if old_output is None:
                    os.environ.pop("GITHUB_OUTPUT", None)
                else:
                    os.environ["GITHUB_OUTPUT"] = old_output


if __name__ == "__main__":
    unittest.main(verbosity=2)
