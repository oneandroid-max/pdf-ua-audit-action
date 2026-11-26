#!/usr/bin/env python3
"""Zero-dependency ISO 14289-1 (PDF/UA-1) & WCAG 2.1 AA PDF accessibility auditor.

Pure Python 3 standard library only — zero external packages required.
Designed for GitHub Actions CI pipelines and local ADA Title II audits.

Built and operated by an AI agent (Google Gemini) with Paul Lewis human sign-off,
guaranteed by Second Foreman LLC (https://secondforeman.com/pdf-remediation/).
"""

from __future__ import annotations

import argparse
import glob as glob_mod
import json
import math
import os
import re
import sys
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REMEDIATION_URL = "https://secondforeman.com/pdf-remediation/"

# Published Second Foreman LLC unit rates (Fixed-Fee Remediation Order Schedule)
RATE_STANDARD_TEXT_PAGE = 1.50
RATE_SCANNED_OCR_PAGE = 3.00
RATE_COMPLEX_TABLE_PAGE = 4.50

SEVERITY_RANK = {
    "PASS": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

_FILENAME_TITLE_RE = re.compile(
    r"^(microsoft\s+word\s*-|untitled|document\d*|slide\s*\d*|powerpoint\s+presentation|"
    r"adobe\s+indesign|word\s+document)|(\.(pdf|docx?|xlsx?|pptx?|pub|indd|txt|rtf))$",
    re.IGNORECASE,
)

_OBJ_HEADER_RE = re.compile(rb"(?:^|[\r\n\s])(\d+)\s+(\d+)\s+obj\b")
_REF_RE = re.compile(rb"^\s*(\d+)\s+(\d+)\s+R\b")
_ALL_REFS_RE = re.compile(rb"(\d+)\s+(\d+)\s+R\b")


@dataclass
class PdfObject:
    obj_num: int
    raw: bytes
    dict_bytes: bytes
    stream_bytes: bytes | None = None


def _find_matching_dict(data: bytes, start: int) -> int:
    """Given index of '<<', return index immediately after matching '>>'."""
    depth = 0
    i = start
    n = len(data)
    in_parens = 0
    while i < n:
        ch = data[i]
        if in_parens > 0:
            if ch == 0x5C:  # backslash escape
                i += 2
                continue
            if ch == 0x28:  # '('
                in_parens += 1
            elif ch == 0x29:  # ')'
                in_parens -= 1
            i += 1
            continue
        if ch == 0x28:  # '('
            in_parens = 1
            i += 1
            continue
        if ch == 0x25:  # '%' comment
            nl = data.find(b"\n", i)
            cr = data.find(b"\r", i)
            ends = [p for p in (nl, cr) if p != -1]
            i = min(ends) + 1 if ends else n
            continue
        if ch == 0x3C and i + 1 < n and data[i + 1] == 0x3C:  # '<<'
            depth += 1
            i += 2
            continue
        if ch == 0x3E and i + 1 < n and data[i + 1] == 0x3E:  # '>>'
            depth -= 1
            i += 2
            if depth <= 0:
                return i
            continue
        i += 1
    return n


def _find_matching_array(data: bytes, start: int) -> int:
    """Given index of '[', return index immediately after matching ']'."""
    depth = 0
    i = start
    n = len(data)
    in_parens = 0
    while i < n:
        ch = data[i]
        if in_parens > 0:
            if ch == 0x5C:
                i += 2
                continue
            if ch == 0x28:
                in_parens += 1
            elif ch == 0x29:
                in_parens -= 1
            i += 1
            continue
        if ch == 0x28:
            in_parens = 1
            i += 1
            continue
        if ch == 0x5B:  # '['
            depth += 1
        elif ch == 0x5D:  # ']'
            depth -= 1
            if depth <= 0:
                return i + 1
        i += 1
    return n


def _find_matching_paren(data: bytes, start: int) -> int:
    """Given index of '(', return index immediately after matching ')'."""
    depth = 0
    i = start
    n = len(data)
    while i < n:
        ch = data[i]
        if ch == 0x5C:  # backslash
            i += 2
            continue
        if ch == 0x28:
            depth += 1
        elif ch == 0x29:
            depth -= 1
            if depth <= 0:
                return i + 1
        i += 1
    return n


def _decode_pdf_bytes_text(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        text = raw[2:].decode("utf-16-be", errors="replace")
    elif raw.startswith(b"\xff\xfe"):
        text = raw[2:].decode("utf-16-le", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    return re.sub(r"\s+", " ", text.replace("\x00", "")).strip()


def _decode_pdf_literal(token: bytes) -> str:
    """Decode a PDF literal string '(...)' including escapes and UTF-16BE BOM."""
    if token.startswith(b"(") and token.endswith(b")"):
        inner = token[1:-1]
    else:
        inner = token
    out = bytearray()
    i = 0
    n = len(inner)
    escape_map = {
        ord("n"): 10,
        ord("r"): 13,
        ord("t"): 9,
        ord("b"): 8,
        ord("f"): 12,
        ord("("): ord("("),
        ord(")"): ord(")"),
        ord("\\"): ord("\\"),
    }
    while i < n:
        ch = inner[i]
        if ch == 0x5C and i + 1 < n:
            nxt = inner[i + 1]
            if nxt in escape_map:
                out.append(escape_map[nxt])
                i += 2
            elif nxt in (10, 13):  # line continuation
                i += 2
                if nxt == 13 and i < n and inner[i] == 10:
                    i += 1
            elif 48 <= nxt <= 55:  # octal escape \ddd
                oct_digits = bytes([nxt])
                j = i + 2
                while j < n and len(oct_digits) < 3 and 48 <= inner[j] <= 55:
                    oct_digits += bytes([inner[j]])
                    j += 1
                out.append(int(oct_digits, 8) & 0xFF)
                i = j
            else:
                out.append(nxt)
                i += 2
        else:
            out.append(ch)
            i += 1
    return _decode_pdf_bytes_text(bytes(out))


def _decode_pdf_hex(token: bytes) -> str:
    inner = token.strip(b"<> \t\r\n")
    inner = re.sub(rb"\s+", b"", inner)
    if len(inner) % 2 == 1:
        inner += b"0"
    try:
        raw = bytes.fromhex(inner.decode("ascii"))
    except Exception:
        return ""
    return _decode_pdf_bytes_text(raw)


def _dict_get_raw_value(dict_bytes: bytes, key: bytes) -> bytes | None:
    """Extract the top-level PDF value bytes associated with /Key in a << ... >> dict."""
    if not dict_bytes:
        return None
    start = dict_bytes.find(b"<<")
    if start == -1:
        return None
    end = _find_matching_dict(dict_bytes, start)
    inner = dict_bytes[start + 2 : max(start + 2, end - 2)]

    i = 0
    n = len(inner)
    while i < n:
        # Skip whitespace and comments
        while i < n and inner[i] in b" \t\r\n\f\x00":
            i += 1
        if i >= n:
            break
        if inner[i] == 0x25:  # '%'
            nl = inner.find(b"\n", i)
            i = nl + 1 if nl != -1 else n
            continue
        if inner[i] != 0x2F:  # must start with '/'
            i += 1
            continue

        # Read key name
        k_start = i
        i += 1
        while i < n and inner[i] not in b" \t\r\n\f/[]<>(){}%":
            i += 1
        cur_key = inner[k_start:i]

        # Skip whitespace before value
        while i < n and inner[i] in b" \t\r\n\f\x00":
            i += 1
        if i >= n:
            break

        # Read value token
        v_start = i
        ch = inner[i]
        if ch == 0x3C and i + 1 < n and inner[i + 1] == 0x3C:  # << ... >>
            v_end = _find_matching_dict(inner, i)
        elif ch == 0x3C:  # <hex>
            gt = inner.find(b">", i + 1)
            v_end = gt + 1 if gt != -1 else n
        elif ch == 0x5B:  # [...]
            v_end = _find_matching_array(inner, i)
        elif ch == 0x28:  # (...)
            v_end = _find_matching_paren(inner, i)
        elif ch == 0x2F:  # /Name
            j = i + 1
            while j < n and inner[j] not in b" \t\r\n\f/[]<>(){}%":
                j += 1
            v_end = j
        else:
            # Check for indirect reference 'N G R'
            m_ref = _REF_RE.match(inner[i:])
            if m_ref:
                v_end = i + m_ref.end()
            else:
                j = i
                while j < n and inner[j] not in b" \t\r\n\f/[]<>(){}%":
                    j += 1
                v_end = j

        val = inner[v_start:v_end].strip()
        if cur_key == key:
            return val
        i = v_end

    return None


def _decompress_stream(dict_bytes: bytes, stream_bytes: bytes | None) -> bytes | None:
    if stream_bytes is None:
        return None
    filt = _dict_get_raw_value(dict_bytes, b"/Filter")
    if not filt:
        return stream_bytes
    if b"/FlateDecode" in filt and b"/DCTDecode" not in filt and b"/JPXDecode" not in filt:
        # Handle predictor if none or standard zlib stream
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 32):
            try:
                return zlib.decompress(stream_bytes.strip(b"\r\n"), wbits)
            except Exception:
                try:
                    return zlib.decompress(stream_bytes, wbits)
                except Exception:
                    continue
        return None
    return None


def _parse_pdf_objects(data: bytes) -> tuple[dict[int, PdfObject], int | None, int | None]:
    """Parse indirect objects, ObjStm compressed objects, and trailer /Root + /Info refs."""
    objects: dict[int, PdfObject] = {}
    pos = 0
    n = len(data)

    while pos < n:
        m = _OBJ_HEADER_RE.search(data, pos)
        if not m:
            break
        obj_num = int(m.group(1))
        body_start = m.end()

        # Skip whitespace after 'obj'
        i = body_start
        while i < n and data[i] in b" \t\r\n":
            i += 1

        dict_bytes = b""
        stream_bytes: bytes | None = None

        if i + 1 < n and data[i : i + 2] == b"<<":
            dict_end = _find_matching_dict(data, i)
            dict_bytes = data[i:dict_end]
            after = dict_end
            while after < n and data[after] in b" \t\r\n":
                after += 1

            if data[after : after + 6] == b"stream":
                s_start = after + 6
                if s_start < n and data[s_start] == 13:  # \r
                    s_start += 1
                if s_start < n and data[s_start] == 10:  # \n
                    s_start += 1

                # Use direct integer /Length when available for exact binary slicing
                length_val = _dict_get_raw_value(dict_bytes, b"/Length")
                s_end = -1
                if length_val and length_val.isdigit():
                    declared_len = int(length_val)
                    cand_end = s_start + declared_len
                    # Verify endstream follows shortly after declared_len
                    probe = data[cand_end : cand_end + 32]
                    if b"endstream" in probe:
                        s_end = cand_end
                if s_end == -1:
                    s_end = data.find(b"endstream", s_start)
                if s_end == -1:
                    pos = after + 6
                    continue

                stream_bytes = data[s_start:s_end]
                endobj_idx = data.find(b"endobj", s_end)
                raw = data[body_start:endobj_idx] if endobj_idx != -1 else dict_bytes
                pos = endobj_idx + 6 if endobj_idx != -1 else s_end + 9
            else:
                endobj_idx = data.find(b"endobj", dict_end)
                raw = data[body_start:endobj_idx] if endobj_idx != -1 else dict_bytes
                pos = endobj_idx + 6 if endobj_idx != -1 else dict_end
        else:
            endobj_idx = data.find(b"endobj", body_start)
            if endobj_idx == -1:
                break
            raw = data[body_start:endobj_idx].strip()
            pos = endobj_idx + 6

        objects[obj_num] = PdfObject(
            obj_num=obj_num,
            raw=raw.strip(),
            dict_bytes=dict_bytes,
            stream_bytes=stream_bytes,
        )

    # Decompress /ObjStm (PDF 1.5+ compressed object streams)
    for obj in list(objects.values()):
        obj_type = _dict_get_raw_value(obj.dict_bytes, b"/Type")
        if obj_type != b"/ObjStm":
            continue
        decompressed = _decompress_stream(obj.dict_bytes, obj.stream_bytes)
        if not decompressed:
            continue
        first_val = _dict_get_raw_value(obj.dict_bytes, b"/First")
        n_val = _dict_get_raw_value(obj.dict_bytes, b"/N")
        if not (first_val and first_val.isdigit() and n_val and n_val.isdigit()):
            continue
        first_off = int(first_val)
        count = int(n_val)
        header_tokens = decompressed[:first_off].decode("latin1", errors="ignore").split()
        pairs: list[tuple[int, int]] = []
        for idx in range(0, min(len(header_tokens) - 1, count * 2), 2):
            try:
                pairs.append((int(header_tokens[idx]), int(header_tokens[idx + 1])))
            except ValueError:
                break
        body = decompressed[first_off:]
        for idx, (sub_num, rel_off) in enumerate(pairs):
            next_off = pairs[idx + 1][1] if idx + 1 < len(pairs) else len(body)
            chunk = body[rel_off:next_off].strip()
            sub_dict = b""
            if chunk.startswith(b"<<"):
                sub_dict = chunk[: _find_matching_dict(chunk, 0)]
            if sub_num not in objects:
                objects[sub_num] = PdfObject(obj_num=sub_num, raw=chunk, dict_bytes=sub_dict)

    # Locate latest /Root and /Info refs from trailer dicts or /XRef stream dicts
    root_num: int | None = None
    info_num: int | None = None

    for m_tr in re.finditer(rb"trailer\s*<<", data):
        d_start = m_tr.end() - 2
        d_end = _find_matching_dict(data, d_start)
        td = data[d_start:d_end]
        r_val = _dict_get_raw_value(td, b"/Root")
        if r_val:
            mr = _REF_RE.match(r_val)
            if mr:
                root_num = int(mr.group(1))
        i_val = _dict_get_raw_value(td, b"/Info")
        if i_val:
            mi = _REF_RE.match(i_val)
            if mi:
                info_num = int(mi.group(1))

    # Also check /Type /XRef objects (PDF 1.5+ cross-reference streams)
    for obj in objects.values():
        if _dict_get_raw_value(obj.dict_bytes, b"/Type") == b"/XRef":
            r_val = _dict_get_raw_value(obj.dict_bytes, b"/Root")
            if r_val:
                mr = _REF_RE.match(r_val)
                if mr:
                    root_num = int(mr.group(1))
            i_val = _dict_get_raw_value(obj.dict_bytes, b"/Info")
            if i_val:
                mi = _REF_RE.match(i_val)
                if mi:
                    info_num = int(mi.group(1))

    # Fallback: find /Type /Catalog directly
    if root_num is None:
        for obj in objects.values():
            if _dict_get_raw_value(obj.dict_bytes, b"/Type") == b"/Catalog":
                root_num = obj.obj_num
                break

    return objects, root_num, info_num


class PurePdfInspector:
    """Zero-dependency PDF structure & accessibility inspector."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.objects, self.root_num, self.info_num = _parse_pdf_objects(data)

    def resolve_dict(self, val: bytes | None) -> bytes | None:
        if not val:
            return None
        val = val.strip()
        if val.startswith(b"<<"):
            return val
        m = _REF_RE.match(val)
        if m:
            obj = self.objects.get(int(m.group(1)))
            if obj and obj.dict_bytes:
                return obj.dict_bytes
        return None

    def resolve_obj(self, val: bytes | None) -> PdfObject | None:
        if not val:
            return None
        m = _REF_RE.match(val.strip())
        if m:
            return self.objects.get(int(m.group(1)))
        return None

    def resolve_string(self, val: bytes | None) -> str | None:
        if not val:
            return None
        val = val.strip()
        m = _REF_RE.match(val)
        if m:
            obj = self.objects.get(int(m.group(1)))
            if obj:
                val = obj.raw.strip()
            else:
                return None
        if val.startswith(b"("):
            return _decode_pdf_literal(val) or None
        if val.startswith(b"<") and not val.startswith(b"<<"):
            return _decode_pdf_hex(val) or None
        return None

    def extract_xmp(self, root_dict: bytes) -> tuple[bool, str | None]:
        meta_obj = self.resolve_obj(_dict_get_raw_value(root_dict, b"/Metadata"))
        if not meta_obj:
            return False, None
        raw = _decompress_stream(meta_obj.dict_bytes, meta_obj.stream_bytes)
        if not raw:
            return False, None

        xmp_text = raw.decode("utf-8", errors="replace")
        has_pdfua_ns = "http://www.aiim.org/pdfua/ns/id/" in xmp_text.lower()
        has_pdfua_part = bool(
            re.search(r"pdfuaid:part\s*(?:=\s*['\"]1['\"]|>\s*1\s*<)", xmp_text, re.IGNORECASE)
        )
        pdf_ua_xmp = has_pdfua_ns and has_pdfua_part
        if not pdf_ua_xmp and has_pdfua_ns and "pdfuaid" in xmp_text.lower():
            pdf_ua_xmp = bool(re.search(r"<[^>]*part[^>]*>\s*1\s*<", xmp_text, re.IGNORECASE))

        xmp_title: str | None = None
        try:
            s = xmp_text.find("<x:xmpmeta")
            e = xmp_text.rfind("</x:xmpmeta>")
            xml_slice = xmp_text[s : e + len("</x:xmpmeta>")] if s != -1 and e != -1 else xmp_text
            tree = ET.fromstring(xml_slice)
            for elem in tree.iter():
                if elem.tag.endswith("}title") or elem.tag == "title":
                    parts = [t.strip() for t in elem.itertext() if t and t.strip()]
                    if parts:
                        xmp_title = re.sub(r"\s+", " ", " ".join(parts)).strip()
                        break
        except Exception:
            m = re.search(r"<dc:title[^>]*>.*?</dc:title>", xmp_text, re.IGNORECASE | re.DOTALL)
            if m:
                cleaned = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(0))).strip()
                if cleaned:
                    xmp_title = cleaned

        return pdf_ua_xmp, xmp_title

    def walk_struct_tree(self, struct_root_dict: bytes) -> dict[str, int]:
        role_map: dict[str, str] = {}
        rm_dict = self.resolve_dict(_dict_get_raw_value(struct_root_dict, b"/RoleMap"))
        if rm_dict:
            for k, v in re.findall(rb"(/[A-Za-z0-9_.+-]+)\s+(/[A-Za-z0-9_.+-]+)", rm_dict):
                role_map[k.decode("latin1")] = v.decode("latin1")

        def _resolve_role(tag: str) -> str:
            seen: set[str] = set()
            cur = tag
            while cur in role_map and cur not in seen:
                seen.add(cur)
                cur = role_map[cur]
            return cur

        counts = {
            "missing_alt_figures": 0,
            "table_count": 0,
            "table_header_count": 0,
        }
        visited_objs: set[int] = set()

        def _visit_dict(d: bytes) -> None:
            s_val = _dict_get_raw_value(d, b"/S")
            if s_val and s_val.startswith(b"/"):
                role = _resolve_role(s_val.decode("latin1", errors="ignore"))
                if role == "/Figure":
                    alt = self.resolve_string(_dict_get_raw_value(d, b"/Alt"))
                    actual = self.resolve_string(_dict_get_raw_value(d, b"/ActualText"))
                    if not alt and not actual:
                        counts["missing_alt_figures"] += 1
                elif role == "/Table":
                    counts["table_count"] += 1
                elif role == "/TH":
                    counts["table_header_count"] += 1

            k_val = _dict_get_raw_value(d, b"/K")
            if k_val:
                _visit_k(k_val)

        def _visit_k(val: bytes) -> None:
            val = val.strip()
            if val.startswith(b"<<"):
                _visit_dict(val)
                return
            m = _REF_RE.match(val)
            if m:
                oid = int(m.group(1))
                if oid not in visited_objs:
                    visited_objs.add(oid)
                    obj = self.objects.get(oid)
                    if obj and obj.dict_bytes:
                        _visit_dict(obj.dict_bytes)
                return
            if val.startswith(b"["):
                # Scan inline dicts and indirect references inside /K array
                for m_ref in _ALL_REFS_RE.finditer(val):
                    oid = int(m_ref.group(1))
                    if oid not in visited_objs:
                        visited_objs.add(oid)
                        obj = self.objects.get(oid)
                        if obj and obj.dict_bytes:
                            _visit_dict(obj.dict_bytes)
                # Also check inline << ... >> dicts in array
                idx = 1
                while idx < len(val):
                    d_pos = val.find(b"<<", idx)
                    if d_pos == -1:
                        break
                    d_end = _find_matching_dict(val, d_pos)
                    _visit_dict(val[d_pos:d_end])
                    idx = d_end

        _visit_dict(struct_root_dict)
        return counts

    def _extract_page_text_len(self, page_dict: bytes) -> int:
        contents_val = _dict_get_raw_value(page_dict, b"/Contents")
        if not contents_val:
            return 0
        refs: list[int] = []
        m = _REF_RE.match(contents_val.strip())
        if m:
            refs.append(int(m.group(1)))
        elif contents_val.strip().startswith(b"["):
            refs.extend(int(mr.group(1)) for mr in _ALL_REFS_RE.finditer(contents_val))

        total_chars = 0
        for oid in refs:
            obj = self.objects.get(oid)
            if not obj:
                continue
            stream = _decompress_stream(obj.dict_bytes, obj.stream_bytes)
            if not stream:
                continue
            # Extract text operands inside Tj / TJ / ' / " operators
            for lit in re.findall(rb"\((?:\\.|[^\\)])*\)\s*(?:Tj|'|\")", stream):
                paren_end = lit.rfind(b")")
                if paren_end != -1:
                    total_chars += len(_decode_pdf_literal(lit[: paren_end + 1]))
            for hex_s in re.findall(rb"<([0-9A-Fa-f\s]+)>\s*(?:Tj|'|\")", stream):
                total_chars += max(1, len(re.sub(rb"\s+", b"", hex_s)) // 2)
            for tj_arr in re.findall(rb"\[(.*?)\]\s*TJ", stream, re.DOTALL):
                for lit in re.findall(rb"\((?:\\.|[^\\)])*\)", tj_arr):
                    total_chars += len(_decode_pdf_literal(lit))
                for hex_s in re.findall(rb"<([0-9A-Fa-f\s]+)>", tj_arr):
                    total_chars += max(1, len(re.sub(rb"\s+", b"", hex_s)) // 2)
        return total_chars

    def audit_pages(self, root_dict: bytes) -> tuple[int, int, int]:
        """Return (page_count, scanned_image_pages, meaningful_untagged_images)."""
        page_objs: list[PdfObject] = [
            obj
            for obj in self.objects.values()
            if _dict_get_raw_value(obj.dict_bytes, b"/Type") == b"/Page"
        ]
        pages_root = self.resolve_dict(_dict_get_raw_value(root_dict, b"/Pages"))
        declared_count = 0
        if pages_root:
            cnt = _dict_get_raw_value(pages_root, b"/Count")
            if cnt and cnt.isdigit():
                declared_count = int(cnt)
        page_count = max(len(page_objs), declared_count)

        scanned_pages = 0
        meaningful_images = 0

        for page in page_objs:
            smask_objs: set[int] = set()
            image_objs: list[tuple[int, bytes]] = []

            def _collect_xobjs(res_val: bytes | None, depth: int = 0) -> None:
                if depth > 2:
                    return
                res_dict = self.resolve_dict(res_val)
                if not res_dict:
                    return
                xobj_dict = self.resolve_dict(_dict_get_raw_value(res_dict, b"/XObject"))
                if not xobj_dict:
                    return
                for mr in _ALL_REFS_RE.finditer(xobj_dict):
                    oid = int(mr.group(1))
                    xobj = self.objects.get(oid)
                    if not xobj or not xobj.dict_bytes:
                        continue
                    subtype = _dict_get_raw_value(xobj.dict_bytes, b"/Subtype")
                    if subtype == b"/Image":
                        smask = _dict_get_raw_value(xobj.dict_bytes, b"/SMask")
                        if smask:
                            msm = _REF_RE.match(smask)
                            if msm:
                                smask_objs.add(int(msm.group(1)))
                        image_objs.append((oid, xobj.dict_bytes))
                    elif subtype == b"/Form":
                        _collect_xobjs(_dict_get_raw_value(xobj.dict_bytes, b"/Resources"), depth + 1)

            _collect_xobjs(_dict_get_raw_value(page.dict_bytes, b"/Resources"))

            non_mask_images = 0
            large_images = 0
            for oid, img_dict in image_objs:
                if oid in smask_objs:
                    continue
                if (_dict_get_raw_value(img_dict, b"/ImageMask") or b"").lower() == b"true":
                    continue
                w_val = _dict_get_raw_value(img_dict, b"/Width") or b"0"
                h_val = _dict_get_raw_value(img_dict, b"/Height") or b"0"
                w = int(w_val) if w_val.isdigit() else 0
                h = int(h_val) if h_val.isdigit() else 0
                if w >= 32 and h >= 32:
                    non_mask_images += 1
                if w >= 200 and h >= 200:
                    large_images += 1

            meaningful_images += non_mask_images
            text_len = self._extract_page_text_len(page.dict_bytes)
            if text_len < 25 and (large_images > 0 or non_mask_images > 0):
                scanned_pages += 1

        return page_count, scanned_pages, meaningful_images

    def audit_forms(self, root_dict: bytes) -> tuple[int, int]:
        """Return (form_field_count, missing_tooltips)."""
        seen_objs: set[int] = set()
        field_count = 0
        missing_tooltips = 0

        def _walk_field_dict(
            d: bytes,
            oid: int | None = None,
            inherited_ft: bytes | None = None,
            inherited_tu: str | None = None,
        ) -> None:
            nonlocal field_count, missing_tooltips
            if oid is not None:
                if oid in seen_objs:
                    return
                seen_objs.add(oid)

            ft = _dict_get_raw_value(d, b"/FT") or inherited_ft
            tu = self.resolve_string(_dict_get_raw_value(d, b"/TU")) or inherited_tu
            kids_val = _dict_get_raw_value(d, b"/Kids")

            if kids_val:
                kid_refs = [int(mr.group(1)) for mr in _ALL_REFS_RE.finditer(kids_val)]
                has_child_fields = False
                for kid_id in kid_refs:
                    kobj = self.objects.get(kid_id)
                    if kobj and kobj.dict_bytes and (
                        _dict_get_raw_value(kobj.dict_bytes, b"/T") is not None
                        or _dict_get_raw_value(kobj.dict_bytes, b"/FT") is not None
                    ):
                        has_child_fields = True
                        break
                if has_child_fields:
                    for kid_id in kid_refs:
                        kobj = self.objects.get(kid_id)
                        if kobj and kobj.dict_bytes:
                            _walk_field_dict(kobj.dict_bytes, kid_id, ft, tu)
                    return

            subtype = _dict_get_raw_value(d, b"/Subtype")
            if ft or subtype == b"/Widget":
                field_count += 1
                if not tu:
                    missing_tooltips += 1

        acro_dict = self.resolve_dict(_dict_get_raw_value(root_dict, b"/AcroForm"))
        if acro_dict:
            fields_val = _dict_get_raw_value(acro_dict, b"/Fields")
            if fields_val:
                for mr in _ALL_REFS_RE.finditer(fields_val):
                    fid = int(mr.group(1))
                    fobj = self.objects.get(fid)
                    if fobj and fobj.dict_bytes:
                        _walk_field_dict(fobj.dict_bytes, fid)

        # Also inspect standalone Widget annotations
        for obj in self.objects.values():
            if obj.obj_num in seen_objs or not obj.dict_bytes:
                continue
            if _dict_get_raw_value(obj.dict_bytes, b"/Subtype") != b"/Widget":
                continue
            parent_val = _dict_get_raw_value(obj.dict_bytes, b"/Parent")
            if parent_val:
                mp = _REF_RE.match(parent_val)
                if mp and int(mp.group(1)) in seen_objs:
                    continue
            _walk_field_dict(obj.dict_bytes, obj.obj_num)

        return field_count, missing_tooltips


def _estimate_remediation_usd(
    *,
    severity: str,
    page_count: int,
    scanned_image_pages: int,
    table_count: int,
    form_field_count: int,
) -> float:
    if severity == "PASS" or page_count <= 0:
        return 0.0

    scanned = min(page_count, max(0, scanned_image_pages))
    remaining = max(0, page_count - scanned)
    table_pages = min(remaining, max(0, table_count))
    standard_pages = max(0, remaining - table_pages)

    page_cost = (
        scanned * RATE_SCANNED_OCR_PAGE
        + table_pages * RATE_COMPLEX_TABLE_PAGE
        + standard_pages * RATE_STANDARD_TEXT_PAGE
    )

    if form_field_count <= 0:
        form_cost = 0.0
    elif form_field_count <= 25:
        form_cost = 25.0
    elif form_field_count <= 75:
        form_cost = 40.0
    elif form_field_count <= 150:
        form_cost = 60.0
    else:
        form_cost = 60.0 + math.ceil((form_field_count - 150) / 50) * 20.0

    return round(page_cost + form_cost, 2)


def compute_score_and_severity(metrics: dict[str, Any]) -> tuple[int, str, list[str]]:
    """Compute ISO 14289-1 / WCAG 2.1 AA passScore (0-100), severity, and issue list."""
    issues: list[str] = []
    score = 0

    struct_tree_root = bool(metrics["structTreeRoot"])
    marked = bool(metrics["marked"])
    lang = metrics["lang"]
    title = metrics["title"]
    display_doc_title = bool(metrics["displayDocTitle"])
    pdf_ua_xmp = bool(metrics["pdfUaXmp"])
    page_count = int(metrics["pageCount"])
    scanned_pages = int(metrics["scannedImagePages"])
    missing_alt = int(metrics["missingAltFigures"])
    table_count = int(metrics["tableCount"])
    table_header_count = int(metrics["tableHeaderCount"])
    form_field_count = int(metrics["formFieldCount"])
    missing_tooltips = int(metrics["missingTooltips"])

    if struct_tree_root:
        score += 30
    else:
        issues.append("Missing /StructTreeRoot: document is untagged (ISO 14289-1 §7.1 / WCAG 1.3.1)")

    if marked:
        score += 10
    else:
        issues.append("Missing /MarkInfo /Marked=true flag (ISO 14289-1 §7.1)")

    if lang:
        score += 15
    else:
        issues.append("Missing /Lang primary document language (WCAG 3.1.1 / ISO 14289-1 §7.2)")

    if title:
        if _FILENAME_TITLE_RE.search(title):
            score += 5
            issues.append(f"Document title appears auto-generated ('{title[:60]}') (WCAG 2.4.2)")
        else:
            score += 10
    else:
        issues.append("Missing document title in XMP dc:title / Info /Title (WCAG 2.4.2)")

    if display_doc_title:
        score += 10
    else:
        issues.append("Missing /ViewerPreferences /DisplayDocTitle=true (ISO 14289-1 §7.1)")

    if pdf_ua_xmp:
        score += 15
    else:
        issues.append("Missing PDF/UA-1 XMP identifier pdfuaid:part=1 (ISO 14289-1 §5)")

    content_pts = 10
    if scanned_pages > 0:
        ratio_penalty = round(10 * scanned_pages / max(1, page_count))
        content_pts -= max(4, min(10, ratio_penalty))
        issues.append(f"{scanned_pages}/{page_count} page(s) appear to be scanned images without OCR text (WCAG 1.4.5)")

    if missing_alt > 0:
        content_pts -= min(10 if not struct_tree_root else 6, missing_alt * 2)
        if struct_tree_root:
            issues.append(f"{missing_alt} /Figure tag(s) missing /Alt text (WCAG 1.1.1 / ISO 14289-1 §7.3)")
        else:
            issues.append(f"{missing_alt} untagged image(s) lacking /Figure tags and /Alt text (WCAG 1.1.1)")

    if table_count > 0 and table_header_count == 0:
        content_pts -= 4
        issues.append(f"{table_count} /Table element(s) missing /TH header cells (WCAG 1.3.1 / ISO 14289-1 §7.5)")

    if form_field_count > 0 and missing_tooltips > 0:
        content_pts -= min(5, missing_tooltips * 2)
        issues.append(f"{missing_tooltips}/{form_field_count} form field(s) missing /TU accessible tooltip (WCAG 4.1.2)")

    score += max(0, content_pts)
    score = max(0, min(100, score))

    has_blocking_content_issue = (
        scanned_pages > 0
        or missing_alt > 0
        or missing_tooltips > 0
        or (table_count > 0 and table_header_count == 0)
    )
    if score >= 90 and struct_tree_root and marked and bool(lang) and not has_blocking_content_issue:
        severity = "PASS"
    elif score < 30 or (not struct_tree_root and not marked and not lang):
        severity = "CRITICAL"
    elif score < 55 or not struct_tree_root or scanned_pages > 0:
        severity = "HIGH"
    elif score < 80:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity, issues


def audit_pdf_bytes(data: bytes, *, file_path: str = "") -> dict[str, Any]:
    """Audit raw PDF bytes with zero third-party dependencies."""
    audited_at = datetime.now(timezone.utc).isoformat()
    result: dict[str, Any] = {
        "file": file_path,
        "fileSizeBytes": len(data),
        "structTreeRoot": False,
        "marked": False,
        "lang": None,
        "title": None,
        "displayDocTitle": False,
        "pdfUaXmp": False,
        "pageCount": 0,
        "scannedImagePages": 0,
        "missingAltFigures": 0,
        "tableCount": 0,
        "tableHeaderCount": 0,
        "formFieldCount": 0,
        "missingTooltips": 0,
        "passScore": 0,
        "severity": "CRITICAL",
        "status": "FAIL",
        "remediationEstimateUsd": 0.0,
        "issues": [],
        "remediationUrl": REMEDIATION_URL,
        "auditedAt": audited_at,
    }

    if b"%PDF-" not in data[:1024]:
        result["issues"] = ["File does not contain a valid %PDF- header"]
        return result

    if b"/Encrypt" in data and re.search(rb"/Encrypt\s+\d+\s+\d+\s+R", data):
        result["issues"] = ["PDF is encrypted and cannot be reliably parsed without decryption"]
        return result

    inspector = PurePdfInspector(data)
    root_obj = inspector.objects.get(inspector.root_num) if inspector.root_num is not None else None
    if root_obj is None or not root_obj.dict_bytes:
        result["issues"] = ["Malformed PDF: unable to locate /Root Catalog dictionary"]
        return result

    root_dict = root_obj.dict_bytes
    struct_root_dict = inspector.resolve_dict(_dict_get_raw_value(root_dict, b"/StructTreeRoot"))
    has_struct_tree = struct_root_dict is not None

    mark_info_dict = inspector.resolve_dict(_dict_get_raw_value(root_dict, b"/MarkInfo"))
    marked = bool(
        mark_info_dict and (_dict_get_raw_value(mark_info_dict, b"/Marked") or b"").lower() == b"true"
    )

    lang = inspector.resolve_string(_dict_get_raw_value(root_dict, b"/Lang"))

    viewer_prefs_dict = inspector.resolve_dict(_dict_get_raw_value(root_dict, b"/ViewerPreferences"))
    display_doc_title = bool(
        viewer_prefs_dict
        and (_dict_get_raw_value(viewer_prefs_dict, b"/DisplayDocTitle") or b"").lower() == b"true"
    )

    pdf_ua_xmp, xmp_title = inspector.extract_xmp(root_dict)
    info_title: str | None = None
    if inspector.info_num is not None and inspector.info_num in inspector.objects:
        info_dict = inspector.objects[inspector.info_num].dict_bytes
        if info_dict:
            info_title = inspector.resolve_string(_dict_get_raw_value(info_dict, b"/Title"))
    title = xmp_title or info_title

    page_count, scanned_pages, meaningful_images = inspector.audit_pages(root_dict)

    if has_struct_tree and struct_root_dict:
        st_counts = inspector.walk_struct_tree(struct_root_dict)
        missing_alt = st_counts["missing_alt_figures"]
        table_count = st_counts["table_count"]
        table_header_count = st_counts["table_header_count"]
    else:
        missing_alt = meaningful_images
        table_count = 0
        table_header_count = 0

    form_field_count, missing_tooltips = inspector.audit_forms(root_dict)

    metrics = {
        "structTreeRoot": has_struct_tree,
        "marked": marked,
        "lang": lang,
        "title": title,
        "displayDocTitle": display_doc_title,
        "pdfUaXmp": pdf_ua_xmp,
        "pageCount": page_count,
        "scannedImagePages": scanned_pages,
        "missingAltFigures": missing_alt,
        "tableCount": table_count,
        "tableHeaderCount": table_header_count,
        "formFieldCount": form_field_count,
        "missingTooltips": missing_tooltips,
    }

    pass_score, severity, issues = compute_score_and_severity(metrics)
    remediation_usd = _estimate_remediation_usd(
        severity=severity,
        page_count=page_count,
        scanned_image_pages=scanned_pages,
        table_count=table_count,
        form_field_count=form_field_count,
    )

    result.update(metrics)
    result["passScore"] = pass_score
    result["severity"] = severity
    result["status"] = "PASS" if severity == "PASS" else "FAIL"
    result["remediationEstimateUsd"] = remediation_usd
    result["issues"] = issues
    return result


def audit_pdf_file(path: str | Path, *, base_dir: Path | None = None) -> dict[str, Any]:
    p = Path(path)
    display_path = str(p.relative_to(base_dir)) if base_dir and p.is_relative_to(base_dir) else str(p)
    data = p.read_bytes()
    return audit_pdf_bytes(data, file_path=display_path)


def discover_pdfs(root_dir: str | Path, pattern: str = "**/*.pdf") -> list[Path]:
    root = Path(root_dir).resolve()
    if root.is_file() and root.suffix.lower() == ".pdf":
        return [root]

    # Case-insensitive matching while supporting standard **/*.pdf glob patterns
    found: set[Path] = set()
    for match in glob_mod.glob(str(root / pattern), recursive=True):
        candidate = Path(match)
        if candidate.is_file() and ".git" not in candidate.parts:
            found.add(candidate.resolve())

    # Also match uppercase .PDF when default **/*.pdf is used
    if pattern == "**/*.pdf":
        for match in glob_mod.glob(str(root / "**/*.PDF"), recursive=True):
            candidate = Path(match)
            if candidate.is_file() and ".git" not in candidate.parts:
                found.add(candidate.resolve())

    return sorted(found)


def _yn(val: bool) -> str:
    return "Yes" if val else "No"


def _escape_md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown_summary(results: list[dict[str, Any]]) -> str:
    """Render a crisp GitHub-Flavored Markdown table for $GITHUB_STEP_SUMMARY."""
    total = len(results)
    passed = sum(1 for r in results if r["severity"] == "PASS")
    failed = total - passed
    avg_score = round(sum(r["passScore"] for r in results) / total, 1) if total else 0.0
    total_usd = round(sum(r["remediationEstimateUsd"] for r in results), 2)

    lines = [
        "## ADA Title II & PDF/UA-1 Accessibility Audit",
        "",
        f"- **PDFs Scanned:** {total} | **Passed:** {passed} | **Failed:** {failed} | **Avg Score:** {avg_score}/100 | **Est. Remediation:** ${total_usd:,.2f}",
        "",
    ]

    if total == 0:
        lines.append("_No PDF files matched the configured scan pattern._")
    else:
        lines.extend(
            [
                "| File | Score | Severity | Pages | Tagged | Marked | Lang | Display Title | PDF/UA XMP | Scanned | Missing Alt | Forms (No /TU) | Est. Fix |",
                "| --- | ---: | :---: | ---: | :---: | :---: | :---: | :---: | :---: | ---: | ---: | :---: | ---: |",
            ]
        )
        for r in results:
            badge = f"**{r['severity']}**"
            lang_cell = _escape_md(r["lang"]) if r["lang"] else "—"
            forms_cell = (
                f"{r['formFieldCount']} ({r['missingTooltips']})"
                if r["formFieldCount"] > 0
                else "0"
            )
            lines.append(
                f"| `{_escape_md(r['file'])}` "
                f"| {r['passScore']}/100 "
                f"| {badge} "
                f"| {r['pageCount']} "
                f"| {_yn(r['structTreeRoot'])} "
                f"| {_yn(r['marked'])} "
                f"| {lang_cell} "
                f"| {_yn(r['displayDocTitle'])} "
                f"| {_yn(r['pdfUaXmp'])} "
                f"| {r['scannedImagePages']} "
                f"| {r['missingAltFigures']} "
                f"| {forms_cell} "
                f"| ${r['remediationEstimateUsd']:,.2f} |"
            )

        failing = [r for r in results if r["issues"]]
        if failing:
            lines.extend(["", "### Issues Detected", ""])
            for r in failing:
                lines.append(f"- **`{_escape_md(r['file'])}`** ({r['severity']}, {r['passScore']}/100):")
                for issue in r["issues"]:
                    lines.append(f"  - {issue}")

    lines.extend(
        [
            "",
            "---",
            (
                f"Need failing PDFs remediated to **0-failure veraPDF ISO 14289-1 (PDF/UA-1)**? "
                f"Request a free Page-1 proof or fixed-fee remediation quote at "
                f"[Second Foreman LLC]({REMEDIATION_URL})."
            ),
            "",
            (
                "_Built and operated by an AI agent (Google Gemini) with Paul Lewis human sign-off, "
                "guaranteed by Second Foreman LLC._"
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _write_github_output(outputs: dict[str, Any]) -> None:
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if not gh_out:
        return
    with open(gh_out, "a", encoding="utf-8") as fh:
        for key, value in outputs.items():
            fh.write(f"{key}={value}\n")


def _emit_annotations(results: list[dict[str, Any]]) -> None:
    if not os.environ.get("GITHUB_ACTIONS"):
        return
    for r in results:
        if r["severity"] == "PASS":
            continue
        level = "error" if r["severity"] in {"CRITICAL", "HIGH"} else "warning"
        summary = "; ".join(r["issues"][:3]) if r["issues"] else "PDF/UA-1 conformance issues detected"
        print(f"::{level} file={r['file']}::PDF/UA-1 {r['severity']} ({r['passScore']}/100): {summary}")


def _parse_bool(val: str | bool) -> bool:
    if isinstance(val, bool):
        return val
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Zero-dependency ADA Title II & PDF/UA-1 (ISO 14289-1) GitHub Action Auditor"
    )
    parser.add_argument("--path", default=".", help="Root directory or single PDF file to scan (default: .)")
    parser.add_argument("--glob", default="**/*.pdf", help="Recursive glob pattern under --path (default: **/*.pdf)")
    parser.add_argument("--fail-on-error", default="false", help="Fail CI when PDFs violate thresholds (true/false)")
    parser.add_argument("--min-score", type=int, default=90, help="Minimum passing passScore 0-100 (default: 90)")
    parser.add_argument(
        "--fail-severity",
        default="CRITICAL",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity that triggers failure when --fail-on-error=true (default: CRITICAL)",
    )
    parser.add_argument("--write-summary", default="true", help="Write Markdown table to $GITHUB_STEP_SUMMARY")
    parser.add_argument("--output-json", default="", help="Optional path to write full JSON report")
    args = parser.parse_args(argv)

    root = Path(args.path).resolve()
    base_dir = root.parent if root.is_file() else root
    pdf_files = discover_pdfs(root, args.glob)

    results = [audit_pdf_file(pdf_path, base_dir=base_dir) for pdf_path in pdf_files]
    total = len(results)
    passed = sum(1 for r in results if r["severity"] == "PASS")
    failed = total - passed
    avg_score = round(sum(r["passScore"] for r in results) / total, 1) if total else 0.0
    total_usd = round(sum(r["remediationEstimateUsd"] for r in results), 2)

    markdown = render_markdown_summary(results)
    print(markdown)

    if _parse_bool(args.write_summary):
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            with open(summary_path, "a", encoding="utf-8") as fh:
                fh.write(markdown + "\n")

    report_path = args.output_json.strip()
    if report_path:
        payload = {
            "summary": {
                "totalPdfs": total,
                "passedPdfs": passed,
                "failedPdfs": failed,
                "averageScore": avg_score,
                "estimatedRemediationUsd": total_usd,
                "remediationUrl": REMEDIATION_URL,
            },
            "results": results,
        }
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(report_path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    _emit_annotations(results)
    _write_github_output(
        {
            "total-pdfs": total,
            "passed-pdfs": passed,
            "failed-pdfs": failed,
            "average-score": avg_score,
            "estimated-remediation-usd": f"{total_usd:.2f}",
            "report-json": report_path,
        }
    )

    if _parse_bool(args.fail_on_error):
        min_sev_rank = SEVERITY_RANK[args.fail_severity]
        violators = [
            r
            for r in results
            if r["passScore"] < args.min_score or SEVERITY_RANK[r["severity"]] >= min_sev_rank
        ]
        if violators:
            print(
                f"ADA Title II / PDF/UA-1 audit failed: {len(violators)} PDF(s) did not meet "
                f"min-score={args.min_score} or triggered severity >= {args.fail_severity}.",
                file=sys.stderr,
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
