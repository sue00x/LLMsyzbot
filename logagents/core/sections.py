
# -*- coding: utf-8 -*-
import re
from typing import List, Tuple

SECTION_SPECS = [
    ("BUG",   re.compile(r"^.*BUG:\s*KASAN.*$", re.I)),
    ("RW",    re.compile(r"^(?:.*(?:Read|Write) of size \d+.*)$", re.I)),
    ("CPU",   re.compile(r"^CPU:\s*\d+.*$", re.I)),
    ("HW",    re.compile(r"^Hardware name:.*$", re.I)),
    ("CALL",  re.compile(r"^Call Trace:\s*$", re.I)),
    ("ALLOC", re.compile(r"^Allocated by task.*$", re.I)),
    ("FREED", re.compile(r"^Freed by task.*$", re.I)),
    ("BUGGY", re.compile(r"^The buggy address belongs to.*$", re.I)),
    ("MEM",   re.compile(r"^Memory state around.*$", re.I)),
]
SECTION_ORDER = ["BUG","RW","CPU","HW","CALL","ALLOC","FREED","BUGGY","MEM","DIAG"]

_HEX_DUMP  = re.compile(r"^(?:[0-9a-f]{2}\s+){8,}[0-9a-f]{2}\s*$", re.I)

def _collect_block_from(lines: List[str], start_idx: int, max_len=120, stop_headers=None):
    out = []
    n = len(lines); i = start_idx
    while i < n and len(out) < max_len:
        ln = lines[i].rstrip("\n")
        out.append(ln)
        if stop_headers:
            if not _HEX_DUMP.match(ln):
                nxt = (i+1 < n) and any(hdr.search(lines[i+1]) for hdr in stop_headers)
                if nxt:
                    break
        i += 1
    return out

def extract_sections_from_log(lines: List[str]):
    found = {}
    n = len(lines)
    for i, ln in enumerate(lines):
        for name, pat in SECTION_SPECS:
            if name in found:
                continue
            if pat.search(ln):
                stop_headers = [p for _, p in SECTION_SPECS if _ != name]
                if name == "CALL":
                    block = _collect_block_from(lines, i, max_len=200, stop_headers=stop_headers)
                elif name in ("MEM", "ALLOC", "FREED", "BUGGY"):
                    block = _collect_block_from(lines, i, max_len=300, stop_headers=stop_headers)
                else:
                    block = _collect_block_from(lines, i, max_len=120, stop_headers=stop_headers)
                found[name] = block
    return found
