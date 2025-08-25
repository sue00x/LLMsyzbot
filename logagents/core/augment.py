
# -*- coding: utf-8 -*-
import re
from typing import List
from .sections import extract_sections_from_log
from .ordering import _normalize_for_match

def augment_missing_sections(all_lines_in_log: List[str], candidate_text: str) -> str:
    cand_lines = [ln for ln in candidate_text.splitlines() if ln.strip()]
    log_secs = extract_sections_from_log(all_lines_in_log)
    needs = {
        "CALL": r"^Call Trace:",
        "ALLOC": r"^Allocated by task",
        "FREED": r"^Freed by task",
        "BUGGY": r"^The buggy address belongs to",
        "MEM": r"^Memory state around",
    }
    def _present(header_regex):
        rx = re.compile(header_regex, re.I)
        return any(rx.search(_normalize_for_match(ln)) for ln in cand_lines)
    for key, header_pat in needs.items():
        if key in log_secs and not _present(header_pat):
            # 段间留一空行，避免紧贴 Call Trace 造成“视觉上像在 Call Trace 内”
            if cand_lines and cand_lines[-1].strip():
                cand_lines.append("")
            for ln in log_secs[key]:
                if ln.strip() and '?' not in ln and '？' not in ln:
                    cand_lines.append(ln)


    return "\n".join(cand_lines)

# Diagnostics tail augmentation
DIAG_PATTERNS = [
    ("MEM_HEX", re.compile(r"^Memory state around.*$", re.I)),
    ("PAGE_OWNER", re.compile(r"\bpage_owner\b", re.I)),
    ("PAGE_DUMP", re.compile(r"^page:\s*[0-9a-fx]+", re.I)),
    ("SLAB_OBJ", re.compile(r"\b(slab|kmalloc|kmem_cache|object)\b", re.I)),
    ("DISASM", re.compile(r"\bDisassembly\b|\bCode:\b", re.I)),
    ("FTRACE", re.compile(r"\bftrace\b|\btracing\b|^trace:", re.I)),
    ("REGS", re.compile(r"\bRIP:|^RSP:|^RAX:|^RBX:|^RDX:|^RCX:|^RDI:|^RSI:|^RBP:|^R\d{2}:|^EIP:|^ESP:", re.I)),
]

def _collect_block_from(lines, start_idx, max_len=800, stop_headers=None):
    out = []
    n = len(lines); i = start_idx
    while i < n and len(out) < max_len:
        ln = lines[i].rstrip("\n")
        out.append(ln)
        if stop_headers:
            if i+1 < n and any(hdr.search(lines[i+1]) for hdr in stop_headers):
                break
        i += 1
    return out

def _find_diag_blocks(lines: List[str]) -> List[List[str]]:
    from .sections import SECTION_SPECS
    n = len(lines)
    stop_headers = [p for _, p in SECTION_SPECS]
    diag_blocks = []
    i = 0
    while i < n:
        ln = lines[i]
        matched = None
        for name, rx in DIAG_PATTERNS:
            if rx.search(ln):
                matched = name
                break
        if matched:
            block = _collect_block_from(lines, i, max_len=800, stop_headers=stop_headers)
            diag_blocks.append(block)
            i += len(block)
        else:
            i += 1
    return diag_blocks

def _normalize_text_block(s: str) -> str:
    import re
    _TS_PREFIX = re.compile(r"^\s*\[[^\]]+\]\s*")
    _WS_MULTI  = re.compile(r"\s+")
    def _norm_line(x): 
        x = _TS_PREFIX.sub("", x.rstrip("\r\n")); 
        return _WS_MULTI.sub(" ", x).strip()
    return "\n".join(_norm_line(ln) for ln in s.splitlines())

def _cand_contains_block(cand_text_norm: str, block: List[str]) -> bool:
    head_two = [ _normalize_text_block(x) for x in block[:2] if x.strip() ]
    return all((h and h in cand_text_norm) for h in head_two) if head_two else False

def augment_diagnostics_tail(all_lines_in_log: List[str], candidate_text: str) -> str:
    cand_norm = _normalize_text_block(candidate_text)
    blocks = _find_diag_blocks(all_lines_in_log)
    if not blocks:
        return candidate_text
    out = candidate_text.splitlines()
    for blk in blocks:
        if not _cand_contains_block(cand_norm, blk):
            out.extend(ln for ln in blk if ln.strip())
            cand_norm += "\n" + _normalize_text_block("\n".join(blk))
    return "\n".join(out)
