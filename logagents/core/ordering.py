# -*- coding: utf-8 -*-
"""
ordering_ct_hoist.py — canonicalizer with safe </TASK> hoisting.
v2025-08-19e:
  • Include RIP/Code:/registers inside Call Trace.
  • Exclude Alloc/Freed/buggy/mem/page from Call Trace.
  • Do NOT output "Kernel panic ..." and "Kernel Offset ...".
"""

import re
from typing import Dict, List, Tuple

print("[ORDER] ordering_ct_hoist.py v2025-08-19e is active")

_WS_MULTI  = re.compile(r"\s+")
_TS_PREFIX = re.compile(r"^\s*(\[[^\]]+\]\s*){1,2}")
def _normalize_for_match(s: str) -> str:
    return _WS_MULTI.sub(" ", _TS_PREFIX.sub("", s)).strip()

# ---------- headers/markers ----------
R_BUG    = re.compile(r"^.*BUG:\s*KASAN.*$", re.I)
R_RW     = re.compile(r"^(?:.*(?:Read|Write) of size \d+.*)$", re.I)
R_CPU    = re.compile(r"^CPU:\s*\d+.*$", re.I)
R_HW     = re.compile(r"^Hardware name:.*$", re.I)

R_CT     = re.compile(r"^Call Trace:\s*$", re.I)
R_T_OPEN = re.compile(r"^<TASK>\s*$", re.I)
R_T_END  = re.compile(r"^</TASK>\s*$", re.I)

R_ALLOC  = re.compile(r"^Allocated by task.*$", re.I)
R_FREED  = re.compile(r"^Freed by task.*$", re.I)
R_BUGGY  = re.compile(r"^The buggy address belongs to.*$", re.I)
R_MEM    = re.compile(r"^Memory state around.*$", re.I)
R_PAGE   = re.compile(r"^(?:page_owner|page last (?:allocated|free) pid|page last free pid|page:\s*).*$", re.I)

R_PANIC  = re.compile(r"^Kernel panic\b|^panic\b", re.I)    # hard break only
R_RIP    = re.compile(r"^RIP:\s*", re.I)
R_CODE   = re.compile(r"^Code:\s*", re.I)
R_REGS   = re.compile(r"^(RSP|RAX|RBX|RCX|RDX|RSI|RDI|RBP|R08|R09|R10|R11|R12|R13|R14|R15):\s*", re.I)
R_OFFS   = re.compile(r"^Kernel Offset:\s*", re.I)          # hard break only
R_REBOOT = re.compile(r"^Rebooting in \d+ seconds\.\.", re.I)

# Hard-breakers: used to terminate CT or blocks, but not necessarily emitted.
_HARD = [R_BUG, R_RW, R_CPU, R_HW, R_CT, R_ALLOC, R_FREED, R_BUGGY, R_MEM, R_PAGE,
         R_PANIC, R_RIP, R_CODE, R_OFFS, R_REBOOT, R_T_OPEN, R_T_END]

ORDER = (
    "BUG", "RW", "CPU", "HW",
    "CALLTRACE",
    "ALLOC", "FREED", "BUGGY", "MEM", "PAGE",
    # "PANIC",   # removed from output
    "RIPCODE", "REGS",
    # "OFFSET",  # removed from output
    "REBOOT",
    "_OTHER",
)

# ---------- frame patterns ----------
R_FRAME_STD   = re.compile(r"^[ \t]*[A-Za-z_.$<>][A-Za-z0-9_.$<>-]*\+0x[0-9a-fA-F]+/[0-9xa-fA-F]+(?:\b.*)?$")
R_FRAME_HINT  = re.compile(r"^[ \t]*(?:__sys_|__x64_sys_|do_syscall_|entry_SYSCALL_|dump_stack|ret_from_|end_report|check_|kasan_).*$")

def _is_frame(line: str) -> bool:
    s = _normalize_for_match(line)
    if not s: return False
    c = s[0]
    if not (c.isalpha() or c in "_<"):
        return False
    return bool(R_FRAME_STD.match(s) or R_FRAME_HINT.match(s))

def _is_hard_break(s: str) -> bool:
    for rx in _HARD:
        if rx.match(s):
            return True
    return False

def _dedupe(lines: List[str]) -> List[str]:
    seen=set(); out=[]
    for ln in lines:
        k = _normalize_for_match(ln)
        if k in seen: continue
        seen.add(k); out.append(ln)
    return out

def _score_cpu(s: str) -> Tuple[int, int]:
    t = s.lower()
    has_comm = ("comm:" in t)
    return (1 if has_comm else 0, len(_normalize_for_match(s)))

def _score_hw(s: str) -> Tuple[int, int]:
    return (0, len(_normalize_for_match(s)))

def _pick_best(lines: List[str], which: str) -> List[str]:
    if not lines: return []
    if len(lines) == 1: return [lines[0]]
    if which == "CPU":
        return [max(lines, key=_score_cpu)]
    if which == "HW":
        return [max(lines, key=_score_hw)]
    return [lines[0]]

def _collect_regs_tail(lines, j, n):
    """Collect RIP / Code: / registers sequence starting at current j."""
    emit = []
    # optional RIP
    if j < n and R_RIP.match(lines[j]):
        emit.append(j); j += 1
        # optional Code:
        if j < n and R_CODE.match(lines[j]):
            emit.append(j); j += 1
        # one or more register lines
        while j < n and R_REGS.match(lines[j]):
            emit.append(j); j += 1
    return emit, j

def _find_ct_blocks_with_hoist(lines: List[str], max_scan: int = 400):
    """
    Build CT blocks:
      Call Trace: [<TASK>] frames... [RIP] [Code:] [REGS...] [</TASK (hoisted if found later)>]
    Exclude diagnostics. PANIC/OFFSET are hard breaks only.
    """
    n = len(lines)
    i = 0
    blocks = []
    while i < n:
        if not R_CT.match(lines[i]):
            i += 1; continue

        used = set()
        emit = []

        # 'Call Trace:' header
        emit.append(i); used.add(i)
        j = i + 1

        # optional immediate <TASK>
        if j < n and R_T_OPEN.match(lines[j]):
            emit.append(j); used.add(j); j += 1

        # frames until blank or diagnostics/hard breaks (panic/offset etc. stop frames as well)
        while j < n:
            s = lines[j]
            if not s.strip():
                break
            if R_ALLOC.match(s) or R_FREED.match(s) or R_BUGGY.match(s) or R_MEM.match(s) or R_PAGE.match(s) or R_PANIC.match(s) or R_OFFS.match(s) or R_REBOOT.match(s):
                break
            if _is_frame(s):
                emit.append(j); used.add(j); j += 1; continue
            break

        # attach RIP/Code:/registers immediately after frames (if present)
        regs_emit, j2 = _collect_regs_tail(lines, j, n)
        for idx in regs_emit:
            emit.append(idx); used.add(idx)
        j = j2

        # hoist a later </TASK> if exists within scan window
        end_pos = None
        scan_upto = min(n, i + 1 + max_scan)
        k = j
        while k < scan_upto:
            if R_T_END.match(lines[k]):
                end_pos = k
                break
            if R_CT.match(lines[k]):  # don't scan across another CT
                break
            k += 1
        if end_pos is not None:
            used.add(end_pos)
            emit.append(end_pos)

        blocks.append({'emit': emit, 'used': used})
        i = j + 1
    return blocks

def order_normalize(candidate_text: str) -> str:
    if not candidate_text:
        return ""

    raw = [ln.rstrip("\r") for ln in candidate_text.splitlines()]
    n = len(raw)

    # 1) CT blocks with safe hoist of </TASK>, including RIP/Code:/registers inside
    ct_blocks = _find_ct_blocks_with_hoist(raw)

    used = set()
    for b in ct_blocks:
        used.update(b['used'])

    # 2) Bucketize (block-aware) excluding already used lines
    buckets: Dict[str, List[str]] = {k: [] for k in ORDER}
    def add(bucket, line_idx):
        s = raw[line_idx]
        if s.strip():
            buckets[bucket].append(s)
        used.add(line_idx)

    # Place CALLTRACE
    for b in ct_blocks:
        if buckets["CALLTRACE"] and buckets["CALLTRACE"][-1] != "":
            buckets["CALLTRACE"].append("")
        buckets["CALLTRACE"].extend([raw[idx] for idx in b['emit']])

    def collect_block(start: int) -> int:
        j = start
        block = []
        while j < n:
            if j != start and _is_hard_break(raw[j]):
                break
            block.append(raw[j])
            j += 1
        return j, block

    i = 0
    while i < n:
        if i in used or not raw[i].strip():
            i += 1; continue

        s = raw[i]
        if R_BUG.match(s):    add("BUG", i); i += 1; continue
        if R_RW.match(s):     add("RW", i); i += 1; continue

        if R_CPU.match(s):    add("CPU", i); i += 1; continue
        if R_HW.match(s):     add("HW", i); i += 1; continue

        if R_ALLOC.match(s):
            j, blk = collect_block(i)
            buckets["ALLOC"].extend(blk); used.update(range(i, j)); i = j; continue
        if R_FREED.match(s):
            j, blk = collect_block(i)
            buckets["FREED"].extend(blk); used.update(range(i, j)); i = j; continue
        if R_BUGGY.match(s):
            j, blk = collect_block(i)
            buckets["BUGGY"].extend(blk); used.update(range(i, j)); i = j; continue
        if R_MEM.match(s):
            j, blk = collect_block(i)
            buckets["MEM"].extend(blk); used.update(range(i, j)); i = j; continue
        if R_PAGE.match(s):
            j, blk = collect_block(i)
            buckets["PAGE"].extend(blk); used.update(range(i, j)); i = j; continue

        # PANIC: intentionally skipped (never output)
        # OFFSET: intentionally skipped (never output)

        if R_RIP.match(s) or R_CODE.match(s) or R_REGS.match(s):
            j, blk = collect_block(i)
            for ln in blk:
                if R_RIP.match(ln) or R_CODE.match(ln):
                    buckets["RIPCODE"].append(ln)
                elif R_REGS.match(ln):
                    buckets["REGS"].append(ln)
            used.update(range(i, j)); i = j; continue

        if R_REBOOT.match(s):
            add("REBOOT", i); i += 1; continue

        # drop stray frames outside CT
        if _is_frame(s):
            used.add(i); i += 1; continue

        buckets["_OTHER"].append(raw[i]); used.add(i); i += 1

    # 3) Emit in canonical order; dedupe block-wise; pick best CPU/HW
    out: List[str] = []
    def emit_block(lines: List[str]):
        lines = [x for x in lines if x.strip() != ""]
        lines = _dedupe(lines)
        if not lines: return
        if out and out[-1] != "":
            out.append("")
        out.extend(lines)

    for key in ORDER:
        arr = buckets.get(key, [])
        if not arr: continue
        if key == "CPU":
            emit_block(_pick_best(arr, "CPU"))
        elif key == "HW":
            emit_block(_pick_best(arr, "HW"))
        else:
            emit_block(arr)

    # 4) Final tidy: ensure no <TASK> or </TASK> appear outside CALLTRACE
    final = []
    in_ct = False
    for ln in out:
        if R_CT.match(ln):
            in_ct = True
            final.append(ln); continue
        if in_ct:
            final.append(ln)
            if R_T_END.match(ln):
                in_ct = False
        else:
            if R_T_OPEN.match(ln) or R_T_END.match(ln):
                continue
            final.append(ln)

    # compress blank lines
    cleaned = []
    prev_blank = False
    for ln in final:
        if ln.strip():
            cleaned.append(ln); prev_blank = False
        else:
            if not prev_blank and cleaned:
                cleaned.append("")
            prev_blank = True

    while cleaned and cleaned[0] == "": cleaned.pop(0)
    while cleaned and cleaned[-1] == "": cleaned.pop()

    return "\n".join(cleaned)
