
# -*- coding: utf-8 -*-
import re
from dataclasses import dataclass
from typing import List, Dict
from .sections import SECTION_ORDER
from .ordering import _normalize_for_match as _norm
from .ordering import _TS_PREFIX, _WS_MULTI

REPORT_IGNORES = [
    re.compile(r"^Kernel panic - not syncing", re.I),
    re.compile(r"^invalid opcode: 0000", re.I),
    re.compile(r"^Internal error:", re.I),
    re.compile(r"^PANIC: double fault", re.I),
    re.compile(r"^unregister_netdevice: waiting for", re.I),
]

_RX = {
    "BUG":   re.compile(r"BUG:\s*KASAN", re.I),
    "RW":    re.compile(r"(?:Read|Write) of size \d+", re.I),
    "CPU":   re.compile(r"^CPU:", re.I),
    "HW":    re.compile(r"^Hardware name:", re.I),
    "CALL":  re.compile(r"^Call Trace:", re.I),
    "ALLOC": re.compile(r"^Allocated by task", re.I),
    "FREED": re.compile(r"^Freed by task", re.I),
    "BUGGY": re.compile(r"^The buggy address belongs to", re.I),
    "MEM":   re.compile(r"^Memory state around", re.I),
    "DIAG": re.compile(r"(?:page_owner|^page:\s*[0-9a-fx]+|\b(?:slab|kmalloc|kmem_cache|object)\b|Disassembly|^Code:|ftrace|tracing|^trace:|\bRIP:|^RSP:|^RAX:|^RBX:|^RDX:|^RCX:|^RDI:|^RSI:|^RBP:|^R\d{2}:|^EIP:|^ESP:)", re.I),
    "HEX": re.compile(r"^(?:[0-9a-f]{2}\s+){8,}[0-9a-f]{2}\s*$", re.I),
    "BLANK": re.compile(r"^\s*$"),
}

def _compact_blank_lines(lines: List[str]) -> List[str]:
    out = []
    blank = False
    for ln in lines:
        if _RX["BLANK"].match(ln):
            if not blank:
                out.append("")
            blank = True
        else:
            out.append(ln); blank = False
    while out and _RX["BLANK"].match(out[0]): out.pop(0)
    while out and _RX["BLANK"].match(out[-1]): out.pop()
    return out

def _split_into_buckets(text: str) -> Dict[str, List[str]]:
    buckets = {k: [] for k in SECTION_ORDER}
    current = None
    for ln in (text or "").splitlines():
        n = _norm(ln)
        matched = None
        for k in SECTION_ORDER:
            if _RX[k].search(n):
                matched = k
                break
        if matched:
            current = matched; buckets[current].append(ln)
        else:
            if current: buckets[current].append(ln)
    return buckets

def _trim_call_trace(call_lines: List[str], tool_rx: str, max_frames: int) -> List[str]:
    if not call_lines:
        return []
    tool = re.compile(tool_rx, re.I)
    out = []; started = False
    for i, ln in enumerate(call_lines):
        if i == 0:
            out.append(ln); continue
        if _RX["BLANK"].match(ln): break
        n = _norm(ln)
        if not started:
            if tool.search(n): 
                continue
            else:
                started = True; out.append(ln); continue
        if len(out) - 1 >= max_frames: break
        out.append(ln)
    return _compact_blank_lines(out)

def _cap_block(lines: List[str], max_lines: int) -> List[str]:
    if not lines: return []
    return _compact_blank_lines(lines[:max_lines])

def _cap_mem_block(mem_lines: List[str], hex_cap: int) -> List[str]:
    if not mem_lines: return []
    head = []; hex_lines = []; in_hex = False
    for ln in mem_lines:
        if _RX["HEX"].match(ln):
            in_hex = True; hex_lines.append(ln)
        else:
            head.append(ln)
    if len(hex_lines) <= hex_cap:
        hex_kept = hex_lines
    else:
        front = min(64, hex_cap)
        back = max(0, hex_cap - front)
        hex_kept = hex_lines[:front] + (hex_lines[-back:] if back > 0 else [])
    return _compact_blank_lines(head + hex_kept)

def _collect_diag_blocks(diag_lines: List[str]) -> List[List[str]]:
    if not diag_lines: return []
    blocks = []; cur = []
    for ln in diag_lines:
        if _RX["BLANK"].match(ln):
            if cur: blocks.append(cur); cur = []
        else:
            cur.append(ln)
    if cur: blocks.append(cur)
    return blocks

def _dedupe_diag_blocks(blocks):
    seen=set(); kept=[]
    def key_of(blk):
        ks=[]
        for ln in blk[:2]:
            n=_norm(ln)
            if n: ks.append(n)
        return "\n".join(ks)
    for blk in blocks:
        k=key_of(blk)
        if k and k not in seen:
            seen.add(k); kept.append(blk)
    return kept

def _apply_diag_policy(diag_lines: List[str], include: bool, total_max: int) -> List[str]:
    if not include or not diag_lines: return []
    blocks=_dedupe_diag_blocks(_collect_diag_blocks(diag_lines))
    out=[]; total=0
    for blk in blocks:
        blk=_compact_blank_lines(blk)
        if not blk: continue
        if total+len(blk)>total_max:
            remain=max(0,total_max-total)
            out.extend(blk[:remain]); break
        out.extend(blk); total+=len(blk)
    return _compact_blank_lines(out)

@dataclass
class SyzPolicy:
    call_trace_max: int = 25
    alloc_max: int = 80
    freed_max: int = 80
    buggy_max: int = 80
    mem_hex_max: int = 96
    diag_total_max: int = 400
    include_diag: bool = False
    tool_frames_rx: str = r"(dump_stack|kasan_report|__asan_|printk|__warn|report_bug|show_regs|warn_slowpath|__dump_stack|__traceiter_)"
    forbid_question_mark: bool = True


def split_into_buckets(text: str):
    return _split_into_buckets(text)

def apply_syzbot_policy(text: str, policy: SyzPolicy) -> str:
    # 首先去除所有行的时间戳
    cleaned_lines = []
    for line in text.splitlines():
        cleaned_line = _TS_PREFIX.sub("", line).strip()
        # 同时过滤包含问号的行
        if '?' not in cleaned_line and '？' not in cleaned_line:
            cleaned_lines.append(cleaned_line)
        else:
            print(f"[POLICY] 过滤掉问号行: {line}")
    
    # 添加去重逻辑
    def _normalize_for_match(s: str) -> str:
        return _WS_MULTI.sub(" ", s).strip()
    
    seen = set()
    dedup_lines = []
    for ln in cleaned_lines:
        if not ln.strip():
            continue
        n = _normalize_for_match(ln)
        if n in seen:
            print(f"[POLICY] 去重跳过: {ln}")
            continue
        seen.add(n)
        dedup_lines.append(ln)
    
    # 压缩空行
    final_lines = []
    prev_blank = False
    for ln in dedup_lines:
        if not ln.strip():
            if not prev_blank:
                final_lines.append("")
            prev_blank = True
        else:
            final_lines.append(ln)
            prev_blank = False
    
    # 去除首尾空行
    while final_lines and not final_lines[0].strip():
        final_lines.pop(0)
    while final_lines and not final_lines[-1].strip():
        final_lines.pop()
    
    filtered_text = "\n".join(final_lines)
    print(f"[POLICY] 最终输出: {len(final_lines)} 行")
    
    return filtered_text
