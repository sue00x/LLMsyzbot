# -*- coding: utf-8 -*-
"""
Build logs.jsonl / gold_short.jsonl / gold_full.jsonl for the closed-loop pipeline
from either:
  (A) your crawler JSON (directory of *.json or a single file), or
  (B) the few-shot jsonl produced by syz_prompt_builder.py

Usage examples:

# From crawler outputs (recommended)
python build_round_files.py \
  --input ./crawler_output_dir \
  --out   ./round_data \
  --source crawler

# From few-shot jsonl
python build_round_files.py \
  --input ./result/icl/fewshot.jsonl \
  --out   ./round_data \
  --source builder_jsonl

完整示例：
    python build_round_files.py --input crawler/result --out ./preprocess --source crawler
"""

import os, json, glob, re, argparse, sys
from typing import List, Dict, Any

# ---------------- Utilities ----------------

def ensure_dir(p: str):
    os.makedirs(p, exist_ok=True)

def read_json(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def read_jsonl(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln: continue
            try:
                rows.append(json.loads(ln))
            except:
                pass
    return rows

def write_jsonl(rows: List[dict], path: str):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def pick_first_nonempty(lst: List[str]) -> str:
    for x in lst or []:
        if isinstance(x, str) and x.strip():
            return x
    return ""

# ---------------- Regex & Normalization ----------------

TS_PREFIX = re.compile(r'^\s*\[\s*\d+(?:\.\d+)?\]\s*', re.I)

BUG_RE = re.compile(r'BUG:\s*KASAN:', re.I)
RW_RE  = re.compile(r'\b(?:Read|Write)\s+of\s+size\s+\d+', re.I)
CT_RE  = re.compile(r'^\s*Call Trace:\s*$', re.I)
CPU_RE = re.compile(r'^CPU:\s+.*Not tainted', re.I)

RIP_RE = re.compile(r'^\s*RIP:\s', re.I)
RSP_RE = re.compile(r'^\s*RSP:\s', re.I)
ALLOCATED_BY = re.compile(r'^\s*Allocated by task', re.I)
FREED_BY     = re.compile(r'^\s*Freed by task', re.I)
MEM_AROUND   = re.compile(r'^\s*Memory state around', re.I)
BUGGY_ADDR   = re.compile(r'^\s*The buggy address belongs to', re.I)

SKIP_PREFIX = re.compile(
    r'^(?:dump_stack|show_stack|print_address|print_report|kasan_report|__pfx_|__warn|'
    r'warn_slowpath|__virt_addr_valid|kasan_|__asan_|_printk|printk|vprintk|report_bug)\b',
    re.I
)

def norm_line(s: str) -> str:
    s = (s or "").rstrip("\r\n")
    return TS_PREFIX.sub("", s)

# ---------------- Short (slice) extraction ----------------

def extract_anchor_lines(src_text: str, max_lines: int = 5) -> List[str]:
    """Extract up to 5 anchor lines: BUG -> RW -> 'Call Trace:' -> first frame -> CPU."""
    if not isinstance(src_text, str) or not src_text.strip():
        return []
    lines = [norm_line(x) for x in src_text.splitlines() if x.strip()]

    bug = next((ln for ln in lines if BUG_RE.search(ln)), None)
    rw  = next((ln for ln in lines if RW_RE.search(ln)), None)

    ct_idx = next((i for i, ln in enumerate(lines) if CT_RE.search(ln)), None)
    ct_idx = next((i for i,ln in enumerate(lines) if CT_RE.search(ln)), None)
    ct = lines[ct_idx] if ct_idx is not None else None

    first_frame = None
    if ct_idx is not None:
        for j in range(ct_idx+1, min(ct_idx+15, len(lines))):
            cand = lines[j].strip()
            if cand and not SKIP_PREFIX.search(cand):
                first_frame = cand
                break

    cpu = next((ln for ln in lines if CPU_RE.search(ln)), None)

    out = []
    if bug: out.append(bug)
    if rw: out.append(rw)
    if ct: out.append(ct)
    if first_frame: out.append(first_frame)
    if cpu: out.append(cpu)
    return out[:max_lines]

# ---------------- Full extraction (multi-sections) ----------------

def _collect_block(lines: List[str], start_idx: int, stop_pred, max_next=64) -> List[str]:
    out = [lines[start_idx]]
    for j in range(start_idx+1, min(len(lines), start_idx+1+max_next)):
        s = lines[j]
        if not s.strip(): break
        if stop_pred(s): break
        out.append(s)
    return out

def extract_full_from_text(src_text: str, max_frames: int = 32) -> List[str]:
    """
    Try to reconstruct a syzbot-like long report from raw text.
    Sections (optional, order flexible):
      - BUG / RW / RIP / RSP / CPU
      - Call Trace: + frames (skip utility frames)
      - Allocated by task ... (with subsequent lines)
      - Freed by task ... (with subsequent lines)
      - The buggy address belongs to ...
      - Memory state around ... (with subsequent hexdump)
    Fallback to slice if empty.
    """
    if not isinstance(src_text, str) or not src_text.strip():
        return []
    raw_lines = src_text.splitlines()
    lines = [norm_line(x) for x in raw_lines]

    out = []

    # 1) single-line key facts
    for pat in (BUG_RE, RW_RE, RIP_RE, RSP_RE, CPU_RE):
        m = next((ln for ln in lines if ln and pat.search(ln)), None)
        if m and m not in out:
            out.append(m)

    # 2) call trace + frames
    ct_idx = next((i for i,s in enumerate(lines) if s and CT_RE.search(s)), None)
    if ct_idx is not None:
        out.append(lines[ct_idx])
        frames = []
        for j in range(ct_idx+1, min(ct_idx+1+max_frames*2, len(lines))):
            cand = lines[j].strip()
            if not cand: break
            if SKIP_PREFIX.search(cand): continue
            frames.append(lines[j])
            if len(frames) >= max_frames: break
        out.extend(frames)

    # 3) allocated by ...
    idx_alloc = next((i for i,s in enumerate(lines) if s and ALLOCATED_BY.search(s)), None)
    if idx_alloc is not None:
        blk = _collect_block(lines, idx_alloc, lambda s: FREED_BY.search(s) or BUG_RE.search(s) or CT_RE.search(s))
        out.extend(blk)

    # 4) freed by ...
    idx_freed = next((i for i,s in enumerate(lines) if s and FREED_BY.search(s)), None)
    if idx_freed is not None:
        blk = _collect_block(lines, idx_freed, lambda s: ALLOCATED_BY.search(s) or BUG_RE.search(s) or CT_RE.search(s))
        out.extend(blk)

    # 5) buggy address ...
    m_buggy = next((i for i,s in enumerate(lines) if s and BUGGY_ADDR.search(s)), None)
    if m_buggy is not None:
        out.append(lines[m_buggy])

    # 6) memory state around ...
    m_mem = next((i for i,s in enumerate(lines) if s and MEM_AROUND.search(s)), None)
    if m_mem is not None:
        blk = _collect_block(lines, m_mem, lambda s: BUG_RE.search(s) or CT_RE.search(s) or CPU_RE.search(s), max_next=32)
        out.extend(blk)

    # dedup + drop blanks
    out2, seen = [], set()
    for s in out:
        if not s or not s.strip(): continue
        if s in seen: continue
        out2.append(s); seen.add(s)

    if not out2:
        out2 = extract_anchor_lines(src_text)
    return out2

# ---------------- Crawler input parsing ----------------

def is_bug_obj(x: Any) -> bool:
    return isinstance(x, dict) and "title" in x and "crashes" in x

def load_all_bugs_from_crawler(input_path: str) -> List[Dict]:
    bugs = []
    if os.path.isdir(input_path):
        for fp in glob.glob(os.path.join(input_path, "*.json")):
            try:
                data = read_json(fp)
            except Exception as e:
                print(f"[WARN] read fail: {fp}: {e}", file=sys.stderr); continue
            if isinstance(data, list) and data and is_bug_obj(data[0]):
                bugs.extend(data)
            elif isinstance(data, list) and data and all(isinstance(x, dict) for x in data):
                bugs.extend([x for x in data if is_bug_obj(x)])
            elif isinstance(data, dict) and is_bug_obj(data):
                bugs.append(data)
    else:
        data = read_json(input_path)
        if isinstance(data, list):
            bugs.extend([x for x in data if is_bug_obj(x)])
        elif isinstance(data, dict) and is_bug_obj(data):
            bugs.append(data)

    # dedup by extid/url
    seen, uniq = set(), []
    for b in bugs:
        key = b.get("extid") or b.get("url") or id(b)
        if key in seen: continue
        uniq.append(b); seen.add(key)
    return uniq

def collect_artifacts(crashes: List[Dict]) -> Dict[str, List[str]]:
    out = {"logs": [], "reports": [], "syz_repro": [], "c_repro": []}
    for rec in crashes or []:
        for k, cell in rec.items():
            if isinstance(cell, dict) and "content" in cell:
                content = cell.get("content") or ""
                lk = k.lower()
                if "log" in lk:
                    out["logs"].append(content)
                elif "report" in lk:
                    out["reports"].append(content)
                elif "syz" in lk:
                    out["syz_repro"].append(content)
                elif "c repro" in lk or "c-repro" in lk or (lk.strip() == "c"):
                    out["c_repro"].append(content)
    return out

# ---------------- Builder jsonl parsing ----------------

def load_from_builder_jsonl(input_path: str) -> List[Dict]:
    rows = read_jsonl(input_path)
    bugs = []
    for r in rows:
        bug = {
            "extid": r.get("id") or r.get("source_url") or f"id-{len(bugs)}",
            "title": r.get("title",""),
            "crash_report": (r.get("artifacts",{}) or {}).get("crash_report",""),
            "crashes": []
        }
        # try to recover logs from user message "# Logs" section
        user_msgs = [m for m in r.get("messages",[]) if m.get("role")=="user"]
        log_txt = ""
        for um in user_msgs:
            cont = um.get("content","")
            m = re.search(r"# Logs.*?\n([\s\S]+)$", cont)
            if m:
                log_txt = m.group(1).strip()
                break
        if log_txt:
            bug["crashes"].append({"Log": {"content": log_txt}})
        bugs.append(bug)
    return bugs

# ---------------- Main build ----------------

def build_round_files(bugs: List[Dict], out_dir: str):
    ensure_dir(out_dir)
    logs_rows, gold_short_rows, gold_full_rows = [], [], []

    for b in bugs:
        extid = b.get("extid") or b.get("url") or ""
        arts = collect_artifacts(b.get("crashes") or [])
        log_txt = pick_first_nonempty(arts["logs"])
        crash_report = b.get("crash_report") or pick_first_nonempty(arts["reports"])

        # SHORT gold（优先从 crash_report 抽锚点，否则从 log）
        anchors = extract_anchor_lines(crash_report) if crash_report else []
        if not anchors and log_txt:
            anchors = extract_anchor_lines(log_txt)

        # FULL gold（如果有官方 crash_report，直接用；否则从 log/report 尽量还原）
        full_lines = []
        if crash_report:
            # 直接用原文（已是“长版”），必要时做一次标准化（仅去时间戳）
            full_lines = [norm_line(x) for x in crash_report.splitlines() if x.strip()]
        else:
            candidate_text = crash_report or log_txt or ""
            full_lines = extract_full_from_text(candidate_text)

        if log_txt:
            logs_rows.append({"id": extid, "log": log_txt})
        if anchors:
            gold_short_rows.append({"id": extid, "report": "\n".join(anchors)})
        if full_lines:
            gold_full_rows.append({"id": extid, "report": "\n".join(full_lines)})

    logs_path       = os.path.join(out_dir, "logs.jsonl")
    gold_short_path = os.path.join(out_dir, "gold_short.jsonl")
    gold_full_path  = os.path.join(out_dir, "gold_full.jsonl")
    write_jsonl(logs_rows, logs_path)
    write_jsonl(gold_short_rows, gold_short_path)
    write_jsonl(gold_full_rows, gold_full_path)

    print(f"[DONE] logs:       {len(logs_rows)} → {logs_path}")
    print(f"[DONE] gold_short: {len(gold_short_rows)} → {gold_short_path}")
    print(f"[DONE] gold_full:  {len(gold_full_rows)} → {gold_full_path}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="crawler dir|file or builder jsonl")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--source", choices=["crawler","builder_jsonl"], required=True)
    args = ap.parse_args()

    bugs = load_all_bugs_from_crawler(args.input) if args.source == "crawler" else load_from_builder_jsonl(args.input)
    if not bugs:
        print("[ERROR] No bugs found from input.", file=sys.stderr); sys.exit(2)

    build_round_files(bugs, args.out)

if __name__ == "__main__":
    main()
