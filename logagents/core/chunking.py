
# -*- coding: utf-8 -*-
import re, time, threading
from typing import List, Tuple, Dict, Any
from dataclasses import dataclass
from collections import deque
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout
from tqdm import tqdm

RE_ANCHORS = [
    re.compile(r"BUG:\s*KASAN", re.I),
    re.compile(r"\bCall Trace:")
]
RE_SECONDARY = [
    re.compile(r"\b(Read|Write) of size \d+", re.I),
    re.compile(r"\bCPU:\s*\d+", re.I),
    re.compile(r"\bHardware name:\s*", re.I),
    re.compile(r"\bAllocated by task\b", re.I),
    re.compile(r"\bFreed by task\b", re.I),
    re.compile(r"\bThe buggy address belongs to\b", re.I),
    re.compile(r"\bMemory state around\b", re.I),
    re.compile(r"\bpage_owner\b", re.I),
    re.compile(r"^page:\s*[0-9a-fx]+", re.I),
    re.compile(r"\b(slab|kmalloc|kmem_cache|object)\b", re.I),
    re.compile(r"\bDisassembly\b|\bCode:\b", re.I),
    re.compile(r"\bftrace\b|\btracing\b|^trace:", re.I),
]

def chunk_lines(lines: List[str], max_lines: int, stride: int) -> List[Tuple[int, int]]:
    spans = []
    n = len(lines)
    i = 0
    while i < n:
        j = min(i + max_lines, n)
        spans.append((i, j))
        if j == n:
            break
        i = max(0, j - (max_lines - stride))
    return spans

def _find_anchor_lines(lines: List[str]) -> List[int]:
    idxs = []
    for i, ln in enumerate(lines):
        if any(p.search(ln) for p in RE_ANCHORS) or any(p.search(ln) for p in RE_SECONDARY):
            idxs.append(i)
    seen = set(); out = []
    for x in idxs:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

def _merge_intervals(intervals: List[Tuple[int, int]], max_lines: int) -> List[Tuple[int, int]]:
    if not intervals:
        return []
    intervals = sorted(intervals)
    merged: List[List[int]] = []
    for s, e in intervals:
        if not merged or s > merged[-1][1] - 10:
            merged.append([s, e])
        else:
            merged[-1][1] = max(merged[-1][1], e)
            if merged[-1][1] - merged[-1][0] > max_lines:
                merged[-1][1] = merged[-1][0] + max_lines
    return [(s, e) for s, e in merged]

def anchor_spans(lines: List[str], max_lines: int, pre: int = 20) -> List[Tuple[int, int]]:
    n = len(lines)
    anchors = _find_anchor_lines(lines)
    if not anchors:
        return []
    intervals = []
    for a in anchors:
        s = max(0, a - pre)
        e = min(n, s + max_lines)
        intervals.append((s, e))
    return _merge_intervals(intervals, max_lines)

def make_windows(lines: List[str], max_lines: int, stride: int):
    spans = anchor_spans(lines, max_lines=max_lines, pre=20)
    if spans:
        return spans, "anchor"
    return chunk_lines(lines, max_lines=max_lines, stride=stride), "sliding"

class Task:
    __slots__ = ("gids", "tok_budget", "max_lines", "stride", "depth", "fewshot_level")
    def __init__(self, gids, tok_budget, max_lines, stride, depth=0, fewshot_level=2):
        self.gids = gids
        self.tok_budget = tok_budget
        self.max_lines = max_lines
        self.stride = stride
        self.depth = depth
        self.fewshot_level = fewshot_level

def schedule_adaptive(task: Task,
                      SPLIT_MAX_DEPTH=2,
                      SHRINK_MAX_DEPTH=3,
                      TOK_SHRINK_FACTOR=0.7,
                      LINE_SHRINK_FACTOR=0.7,
                      MIN_TOK=220,
                      MIN_LINES=30):
    new_tasks = []
    if len(task.gids) > 1 and task.depth < SPLIT_MAX_DEPTH:
        mid = (len(task.gids)+1)//2
        next_tok = max(int(task.tok_budget*TOK_SHRINK_FACTOR), MIN_TOK)
        next_ln  = max(int(task.max_lines*LINE_SHRINK_FACTOR), MIN_LINES)
        next_fs  = max(task.fewshot_level - 1, 0)
        left  = Task(task.gids[:mid], next_tok, next_ln, task.stride, depth=task.depth+1, fewshot_level=next_fs)
        right = Task(task.gids[mid:], next_tok, next_ln, task.stride, depth=task.depth+1, fewshot_level=next_fs)
        new_tasks.extend([left, right]); return new_tasks
    if task.depth < SHRINK_MAX_DEPTH:
        next_tok = max(int(task.tok_budget*TOK_SHRINK_FACTOR), MIN_TOK)
        next_ln  = max(int(task.max_lines*LINE_SHRINK_FACTOR), MIN_LINES)
        next_fs  = max(task.fewshot_level - 1, 0)
        shrinked = Task(task.gids, next_tok, next_ln, task.stride, depth=task.depth+1, fewshot_level=next_fs)
        new_tasks.append(shrinked); return new_tasks
    return new_tasks

def _run_with_timeout(desc: str, timeout_s: int, func):
    step = 0.2
    bar = tqdm(total=timeout_s, desc=desc, unit="s", position=2, leave=False)
    stop = {"v": False}
    def ticker():
        import time as _t
        t = 0.0
        while not stop["v"] and t < timeout_s:
            _t.sleep(step); t += step
            try: bar.update(step)
            except Exception: break
        try: bar.close()
        except Exception: pass
    th = threading.Thread(target=ticker, daemon=True); th.start()
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(func)
            return fut.result(timeout=timeout_s)
    except FTimeout:
        raise TimeoutError(f"{desc} timed out after {timeout_s}s")
    finally:
        stop["v"] = True
        try: bar.close()
        except Exception: pass
