
# -*- coding: utf-8 -*-
import re
from typing import List, Dict, Any
import re as _re

# ---- CoT driver helpers ----
Log_Explain_COT = """You are a senior Linux kernel crash analyst.
You will read a syzkaller/syzbot-style crash report and produce a diagnosis using Chain-of-Thought reasoning.

Instructions:
1. Show your step-by-step analysis process explicitly
2. Walk through each section of the crash report systematically
3. Explain your reasoning for each conclusion
4. Then provide a final structured summary

Analysis Steps to Follow:
Step 1: Identify the crash type from error messages/stack traces
Step 2: Locate the faulting instruction and memory access details
Step 3: Trace the call stack to find the trigger function
Step 4: Determine the affected kernel subsystem
Step 5: Assess the security/stability impact
Step 6: Suggest debugging approaches

Format:
## Step-by-Step Analysis
[Show your reasoning for each step]

## Final Diagnosis
- Bug type: [conclusion with reasoning]
- Suspected subsystem: [conclusion with reasoning]  
- Trigger function(s): [conclusion with reasoning]
- Memory access: [details if present]
- Stack highlight: [top 1-3 frames]
- Risk assessment: [1-3 bullets]
- Debug suggestions: [1-5 bullets]
"""

def extract_final_block(text: str) -> str:
    m = _re.search(r"<final>(.*?)</final>", text, flags=_re.S|_re.I)
    return (m.group(1).strip() if m else "").strip()

def diagnose_crash_report_cot(text: str, llm, cfg, timeout_s: int = 90) -> str:
    user_prompt = (
        "Report:\n"
        "----------------------------------------\n"
        f"{text}\n"
        "----------------------------------------\n"
        "Remember: produce ONLY the final Markdown between <final> and </final>."
    )
    def _call():
        return llm.chat(
            [
                {"role":"system","content": Log_Explain_COT},
                {"role":"user",  "content": user_prompt}
            ],
            temperature=float(cfg.get("temperature_diagnose", 0.2)),
            _retries=0
        )
    from .chunking import _run_with_timeout
    try:
        out = _run_with_timeout(desc="[diagnose-cot] llm", timeout_s=timeout_s, func=_call)
        final_md = extract_final_block(out or "")
        if not final_md:
            return diagnose_crash_report(text)
        return final_md
    except Exception:
        return diagnose_crash_report(text)

# ---- Rules-based parsing ----
_BUG_CLASSES = [
    ("use-after-free", re.compile(r"\buse-after-free\b", re.I)),
    ("null-ptr-deref", re.compile(r"\bnull[- ]?ptr[- ]?deref(erence)?\b|\bNULL pointer dereference\b", re.I)),
    ("out-of-bounds", re.compile(r"\b(out[- ]?of[- ]?bounds|oob)\b", re.I)),
    ("kasan-generic", re.compile(r"\bKASAN\b", re.I)),
    ("kcsan-race", re.compile(r"\bKCSAN\b|\bdata[- ]?race\b", re.I)),
    ("lockdep", re.compile(r"\blockdep\b|\bpossible recursive locking\b|\bdeadlock\b", re.I)),
    ("ubsan", re.compile(r"\bUBSAN\b|\bundefined behavior\b", re.I)),
]
_RW_LINE_RX = re.compile(r"\b(Read|Write)\s+of\s+size\s+(\d+)\b.*?\baddr\b\s+([0-9a-fx]+)", re.I)
_BUG_TITLE_RX = re.compile(r"^BUG:\s*(KASAN|KCSAN|lockdep|UBSAN).*?\b(in|at)\b\s+([A-Za-z0-9_./:-]+)", re.I)
_FUNC_RX      = re.compile(r"\b(in|at)\b\s+([A-Za-z0-9_./:-]+)")
_CALLTRACE_HDR= re.compile(r"^\s*Call Trace:\s*$", re.I)
_FRAME_RX     = re.compile(r"^\s*([A-Za-z0-9_./:-]+)\+0x[0-9a-f]+/0x[0-9a-f]+(?:\s+\S+)?", re.I)
_CPU_LINE_RX  = re.compile(r"^\s*CPU:\s*\d+.*?\btask\b\s+([A-Za-z0-9._-]+)(?:/(\d+))?", re.I)
_SUBSYS_HINTS = [
    ("io_uring", re.compile(r"\bio_uring\b", re.I)),
    ("net",      re.compile(r"\b(net/|net_)\b", re.I)),
    ("mm",       re.compile(r"\b(mm/|kmalloc|slab|page)\b", re.I)),
    ("fs",       re.compile(r"\b(fs/|vfs|inode|dentry)\b", re.I)),
    ("block",    re.compile(r"\b(block/|bio|blk_)\b", re.I)),
]

def _first_match(rx, lines):
    for ln in lines:
        m = rx.search(ln)
        if m:
            return m
    return None

def _collect_calltrace(lines):
    frames = []
    in_ct = False
    for ln in lines:
        if _CALLTRACE_HDR.search(ln):
            in_ct = True
            continue
        if in_ct:
            if not ln.strip():
                break
            if _FRAME_RX.search(ln):
                frames.append(ln.strip())
            else:
                if ln.strip().endswith(":"):
                    break
    return frames

def _guess_bug_class(lines):
    text = "\n".join(lines)
    for name, rx in _BUG_CLASSES:
        if rx.search(text):
            return name
    return "unknown"

def _guess_subsystem(lines):
    text = "\n".join(lines)
    for name, rx in _SUBSYS_HINTS:
        if rx.search(text):
            return name
    return "unknown"

def parse_core_facts_from_report(text: str) -> dict:
    lines = [ln.rstrip("\n") for ln in text.splitlines()]
    bug_title   = _first_match(_BUG_TITLE_RX, lines)
    rw_info     = _first_match(_RW_LINE_RX, lines)
    cpu_line    = _first_match(_CPU_LINE_RX, lines)
    frames      = _collect_calltrace(lines)
    top_frame   = frames[0] if frames else ""
    bug_class   = _guess_bug_class(lines)
    subsystem   = _guess_subsystem(lines)

    func = None
    if bug_title:
        func = bug_title.group(3)
    else:
        m2 = _first_match(_FUNC_RX, lines[:10])
        func = m2.group(2) if m2 else None

    rw_dir, rw_size, rw_addr = None, None, None
    if rw_info:
        rw_dir, rw_size, rw_addr = rw_info.group(1).lower(), int(rw_info.group(2)), rw_info.group(3)

    task_name, task_tid = None, None
    if cpu_line:
        task_name = cpu_line.group(1)
        task_tid  = cpu_line.group(2)

    return {
        "bug_class": bug_class,
        "subsystem": subsystem,
        "function": func,
        "rw_dir": rw_dir, "rw_size": rw_size, "rw_addr": rw_addr,
        "task": task_name, "tid": task_tid,
        "top_frame": top_frame,
        "frame_count": len(frames),
    }

def diagnose_crash_report(text: str) -> str:
    f = parse_core_facts_from_report(text)
    bullets = []

    bc = f["bug_class"]
    func = f["function"] or "unknown"
    subsys = f["subsystem"]
    bullets.append(f"- **Bug 类型**：`{bc}`；**触发点函数**：`{func}`；**子系统猜测**：`{subsys}`。")

    if f["rw_dir"]:
        bullets.append(f"- **内存访问**：{f['rw_dir']} of size {f['rw_size']} @ `{f['rw_addr']}`。")
    else:
        bullets.append("- **内存访问**：报告中未提取到 `Read/Write of size ... @ addr` 明确行。")

    if f["top_frame"]:
        bullets.append(f"- **调用栈顶部**：`{f['top_frame']}`；（共 {f['frame_count']} 帧）")
    else:
        bullets.append("- **调用栈**：未检测到 `Call Trace:` 段或栈帧。")

    if f["task"]:
        tid = f["tid"] or "?"
        bullets.append(f"- **任务/线程**：`{f['task']}/{tid}`（由 CPU 段提取）。")

    risk = []
    if bc == "use-after-free":
        risk.append("访问已释放对象，典型根因包括竞态释放、双重释放后的悬挂指针、未正确延长对象生命周期。")
        risk.append("通常会导致不可预期行为，严重时内核崩溃或权限提升。")
    elif bc == "null-ptr-deref":
        risk.append("空指针解引用，常因错误的错误路径处理或未初始化对象。")
        risk.append("通常会触发 Oops/崩溃（可被 KASAN 先行捕获）。")
    elif bc == "out-of-bounds":
        risk.append("越界读/写，可能破坏相邻对象或泄露敏感信息。")
    elif bc == "kcsan-race":
        risk.append("数据竞争（未同步的并发访问），需要添加适当的锁或内存序。")
    elif bc == "lockdep":
        risk.append("锁依赖问题（死锁或递归锁），检查锁顺序与持有时机。")
    elif bc == "ubsan":
        risk.append("未定义行为（UB），表明存在未约束的算术/类型转换等问题。")
    else:
        risk.append("泛化内存/同步异常，建议结合完整日志进一步定位。")
    bullets.append("- **风险解读**：\n  - " + "\n  - ".join(risk))

    hints = []
    if subsys == "io_uring":
        hints.append("检查提交/完成路径中对象生命周期（req/ctx），特别是 task_work/完成回调的释放时序。")
        hints.append("核对 refcount 与取消路径（cancelation）是否存在双重释放或重用。")
    elif subsys == "mm":
        hints.append("检查 slab/页面生命周期，确认释放与再次使用之间是否有竞态。")
    elif subsys == "fs":
        hints.append("关注 inode/dentry 生命周期，mount/umount 与文件操作的并发。")
    elif subsys == "net":
        hints.append("关注 skb/套接字引用计数与回收路径的并发。")

    if func and func != "unknown":
        hints.append(f"在 `{func}` 附近加断点或打印，追踪对象分配/释放与访问路径。")

    if hints:
        bullets.append("- **排查建议**：\n  - " + "\n  - ".join(hints))

    return "\n".join(bullets)
