# # -*- coding: utf-8 -*-
import re
from typing import List, Dict

SYZBOT_RULES = """You are extracting a syzbot-style crash report from a Linux kernel log.
STRICT RULES:
- Output ONLY raw lines that appear VERBATIM in the input logs (you may drop leading timestamps like "[ 12.345]").
- Output MUST follow this order IF present in the logs (skip any missing parts WITHOUT commentary):
  1) BUG/KASAN line(s)
  2) "Read/Write of size ..." line
  3) "CPU:" (and optional "Hardware name:")
  4) "Call Trace:" and subsequent stack frames (skip tool frames like dump_stack/kasan_report/__asan_/printk)
  5) KASAN details in this exact order:
     5.1) "Allocated by task" block
     5.2) "Freed by task" block
     5.3) "The buggy address belongs to" block
     5.4) "Memory state around" block
- If you see diagnostics blocks like "page_owner", "page:", "slab/object/kmalloc/kmem_cache", "Disassembly/Code:", "ftrace/tracing", or register dumps (RIP/RSP/RAX...), copy them verbatim as well.
- Do NOT invent or rewrite text. If a section is missing, omit it (no JSON, no explanations, no headings, no extra punctuation).
- IMPORTANT: Do not output any line that contains a question mark ('?' or '？'); if such a line appears in the logs, skip that line."""

# SYZBOT_RULES = """You are extracting a syzbot-style crash report from a Linux kernel log.
# STRICT RULES:
# - Treat the following as ANCHORS. If they exist in the log, copy them VERBATIM (remove only leading timestamps like "[ 12.345]"):
#   ANCHORS (in order):
#     1) Lines starting with "BUG:" or "KASAN:"
#     2) Lines starting with "Read of size" or "Write of size"
#     3) Lines starting with "CPU:" (and optional "Hardware name:")
#     4) Line "Call Trace:" and subsequent stack frames (skip dump_stack/kasan_report/__asan_/printk)
#     5) Diagnostic blocks:
#        - "Allocated by task"
#        - "Freed by task"
#        - "The buggy address belongs to"
#        - "Memory state around"
#        - any "page_owner", "page:", "slab/object/kmalloc/kmem_cache", "Disassembly/Code:", "ftrace/tracing", registers (RIP/RSP/RAX...)
# - Output ONLY these anchors + their verbatim lines.
# - Skip any missing anchors (do not invent text).
# - IMPORTANT: Do not output any line that contains a question mark ('?' or '？')."""

FEWSHOT_FULL  = None
FEWSHOT_LIGHT = None

def build_fx_fz_prompts(gids: List[str], gid2text: Dict[str, str], tok_budget: int, max_lines: int, stride: int, fewshots=None) -> str:
    remain = max(tok_budget, 200) * 4  # rough char budget
    blocks = []
    for gid in gids:
        txt = gid2text[gid]
        if len(txt) > remain:
            txt = txt[:remain]
        remain = max(0, remain - len(txt))
        block = (
            f"### INPUT CHUNK {gid} START\n"
            f"{txt}\n"
            f"### INPUT CHUNK {gid} END\n"
            f"要求：从该 chunk 中，抽取 syzbot 风格报告的所有【在本 chunk 内出现的】段落，并严格逐行拷贝原文子串（允许去掉开头形如\"[ 12.345]\"的时间戳）。\n"
            f"⚠️ 特别注意：\n"
            f"- 函数调用行必须完整保留，包括偏移量、源文件路径、行号以及 [inline] 标记（例如：do_check_common+0x13f/0x20b0 kernel/bpf/verifier.c:22798 [inline]）。绝不能截断或省略任何部分。\n"
            f"- 不要只保留函数名；必须逐字输出整行。\n"
            f"- 除去时间戳外，任何字符都不能删除或改写。\n"
            f"\n"
            f"可抽取的段包括：\n"
            f"1) 以 'BUG: KASAN:' 开头的行（若本 chunk 不含则跳过）\n"
            f"2) 'Read of size N...' 或 'Write of size N...'（若不含则跳过）\n"
            f"3) 'CPU:'（以及可选的 'Hardware name:'）（若不含则跳过）\n"
            f"4) 'Call Trace:' 起始到若干栈帧：\n"
            f"   - 保留所有栈帧行，逐字拷贝。\n"
            f"   - 跳过 dump_stack/kasan_report/__asan_/printk 等工具帧。\n"
            f"   - 其余函数调用行必须完整逐字输出，包括路径、行号、[inline]。\n"
            f"5) 如出现以下任何 KASAN 详情或诊断块请完整拷贝：\n"
            f"   5.1) 'Allocated by task' 块；5.2) 'Freed by task'；5.3) 'The buggy address belongs to'；5.4) 'Memory state around'（含后续十六进制字节块）\n"
            f"   5.5) 'page_owner' / 以 'page:' 开头的 page dump；'slab/object/kmalloc/kmem_cache' 相关块；'Disassembly/Code:'；'ftrace/tracing'；寄存器组（RIP/RSP/RAX...）\n"
            f"\n"
            f"只输出原文行，不添加注释/JSON/标签/多余标点。\n"
            f"重要：如果任何行包含问号（'?' 或 '？'），请跳过该行不要输出。\n"
            f"### CHUNK {gid} START\n"
            f"...拷贝的原文行...\n"
            f"### CHUNK {gid} END\n"
        )

        blocks.append(block)
    header = ""
    if fewshots:
        header = f"### FEWSHOT ###\n{fewshots}\n### END FEWSHOT ###\n"
    return header + "\n".join(blocks)

def align_answer_to_chunks(output_text: str, gids: List[str]) -> Dict[str, str]:
    res = {gid: "" for gid in gids}
    for gid in gids:
        pattern = re.compile(
            r"###\s*CHUNK\s*{}\s*START\s*\n(.*?)\n###\s*CHUNK\s*{}\s*END".format(
                re.escape(gid), re.escape(gid)
            ), re.S | re.I
        )
        m = pattern.search(output_text)
        if m:
            res[gid] = m.group(1).strip("\n")
    return res
