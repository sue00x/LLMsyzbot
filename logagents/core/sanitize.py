
# -*- coding: utf-8 -*-
import re
# _TS_PREFIX = re.compile(r"^\s*\[[^\]]+\]\s*")
_TS_PREFIX = re.compile(r"^\s*(\[[^\]]+\]\s*){1,2}")

_WS_MULTI  = re.compile(r"\s+")

def _normalize_line(s: str) -> str:
    s = _TS_PREFIX.sub("", s)
    s = s.rstrip("\r\n")
    s = _WS_MULTI.sub(" ", s)
    return s.strip()

def _normalize_text_block(s: str) -> str:
    return "\n".join(_normalize_line(ln) for ln in s.splitlines())

def sanitize_from_log(extracted: str, whole_log_text: str, span: str = "full"):
    if not extracted:
        return []
    kept = []
    norm_whole = _normalize_text_block(whole_log_text)
    for line in extracted.splitlines():
        s = line.strip("\r")
        if not s:
            continue
        if s in whole_log_text:
            kept.append(s); continue
        ns = _normalize_line(s)
        if ns and ns in norm_whole:
            kept.append(s)
    return kept


# def sanitize_from_log(extracted, whole_log_text, span="full"):
#     print(f"[SANITIZE] LLM完整原始输出:")
#     print("=" * 50)
#     print(extracted)  # 完整输出，不截断
#     print("=" * 50)
    
#     # 临时关闭验证，直接返回
#     return extracted.splitlines()