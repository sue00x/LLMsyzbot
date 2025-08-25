
# -*- coding: utf-8 -*-
import re
from typing import List, Dict

def rule_extract_fallback(logtxt: str, gid_list: List[str], gid2text: Dict[str, str]) -> Dict[str, str]:
    print(f"🚨 [FALLBACK] ===== RULE FALLBACK TRIGGERED =====")
    print(f"🚨 [FALLBACK] This means ALL LLM attempts failed!")
    print(f"🚨 [FALLBACK] Processing gids: {gid_list}")
    
    out = {}
    for gid in gid_list:
        s = gid2text.get(gid, "")
        print(f"🚨 [FALLBACK] Processing {gid}, text length: {len(s)}")
        
        m = re.search(
            r"(BUG:\s*KASAN[^\n]*\n(?:.*\n){0,200}?(?:Memory state around[^\n]*\n(?:.*\n){0,200})?)",
            s, re.M
        )
        if m:
            result = m.group(1).strip("\n")
            print(f"🚨 [FALLBACK] Found KASAN pattern, extracted {len(result)} chars")
            out[gid] = result
            continue
            
        m2 = re.search(r"(Call Trace:\n(?:.+\n){1,120})", s, re.M)
        if m2:
            result = m2.group(1).strip("\n")
            print(f"🚨 [FALLBACK] Found Call Trace pattern, extracted {len(result)} chars")
            out[gid] = result
        else:
            print(f"🚨 [FALLBACK] No patterns found for {gid}")
            out[gid] = ""
    
    print(f"🚨 [FALLBACK] ===== RULE FALLBACK END =====")
    return out