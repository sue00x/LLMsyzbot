"""
python -m logagents.pipelines.pl_diagnose --candidates ./out/full/candidates.jsonl --out ./out/full/explain_CoT --mode cot --format md
"""

# -*- coding: utf-8 -*-
import os, argparse
from ..core.io_utils import read_jsonl, write_jsonl, read_config
from ..core.diagnose import diagnose_crash_report, diagnose_crash_report_cot, parse_core_facts_from_report
from llm_client import LLMClient
from tqdm import tqdm

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", choices=["cot","rules"], default="cot")
    ap.add_argument("--format", choices=["json","md"], default="json")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    rows = read_jsonl(args.candidates)
    cfg = read_config("config.json")
    has_llm = (args.mode=="cot")
    if has_llm:
        llm = LLMClient(
            cfg.get("API_URL"),
            cfg.get("API_KEY"),
            cfg.get("MODEL"),
            timeout=int(cfg.get("LLM_TIMEOUT_DIAGNOSE", cfg.get("LLM_TIMEOUT", 90))),
            retries=int(cfg.get("LLM_RETRIES", 0)),
            connect_timeout=int(cfg.get("LLM_CONNECT_TIMEOUT", 10)),
            read_timeout=int(cfg.get("LLM_READ_TIMEOUT", 55))
        )
    out_json = []
    out_dir_md = os.path.join(args.out, "diagnose_CoT")
    if args.format=="md": os.makedirs(out_dir_md, exist_ok=True)

    pbar = tqdm(total=len(rows), desc="diagnose")
    for r in rows:
        cid = r.get("id"); ctext = r.get("candidate","")
        if not ctext.strip():
            pbar.update(1); continue
        if args.format=="json":
            facts = parse_core_facts_from_report(ctext)
            out_json.append({"id": cid, "facts": facts})
        else:
            if args.mode=="cot":
                md_body = diagnose_crash_report_cot(ctext, llm, cfg, timeout_s=int(cfg.get("LLM_TIMEOUT_DIAGNOSE", cfg.get("LLM_TIMEOUT", 90))))
            else:
                md_body = diagnose_crash_report(ctext)
            with open(os.path.join(out_dir_md, f"{cid}.md"), "w", encoding="utf-8") as f:
                f.write(f"# Report Explain for {cid}\n\n{md_body}\n")
        pbar.update(1)
    pbar.close()

    if args.format=="json":
        write_jsonl(out_json, os.path.join(args.out, "diagnose.jsonl"))

if __name__ == "__main__":
    main()
