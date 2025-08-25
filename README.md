# LogAgents: Modular KASAN Log Analysis & Explainable Report Generation

This suite implements a **modular LLM + rules hybrid pipeline** for:
1. **Anchor-first extraction** of syzbot-style crash report slices from raw kernel logs (LLM with rule fallback);
2. **Post-process normalization** (order, dedup, cap lengths) under strict "verbatim-from-log" constraints;
3. **Section completion** for missing core blocks and diagnostic tails;
4. **Policy enforcement** to stabilize output length, order, and content;
5. **Explainable diagnosis** in **rules** and **CoT** modes.

> This is *not* model training. It is **prompt- and strategy-controlled extraction** combined with deterministic rule verification to minimize hallucination risk.



## Structure

```

logagents/
├─ core/
│  ├─ io\_utils.py        # IO helpers for json/jsonl/config
│  ├─ chunking.py        # Anchor-based + sliding-window chunking
│  ├─ prompts.py         # System prompt blocks + few-shot injection
│  ├─ sanitize.py        # "Verbatim-only" line filtering
│  ├─ sections.py        # Section definitions & finders
│  ├─ augment.py         # Section completion (core blocks + diagnostics)
│  ├─ ordering.py        # Fixed order + tool-frame filtering + deduplication
│  ├─ policy.py          # Policy caps, filters, and diagnostic quotas
│  ├─ fallback.py        # Regex-based extraction fallback
│  ├─ explain.py         # Sidecar explain metadata recorder
│  └─ diagnose.py        # Rules-based & CoT-based diagnosis
├─ pipelines/
│  ├─ pl\_extract.py      # Main pipeline: extract → augment → normalize → policy → explain
│  └─ pl\_diagnose.py     # Post-process diagnosis from candidates
├─ llm\_client.py         # Thin LLM API wrapper (Chat Completions)
└─ config.json           # Model, API, and runtime parameters

````

---

## Quickstart

1. Edit `config.json` with your `API_URL`, `API_KEY`, `MODEL`, and runtime settings.
2. Prepare input logs in JSONL format:
```json
   {"id": "bug01", "log": "<full kernel log text>"}
````
3. You can use syz_kasan_scraper_full.py to scrape the log from syzbot:

```bash
python syz_kasan_scraper_full.py --max-bugs 1 --combine 
```
4. Then use build_round_files.py to prepare the input log:
```bash
python build_round_files.py --input crawler/result --out ./preprocess --source crawler
```

5. Run parsing pipeline:

```bash
python -m logagents.pipelines.pl_extract --logs ./preprocess/bug01/logs.jsonl --out  ./out/full --span full --mode ai_try --compact --explain sidecar --include_diag true
```

Artifacts:

* `out/full/candidates.jsonl` — LLM+rules extracted crash reports
* `out/full/explain_sidecar/` — Per-sample explain metadata
* Optional: `fallback_hits.jsonl` — Logs where rules fallback triggered

6. (Optional) Run diagnosis on candidates:

**Rules JSON**

```bash
python -m logagents.pipelines.pl_diagnose --candidates ./out/full/candidates.jsonl --out ./out/full/explain_CoT --mode rules --format json
```

**CoT Markdown**

```bash
python -m logagents.pipelines.pl_diagnose --candidates ./out/full/candidates.jsonl --out ./out/full/explain_CoT --mode cot --format md
```

**Log Explain**
```bash
python -m logagents.pipelines.pl_extract --logs ./preprocess/bug01/logs.jsonl --out  ./out/full --span full --mode ai_try --compact --explain sidecar --include_diag true   
```
---

## Notes

* Extraction uses **anchor-first chunking** with fallback to sliding-window.
* All lines in output are **verbatim substrings of the original log**; non-verbatim lines are dropped.
* Missing core sections (BUG, RW, Call Trace, etc.) are auto-completed from the original log.
* Diagnostic tail sections (page\_owner, Disassembly, registers) are optional via `--include_diag`.
* Policy caps (max lines per section, diagnostic quotas) prevent runaway outputs.
* Explain sidecar provides a full trace of chunking, few-shot usage, filtering, and policy application.

---

## Advantages

| Dimension           | Syzkaller Rules Only | LLM Only        | LogAgents Hybrid                   |
| ------------------- | -------------------- | --------------- | ---------------------------------- |
| Generalization      | Low                  | High            | High (anchor+LLM)                  |
| Maintenance         | High                 | Low             | Medium                             |
| Multi-language      | Weak                 | Strong          | Strong                             |
| Context Utilization | Local                | Global          | Global (windowed)                  |
| Explainability      | Weak                 | Strong          | Strong                             |
| Hallucination Risk  | None                 | High            | Very Low                           |
| Output Stability    | High                 | Medium          | High                               |
| Use Cases           | Fixed formats        | New/hetero logs | Hetero logs with controlled output |

---

## License

