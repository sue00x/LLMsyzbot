"""
python -m logagents.pipelines.pl_extract \
  --logs ./preprocess/logs.jsonl \
  --out  ./out/full \
  --span full \
  --mode ai_try \
  --compact \
  --explain sidecar \
  --fewshot_full prompts/fewshot_pool.jsonl \
  --include_diag true \
  --call_trace_max 25 --mem_hex_max 96 --diag_total_max 400

  
python -m logagents.pipelines.pl_extract --logs ./preprocess/bug01/logs.jsonl --out  ./out/full --span full --mode ai_try --compact --explain sidecar --include_diag true   
"""
# -*- coding: utf-8 -*-
import os, argparse
from collections import defaultdict, deque
from typing import Dict, List
from tqdm import tqdm

from ..core.io_utils import read_jsonl, write_jsonl, read_config
from ..core.chunking import make_windows, Task, schedule_adaptive, _run_with_timeout, RE_ANCHORS, RE_SECONDARY
from ..core.prompts import SYZBOT_RULES, build_fx_fz_prompts, align_answer_to_chunks, FEWSHOT_FULL, FEWSHOT_LIGHT
from ..core.sanitize import sanitize_from_log
from ..core.augment import augment_missing_sections, augment_diagnostics_tail
from ..core.ordering import order_normalize
from ..core.policy import SyzPolicy, apply_syzbot_policy, split_into_buckets
from ..core.explain import ExplainRecorder
from ..core.fallback import rule_extract_fallback

# NOTE: expect llm_client.py in PYTHONPATH as before
from llm_client import LLMClient

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--logs', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--span', default="full", choices=["full","slice"])
    parser.add_argument('--mode', default="ai_try")
    parser.add_argument('--compact', action='store_true')
    parser.add_argument('--evolve', action='store_true')
    parser.add_argument('--explain', default="off", choices=["off","json","sidecar","diagnose","diagnose_json"])
    parser.add_argument('--diagnose_mode', default="cot", choices=["cot","rules"])
    parser.add_argument('--gold', default="")
    parser.add_argument('--repair_mode', default="none")
    # new optional knobs
    parser.add_argument('--fewshot_full', default="")
    parser.add_argument('--fewshot_light', default="")
    parser.add_argument('--include_diag', default=False)  # true/false
    parser.add_argument('--call_trace_max', type=int, default=25)
    parser.add_argument('--mem_hex_max', type=int, default=4096)
    parser.add_argument('--alloc_max', type=int, default=80)
    parser.add_argument('--freed_max', type=int, default=80)
    parser.add_argument('--buggy_max', type=int, default=80)
    parser.add_argument('--diag_total_max', type=int, default=400)
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    cfg = read_config("config.json")

    # fewshot loading (optional)
    def _maybe_read(p):
        if p and os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return f.read()
        return None
    from ..core import prompts as _P
    _P.FEWSHOT_FULL = _maybe_read(args.fewshot_full) or _P.FEWSHOT_FULL
    _P.FEWSHOT_LIGHT= _maybe_read(args.fewshot_light) or _P.FEWSHOT_LIGHT

    llm = LLMClient(
        cfg.get("API_URL"),
        cfg.get("API_KEY"),
        cfg.get("MODEL"),
        timeout=int(cfg.get("LLM_TIMEOUT", 90)),
        retries=int(cfg.get("LLM_RETRIES", 0)),
        connect_timeout=int(cfg.get("LLM_CONNECT_TIMEOUT", 10)),
        read_timeout=int(cfg.get("LLM_READ_TIMEOUT", 55))
    )

    token_budget = int(cfg.get("token_budget", 500))
    max_lines    = int(cfg.get("max_lines_per_chunk", 60))
    stride       = int(cfg.get("chunk_stride", 50))
    max_workers  = int(cfg.get("LLM_CONCURRENCY", 2))
    timeout_s    = int(cfg.get("LLM_TIMEOUT", 90))
    group_size   = int(cfg.get("group_size", 1))

    logs = read_jsonl(args.logs)
    pbar_logs = tqdm(total=len(logs), desc="logs", position=0)

    all_candidates = []
    all_explains   = []

    for row in logs:
        gid_all = row.get("id") or row.get("gid") or "sample"
        logtxt = row.get("log") or row.get("text") or ""
        lines  = logtxt.splitlines()

        rec = ExplainRecorder(gid_all)
        rec.set_pipeline(token_budget=token_budget, max_lines_per_chunk=max_lines, stride=stride, group_size=group_size)

        spans, span_mode = make_windows(lines, max_lines=max_lines, stride=stride)
        rec.note_span_mode(span_mode)

        gid2text: Dict[str, str] = {}
        chunk_ids: List[str] = []
        for idx, (s, e) in enumerate(spans, start=1):
            gid = f"{gid_all}#c{idx}"
            chunk_ids.append(gid)
            gid2text[gid] = "\n".join(lines[s:e])

        id_groups: List[List[str]] = [chunk_ids[i:i+group_size] for i in range(0, len(chunk_ids), group_size)]
        tqdm.write(f"[{gid_all}] compact={bool(args.compact)} chunks={len(chunk_ids)} prompts={len(id_groups)} "
                   f"tok_budget={token_budget} lines_per_chunk={max_lines} stride={stride} windows={span_mode}")

        try:
            rec.note_anchors({
                "primary": [i for i,l in enumerate(lines) if any(p.search(l) for p in RE_ANCHORS)],
                "secondary": [i for i,l in enumerate(lines) if any(p.search(l) for p in RE_SECONDARY)],
            })
        except Exception:
            pass

        from concurrent.futures import ThreadPoolExecutor, as_completed
        chunk_segments = defaultdict(list)
        done_gids, fail_gids = set(), set()

        from collections import deque
        workq = deque()
        for gids in id_groups:
            workq.append(Task(gids=gids, tok_budget=token_budget, max_lines=max_lines, stride=stride, depth=0, fewshot_level=2))

        def build_prompt_for_task(task):
            from ..core.prompts import FEWSHOT_FULL, FEWSHOT_LIGHT, build_fx_fz_prompts
            fewshots = FEWSHOT_FULL if task.fewshot_level==2 else (FEWSHOT_LIGHT if task.fewshot_level==1 else None)
            return build_fx_fz_prompts(task.gids, gid2text, task.tok_budget, task.max_lines, task.stride, fewshots=fewshots)

        def submit_and_collect(task):
            prompt = build_prompt_for_task(task)
            print(f"[LLM_CALL] ===== 即将调用LLM =====")
            print(f"[LLM_CALL] 任务: {task.gids}")
            print(f"[LLM_CALL] 系统提示词: {SYZBOT_RULES}")
            print(f"[LLM_CALL] 用户提示词长度: {len(prompt)} 字符")
            print(f"[LLM_CALL] 用户提示词前200字符: {prompt[:200]}")
            def _call():
                try:
                    result = llm.chat(
                        [
                            {"role": "system", "content": SYZBOT_RULES},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=float(cfg.get("temperature_report", 0.0)),
                        _retries=0
                    )
                    
                    print(f"[LLM_CALL] LLM调用成功!")
                    print(f"[LLM_CALL] 返回长度: {len(result)} 字符")
                    print(f"[LLM_CALL] 返回类型: {type(result)}")
                    print(f"[LLM_CALL] 返回内容: '{result}'")  # 用引号包围，看清楚是否真的为空
                    print(f"[LLM_CALL] ===== LLM调用结束 =====")
                    
                    return result
                except Exception as e:
                    print(f"[LLM_CALL] LLM调用失败: {e}")
                    raise e

            try:
                out_text = _run_with_timeout(
                    desc=f"[{gid_all}] batch {task.gids[0]}..{task.gids[-1]} (d{task.depth},fs{task.fewshot_level},tok{task.tok_budget})",
                    timeout_s=timeout_s, func=_call
                )
            except TimeoutError:
                for g in task.gids:
                    rec.add_chunk_result(g, "timeout", task.fewshot_level, "", [], dropped_reason="timeout")
                return "timeout", task, {}

            try:
                parts = align_answer_to_chunks(out_text, task.gids)
            except Exception:
                for g in task.gids:
                    rec.add_chunk_result(g, "bad", task.fewshot_level, "", [], dropped_reason="parse_fail")
                return "bad", task, {}

            result_map = {}; kept_any = False
            for g in task.gids:
                seg = parts.get(g, "")
                kept = sanitize_from_log(seg, logtxt, span=args.span)
                rec.add_chunk_result(g, "ok", task.fewshot_level, seg, kept, dropped_reason=("empty_after_sanitize" if (seg and not kept) else ""))
                if kept:
                    kept_any = True
                    result_map[g] = "\n".join(kept)
            return ("ok" if kept_any else "empty"), task, result_map

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {}
            def submit_task(t): futures[pool.submit(submit_and_collect, t)] = t
            while workq and len(futures) < max_workers:
                submit_task(workq.pop())
            while futures or workq:
                for fut in as_completed(list(futures.keys())):
                    t = futures.pop(fut)
                    try:
                        status, task, result_map = fut.result()
                    except Exception as e:
                        tqdm.write(f"[{gid_all}] unexpected error: {e}")
                        status, task, result_map = ("bad", t, {})
                    if status == "ok":
                        for g, txt in result_map.items():
                            chunk_segments[g].append(txt); done_gids.add(g)
                        postfix = "ok"
                    elif status in ("empty", "timeout", "bad"):
                        new_tasks = schedule_adaptive(task)
                        if new_tasks:
                            for nt in reversed(new_tasks): workq.appendleft(nt)
                            postfix = f"retry(d={task.depth})"
                        else:
                            fb = rule_extract_fallback(logtxt, task.gids, gid2text)
                            for g, txt in fb.items():
                                if txt:
                                    chunk_segments[g].append(txt); done_gids.add(g)
                                else:
                                    fail_gids.add(g)
                            postfix = "fallback"
                    else:
                        postfix = status
                    while workq and len(futures) < max_workers:
                        submit_task(workq.popleft())
                    tqdm.write(f"[{gid_all}] {task.gids} -> {postfix}")
                    break

        remaining = set(sum(id_groups, [])) - done_gids
        if remaining:
            fb = rule_extract_fallback(logtxt, list(remaining), gid2text)
            for g, txt in fb.items():
                if txt:
                    chunk_segments[g].append(txt); done_gids.add(g)
                else:
                    fail_gids.add(g)

        tqdm.write(f"[{gid_all}] finished. ok={len(done_gids)} fail={len(fail_gids)}")

        ordered_chunks = [f"{gid_all}#c{i+1}" for i in range(len(spans))]
        merged_lines = []
        last_line = None
        seg_cnt = 0
        for cg in ordered_chunks:
            for seg in chunk_segments.get(cg, []):
                seg_cnt += 1
                for ln in seg.splitlines():
                    if ln != last_line:
                        merged_lines.append(ln)
                    last_line = ln
        candidate_text = "\n".join(merged_lines).strip("\n")
        rec.note_merge(seg_cnt, before_lines=len(merged_lines), after_lines=len(candidate_text.splitlines()))

        before_sections = []  # kept minimal to avoid heavy dependency

        if candidate_text:
            # 1) 补段
            candidate_text = augment_missing_sections(lines, candidate_text)
            candidate_text = augment_diagnostics_tail(lines, candidate_text)

            # 2) 先做策略裁剪（只做“截断/保留”，不关心顺序）
            policy = SyzPolicy(
                call_trace_max=args.call_trace_max or 25,
                alloc_max=args.alloc_max or 80,
                freed_max=args.freed_max or 80,
                buggy_max=args.buggy_max or 80,
                mem_hex_max=args.mem_hex_max or 96,
                diag_total_max=args.diag_total_max or 400,
                include_diag=(
                    (str(args.include_diag).lower()=="true") if args.include_diag is not None
                    else True
                ),
            )
            before_buckets = split_into_buckets(candidate_text)
            qm_before = len("\n".join(sum(before_buckets.values(), [])).splitlines())
            candidate_text = apply_syzbot_policy(candidate_text, policy)
            after_buckets  = split_into_buckets(candidate_text)
            qm_after  = len("\n".join(sum(after_buckets.values(), [])).splitlines())

            # 3) 最后一遍排序归一 + 缝合（确保 RIP/REGS 在尾部、Call Trace 成块、CPU/HW 只留最佳）
            candidate_text = order_normalize(candidate_text)
            caps = {}
            # simple caps diff for explain
            for k in before_buckets.keys():
                b=len(before_buckets.get(k,[]) or [])
                a=len(after_buckets.get(k,[]) or [])
                caps[k]={"before":b,"after":a,"trimmed":max(0,b-a)}
            caps["__notes__"]={
                "call_trace_max": policy.call_trace_max,
                "alloc_max": policy.alloc_max,
                "freed_max": policy.freed_max,
                "buggy_max": policy.buggy_max,
                "mem_hex_max": policy.mem_hex_max,
                "diag_total_max": policy.diag_total_max,
            }
            rec.note_policy_caps(caps, include_diag=policy.include_diag, qm_filtered=max(0, qm_before - qm_after))

        all_candidates.append({"id": gid_all, "candidate": candidate_text})
        all_explains.append(rec.to_json())
        pbar_logs.update(1)

    has_any_candidate = any((r.get("candidate") or "").strip() for r in all_candidates)

    write_jsonl(all_candidates, os.path.join(args.out, "candidates.jsonl"))
    tqdm.write(f"[pipeline] Done. Artifacts in {args.out}")

    if args.explain in ("json","sidecar") and has_any_candidate:
        if args.explain == "json":
            write_jsonl(all_explains, os.path.join(args.out, "explain.jsonl"))
            tqdm.write("[explain] wrote explain.jsonl")
        else:
            side_dir = os.path.join(args.out, "explain_sidecar")
            os.makedirs(side_dir, exist_ok=True)
            for ex in all_explains:
                gid = ex["gid"]
                md = []
                md.append(f"# Explain for {gid}\n")
                p = ex["pipeline"]
                md.append(f"- span_mode: **{p['span_mode']}**, token_budget={p['token_budget']}, max_lines_per_chunk={p['max_lines_per_chunk']}, stride={p['stride']}, group_size={p['group_size']}\n")
                md.append("## Anchors\n")
                md.append(f"- primary hits: {len(ex['anchors'].get('primary',[]))}, secondary hits: {len(ex['anchors'].get('secondary',[]))}\n")
                md.append("## Chunks & Sanitization\n")
                for c in ex["chunks"]:
                    md.append(f"- {c['chunk_id']}: fewshot={c['fewshot_level']}, model_out={c['model_out_len']} lines, kept={c['kept_lines']} {'('+c['dropped_reason']+')' if c['dropped_reason'] else ''}")
                md.append("\n## Merge\n")
                m = ex["merge"]; md.append(f"- segments={m['segments']}, lines_before={m['lines_before']}, lines_after={m['lines_after']}\n")
                md.append("## Augmentation\n")
                md.append(f"- missing sections added: {ex['augment']['missing_sections_added']}\n")
                md.append(f"- diagnostics blocks added: {ex['augment']['diagnostics_blocks_added']}\n")
                md.append("## Order Normalization\n")
                on = ex["order_norm"]; md.append(f"- before: {on['before_sections']}\n- after: {on['after_sections']}\n")
                md.append("## Policy & Caps\n")
                pol = ex["policy"]
                md.append(f"- include_diag={pol['include_diag']}, question_mark_filtered={pol['question_mark_filtered']}\n")
                md.append(f"- caps: {pol['caps']}\n")
                if ex["prompt_tips"]:
                    md.append("## Prompt/Strategy Tips\n")
                    for t in ex["prompt_tips"]: md.append(f"- {t}")
                with open(os.path.join(side_dir, f"{gid}.md"), "w", encoding="utf-8") as f:
                    f.write("\n".join(md))
            tqdm.write(f"[explain] wrote sidecar markdowns in {side_dir}")

if __name__ == "__main__":
    main()
