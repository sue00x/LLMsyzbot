
# -*- coding: utf-8 -*-
from copy import deepcopy
from datetime import datetime

class ExplainRecorder:
    """Collects end-to-end provenance for one log id."""
    def __init__(self, gid_all: str):
        self.gid = gid_all
        self.meta = {
            "gid": gid_all,
            "ts": datetime.utcnow().isoformat() + "Z",
            "pipeline": {
                "span_mode": None,
                "token_budget": None,
                "max_lines_per_chunk": None,
                "stride": None,
                "group_size": None,
            },
            "anchors": {},
            "chunks": [],
            "merge": {"segments": 0, "lines_before": 0, "lines_after": 0},
            "augment": {"missing_sections_added": [], "diagnostics_blocks_added": 0},
            "order_norm": {"before_sections": [], "after_sections": []},
            "policy": {"caps": {}, "include_diag": None, "question_mark_filtered": 0},
            "prompt_tips": [],
        }

    def set_pipeline(self, **kwargs):
        self.meta["pipeline"].update({k:v for k,v in kwargs.items() if v is not None})

    def note_span_mode(self, mode: str):
        self.meta["pipeline"]["span_mode"] = mode

    def note_anchors(self, anchors: dict):
        self.meta["anchors"] = anchors

    def add_chunk_result(self, gid, span, fewshot_level, out_text, kept_list, dropped_reason=None):
        self.meta["chunks"].append({
            "chunk_id": gid,
            "span": span,
            "fewshot_level": fewshot_level,
            "model_out_len": len(out_text.splitlines()) if out_text else 0,
            "kept_lines": len(kept_list),
            "dropped_reason": dropped_reason or ""
        })

    def note_merge(self, seg_cnt, before_lines, after_lines):
        self.meta["merge"] = {"segments": seg_cnt, "lines_before": before_lines, "lines_after": after_lines}

    def note_augment_missing(self, added_keys):
        self.meta["augment"]["missing_sections_added"].extend(added_keys)

    def note_augment_diag(self, added_blocks_cnt):
        self.meta["augment"]["diagnostics_blocks_added"] += int(added_blocks_cnt)

    def note_order_sections(self, before_list, after_list):
        self.meta["order_norm"] = {"before_sections": before_list, "after_sections": after_list}

    def note_policy_caps(self, caps_dict, include_diag, qm_filtered):
        self.meta["policy"]["caps"] = caps_dict
        self.meta["policy"]["include_diag"] = include_diag
        self.meta["policy"]["question_mark_filtered"] = int(qm_filtered)

    def add_prompt_tip(self, text):
        if text and text not in self.meta["prompt_tips"]:
            self.meta["prompt_tips"].append(text)

    def to_json(self):
        return deepcopy(self.meta)
