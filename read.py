import os
import glob
import json

# === 配置 ===
input_dir = "./out/full"          # 输入目录：包含若干 .jsonl
output_dir = "./readable"         # 输出目录：存放生成的 .txt / .md
os.makedirs(output_dir, exist_ok=True)

def pick_text_field(rec: dict) -> str:
    """
    选择最合适的文本字段：candidate > repaired > answer > text > ""
    防止某些文件字段名不一致导致 KeyError。
    """
    for k in ("candidate", "repaired", "answer", "text"):
        if k in rec and isinstance(rec[k], str):
            return rec[k]
    return ""

def safe_loads(line: str):
    try:
        return json.loads(line)
    except Exception:
        return None

# 遍历目录下的所有 .jsonl
jsonl_files = glob.glob(os.path.join(input_dir, "*.jsonl"))

for input_file in jsonl_files:
    base = os.path.basename(input_file)
    stem, _ = os.path.splitext(base)
    out_txt = os.path.join(output_dir, f"{stem}_readable.txt")
    out_md  = os.path.join(output_dir, f"{stem}_readable.md")

    # 逐条写 TXT
    with open(input_file, "r", encoding="utf-8") as fin, \
         open(out_txt, "w", encoding="utf-8") as ftxt, \
         open(out_md,  "w", encoding="utf-8") as fmd:

        # Markdown 文件头（可选）
        fmd.write(f"# {stem} 解析结果\n\n")

        for line in fin:
            rec = safe_loads(line)
            if not rec:
                continue

            rid = rec.get("id", "N/A")
            text = pick_text_field(rec)

            # 写 TXT
            ftxt.write(f"=== ID: {rid} ===\n")
            ftxt.write(text)
            ftxt.write("\n\n" + "="*80 + "\n\n")

            # 写 MD
            fmd.write(f"## {rid}\n\n")
            fmd.write("```\n")
            fmd.write(text)
            fmd.write("\n```\n\n")

    print(f"已生成：{out_txt}")
    print(f"已生成：{out_md}")

print("全部完成 ✅")
