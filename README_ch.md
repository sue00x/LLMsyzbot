
# LogAgents：模块化 KASAN 日志分析与可解释报告生成

本套件实现了一个 **LLM + 规则混合的模块化流水线**，用于：
1. **锚点优先提取（Anchor-first extraction）**:从原始内核日志中提取syzbot风格崩溃报告片段, 采用LLM主处理+规则降级机制（rule fallback）；
2. **后处理标准化（Post-process normalization）**：在严格 **“仅拷原文”** 约束下进行 **后处理规范化**（顺序、去重、长度控制）；
3. **区块补全（Section completion）**：对缺失的核心段落和诊断尾段进行 **自动补齐**；
4. **策略强化（Policy enforcement）**：通过 **策略裁剪** 稳定输出长度、顺序和内容；
5. **可解释诊断（Explainable diagnosis）**：以 **规则**模式 或 **CoT（思维链）**模式 生成可解释的诊断分析。

> 本项目**不涉及**模型权重训练，而是通过 **提示词和策略控制**，结合确定性的规则验证，最大限度降低幻觉风险。

---

## 目录结构

```

logagents/
├─ core/
│  ├─ io\_utils.py        # 读写 json/jsonl/config 工具
│  ├─ chunking.py        # 锚点+滑窗切分
│  ├─ prompts.py         # 系统提示词块 + few-shot 注入
│  ├─ sanitize.py        # “仅拷原文”行过滤
│  ├─ sections.py        # 段落定义与提取方法
│  ├─ augment.py         # 段落补齐（核心段落 + 诊断尾段）
│  ├─ ordering.py        # 固定顺序 + 工具栈帧过滤 + 去重
│  ├─ policy.py          # 策略裁剪（段落限长、问号过滤、诊断配额）
│  ├─ fallback.py        # 规则兜底提取（LLM 失败时回退）
│  ├─ explain.py         # Explain 元数据记录
│  └─ diagnose.py        # 规则版与 CoT 版诊断
├─ pipelines/
│  ├─ pl\_extract.py      # 主流程：抽取 → 补齐 → 规范化 → 策略 → Explain
│  └─ pl\_diagnose.py     # 从 candidates 做诊断
├─ llm\_client.py         # LLM API 封装（Chat Completions）
└─ config.json           # 模型、API 和运行参数

````

---

## 快速开始

1. 编辑 `config.json`，填入 `API_URL`、`API_KEY`、`MODEL` 以及运行参数。
2. 准备输入日志（JSONL 格式）：
```json
   {"id": "bug01", "log": "<完整内核日志文本>"}
````
3. 你可以用 syz_kasan_scraper_full.py 从syzbot爬取标准日志以供测试:

```bash
python syz_kasan_scraper_full.py --max-bugs 1 --combine 
```
4. 接着用 build_round_files.py 为输入日志做准备:
```bash
python build_round_files.py --input crawler/result --out ./preprocess --source crawler
```
5. 运行解析流程：

```bash
python -m logagents.pipelines.pl_extract --logs ./preprocess/bug01/logs.jsonl --out  ./out/full --span full --mode ai_try --compact --explain sidecar --include_diag true
```

生成的文件：

* `out/full/candidates.jsonl` — LLM + 规则提取的崩溃报告
* `out/full/explain_sidecar/` — 每条样本的 Explain 元数据
* 可选：`fallback_hits.jsonl` — 触发规则兜底的样本

6. （可选）对 candidates 进行诊断：

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

## 说明

* 抽取流程优先使用 **锚点切分**，无法命中时回退到滑窗切分。
* 所有输出行均为 **原始日志的逐字子串**，不允许改写。
* 缺失的核心段落（BUG、RW、Call Trace 等）会自动从原日志补齐。
* 诊断尾段（page\_owner、反汇编、寄存器等）可通过 `--include_diag` 启用。
* 策略裁剪会限制段落最大行数、诊断尾段配额，并过滤带问号的行。
* Explain Sidecar 会完整记录切分、few-shot 选择、过滤、策略裁剪等信息。

---

## 优势对比

| 维度    | 仅规则 (Syzkaller) | 仅 LLM | 混合方案 (LogAgents) |
| ----- | --------------- | ----- | ---------------- |
| 泛化能力  | 低               | 高     | 高（锚点+LLM 抽取）     |
| 维护成本  | 高               | 低     | 中                |
| 多语言   | 弱               | 强     | 强                |
| 上下文利用 | 局部              | 全局    | 全局（窗口化）          |
| 可解释性  | 弱               | 强     | 强                |
| 幻觉风险  | 无               | 高     | 极低（验证+仅拷原文）      |
| 输出稳定性 | 高               | 中     | 高                |
| 适用场景  | 固定格式            | 异构/新域 | 异构 + 可控输出        |

---

