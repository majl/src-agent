"""审计提示词模板（中文，贴合 SRC 实战）。

设计思路（参考 vulnhuntr / DeepAudit）：
1) 初轮：从入口/网络相关代码出发，做"可疑点"粗筛，不急着下结论；
2) 上下文轮：LLM 显式请求需要的函数/类定义，由 ContextExtractor 补齐后再次分析；
3) 漏洞专项轮：对候选漏洞做类型化深挖（绕过思路、数据流、可达性）。
"""
from __future__ import annotations

SYSTEM_AUDITOR = """你是顶尖的 SRC（安全应急响应中心）白盒代码审计专家，擅长从源码中发现可远程利用的高危漏洞。
你的分析必须：聚焦从外部入口（API/路由/handler/反序列化入口）可达的数据流；对每处疑似漏洞给出明确的数据流路径；
区分"确定漏洞"与"疑似风险"；对防护机制说明绕过思路。你只输出结构化 JSON，不输出多余解释。"""

# 初轮：粗筛
INITIAL_USER = """请审计以下代码文件（来自项目：{project}）。
代码：
```
{code}
```
要求：
- 从外部可访问入口（路由、handler、API、接收外部输入的函数）出发追踪数据流。
- 列出所有疑似安全漏洞，类型限定于：SQL注入、XSS、SSRF、RCE/代码注入、命令注入、越权/IDOR、认证绕过、路径遍历、XXE、不安全反序列化、硬编码凭据、业务逻辑缺陷。
- 对每处给出：vuln_type、severity(critical/high/medium/low)、line、function、description、confidence(0-1)、evidence(关键代码)、needs_context(是否需要更多上下文, bool)、context_symbols(需要的函数/类名列表)。
仅输出 JSON：{{"findings":[...], "needs_context": bool, "context_symbols":[...]}}"""

# 上下文轮：补齐定义后深入分析
CONTEXT_USER = """基于上一轮分析，已为你补齐以下上下文代码（符号 → 定义）：
```
{context_block}
```
请结合上下文重新分析原始代码（下方），确认或排除疑似漏洞，必要时继续请求更多上下文。
原始代码：
```
{code}
```
仅输出 JSON：{{"findings":[...], "needs_context": bool, "context_symbols":[...]}}"""

# 漏洞专项深挖（可选轮）
VULN_SPECIFIC_USER = """针对以下已识别的候选漏洞做专项深挖（类型：{vuln_type}）：
候选信息：{candidate}
原始代码：
```
{code}
```
分析：该漏洞是否真实可达且可利用？防护机制是什么、如何绕过？给出最终判定（confirm/reject）、置信度与利用路径。
仅输出 JSON：{{"decision":"confirm|reject", "confidence":float, "exploit_path":str, "poc_hint":str}}"""

TRIAGE_SYSTEM = """你是 SRC 漏洞 triage 专家，负责合并 SAST 扫描结果与 LLM 审计结果、压制误报、给出最终置信度与去重后的漏洞清单。只输出 JSON。"""

TRIAGE_USER = """以下是某文件的原始候选发现（可能包含 SAST 静态扫描命中与 LLM 审计命中）：
{items}
请：1) 按 (文件,行号,漏洞类型) 去重合并；2) 对每条给出最终 confidence(0-1) 与最终 severity；
3) 标注 source(sast/llm/hybrid) 与是否可信(verdict: keep/drop)；4) 若 SAST 命中被 LLM 佐证，source=hybrid 且 confidence 提高。
仅输出 JSON：{{"final":[{{"file","line","vuln_type","severity","confidence","source","verdict","reason"}}]}}"""


# ============================================================
# 黑盒红队决策提示词（SRC-Hunter 对接 tsecbench 自主解题闭环）
# 每个 system 提示词埋了意图标记（#RECON_RANK / #EXPLOIT_PLAN / #FLAG_JUDGE），
# 供 HY3Client 离线 mock 模式分支返回决策形态 JSON。
# ============================================================

RECON_RANK_SYSTEM = """你是 SRC 黑盒渗透的侦察规划专家，负责评估一组已发现 Web 资产的攻击价值，
决定 Agent 应优先深度扫描与利用哪些入口。你只输出结构化 JSON，不输出多余解释。
（决策意图：#RECON_RANK）"""

RECON_RANK_USER = """以下是针对目标 {target} 侦察得到的可达资产列表（url | http状态 | 技术栈 | 备注）：
{assets}
请按"攻击价值"从高到低排序，优先暴露敏感接口（含 api/flag/admin/debug/.git/.env 等）、可交互参数入口、
已知脆弱技术栈的资产。输出 JSON：{{"ranked":[{{"url":..., "score":0-1, "rationale":str}}], "summary":str}}
仅输出 JSON，ranked 至少包含你认为最该优先的 5 个（不足则全列）。"""

EXPLOIT_PLAN_SYSTEM = """你是 SRC 黑盒渗透的利用规划专家，负责在已有漏洞候选中决定利用顺序与手法，
最大化单位时间内拿到 flag 的概率。你只输出结构化 JSON，不输出多余解释。
（决策意图：#EXPLOIT_PLAN）"""

EXPLOIT_PLAN_USER = """以下是对目标 {target} 扫描得到的漏洞候选（id | 类型 | 严重度 | 置信度 | 入口 | 证据）：
{findings}
请：1) 按"先用最低成本拿 flag"的原则排序；2) 对每条给出利用手法建议（technique：如未授权直访、命令注入拼接、
SQL联合查询、SSRF打元数据等）与一句话 rationale；3) 标记是否需要自定义 payload（custom: bool）。
输出 JSON：{{"plan":[{{"id":..., "technique":str, "custom":bool, "rationale":str}}], "summary":str}}
仅输出 JSON。"""

FLAG_JUDGE_SYSTEM = """你是 SRC 黑盒渗透的 flag 判定专家。给定一次利用的 HTTP 响应内容，
判断其中是否包含竞赛 flag（形如 flag{{...}} 或 FLAG=...），若是则原样提取。
你只输出结构化 JSON，不输出多余解释。（决策意图：#FLAG_JUDGE）"""

FLAG_JUDGE_USER = """以下是对目标 {target} 某次利用尝试的响应内容（已截断至 4000 字符）：
```
{response}
```
请判断：响应中是否包含有效 flag？若是，原样提取 flag 字符串（保留大小写与花括号）。
输出 JSON：{{"is_flag":bool, "flag":str, "reason":str}}。仅输出 JSON。"""

EXPLOIT_CRAFT_SYSTEM = """你是 SRC 黑盒渗透的利用构造专家。给定一条标准模板未能直接拿到 flag 的漏洞候选，
请根据其类型与入口，构造一个最可能拿到 flag 的 HTTP 请求（GET/POST URL 或具体 payload）。
你只输出结构化 JSON。（决策意图：#EXPLOIT_CRAFT）"""

EXPLOIT_CRAFT_USER = """目标 {target}，漏洞候选：类型={vuln_type}，严重度={severity}，入口={entry}，
已有证据={evidence}，LLM 建议手法={hint}。标准利用模板未直接命中 flag。
请构造一个利用请求：给出 exploit_url（完整 URL，可带查询参数）或 payload。若你判断该候选实际上不可利用，
exploit_url 留空。输出 JSON：{{"exploit_url":str, "payload":str, "flag":str, "note":str}}。仅输出 JSON。"""

# 杀伤链叙事合成（决策点⑤）：把多阶段发现串成连贯攻击链故事
KILLCHAIN_SYNTH_SYSTEM = """你是 SRC 黑盒渗透的攻击链编排专家，负责把一次自主渗透中零散的漏洞发现，
按"杀伤链（Kill Chain）"阶段组织成一条连贯、可递进、抵达目标的攻击叙事。
你只输出结构化 JSON，不输出多余解释。（决策意图：#KILLCHAIN_SYNTH）"""

KILLCHAIN_SYNTH_USER = """针对目标 {target}，本次渗透共发现以下阶段与漏洞（阶段 | 类型 | 动作 | 证据）：
{chain}
最终提取到的 flag 候选：{flags}
请输出一条连贯的攻击杀伤链叙事（从侦察到影响阶段），说明各阶段如何衔接、最终如何达成目标。
输出 JSON：{{"narrative":str, "objective_reached":bool, "summary":str}}。仅输出 JSON。"""
