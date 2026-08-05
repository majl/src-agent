# 团队介绍 · SRC-Hunter 战队

> 参赛赛事：百度 BSRC「Agent+」攻防能力挑战赛 · 赛道【SRC 定向漏洞挖掘】
> 同时原生对接 **tsecbench** 智能攻防跑分平台
> 作品主题：AI 攻防全链路构建与实践落地——以腾讯混元 HY3 为推理核心，把漏洞挖掘从"经验驱动"推进到"智能协同 + 全流程自动化"

---

## 一、团队一句话定位

**"一支由人类安全研究员 + AI 红队 Agent 组成的双人战队：人定方向、Agent 跑全链，把 SRC 漏洞挖掘的侦察、利用、提交闭环压缩到分钟级。"**

---

## 二、团队成员与角色

| 角色 | 成员 | 职责 |
|------|------|------|
| 队长 / 安全研究员 | `<参赛者姓名>`（请替换为真实姓名） | 确定参赛方向、合规边界把控、评测策略制定、最终复核与提交；负责把实战经验沉淀为 Agent 的工具链与决策规则 |
| 数字队友 / 红队 Agent | **SRC-Hunter v1.0.0** | 自动化执行：资产侦察 → Web/云/二进制多维漏洞扫描 → 杀伤链多阶段游走 → PoC 真实利用提取 flag → 平台提交；由 HY3 驱动三个关键决策点（资产排序 / 利用规划 / flag 判定） |
| 推理核心 | 腾讯混元 **HY3** | 提供 fast/deep 双档 LLM 决策与攻击叙事合成；无 Key 时自动降级离线启发式，保证流程可复现 |

> 说明：当前为单人 + AI Agent 的最小作战单元，架构按"可扩展为多 Agent 协作"设计，后续可平滑接入更多专项子 Agent（如专属云安全 / 二进制利用子 Agent）。

---

## 三、为什么是我们（核心优势）

1. **双模覆盖**：白盒代码审计（SAST + HY3 多轮上下文审计 + Triage 降误报）与黑盒自主渗透（真实 HTTP 利用拿 flag）同源共用一套工具链与决策框架。
2. **五维协同**：单次解题同时命中 **WEB / 漏洞利用(EXPLOIT) / 云维度(CLOUD) / 二进制(BINARY) / 杀伤链(KILLCHAIN)** 五大评测维度，并自动合成连贯攻击链（覆盖 7/8 阶段、抵达影响阶段）。
3. **平台原生格式**：封装为 tsecbench 要求的 **标准 AI Agent 包**（`src/agent/`），覆盖官方三种接入形态——**提示词接入 / SDK 接入 / API 接入**，并以官方 Host Bridge（JSONL over stdin/stdout）协议对接托管运行。
4. **成本可控**：fast/deep 分级调用 + token 计量 + 预算护栏，单题 LLM 成本可控在美分级别。
5. **闭环无人值守**：拉题 → 启动靶机 → 解题 → 提交 → 关闭，全程无需人工介入（人机验证时间比≈0）。

---

## 四、技术栈

- **推理**：腾讯混元 HY3（OpenAI 兼容接口），fast/deep 双档
- **语言**：Python 3.11+（纯标准库 + 少量可选增强依赖）
- **白盒**：Semgrep（含离线正则兜底引擎，零依赖可跑）
- **黑盒**：自实现 Web 扫描 / 云维度检测 / 二进制静态分析 / 杀伤链游走（纯 Python 兜底，可选 nuclei / pwntools 增强）
- **平台接入**：tsecbench `/openapi/v1` + Host Bridge 协议（mock 同构协议离线可跑）
- **报告**：Markdown / JSON / SARIF

---

## 五、作品交付形态（对应评审要求）

| 形态 | 产物 |
|------|------|
| 命令行工具 | `cli.py`（demo/scan/bench/tsecbench/web/target/binary/killchain）· `main.py`（tsecbench 标准 Agent 入口） |
| Web 应用 | `src/web/app.py` 控制台看板 |
| 独立脚本 | `scripts/`（recon / solve / cloud_scan / binary_scan / killchain_scan …） |
| 标准 Agent 包 | `src/agent/`（BaseAgent / SRC_HunterAgent / Bridge / runner）+ `agent_prompt.md` + `.env.example` |
| PoC | `src/poc/templates.py` · `src/tools/exploit.py` |

---

## 六、合规承诺

- 所有实战利用仅在 **已授权资产 / SRC 平台授予的靶机** 范围内进行；`target` 命令运行时会强制打印合规声明，严禁对未授权目标发起任何扫描或攻击。
- 白盒默认不真打（`verify_poc=false`），样例靶机全脱敏，不含任何真实目标信息。
- 作品仅用于参赛与防御能力提升，遵循《网络安全法》及赛事规则。

---

*本介绍中 `<参赛者姓名>` 为占位符，提交前请替换为真实参赛信息。*
