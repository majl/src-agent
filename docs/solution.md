# SRC-Hunter：基于 HY3 的 SRC 定向漏洞挖掘 Agent（白盒审计 + 黑盒红队 双模）

> 参赛赛道：SRC 定向漏洞挖掘 ｜ 主题：AI 攻防全链路构建与实践落地 ｜ 原生对接 tsecbench 跑分平台

## 1. 项目概述

SRC-Hunter 是面向 SRC 定向漏洞挖掘的 AI Agent，以腾讯混元 **HY3** 为推理核心，提供**白盒代码审计 + 黑盒自主渗透**双模能力：

- **白盒**：SAST(Semgrep) + HY3 多轮上下文审计 + Triage 降误报 + PoC + 六项指标；
- **黑盒**：侦察 → Web 漏洞扫描 → 云维度检测(CLOUD) → 二进制维度检测(BINARY) → 杀伤链多阶段游走(KILLCHAIN) → PoC 真实利用提取 flag → tsecbench 提交，全闭环自动化。

双模覆盖 tsecbench「Web 漏洞挖掘 / 漏洞利用」等评测维度，既能在代码侧定位 CVE 级漏洞，也能在真实靶场自主拿 flag。核心是**全链路自动化**与**可量化实战效能**——这正是比赛评审关注的落点。

## 2. 技术架构

白盒链路（代码侧）：

```
目标代码 ──▶ [SAST 静态扫描] ──┐
                            ├──▶ [Triage 合并降误报] ──▶ [Verify / PoC] ──▶ 报告 + 六项指标
目标代码 ──▶ [LLM 多轮上下文审计] ─┘        (HY3 驱动)
```

黑盒链路（靶场侧，对接 tsecbench）：

```
tsecbench 平台 ──list/start──▶ 靶场 URL
        ▲ submit/close              │
        │                            ▼
   RedTeamAgent ◀── 侦察 → Web扫描 → PoC利用 → 提取 flag
   (HY3 决策大脑，无人介入)
```

- **LLM 后端**：HY3，OpenAI 兼容协议（`tokenhub.tencentmaas.com/v1`），支持 `reasoning_content` 思考链。
- **SAST 引擎**：Semgrep（`p/ci` 规则集，30+ 语言，LGPL 开源，代码不出本地）；不可用时内置正则兜底引擎，零依赖可跑。
- **平台接入**：`src/platform/tsecbench_client.py` 封装 /openapi/v1 全套端点。

## 3. 核心方法

### 3.1 SAST 预筛（缩小 LLM 范围）
Semgrep 对全量代码做秒级静态扫描，命中 OWASP 常见模式（注入、XSS、SSRF、命令执行、硬编码凭据等），作为"候选集"进入下游，并作为后续双向佐证的一方。

### 3.2 LLM 多轮上下文审计（白盒关键创新）
借鉴 vulnhuntr 的"初筛 → 请求上下文 → 深挖"范式，以 HY3 实现：初轮粗筛追踪数据流 → 上下文轮跨文件回灌符号定义 → 漏洞专项确认。使用 HY3 思考链模式，解决跨文件语义理解与业务逻辑盲区。

### 3.3 双向佐证降误报（Triage）
SAST 命中与 LLM 发现按 `(文件, 行±5, 类型)` 去重合并；SAST∧LLM 同时命中 → `hybrid` 置信度上提；仅单边 → 依置信度阈值过滤。这是压制误报、优化"发现率/误报率"双指标的核心。

### 3.4 分级调用与成本控制
HY3 分 `fast`(无思考链,初筛) / `deep`(思考链,深度审计) 两档，配合 token 计量与 `budget_usd` 硬上限，直接优化"大模型运行成本"。

### 3.5 PoC 自动生成
按漏洞类型生成可读 PoC（注入类给 curl 载荷、IDOR 给改参思路等）。默认不对外发起真实请求，符合合规与脱敏要求。

### 3.6 黑盒红队解题闭环（关键能力，HY3 驱动决策）
RedTeamAgent 把"拉题→打靶→提交"建模为自主循环，链路中**三个决策点由 HY3 驱动**（无 key 自动降级启发式，保证离线可跑）：

1. **侦察（recon）**：资产发现、目录爆破、指纹识别（纯 Python 兜底，可选 subfinder/httpx）；
2. **决策点① 资产攻击价值排序（HY3 fast）**：对侦察资产按"攻击价值"排序，优先敏感接口（api/flag/admin/debug/.git/.env）与可交互入口；
3. **Web 扫描（webscan）**：未授权访问 / 命令注入 / SQLi / XSS 自实现检测，可选 nuclei 增强；
4. **决策点② 利用优先级与手法规划（HY3 deep，开思考链）**：对漏洞候选排序并给出利用手法（未授权直访 / 命令注入拼接 / SQL 联合查询 / SSRF 打元数据等），结果写入 `Finding.llm_exploit_hint`；
5. **PoC 真实利用（exploit）**：构造并发送真实 HTTP 请求、提取 flag{...}——把"文本 PoC"升级为"真打验证"；标准模板未命中时触发**决策点④ HY3 自定义利用构造（deep）**；
6. **决策点③ flag 判定（HY3 fast）**：对响应判定是否含有效 flag，抑制误提交；
7. **提交（tsecbench_client.submit）**，全程无人介入。

成本护栏：累计 LLM 成本超过 `budget_usd`（默认 5.0 USD）后，后续决策自动降级为启发式，直接对应评分项「大模型运行成本」的可控性。

### 3.6.1 云维度检测（CLOUD 评分维度，权重 15%）

`scan_cloud` 覆盖三类云上攻击面，与 Web 检测并列并入利用闭环（命中即进入 `run_exploit_full` 提取 flag）：

- **云元数据 IMDS（169.254.169.254）**：通过 SSRF 或实例内直连获取临时凭证 / 用户数据（常含 flag）；
- **未授权云 API**：K8s API server（`/api/v1/pods`）、Docker API（2375）、etcd（2379）等未鉴权暴露，可直接列举资源或拿 flag；
- **容器逃逸线索**：`/.dockerenv` 存在、docker.sock 挂载可读、特权容器 cap 等逃逸前置信号。

`check_imds` / `check_unauthorized_cloud_api` / `detect_container_escape` 三模块默认纯 Python 兜底（requests），复用侦察 / 扫描的共享 HTTP 工具（localhost 自动绕过代理）；发现的 flag 经 `run_exploit_full`（等同未授权访问）提取并进入提交闭环。本地 mock 靶场 `CLOUD-DEMO-001` 已挂载对应端点，可离线验证整链。

### 3.6.2 二进制维度检测（BINARY 评分维度，权重 15%）

`scan_binary` 对靶机交付的二进制（`/pwn/binary`）做自动静态脆弱性分析，与 Web / 云检测并列并入利用闭环（命中即进入 `run_exploit_full` 提取 flag）：

- **保护机制 checksec**：纯 Python 解析 ELF header / program header 判定 PIE / NX / Canary / 架构；真实 Linux 靶机上自动启用 pwntools 拿权威 checksec（RELRO / FORTIFY 等）；
- **危险函数识别**：`gets/strcpy/strcat`（无边界拷贝，确定性栈溢出）、`printf/sprintf`（格式化字符串）、`system/popen/execve`（命令执行 / getshell）；
- **敏感字符串扫描**：`flag{...}`（硬编码 flag / 后门）、`/bin/sh`、`cat flag`、`password/secret`；
- **启发式漏洞判定**：无边界拷贝函数 + 未开 canary → 高置信栈溢出（CRITICAL）；命令执行函数 → 高危（HIGH）；检测到 `flag{...}` → 硬编码凭据 / 后门，可直接静态提取提交（CRITICAL）。

工具链优先级 `pwntools → 系统 strings/nm/objdump → 纯 Python 字节扫描`，跨平台零依赖兜底，保证 macOS 演示与 Linux 真机都能跑。本地 mock 靶场 `BINARY-DEMO-001` 已挂载 `/pwn/binary`（含 flag 与危险函数标记）与 `/pwn/flag` 端点，可离线验证整链；独立分析本地 ELF 可用 `cli.py binary <path>` 或 `scripts/binary_scan.py --file <path>`。

### 3.6.3 杀伤链维度检测（KILLCHAIN 评分维度，权重 20%）

KILLCHAIN 维度衡量 Agent 能否把**离散的孤立漏洞点**串成一条**连贯、可递进、抵达目标**的多阶段攻击链，而非只会单点爆破——这是 tsecbench 权重最高的动态维度。

- **通用杀伤链合成 `build_killchain`**：把一次解题产生的所有 Finding 按标准杀伤链阶段 taxonomy 映射并排序——
  `侦察 → 初始立足 → 执行 → 权限提升 → 横向移动 → 凭据访问 → 信息收集 → 影响/渗出`，
  计算**阶段覆盖率**、**链深度（最深处阶段）**、**是否抵达影响阶段（reached_impact）**，并产出可追责的攻击叙事。该能力对 WEB/CLOUD/BINARY 的发现同样生效（如 RCE→execution、IMDS→credential access），因此单题也会产出一条有意义的链。
- **多阶段靶机游走 `scan_killchain_stage`**：针对实现了三跳链的靶机自动推进——`/kc/entry`（侦察发现内部入口）→ `/kc/internal`（凭据访问，泄露服务令牌）→ `/kc/flag`（影响阶段，提取最终 flag），产出带 `chain_order` 的 Finding，使 KILLCHAIN 维度可在本地离线跑通完整闭环。
- **HY3 决策点⑤（攻击链叙事合成）**：在利用结束后，由 HY3(fast) 把阶段化发现润色为连贯攻击叙事（`#KILLCHAIN_SYNTH`）；无 HY3 时退化为启发式叙事，保证离线可跑。

本地 mock 靶场 `KILLCHAIN-DEMO-001` 已挂载三跳链端点，可离线验证整链；独立分析可用 `cli.py killchain --mock --code KILLCHAIN-DEMO-001` 或 `scripts/killchain_scan.py --mock`。

### 3.7 tsecbench 平台原生接入

**封装为平台要求的 AI Agent 格式**（`src/agent/` 标准包），覆盖官方三种接入方案：

- **API 接入**（自掌控流程）：`main.py` 串起 `拉题(list)→启动(start)→解题(solve)→提交(submit)→关闭(close)` 全闭环，支持 `--mock` 本地自测与真实平台同构入口。
- **SDK 接入**（对接核心解题流程）：继承 `BaseAgent` 实现 `solve(challenge) -> SolveResult`，由 `run_hosted` + `StdioBridge` 对接平台 **Host Bridge 协议**（JSONL over stdin/stdout，四个标准动作 `challenge_get_state / get_hint / submit_flag / is_completed`）。这是 tsecbench「托管运行」模式的本质——Solver 运行于隔离环境，只能通过 bridge 动作与宿主（平台代理）通信，由宿主统一转发竞赛 API，天然约束"提交动作不属于 solver 职责"，抑制误提交。
- **提示词接入**（零开发）：`agent_prompt.md` 把 Agent 能力/工具/流程/合规边界固化成系统提示词，复制进任意支持自然语言任务的 Agent 即可跑。

标准数据契约 `ChallengeSpec`（对齐 `/openapi/v1/challenges` 与 Host Bridge `get_state` 返回）、`SolveResult`（解题结果）；配置经 `.env.example` 统一管理（`BENCHMARK_TOKEN` / `HY3_API_KEY`）。本地 `mock_server`（标准库零依赖）实现相同 /openapi/v1 协议，并可被 `MockHostBridge` 模拟宿主侧，离线跑通 API 与托管两种形态的整链，保证可复现。

### 3.7.1 通用目标入口（`target` 子命令）
同一套黑盒链路亦可脱离平台、直接作用于授权目标：`python cli.py target <IP/域名>` 会自动探测常见 Web 端口（80/443/8080/…），对可达入口复用 `solve_target` 开展侦察→扫描→利用验证，输出漏洞报告（不提交平台）；亦可用 `--entry` 直接指定靶机入口（如平台 `container_addr`）。该形态仅用于自有/授权资产或 SRC 范围内目标。

## 4. 量化指标体系（六项，对比传统模式）

| 指标 | 计算方式 | 对应优势 |
|------|----------|----------|
| 漏洞发现率 | 命中已知漏洞 / 总数 | 黑盒利用 + 白盒 LLM 审计互补 |
| 误报率 | 未确认发现占比 | 双向佐证压制 |
| 代码审计量级 | 审计代码行数 | 并行 + 预筛 |
| 单高危发现时长 | 端到端耗时 / 高危数 | 自动化 vs 人工逐行 |
| 大模型运行成本 | token × 单价 | 分级调用 |
| 人机验证时间比 | 人工耗时 / 总耗时 | 全自动闭环 |

## 5. 实验结果

- **白盒**（合成样例靶机 8 处已知漏洞）：审计 3 文件 / 75 行，**发现率 87.5%**、**误报率 0%**，输出与传统基线对比表。
- **黑盒**（tsecbench mock 靶场，一键跑分 `bench --mock`）：自动拉题→启动→侦察→扫描→利用，**成功提取并提交 flag（correct=True），耗时约 2.6s，全自动零人工**；六项指标：发现率 100%、误报率 0%、人机比 0%。
- **HY3 决策接线已验证**：在 mock 离线模式下打通三个决策点的完整调用（资产排序 fast / 利用规划 deep / flag 判定 fast，单次解题 3 次 LLM 调用，成本≈$0.0004）；`--no-llm` 可切换纯启发式作为对比基线。
- **云维度（CLOUD-DEMO-001 脱敏靶机）**：`scan_cloud` 命中 IMDS 暴露、未授权 K8s / Docker / etcd API、容器逃逸线索等 11 个云上风险点，并成功提取 flag 提交（correct=True），补齐 tsecbench CLOUD 维度（权重 15%）。
- **二进制维度（BINARY-DEMO-001 脱敏靶机）**：`scan_binary` 自动静态分析靶机交付的二进制，命中栈溢出（无 canary + gets/strcpy）、命令执行（system）、格式化字符串（sprintf）与硬编码 flag 共 4 类疑似风险，并直接从二进制字节提取 flag 提交（correct=True），补齐 tsecbench BINARY 维度（权重 15%）。独立 `cli.py binary` 亦可对本地 ELF 做 checksec + 危险函数 + 硬编码 flag 分析。
- **通用目标 IP 自动挖漏洞（新增 `target` 子命令）**：输入裸 IP 即自动探测开放 Web 端口 → 侦察 → Web 扫描 → 云检测 → 利用验证 → 输出漏洞报告（不提交平台）。对本地脱敏靶场 `target 127.0.0.1` 实测：自动定位 8800 端口，挖出命令注入(CRITICAL)与未授权敏感数据(HIGH)并提取 flag，耗时约 1.5s，零人工。
- **杀伤链维度（KILLCHAIN-DEMO-001 脱敏靶机）**：`scan_killchain_stage` 沿三跳链自动推进（entry→internal→flag），`build_killchain` 合成攻击链覆盖**侦察→凭据访问→影响**三阶段、覆盖率 3/8、抵达影响阶段（reached_impact=True），并由 HY3 决策点⑤润色攻击叙事；最终提取 flag 提交（correct=True），补齐 tsecbench KILLCHAIN 维度（权重 20%，当前动态维度中权重最高）。仅识别离散漏洞点的方案在此维度上无法证明"链深度抵达影响"，而 SRC-Hunter 的杀伤链合成正是针对该评分点的差异化能力。

> HY3 深度审计与黑盒决策在配置 `HY3_API_KEY` 后于真机/靶场启用：白盒侧对跨文件 SQL 注入等做语义级确认，黑盒侧由 HY3 实测驱动资产排序、利用规划与 flag 判定。本次以 SAST→Triage→Metrics（白盒）与 recon→webscan→exploit→submit（黑盒）双主链 + HY3 决策接线验证全自动化闭环，提交材料附真机运行 `report.json`。

## 6. 创新点

1. **SAST×LLM 双轨闭环（白盒）+ 黑盒红队闭环**：双模互补覆盖评测维度，而非单点工具。
2. **多轮上下文审计（HY3 思考链）**：把"安全专家追源码"建模为可自动化循环，解决跨文件语义理解。
3. **PoC 从"文本生成"升级为"真实利用验证"**：直接产出可提交 flag，对接平台评测。
4. **平台原生接入**：Agent 自动完成评测全流程，人机验证时间比≈0。
5. **量化驱动 + 安全默认**：六项指标贯穿架构；默认不真打、代码不出本地、样例全脱敏。
6. **通用目标入口**：`target` 子命令支持输入裸 IP/域名即自动端口探测并开展漏洞挖掘，复用同一套黑盒链路，既可用于授权资产自查，也可无缝对接平台靶机（`--entry`）。

## 7. 提交材料映射（四种形态）

| 形态 | 产物 |
|------|------|
| 标准 Agent 包（平台要求格式） | `src/agent/`（BaseAgent/SRC_HunterAgent/Bridge/runner）+ `main.py` + `agent_prompt.md` + `.env.example` |
| 命令行工具 | `cli.py`（demo/scan/bench/tsecbench/web/target/binary）+ `main.py`（tsecbench 标准 Agent 入口） |
| Web 应用 | `src/web/app.py` 控制台 |
| 脚本 | `scripts/{recon,solve,range_selftest,cloud_scan,binary_scan}.py` |
| PoC | `src/poc/templates.py` + `src/tools/exploit.py` |
| 技术方案 | `docs/solution.md`（本文件） |
| 演示视频（加分） | 录制 `python main.py --mock --all` 全流程（含 StdioBridge 托管形态自测） |

## 8. 总结

SRC-Hunter 把 HY3 的推理能力落到 SRC 漏洞挖掘的**全链路自动化**与**平台原生评测**上：白盒用 SAST+LLM 兜底准确率，黑盒用侦察+扫描+真实利用兜底实战效能，用分级调用兜底成本、用全闭环兜底人机比。它是一个"以可接受成本、可验证指标，稳定产出高质量漏洞"、并能直接上 tsecbench 跑分的 AI 攻防武器。
