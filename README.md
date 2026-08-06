# SRC-Hunter · 面向 SRC 的 AI 漏洞挖掘 Agent（白盒审计 + 黑盒红队 双模）

> 参赛：百度 BSRC「Agent+」攻防能力挑战赛 · 赛道 SRC 定向漏洞挖掘；并原生对接 **tsecbench** 智能攻防跑分平台。
> 主题：**AI 攻防全链路构建与实践落地**——以腾讯混元 HY3 为推理核心，把漏洞挖掘从"经验驱动"推进到"智能协同 + 全流程自动化"。

## 1. 双模能力一览

| 模式 | 输入 | 流程 | 命中评测维度 |
|------|------|------|--------------|
| 白盒代码审计 | 代码仓库 | SAST(Semgrep) + HY3 多轮上下文审计 + Triage 降误报 + PoC + 六项指标 | Web 漏洞挖掘（代码侧） |
| 黑盒自主渗透 | 靶场 URL | 侦察 → Web 扫描 → 云维度检测 → 二进制维度检测 → 杀伤链多阶段游走 → PoC 真实利用提取 flag → tsecbench 提交 | Web 漏洞挖掘 / 漏洞利用 / 云维度(CLOUD) / 二进制(BINARY) / 杀伤链(KILLCHAIN) |

## 2. 核心能力

| 能力 | 实现 |
|------|------|
| 多语言 SAST | Semgrep（含离线正则兜底引擎，零依赖可跑） |
| LLM 多轮上下文审计 | 借鉴 vulnhuntr 范式，HY3 驱动，思考链 |
| 误报压制 | SAST×LLM 双向佐证、置信度阈值、去重 |
| 黑盒侦察 | 资产发现、目录爆破、子域枚举（subfinder 可选）、端口探测 |
| 黑盒 Web 扫描 | 未授权访问 / 命令注入 / SQLi / XSS（纯 Python 自实现 + nuclei 可选） |
| 黑盒云维度检测 | 云元数据 IMDS(169.254.169.254) / 未授权云 API(K8s/Docker/etcd) / 容器逃逸线索（纯 Python 兜底） |
| 黑盒二进制维度检测 | 二进制静态脆弱性分析：checksec 保护机制 / 危险函数(gets/strcpy/system) / 敏感字符串 / 栈溢出·格式化字符串·硬编码flag 启发式判定（`src/tools/binary.py`，pwntools/strings 增强） |
| **黑盒杀伤链维度** | 把离散漏洞点串成连贯多阶段攻击链：`build_killchain` 阶段映射（侦察→初始立足→执行→提权→横向→凭据→收集→影响）+ 覆盖率/链深度评估；`scan_killchain_stage` 多阶段靶机游走（entry→internal→flag）；HY3 决策点⑤润色攻击叙事 |
| PoC 真实利用 | 构造并发送真实 HTTP 请求、提取 flag{...}，不再是文本 PoC |
| 平台原生接入 | tsecbench /openapi/v1 全套（list/start/hint/submit/close） |
| **黑盒 HY3 决策** | 三个决策点由 HY3 驱动：①资产攻击价值排序(fast) ②利用优先级与手法规划(deep) ③响应 flag 判定(fast)，标准模板未命中时④HY3 构造自定义利用 |
| 分级调用 & 成本 | fast/deep 双档，token 计量 + **预算护栏**（超限自动降级启发式） |
| 量化指标 | 六项指标 + 与传统基线对比 |
| 多格式报告 | Markdown / JSON / SARIF |

## 3. 快速开始

### 3.1 白盒离线演示（无需 Key）
```bash
pip install -r requirements.txt
python cli.py demo --out ./out-demo
```

### 3.2 黑盒一键跑分（对接 tsecbench，本地 mock 全闭环，无需真实 token）
```bash
python cli.py bench --mock --out ./out-bench              # Web 维度靶机（默认 WEB-DEMO-001）
python cli.py bench --mock --code CLOUD-DEMO-001 --out ./out-cloud   # 云维度靶机
# → 拉题 → 启动靶机 → 侦察/扫描/云检测/利用拿 flag → 提交(correct=True) → 关闭 + 指标
```

### 3.2a 输入目标 IP/域名，自动化漏洞挖掘（通用形态，不提交平台）
```bash
python cli.py target 192.168.1.10              # 自动探测开放 Web 端口 → 侦察→扫描→利用→出漏洞报告
python cli.py target example.com --ports 80,443,8080,9000
python cli.py target --entry http://host:8080/app   # 已知入口，跳过探针
# → 输出 out-target/target_report.json（按严重程度列出漏洞 + 已验证标记 + 提取到的 flag）
```
> 合规：仅用于自有/授权资产、授权渗透测试或 SRC 范围内的目标；严禁扫描未授权设备。详见第 8 节。

### 3.2b 独立云维度扫描脚本（仅检测，不提交）
```bash
python scripts/cloud_scan.py --target http://127.0.0.1:8800/range          # mock 云靶场
python scripts/cloud_scan.py --target http://127.0.0.1:8800/range --direct-imds  # 同时直连 169.254.169.254
```

### 3.2c 二进制维度（BINARY，权重 15%）：靶机自动分析 + 本地 ELF 分析
```bash
python cli.py bench --mock --code BINARY-DEMO-001 --out ./out-binary   # 靶机二进制自动分析 + 提取 flag 提交
python cli.py binary ./chal                      # 分析本地 ELF（checksec + 危险函数 + 硬编码 flag）
python scripts/binary_scan.py --file ./chal      # 独立脚本：本地 ELF 分析
python scripts/binary_scan.py --target http://127.0.0.1:8800/range  # 靶场二进制端点分析（scan_binary 模式）
```

### 3.2d 杀伤链维度（KILLCHAIN，权重 20%）：多阶段链游走 + 攻击链合成
```bash
python cli.py bench --mock --code KILLCHAIN-DEMO-001 --out ./out-killchain   # 三跳链(entry→internal→flag) + 提交 + 杀伤链报告
python cli.py killchain --mock --code KILLCHAIN-DEMO-001   # 重点输出攻击杀伤链报告（不提交，可加 --no-llm 看启发式差异）
python cli.py killchain --target http://127.0.0.1:8800/range   # 分析任意靶机的杀伤链
python scripts/killchain_scan.py --mock --code KILLCHAIN-DEMO-001   # 独立脚本：仅分析杀伤链（不提交）
```

### 3.3 对接真实 tsecbench 平台
```bash
export BENCHMARK_TOKEN="<你的评测凭证>"
python cli.py bench --base-url https://tsecbench.zc.tencent.com --code <unique_code>
# 或直接操作：
python cli.py tsecbench list   --base-url ... --token ...
python cli.py tsecbench submit --base-url ... --token ... --code ... --flag flag{...}
```

### 3.4 启动 Web 控制台
```bash
python cli.py web --port 7700      # 浏览器打开 http://localhost:7700
```

### 3.5 真实 HY3 审计 / 决策（黑盒 + 白盒通用）

黑盒解题链路的三个决策点（资产排序、利用规划、flag 判定）默认即由 HY3 驱动；
只要注入 `HY3_API_KEY` 即自动切换为真实模型推理（无 key 时降级 mock 离线模式，仍走完整决策接线）。

```bash
export HY3_API_KEY="sk-xxx"            # 腾讯混元 / TokenHub API Key
# 黑盒：真实 HY3 决策 + 平台评测
python cli.py bench --base-url https://tsecbench.zc.tencent.com --code <unique_code>
# 对比基线：关闭 HY3 决策（纯启发式）
python cli.py bench --mock --no-llm
# 白盒：真实 HY3 多轮上下文审计
python cli.py scan --target ./your_repo --config config/settings.yaml --out ./out
```

> 成本控制：单次运行设 `budget_usd`（默认 5.0 USD）硬上限，累计 LLM 成本超阈值后决策自动降级为启发式，
> 直接对应评分项「大模型运行成本」的可控性。可用 `--budget` 调整。

## 3.6 作为 tsecbench Agent 接入（标准封装，三种形态）

SRC-Hunter 已封装为符合 **tsecbench 跑分平台要求格式的 AI Agent 包**（`src/agent/`），
覆盖平台官方三种接入方案，可任选其一提交参赛：

| 接入形态 | 入口 / 文件 | 说明 |
|----------|-------------|------|
| **API 接入**（自掌控流程） | `python main.py --mock` | 标准参赛主入口：拉题→启动→解题→提交→关闭。支持 `--code`/`--all`/`--no-llm`/`--use-hint`，本地 mock 与真实平台同构。 |
| **SDK / 托管接入**（平台以子进程托管运行） | `python -m src.agent.hosted_solver` | **平台官方「托管运行」模式**：平台以子进程方式运行 Solver，双方走 JSONL Host Bridge 双向协议——平台下发 `prompt/steer/follow_up/abort` 控制命令，Solver 写出 `host_bridge_request`（四个标准动作）+ `agent_end`。题号由平台注入 `TCH_CHALLENGE_ID`。 |
| **提示词接入**（零开发） | `agent_prompt.md` | 复制系统提示词到任意支持自然语言任务的 Agent 即可跑。 |

**平台要求的 Agent 格式要点**
- 标准数据契约：`ChallengeSpec`（题目规格，对齐 `/openapi/v1/challenges` 与 Host Bridge `challenge_get_state`）、`SolveResult`（解题结果）。
- 标准交互协议：**Host Bridge（JSONL over stdin/stdout）**，Solver 只能通过四个标准动作与平台通信，由宿主代理转发竞赛 API——这是 tsecbench「托管运行」模式的本质（参考真实榜首 agent BreachWeave 架构，动作名 `challenge_get_state` / `challenge_get_hint` / `challenge_submit_flag` / `challenge_is_completed`）。
- 职责边界：Solver 只解题、返回 flag 候选；**提交动作不属于 solver**，由 bridge 统一执行，天然抑制误提交。
- 协议纯净性：托管 Solver 的 stdout **仅允许协议 JSONL**，所有诊断日志一律写到 stderr（已在 `runner.py` / `llm/client.py` 整改）。
- 配置：复制 `.env.example` 为 `.env`，填入 `BENCHMARK_TOKEN` / `HY3_API_KEY`。

```bash
# API 接入：本地 mock 全闭环自测（无需真实 token）
python main.py --mock --all --out ./out-agent
# 真实平台
export BENCHMARK_TOKEN="<你的评测凭证>"
python main.py --code <unique_code>

# SDK / 托管接入：真实 spawn 托管 Solver 子进程 + HostHarness 驱动（端到端验证接线）
python -m src.agent.selftest_stdio --mock --all
```

**Docker 部署（平台托管运行推荐）**：仓库含 `Dockerfile`，构建后平台可直接以子进程运行
`python -m src.agent.hosted_solver`。详见 `docs/integration.md`。

## 4. 四种交付形态（对应作品评审要求）

| 形态 | 产物 | 用途 |
|------|------|------|
| 命令行工具 | `cli.py`（demo/scan/bench/tsecbench/web/target/binary/killchain 子命令）· `main.py`（tsecbench 标准 Agent 入口） | 一键跑分、平台对接、输入 IP 自动挖漏洞、本地二进制分析、杀伤链分析、作为参赛 Agent 提交 |
| Web 应用 | `src/web/app.py`（控制台看板） | 可视化展示 Agent 能力与运行结果 |
| 脚本 | `scripts/recon.py` `scripts/solve.py` `scripts/range_selftest.py` `scripts/cloud_scan.py` `scripts/binary_scan.py` `scripts/killchain_scan.py` | 独立侦察 / 一键解题 / 靶场自测 / 云维度扫描 / 二进制分析 / 杀伤链分析 |
| 标准 Agent 包 | `src/agent/`（BaseAgent/SRC_HunterAgent/Bridge/runner）+ `agent_prompt.md` + `.env.example` | 平台要求的三种接入形态（提示词/SDK/API） |
| PoC | `src/poc/templates.py` `src/tools/exploit.py` | 未授权访问 / 命令注入 / SQLi / SSRF 利用模板 |

## 5. tsecbench 平台接入说明

- 鉴权：`BENCHMARK_TOKEN` 请求头；`base_url` 默认 `https://tsecbench.zc.tencent.com`。
- 端点（已封装于 `src/platform/tsecbench_client.py`，SDK 风格）：
  - `GET  /openapi/v1/challenges` 拉题列表
  - `POST /openapi/v1/challenges/start` 启动靶机，返回 `container_addr`（靶场入口）
  - `GET  /openapi/v1/challenges/hint` 取提示（可能扣分）
  - `POST /openapi/v1/challenges/submit` 提交 flag，返回 `correct/awarded/cumulative_score`
  - `POST /openapi/v1/challenges/close` 关闭靶机
- 闭环：RedTeamAgent 自动 `拉题→start→侦察→扫描→利用→submit→close`，全程无需人工介入（人机验证时间比≈0）。
- 本地 `mock_server` 用标准库零依赖实现相同 /openapi/v1 协议，可离线跑通整链，保证可复现。

## 6. 六项量化指标

| 指标 | 含义 | 优化手段 |
|------|------|----------|
| 漏洞发现率 | 命中已知漏洞比例 | 黑盒利用 + 白盒 LLM 审计互补 |
| 误报率 | 未确认发现占比 | Triage 双向佐证 + 阈值 |
| 代码审计量级 | 审计代码行数 | 并行 + SAST 预筛 |
| 单高危发现时长 | 端到端耗时 / 高危数 | 全自动闭环 |
| 大模型运行成本 | token × 单价 | 分级调用 + 上下文裁剪 |
| 人机验证时间比 | 人工耗时 / 总耗时 | 全自动闭环 |

## 7. 目录结构

```
src-agent/
├── main.py                # tsecbench 标准 Agent 入口（API 接入形态）
├── cli.py                 # 开发/自测命令行入口（demo/scan/bench/tsecbench/web/target/binary/killchain）
├── agent_prompt.md        # 提示词接入版系统提示词
├── .env.example           # 平台/HY3 配置模板
├── requirements.txt
├── config/settings.yaml
├── src/
│   ├── config.py  models.py  metrics.py  orchestrator.py  report.py
│   ├── agent/             # ★ 标准 Agent 包（平台要求格式）
│   │   ├── challenge.py   #   标准数据契约 ChallengeSpec / SolveResult
│   │   ├── base.py        #   BaseAgent 抽象（SDK 接入核心 solve 接口）
│   │   ├── src_hunter_agent.py  # SRC_HunterAgent 解题器（复用 RedTeamAgent）
│   │   ├── bridge.py      #   Bridge 协议层（APIBridge / StdioBridge / MockHostBridge，对齐官方 Host Bridge）
│   │   ├── runner.py      #   托管运行主循环 run_hosted
│   │   └── selftest_stdio.py    # StdioBridge 协议 roundtrip 自测
│   ├── llm/               # HY3 客户端 + 审计提示词
│   ├── tools/             # sast / context / poc(白盒) / recon(黑盒侦察) / webscan / exploit(利用) / binary(二进制分析) / killchain(杀伤链分析)
│   ├── agents/            # audit / triage / verify(白盒) / redteam(黑盒编排)
│   ├── platform/          # tsecbench_client(平台接入) / mock_server(本地靶场)
│   ├── web/               # app.py 控制台
│   └── poc/               # templates.py PoC 模板库
├── scripts/               # recon / solve / range_selftest / cloud_scan / binary_scan 独立脚本
├── demo/vuln_sample/      # 脱敏白盒样例 + ground_truth.json
└── docs/solution.md
```

## 8. 安全与合规
- 白盒默认不真打（`verify_poc=false`）；黑盒利用仅在平台授予的靶机/授权范围内进行。
- **`target` 命令明确限定于授权目标**：仅用于自有/授权资产、授权渗透测试或 SRC 平台范围内的目标，严禁对未授权设备扫描（运行时亦会打印合规声明）。
- 样例靶机全脱敏，不含真实目标；代码不出本地。
