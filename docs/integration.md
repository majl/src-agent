# tsecbench 平台接入与托管运行协议

本文档说明 SRC-Hunter 如何对接 **tsecbench 智能攻防跑分基准平台**，以及平台
「托管运行」模式的真实协议细节（参考官方榜首 agent BreachWeave 的 Host Bridge 架构，
腾讯同一竞赛生态）。

## 1. 平台三种接入方案

| 方案 | 适用 | SRC-Hunter 对应入口 |
|------|------|---------------------|
| **提示词接入** | 零开发，把系统提示词交给任意 Agent | `agent_prompt.md` |
| **SDK 接入 / 托管运行** | 平台以子进程形式托管运行你的 Solver | `python -m src.agent.hosted_solver` |
| **API 接入** | 自己掌控全流程（拉题/启停/提交） | `python main.py` |

> 官方排行榜计分采用**托管运行模式**（杜绝本地刷分）。因此 **SDK/托管接入** 是
> 最标准、最被认可的提交形态。

## 2. 托管运行（Host Bridge）双向 JSONL 协议

平台把你的 Solver 作为**子进程**启动，双方通过 **stdin / stdout 的单行 JSON**
（JSONL）通信。一条连接上同时承载两类消息，由 `type` 字段区分：

### 2.1 平台（宿主）→ Solver（写 Solver 的 stdin）

控制命令（生命周期与调度）：

```json
{"type": "prompt",   "prompt": "please solve the challenge", "challenge_id": "WEB-DEMO-001"}
{"type": "steer",    "instruction": "..."}      // 可选：动态重定向攻击路线
{"type": "follow_up","instruction": "..."}      // 可选：追加上下文
{"type": "abort"}                                // 终止当前解题
```

以及动作响应（与 Solver 的请求一一对应，按 `request_id` 匹配）：

```json
{"request_id": "<uuid>", "type": "host_bridge_response", "ok": true,
 "data": { "unique_code": "WEB-DEMO-001", "container_addr": ["http://..."], ... }}
```

### 2.2 Solver → 平台（写 Solver 的 stdout）

动作请求（四个标准动作，由宿主代理转发竞赛 API）：

```json
{"type": "host_bridge_request", "request_id": "<uuid>",
 "action": "challenge_get_state",  "params": {"unique_code": "WEB-DEMO-001"}}
{"type": "host_bridge_request", "request_id": "<uuid>",
 "action": "challenge_get_hint",   "params": {"unique_code": "WEB-DEMO-001"}}
{"type": "host_bridge_request", "request_id": "<uuid>",
 "action": "challenge_submit_flag","params": {"unique_code": "WEB-DEMO-001", "flag": "flag{...}"}}
{"type": "host_bridge_request", "request_id": "<uuid>",
 "action": "challenge_is_completed","params": {"unique_code": "WEB-DEMO-001"}}
```

生命周期事件：

```json
{"type": "agent_end", "success": true, "unique_code": "WEB-DEMO-001",
 "flags": ["flag{...}"], "llm_calls": 42, "llm_cost_usd": 0.012, "duration_s": 88.5}
```

### 2.3 题号注入

平台在启动 Solver 子进程时通过**环境变量**注入当前题目码：

```
TCH_CHALLENGE_ID        （首选，BreachWeave 同源命名）
TSEC_CHALLENGE_ID / BENCHMARK_CHALLENGE_ID / CHALLENGE_ID   （兼容兜底）
```

Solver（`src/agent/hosted_solver.py`）优先读取 `--code`，否则回退到上述环境变量。

### 2.4 协议纯净性约束（重要）

托管模式下 **Solver 的 stdout 只允许输出协议 JSONL**。任何诊断 `print` 都会破坏
JSONL 流导致平台解析失败。SRC-Hunter 已整改：`runner.py` 与 `llm/client.py` 的日志
一律写入 **stderr**；`HostChannel.send_event` 是唯一允许写 stdout 的出口。

## 3. 本地端到端验证（无需真实平台）

`selftest_stdio` 会**真实 spawn** `hosted_solver` 子进程，并用 `HostHarness`（宿主侧）
驱动，完整复现平台托管运行：

```bash
# 启动本地 mock 平台 + spawn 托管 Solver + HostHarness 驱动（全题）
python -m src.agent.selftest_stdio --mock --all

# 单题
python -m src.agent.selftest_stdio --mock --code KILLCHAIN-DEMO-001
```

验证通过标准：子进程上报 `agent_end.success == true`，flag 与 mock 平台判定一致。

## 4. 真实平台提交步骤

1. **配置凭证**：复制 `.env.example` → `.env`，填入 `BENCHMARK_TOKEN`（与 `HY3_API_KEY`，可选）。
2. **API 接入自测**（推荐先跑一遍确认可用）：
   ```bash
   export BENCHMARK_TOKEN="<凭证>"
   python main.py --all --out ./out-agent
   ```
3. **托管运行提交**：将仓库按 `Dockerfile` 构建为镜像（或上传源码目录），在平台选择
   「SDK/托管接入」，入口命令 `python -m src.agent.hosted_solver`。平台会以子进程托管
   运行，并按第 2 节协议与之交互。
4. **合规边界**：仅对平台授权的评测靶机发起测试；绝不攻击任何未授权目标。

## 5. 模块映射

| 平台概念 | SRC-Hunter 实现 |
|----------|-----------------|
| 托管 Solver（子进程） | `src/agent/hosted_solver.py`（`HostedSolver`） |
| JSONL 双向通道 | `src/agent/bridge.py` → `HostChannel` |
| Solver 侧动作桥 | `src/agent/bridge.py` → `StdioBridge` |
| 宿主侧（平台/自测） | `src/agent/bridge.py` → `HostHarness` |
| 解题主循环 | `src/agent/runner.py` → `run_hosted` |
| 解题器 | `src/agent/src_hunter_agent.py` → `SRC_HunterAgent` |
| 平台 HTTP 客户端 | `src/platform/tsecbench_client.py` → `TsecBenchClient` |
| 本地靶场 | `src/platform/mock_server.py` |
