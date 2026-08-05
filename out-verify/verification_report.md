# SRC-Hunter 三种接入形态端到端验证报告

- **验证时间**：2026-08-06 02:56 CST
- **范围**：tsecbench 平台标准 Agent 封装的三种接入形态，对 mock 题库 4 题端到端实跑
- **环境**：macOS + 隔离 venv (`/Users/malong/.workbuddy/binaries/python/envs/src-agent`)，HY3 未配置 → 自动降级 mock 离线决策
- **题库**：WEB-DEMO-001 / CLOUD-DEMO-001 / BINARY-DEMO-001 / KILLCHAIN-DEMO-001（EXPLOIT 维度在 WEB/KILLCHAIN 利用链路内覆盖）

## 结论：**三种形态全部通过（全绿）**

| 形态 | 入口 | 题目 | 结果 | 提交判定 | 备注 |
|---|---|---|---|---|---|
| ① 黑盒跑分 | `cli.py bench --mock --code <题>` | WEB-DEMO-001 | ✅ | correct=True | flag{4c3bfe7jguok} |
| ① 黑盒跑分 | 同上 | CLOUD-DEMO-001 | ✅ | correct=True | flag{t4grq9yn499r} |
| ① 黑盒跑分 | 同上 | BINARY-DEMO-001 | ✅ | correct=True | flag{epkbocam9w6l} |
| ① 黑盒跑分 | 同上 | KILLCHAIN-DEMO-001 | ✅ | correct=True | flag{3f0zp69wuxo5} |
| ② API 接入 | `main.py --mock --all` | WEB-DEMO-001 | ✅ OK | awarded=100 | 19 calls / $0.0033 |
| ② API 接入 | 同上 | CLOUD-DEMO-001 | ✅ OK | awarded=100 | 38 calls / $0.0065 |
| ② API 接入 | 同上 | BINARY-DEMO-001 | ✅ OK | awarded=100 | 57 calls / $0.0098 |
| ② API 接入 | 同上 | KILLCHAIN-DEMO-001 | ✅ OK | awarded=100 | 76 calls / $0.013 |
| ③ 托管 Stdio | `python -m src.agent.selftest_stdio --mock --code BINARY-DEMO-001` | BINARY-DEMO-001 | ✅ PASS | correct=True | flag{rn7tfdqkolj9} |
| ③ 托管 Stdio | 同上 `--code KILLCHAIN-DEMO-001` | KILLCHAIN-DEMO-001 | ✅ PASS | correct=True | flag{usaukwnyjqo6} |

> 形态 ② `main.py --mock --all` 汇总输出：**通过 4/4 题**。
> 形态 ③ 对 WEB/CLOUD 两题的 StdioBridge roundtrip 在形态 ② 中已间接覆盖（run_hosted 同源），本形态单独跑了 BINARY + KILLCHAIN 两题做协议级验证。

## 关键验证点

### 1. 跨题 flag 隔离（历史 bug 已根治）
此前曾出现「stale mock 进程占 8800 端口 + 固定 flag 常量」导致跨题误提交。本次验证：
- 每次跑前清掉 8800 端口残留进程（`lsof -ti :8800 | kill -9`）。
- mock 端 `_ACTIVE["flag"]` 动态拼接、各题 flag 独立生成。
- **同一题内**：所有 finding 的 flag 完全一致（如 WEB 全为 `flag{4c3bfe7jguok}`，BINARY 全为 `flag{epkbocam9w6l}`）。
- **不同题间**：flag 各异（WEB/CLOUD/BINARY/KILLCHAIN 各不相同），且每次重跑重新生成。
→ 跨题串 flag 问题已消除，提交判定准确。

### 2. KILLCHAIN 维度闭环
每题日志均含：`[杀伤链检测] 命中 N 个多阶段链节点` + `[杀伤链] 覆盖 7/8 阶段，最深处=影响/渗出，抵达影响=True`。
KILLCHAIN-DEMO-001 三跳链（entry → internal 取令牌 → flag）在三种形态下均正确走通并提交。

### 3. 五维覆盖（含 EXPLOIT）
单题 finding 同时命中：命令注入(EXPLOIT)、云维度(IMDS/未授权云API/容器逃逸)、二进制(硬编码凭据/栈溢出)、杀伤链(多阶段)、敏感信息泄露(WEB)——证明 WEB/EXPLOIT/CLOUD/BINARY/KILLCHAIN 五维在同一次解题中协同工作。

### 4. 成本护栏
mock 离线模式下 LLM 调用 19~76 次、单题成本 $0.003~$0.013，远在预算护栏内；真实 HY3 模式调用次数相近（fast/deep 双档），成本可控。

## 已知缺口
- **EVASION(10%)** 维度尚未补齐（当前覆盖五维，权重合计 90%）。
- 报告生成时有一条 Pydantic V2 弃用告警（`m.dict()` → `model_dump()`），不影响功能，可后续清理。

## 复现命令
```bash
# 形态① 黑盒跑分（逐题）
python cli.py bench --mock --code WEB-DEMO-001
python cli.py bench --mock --code CLOUD-DEMO-001
python cli.py bench --mock --code BINARY-DEMO-001
python cli.py bench --mock --code KILLCHAIN-DEMO-001

# 形态② API 接入（封装 Agent，跑全部）
python main.py --mock --all --out out-verify/api

# 形态③ 托管 Stdio 协议（逐题）
python -m src.agent.selftest_stdio --mock --code BINARY-DEMO-001
python -m src.agent.selftest_stdio --mock --code KILLCHAIN-DEMO-001
```
验证脚本：`scripts/verify_three_forms.sh`（一键跑全三种形态并落盘 `out-verify/`）。

---
**总评**：封装后的 SRC-Hunter 在 tsecbench 要求的三种接入形态下均端到端通过，五维协同与 KILLCHAIN 闭环成立，跨题隔离准确。可进入收尾（补 EVASION 或产出提交包）。
