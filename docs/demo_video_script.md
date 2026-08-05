# SRC-Hunter 演示视频脚本（≤ 5 分钟）

> 用途：参赛作品演示视频分镜脚本，可直接按表拍摄/录屏。
> 总时长：约 4 分 50 秒（含 10s 余量）。建议 **屏幕录屏 + 画外音配音**，关键结论配字幕。
> 录制前提：本地已 `pip install -r requirements.txt`，无需真实 Key（自动降级 mock 离线模式，全流程可复现）。

---

## 分镜总表

| # | 时段 | 场景 | 核心信息 |
|---|------|------|----------|
| 1 | 0:00–0:30 | 开场 | 痛点 + 团队/作品一句话 |
| 2 | 0:30–1:10 | 架构总览 | 双模 + 五维 + 三形态 |
| 3 | 1:10–2:30 | 黑盒一键跑分 | `bench --mock` 真实拿 flag |
| 4 | 2:30–3:10 | 杀伤链维度 | KILLCHAIN 7/8 阶段闭环 |
| 5 | 3:10–4:00 | 三种接入形态 | API / SDK / 提示词 |
| 6 | 4:00–4:30 | 验证报告 | 全绿 + 跨题隔离 + 成本护栏 |
| 7 | 4:30–5:00 | 合规与结尾 | 合规声明 + 致谢 |

---

## 场景 1 · 开场（0:00–0:30）

- **画面**：黑底白字渐显 → SRC-Hunter Logo/标题 → 切到赛事名「百度 BSRC Agent+ 攻防能力挑战赛」。
- **配音**：
  > SRC 漏洞挖掘，传统靠人海战术：翻代码、扫端口、手工构造利用，效率低、易漏报。我们带来一支"双人战队"——人类安全研究员定方向，AI 红队 Agent **SRC-Hunter** 跑全链。人定方向，Agent 拿 flag。
- **字幕**：SRC-Hunter · 人类 + AI 协同的自动化漏洞挖掘 Agent
- **素材**：标题页（可截图 `docs/team.md` 定位句）。

## 场景 2 · 架构总览（0:30–1:10）

- **画面**：架构图（建议用 PPT/Excalidraw 绘制，三组并排）：
  - 左：白盒（SAST + HY3 审计）
  - 中：黑盒（侦察→Web/云/二进制扫描→杀伤链→利用→提交），中心 HY3 三个决策点
  - 右：三形态接入（提示词 / SDK / API）
  - 底部横幅：覆盖 **WEB / EXPLOIT / CLOUD / BINARY / KILLCHAIN** 五维。
- **配音**：
  > SRC-Hunter 采用双模架构：白盒做代码审计，黑盒做自主渗透，共用一套工具链。黑盒链路由 HY3 驱动三个决策点——资产排序、利用规划、flag 判定。最关键的是，它原生封装成 tsecbench 要求的**标准 Agent 包**，覆盖官方三种接入形态，并一次解题协同命中五大评测维度。
- **字幕**：双模架构 · 五维协同 · 标准 Agent 包（提示词/SDK/API）

## 场景 3 · 黑盒一键跑分（1:10–2:30）

- **画面**：终端录屏，依次执行（鼠标高亮命令，停留展示输出）。
- **实操命令**（录屏真实运行）：
  ```bash
  python cli.py bench --mock --code WEB-DEMO-001
  python cli.py bench --mock --code CLOUD-DEMO-001
  python cli.py bench --mock --code BINARY-DEMO-001
  ```
- **配音**（配合输出滚动）：
  > 看实际效果。一条命令对接 mock 靶场，Agent 自动拉题、启动靶机、侦察、多维扫描、真实发送利用请求提取 flag，再提交平台——`correct=True`，满分。Web、云、二进制维度，一条链路全部拿下。注意右下角：LLM 调用仅 19~57 次，单题成本不到 1 美分。
- **字幕**：`submitted_ok: true` · `awarded=100` · 成本 $0.003–$0.013
- **提示**：录屏时把终端字体调大，输出里高亮 `flag{...}` 与 `correct=True` 两行。

## 场景 4 · 杀伤链维度（2:30–3:10）

- **画面**：终端执行 `killchain` 子命令，展示攻击链报告。
- **实操命令**：
  ```bash
  python cli.py killchain --mock --code KILLCHAIN-DEMO-001
  ```
- **配音**：
  > 真正的亮点在杀伤链维度。SRC-Hunter 不满足于"找到一个漏洞"，而是把离散漏洞点串成连贯的多阶段攻击链：侦察→初始立足→执行→提权→横向→凭据→收集→影响。这条三跳链（entry 发现内部入口 → internal 拿到服务令牌 → flag 取得影响），覆盖率 7/8 阶段，抵达影响阶段为 True。
- **字幕**：KILLCHAIN 覆盖 7/8 阶段 · 抵达影响=True
- **素材**：截图 `out-killchain/killchain_report.json` 的 `phases_covered / narrative` 字段。

## 场景 5 · 三种接入形态（3:10–4:00）

- **画面**：分三屏/三段展示三种形态命令与输出。
- **实操命令**（逐段录屏）：
  ```bash
  # ① API 接入：标准主入口，跑全部题目
  python main.py --mock --all --out ./out-agent
  # ② SDK 接入：StdioBridge 协议 roundtrip（托管运行）
  python -m src.agent.selftest_stdio --mock --code BINARY-DEMO-001
  # ③ 提示词接入：复制 agent_prompt.md 到任意 Agent 即可
  ```
- **配音**：
  > 作为参赛 Agent，它支持三种接入：API 接入——`main.py` 自掌控全流程，4/4 题通过；SDK 接入——`StdioBridge` 用官方 Host Bridge 协议（JSONL over stdin/stdout）对接托管运行，roundtrip 验证 PASS；提示词接入——直接复制 `agent_prompt.md` 到任意 Agent 就能跑。无论平台选哪种形态，SRC-Hunter 都能即插即用。
- **字幕**：API 接入 4/4 OK · SDK StdioBridge PASS · 提示词零开发

## 场景 6 · 验证报告（4:00–4:30）

- **画面**：展示 `out-verify/verification_report.md` 的汇总表（可截图或编辑器打开）。
- **配音**：
  > 我们做了三种形态的端到端回归：全部通过。特别验证了历史难点——跨题 flag 隔离：同一题内所有发现 flag 一致、不同题之间各异，彻底杜绝误提交。成本护栏生效，单题美分级别。
- **字幕**：三形态全绿 · 跨题隔离已根治 · 成本护栏生效

## 场景 7 · 合规与结尾（4:30–5:00）

- **画面**：回到标题页，底部叠加合规声明文字。
- **配音**：
  > 最后强调合规：SRC-Hunter 所有利用仅在授权资产与赛事靶机范围内进行，`target` 命令运行即强制打印合规声明，严禁未授权目标。我们是 BSRC SRC-Hunter 战队，用 AI 把漏洞挖掘做得更快、更全、更可控。谢谢观看。
- **字幕**：仅用于授权资产 / SRC 靶机 · 遵循《网络安全法》与赛事规则
- **结束画面**：队名 + 作品名 + 「感谢评审」。

---

## 录制小贴士

1. 全程无需真实 Key：不设置 `HY3_API_KEY` / `BENCHMARK_TOKEN` 即自动走 mock 离线模式，演示稳定可复现。
2. 若想展示真实 HY3 决策，可 `export HY3_API_KEY=sk-xxx` 后重录场景 3–5（决策点输出会从 `[mock]` 变为真实推理）。
3. 录屏分辨率建议 1920×1080，终端字号 ≥ 16px，关键输出（flag / correct=True / PASS）用高亮或字幕强调。
4. 总时长控制：场景 3、5 为命令录屏可加速 1.5× 播放，旁白正常语速，确保 ≤ 5:00。
