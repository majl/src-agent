#!/usr/bin/env python3
"""SRC-Hunter —— tsecbench 参赛 Agent 主入口（API 接入形态）。

平台「API 接入」：自己掌控全部解题流程与异常处理。本入口串起
   拉题(list) → 启动容器(start) → 解题(solve) → 提交(submit) → 关闭(close)
的闭环，支持本地 mock 自测（--mock）与真实平台（配置 BENCHMARK_TOKEN）。

三种接入形态对照：
- 提示词接入：见 agent_prompt.md（复制系统提示词到任意 agent 即可跑）
- SDK 接入  ：见 src/agent/（继承 BaseAgent 实现 solve，或 run_hosted + StdioBridge）
- API 接入  ：即本文件（main.py）

合规声明：本 Agent 仅用于你拥有或已获明确授权的 tsecbench 评测靶机与 SRC 范围，
严禁对任何未授权目标发起攻击。
"""
from __future__ import annotations

import argparse
import os
import sys

# 允许从仓库根直接运行（python main.py）
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.agent import APIBridge, ChallengeSpec, SRC_HunterAgent, run_hosted  # noqa: E402
from src.llm.client import HY3Client  # noqa: E402
from src.platform.tsecbench_client import TsecBenchClient  # noqa: E402


def _build_llm(use_llm: bool):
    if not use_llm:
        return None
    # mock 离线决策：无 HY3_API_KEY 时自动降级为启发式，保证离线可跑
    from src.config import LLMConfig
    cfg = LLMConfig(
        provider="hy3",
        api_key=os.getenv("HY3_API_KEY", ""),  # 空串 → HY3Client 自动进入 mock 模式
        base_url=os.getenv("HY3_BASE_URL", "https://tokenhub.tencentmaas.com/v1"),
    )
    return HY3Client(cfg)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="src-hunter",
        description="SRC-Hunter tsecbench 参赛 Agent（API 接入形态）",
    )
    ap.add_argument("--mock", action="store_true",
                    help="使用本地 mock 平台（http://127.0.0.1:8800）自测，无需 BENCHMARK_TOKEN")
    ap.add_argument("--base-url", default=None, help="平台 base_url（默认读取 BENCHMARK_BASE_URL 或官方地址）")
    ap.add_argument("--token", default=None, help="BENCHMARK_TOKEN（默认读取环境变量）")
    ap.add_argument("--code", default=None, help="只跑指定 unique_code 单题（不指定则跑全部）")
    ap.add_argument("--all", action="store_true", help="依次跑全部题目")
    ap.add_argument("--no-llm", action="store_true", help="关闭 HY3 决策（纯启发式，用于对比/离线）")
    ap.add_argument("--use-hint", action="store_true", help="解题前拉取提示（注意：部分平台提示会扣分）")
    ap.add_argument("--out", "-o", default="./out-agent", help="结果输出目录")
    args = ap.parse_args(argv)

    base_url = args.base_url or ("http://127.0.0.1:8800" if args.mock
                                 else os.getenv("BENCHMARK_BASE_URL"))
    token = args.token or ("mock" if args.mock else os.getenv("BENCHMARK_TOKEN"))
    use_llm = not args.no_llm

    # mock 模式自动拉起本地平台（与 cli.py bench --mock 同构）
    if args.mock and "127.0.0.1" in (base_url or ""):
        from src.platform.mock_server import run_mock_server
        run_mock_server(8800)
        base_url = "http://127.0.0.1:8800"

    client = TsecBenchClient(base_url=base_url, token=token, timeout=60)
    bridge = APIBridge(client)
    agent = SRC_HunterAgent(llm=_build_llm(use_llm), use_llm=use_llm)

    os.makedirs(args.out, exist_ok=True)

    # 选定题目列表
    if args.code:
        codes = [args.code]
    elif args.all or not args.code:
        try:
            codes = [c.unique_code for c in client.list_challenges()]
        except Exception as e:  # noqa
            print(f"[错误] 无法拉取题目列表：{e}", file=sys.stderr)
            return 1
    else:
        codes = []

    if not codes:
        print("[提示] 没有可选题目。使用 --mock --code WEB-DEMO-001 试跑。")
        return 0

    summary = []
    for code in codes:
        print(f"\n===== {code} =====")
        # 真实平台与 mock 均需先 start（mock 的 start 还会激活本题 flag，保证提交判定一致）
        addrs = bridge.start(code)
        spec = bridge.get_state(code)
        if not spec.target_url and addrs:
            spec = ChallengeSpec(unique_code=code, container_addr=addrs)
        if not spec.target_url:
            print(f"[跳过] {code} 无可用入口地址（可能需先 start 或题目未就绪）")
            summary.append({"code": code, "ok": False, "reason": "no-entry"})
            continue
        res = run_hosted(agent, bridge, code, use_hint=args.use_hint, verbose=True)
        summary.append({"code": code, "ok": res.success,
                        "flags": res.flags, "llm_calls": res.llm_calls,
                        "cost_usd": res.llm_cost_usd, "duration_s": res.duration_s})
        # 真实平台：关闭容器释放资源
        if not args.mock:
            try:
                bridge.close(code)
            except Exception:
                pass

    print("\n===== 汇总 =====")
    ok = sum(1 for s in summary if s.get("ok"))
    for s in summary:
        print(f"  {s['code']}: {'OK' if s.get('ok') else 'FAIL'} "
              f"flags={s.get('flags')} calls={s.get('llm_calls')} cost={s.get('cost_usd')}$")
    print(f"通过 {ok}/{len(summary)} 题")

    # 落盘汇总
    import json
    with open(os.path.join(args.out, "agent_run_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"结果汇总已写入 {os.path.join(args.out, 'agent_run_summary.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
