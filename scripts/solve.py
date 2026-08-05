#!/usr/bin/env python3
"""一键解题脚本：对接 tsecbench 平台，自动拉题→启动靶机→解题→提交→关闭。

用法：
    # 本地 mock 全闭环（无需真实 token）
    python scripts/solve.py --mock

    # 对接真实平台
    BENCHMARK_TOKEN=xxx python scripts/solve.py --base-url https://tsecbench.zc.tencent.com
    python scripts/solve.py --base-url https://tsecbench.zc.tencent.com --token xxx --code WEB-XXXX
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.redteam import RedTeamAgent
from src.platform.tsecbench_client import TsecBenchClient


def main():
    ap = argparse.ArgumentParser(description="SRC-Hunter 一键解题（对接 tsecbench）")
    ap.add_argument("--base-url", default=os.getenv("BENCHMARK_BASE_URL"))
    ap.add_argument("--token", default=os.getenv("BENCHMARK_TOKEN"))
    ap.add_argument("--code", default=None, help="指定题目 unique_code，缺省取第一题")
    ap.add_argument("--mock", action="store_true", help="使用本地 mock 平台")
    ap.add_argument("--no-close", action="store_true", help="解题后不关闭靶机")
    args = ap.parse_args()

    if args.mock:
        from src.platform.mock_server import run_mock_server
        run_mock_server(8800)
        args.base_url = "http://127.0.0.1:8800"
        args.token = args.token or "mock-token"

    if not args.base_url or not args.token:
        ap.error("需提供 --base-url 与 --token（或 --mock）")

    client = TsecBenchClient(base_url=args.base_url, token=args.token)
    agent = RedTeamAgent(client=client)
    res = agent.solve_challenge(unique_code=args.code, close=not args.no_close)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
