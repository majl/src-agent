#!/usr/bin/env python3
"""靶场自测：启动本地 mock 靶场并跑通「拉题→解题→提交」全闭环，验证 Agent 可用性。

用法：
    python scripts/range_selftest.py
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.redteam import RedTeamAgent
from src.platform.mock_server import run_mock_server
from src.platform.tsecbench_client import TsecBenchClient


def main():
    print("[selftest] 启动本地 mock 平台 + 脱敏靶场 …")
    srv = run_mock_server(8800)
    time.sleep(1.2)

    client = TsecBenchClient(base_url="http://127.0.0.1:8800", token="mock-token")
    agent = RedTeamAgent(client=client)
    res = agent.solve_challenge()
    srv.shutdown()

    print(json.dumps(res, ensure_ascii=False, indent=2))
    if res.get("flag"):
        print("\n[selftest] ✅ 闭环通过：已自主提取并提取得分")
    else:
        print("\n[selftest] ❌ 未提取到 flag，请检查侦察/扫描/利用链路")


if __name__ == "__main__":
    main()
