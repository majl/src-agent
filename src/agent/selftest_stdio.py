"""StdioBridge 协议 roundtrip 自测：验证「托管运行」形态接线正确。

本地用两个真实管道（os.pipe）把 StdioBridge（agent 侧）与 MockHostBridge（宿主侧）
配成一对，跑通 challenge_get_state → solve → submit_flag → is_completed 全流程，
证明 SRC-Hunter 能以 tsecbench 官方 Host Bridge 协议对接平台（无需真实平台）。

用法：
    python -m src.agent.selftest_stdio --mock --code BINARY-DEMO-001
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.agent import MockHostBridge, SRC_HunterAgent, StdioBridge  # noqa: E402
from src.agent.runner import run_hosted  # noqa: E402
from src.llm.client import HY3Client  # noqa: E402
from src.platform.tsecbench_client import TsecBenchClient  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="StdioBridge 协议自测")
    ap.add_argument("--mock", action="store_true", help="使用本地 mock 平台")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--token", default=None)
    ap.add_argument("--code", default="BINARY-DEMO-001")
    args = ap.parse_args(argv)

    base_url = args.base_url or ("http://127.0.0.1:8800" if args.mock
                                 else os.getenv("BENCHMARK_BASE_URL"))
    token = args.token or ("mock" if args.mock else os.getenv("BENCHMARK_TOKEN"))
    if args.mock and "127.0.0.1" in (base_url or ""):
        from src.platform.mock_server import run_mock_server
        run_mock_server(8800)
        base_url = "http://127.0.0.1:8800"
    client = TsecBenchClient(base_url=base_url, token=token, timeout=60)

    # 双向阻塞管道：agent↔宿主
    r_agent2host, w_agent2host = os.pipe()  # agent 写 → 宿主读
    r_host2agent, w_host2agent = os.pipe()  # 宿主写 → agent 读
    agent_out = os.fdopen(w_agent2host, "w", buffering=1)  # 行缓冲
    host_in = os.fdopen(r_agent2host, "r")
    host_out = os.fdopen(w_host2agent, "w", buffering=1)
    agent_in = os.fdopen(r_host2agent, "r")

    agent_bridge = StdioBridge(stdin=agent_in, stdout=agent_out)
    from src.config import LLMConfig
    cfg = LLMConfig(provider="hy3", api_key="")  # mock 模式
    agent = SRC_HunterAgent(llm=HY3Client(cfg), use_llm=True)

    def host_loop():
        host = MockHostBridge(client, stdin=host_in, stdout=host_out)
        host.serve(args.code)

    t = threading.Thread(target=host_loop, daemon=True)
    t.start()

    result = run_hosted(agent, agent_bridge, args.code, verbose=True)

    print("\n=== StdioBridge 协议 roundtrip 结果 ===")
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    ok = result.success
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
