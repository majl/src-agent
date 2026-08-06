"""托管运行协议端到端自测：真实复现 tsecbench「托管运行」模式。

做法（与平台一致）：
1. 本地拉起 mock 平台（http://127.0.0.1:8800，含脱敏靶场）；
2. 以**子进程**方式运行 ``src/agent/hosted_solver.py``（即平台托管运行 Solver）；
3. 用 ``HostHarness``（宿主侧）向子进程 stdin 下发 prompt、读取其 stdout 的
   host_bridge_request 并分发到 mock 平台、回写 host_bridge_response；
4. 校验子进程上报的 agent_end.success。

这等价于平台托管运行时发生的一切，无需真实平台即可验证「托管/SDK 接入」形态
接线正确。

用法：
    python -m src.agent.selftest_stdio --mock --code BINARY-DEMO-001
    python -m src.agent.selftest_stdio --mock --all
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

from src.agent import HostHarness  # noqa: E402
from src.platform.tsecbench_client import TsecBenchClient  # noqa: E402

PY = sys.executable


def run_one(client: TsecBenchClient, code: str, no_llm: bool) -> dict:
    """spawn 托管 Solver 子进程，用 HostHarness 驱动单题，返回结果。"""
    env = dict(os.environ)
    env["TCH_CHALLENGE_ID"] = code          # 平台注入题号（模拟）
    env["PYTHONPATH"] = ROOT
    env.pop("HY3_API_KEY", None)            # 确保走 mock LLM 决策
    args = [PY, "src/agent/hosted_solver.py", "--mock", "--code", code]
    if no_llm:
        args.append("--no-llm")

    proc = subprocess.Popen(
        args, cwd=ROOT, env=env,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    # HostHarness 读子进程 stdout、写子进程 stdin
    harness = HostHarness(client, stdin=proc.stdout, stdout=proc.stdin)
    end = harness.serve(code)
    try:
        proc.wait(timeout=300)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    stderr_log = ""
    try:
        stderr_log = proc.stderr.read() if proc.stderr else ""
    except Exception:
        pass

    success = bool(end.get("success")) if end else False
    return {
        "code": code,
        "success": success,
        "agent_end": end,
        "returncode": proc.returncode,
        "stderr_tail": (stderr_log or "")[-800:],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="托管运行协议端到端自测（spawn 子进程）")
    ap.add_argument("--mock", action="store_true", help="使用本地 mock 平台")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--token", default=None)
    ap.add_argument("--code", default="BINARY-DEMO-001")
    ap.add_argument("--all", action="store_true", help="跑全部 demo 题")
    ap.add_argument("--no-llm", action="store_true", help="关闭 HY3 决策")
    ap.add_argument("--out", "-o", default="./out-verify/selftest_stdio.json")
    args = ap.parse_args(argv)

    base_url = args.base_url or ("http://127.0.0.1:8800" if args.mock
                                 else os.getenv("BENCHMARK_BASE_URL"))
    token = args.token or ("mock" if args.mock else os.getenv("BENCHMARK_TOKEN"))

    if args.mock and "127.0.0.1" in (base_url or ""):
        from src.platform.mock_server import run_mock_server
        run_mock_server(8800)
        base_url = "http://127.0.0.1:8800"

    client = TsecBenchClient(base_url=base_url, token=token, timeout=60)

    if args.all:
        codes = [c.unique_code for c in client.list_challenges()]
    else:
        codes = [args.code]

    results = []
    for code in codes:
        print(f"\n===== 托管自测 {code} =====", file=sys.stderr)
        r = run_one(client, code, args.no_llm)
        print(f"  success={r['success']} returncode={r['returncode']} "
              f"flags={r['agent_end'].get('flags') if r['agent_end'] else None}",
              file=sys.stderr)
        results.append(r)

    ok = sum(1 for r in results if r["success"])
    print(f"\n托管自测通过 {ok}/{len(results)} 题", file=sys.stderr)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"结果已写入 {args.out}", file=sys.stderr)
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
