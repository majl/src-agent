#!/usr/bin/env python3
"""SRC-Hunter 托管运行 Solver 入口（tsecbench 托管 / SDK 接入形态）。

平台以**子进程**方式运行本文件，并通过 stdin/stdout 的 JSONL 通道进行托管：

    ┌────────────┐   stdin    ┌──────────────────┐
    │  平台宿主   │ ─prompt──▶ │  hosted_solver    │
    │ (HostHarness│ ◀─host_bridge_request──│  (本文件 = Solver) │
    │   / 真平台) │ ──host_bridge_response─▶│  → TsecBenchClient │
    └────────────┘   stdout   └──────────────────┘

- 平台 → Solver（stdin）：控制命令 prompt / steer / follow_up / abort
- Solver → 平台（stdout）：host_bridge_request（四个挑战动作）+ agent_end 生命周期事件
- 题号由平台注入环境变量 TCH_CHALLENGE_ID（兼容 TSEC_CHALLENGE_ID /
  BENCHMARK_CHALLENGE_ID / CHALLENGE_ID）。

**重要**：stdout 仅允许协议 JSONL，任何诊断日志一律写到 stderr，否则会污染
协议流导致平台解析失败。
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time

# 允许从仓库根直接运行（python src/agent/hosted_solver.py）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.agent import HostChannel, StdioBridge, SRC_HunterAgent  # noqa: E402
from src.agent.runner import run_hosted  # noqa: E402
from src.llm.client import HY3Client  # noqa: E402


def _build_llm(use_llm: bool) -> Optional[HY3Client]:
    if not use_llm:
        return None
    from src.config import LLMConfig  # noqa: E402
    cfg = LLMConfig(
        provider="hy3",
        api_key=os.getenv("HY3_API_KEY", ""),  # 空串 → HY3Client 自动进入 mock 模式
        base_url=os.getenv("HY3_BASE_URL", "https://tokenhub.tencentmaas.com/v1"),
    )
    return HY3Client(cfg)


def _resolve_challenge_id(cli_code: Optional[str]) -> Optional[str]:
    """题号优先级：命令行 --code > 平台注入环境变量。"""
    return (
        cli_code
        or os.getenv("TCH_CHALLENGE_ID")
        or os.getenv("TSEC_CHALLENGE_ID")
        or os.getenv("BENCHMARK_CHALLENGE_ID")
        or os.getenv("CHALLENGE_ID")
    )


class HostedSolver:
    """托管 Solver 主控：等待平台 prompt、调用解题器、上报 agent_end。"""

    def __init__(self, agent: SRC_HunterAgent, challenge_id: str, use_llm: bool):
        self.agent = agent
        self.challenge_id = challenge_id
        self.use_llm = use_llm
        self.abort = threading.Event()
        self.done = threading.Event()
        self.channel: Optional[HostChannel] = None

    def on_command(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "prompt":
            # 在独立线程解题，避免阻塞 JSONL 读线程（读线程需持续响应 host_bridge_response）
            threading.Thread(target=self._run_solve, daemon=True).start()
        elif t == "abort":
            self.abort.set()
        # steer / follow_up 目前透传（可在未来扩展为动态重定向攻击路线）

    def _run_solve(self) -> None:
        # 极小概率：读线程在 solver.channel 赋值前就收到 prompt，这里做一次兜底等待
        ch = self.channel
        if ch is None:
            time.sleep(0.1)
            ch = self.channel
        try:
            result = run_hosted(
                self.agent,
                StdioBridge(ch),  # type: ignore[arg-type]
                self.challenge_id,
                abort_check=self.abort.is_set,
                verbose=False,
            )
            ch.send_event({
                "type": "agent_end",
                "success": bool(result.success),
                "unique_code": self.challenge_id,
                "flags": result.flags,
                "llm_calls": result.llm_calls,
                "llm_cost_usd": result.llm_cost_usd,
                "duration_s": result.duration_s,
            })
        except Exception as e:  # noqa
            sys.stderr.write(f"[hosted] solve 异常: {e}\n")
            if ch is not None:
                ch.send_event({
                    "type": "agent_end", "success": False,
                    "unique_code": self.challenge_id, "error": str(e),
                })
        finally:
            self.done.set()

    def serve_forever(self) -> int:
        # 阻塞直到解题完成、被 abort 或 stdin 关闭
        while not self.done.is_set() and not self.abort.is_set():
            time.sleep(0.2)
        return 0 if self.done.is_set() else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="hosted-solver",
        description="SRC-Hunter tsecbench 托管运行 Solver 入口",
    )
    ap.add_argument("--mock", action="store_true",
                    help="本地 mock 平台自测（由 HostHarness 配套启动，一般无需手动传）")
    ap.add_argument("--code", default=None,
                    help="题目 unique_code（不传则读取 TCH_CHALLENGE_ID 等环境变量）")
    ap.add_argument("--no-llm", action="store_true", help="关闭 HY3 决策（纯启发式离线）")
    args = ap.parse_args(argv)

    challenge_id = _resolve_challenge_id(args.code)
    if not challenge_id:
        sys.stderr.write(
            "[hosted] 未提供题目码：请传 --code 或由平台注入 TCH_CHALLENGE_ID 等环境变量\n"
        )
        return 2

    use_llm = not args.no_llm
    agent = SRC_HunterAgent(llm=_build_llm(use_llm), use_llm=use_llm)
    solver = HostedSolver(agent, challenge_id, use_llm)

    # 建立 JSONL 双向通道（stdin 读 / stdout 写），并注册控制命令回调
    solver.channel = HostChannel(
        sys.stdin, sys.stdout, timeout=120.0, on_command=solver.on_command
    )
    sys.stderr.write(f"[hosted] Solver 就绪，等待平台 prompt（challenge={challenge_id}）\n")

    return solver.serve_forever()


if __name__ == "__main__":
    raise SystemExit(main())
