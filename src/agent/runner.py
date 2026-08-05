"""托管运行主循环：把 Solver 与 Bridge 串成平台认可的标准解题流程。

无论底层是 APIBridge 还是 StdioBridge，runner 都遵循同一契约：

    get_state → 构造 ChallengeSpec → agent.solve → 逐个 submit_flag
    → is_completed 检查 → 结束

这是「SDK 接入」形态的核心 loop：Solver 只负责解题，提交/生命周期由 bridge 管控。
"""
from __future__ import annotations

from typing import Optional

from .base import BaseAgent
from .bridge import Bridge
from .challenge import ChallengeSpec, SolveResult


def run_hosted(
    agent: BaseAgent,
    bridge: Bridge,
    unique_code: str,
    use_hint: bool = False,
    verbose: bool = True,
) -> SolveResult:
    """对单题执行托管解题闭环，返回聚合结果。

    Args:
        agent: 解题器（实现 solve）。
        bridge: 平台交互桥（APIBridge / StdioBridge）。
        unique_code: 题目唯一码。
        use_hint: 是否在解题前拉取提示（注意：部分平台提示会扣分）。
        verbose: 是否打印进度日志。
    """
    log: list[str] = []
    spec: Optional[ChallengeSpec] = None

    # 1) get_state：拉取题目元数据与入口地址
    try:
        spec = bridge.get_state(unique_code)
    except Exception as e:  # noqa
        return SolveResult(success=False, log=[f"[bridge] get_state 失败: {e}"])

    if use_hint and spec and not spec.hint:
        h = bridge.get_hint(unique_code)
        if h:
            spec.hint = h
            log.append("[bridge] 已拉取提示（可能扣分）")

    if not spec or not spec.target_url:
        return SolveResult(success=False,
                           log=log + ["[bridge] 题目无可用入口地址（可能未 start 容器）"])

    if verbose:
        print(f"[runner] 解题 {unique_code} 入口={spec.target_url}")

    # 2) solve：Solver 自主解题，返回 flag 候选
    result = agent.solve(spec)
    log += result.log

    # 3) submit_flag：逐个提交候选，平台裁定正确性
    submitted_correct = 0
    for flag in result.flags:
        try:
            r = bridge.submit_flag(unique_code, flag)
        except Exception as e:  # noqa
            log.append(f"[bridge] 提交 {flag} 异常: {e}")
            continue
        if r.get("correct"):
            submitted_correct += 1
            log.append(f"[bridge] 提交正确 {flag} awarded={r.get('awarded')}")
        else:
            log.append(f"[bridge] 提交 {flag} 不正确（候选被平台驳回，已抑制误报）")

    # 4) is_completed：检查题目是否全部完成
    try:
        done = bridge.is_completed(unique_code)
    except Exception:
        done = submitted_correct > 0
    result.success = done or submitted_correct > 0
    result.log = log
    if verbose:
        print(f"[runner] {unique_code} 正确提交 {submitted_correct}/{len(result.flags)} 个 flag，完成={done}")
    return result
