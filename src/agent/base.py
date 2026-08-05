"""tsecbench SDK 接入的核心抽象：Agent 只需实现 solve 解题流程。

平台「SDK 接入」范式：使用 python-sdk 简化开发，**无需关心平台跑分流程细节，
只需对接核心的 agent 解题流程**。本文件即该契约的落地——任何继承 ``BaseAgent``
并实现 ``solve(challenge) -> SolveResult`` 的子类，都可直接作为 tsecbench 参赛
agent 接入（无论底层是 API 接入还是托管 Host Bridge 接入）。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from .challenge import ChallengeSpec, SolveResult


class BaseAgent(ABC):
    """参赛 agent 必须实现的接口。

    子类职责：拿到一道题（ChallengeSpec），自主完成侦察/扫描/利用，
    返回发现的 flag 候选列表（SolveResult.flags）。**提交动作不属于 solver 职责**，
    由上层 bridge / runner 统一执行，以对齐平台「Solver 只能通过 bridge 提交」的
    托管运行约束。
    """

    # 元数据：可被平台/SDK 读取展示
    name: str = "unnamed-agent"
    version: str = "0.0.0"
    author: str = ""
    description: str = ""

    @abstractmethod
    def solve(self, challenge: ChallengeSpec) -> SolveResult:
        """解题核心流程。给定题目规格，返回发现的全部 flag 候选。

        Args:
            challenge: 平台下发的题目规格（含入口地址 target_url、描述、提示等）。

        Returns:
            SolveResult: 含 flags（候选列表）、findings、耗时、LLM 调用/成本等。
        """
        raise NotImplementedError

    def close(self) -> None:
        """可选：释放资源（如关闭会话、清理临时文件）。默认空实现。"""
        return
