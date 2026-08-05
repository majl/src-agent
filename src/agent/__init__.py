"""SRC-Hunter 标准 Agent 包：对齐 tsecbench 三种接入形态的封装。

对外暴露：
- ``BaseAgent`` / ``SRC_HunterAgent``：SDK 接入核心解题器（实现 solve）。
- ``Bridge`` / ``APIBridge`` / ``StdioBridge`` / ``MockHostBridge``：平台交互桥。
- ``ChallengeSpec`` / ``SolveResult``：标准数据契约。
- ``run_hosted``：托管运行主循环。
"""
from .base import BaseAgent
from .bridge import APIBridge, Bridge, MockHostBridge, StdioBridge
from .challenge import ChallengeSpec, SolveResult
from .runner import run_hosted
from .src_hunter_agent import SRC_HunterAgent

__all__ = [
    "BaseAgent",
    "SRC_HunterAgent",
    "Bridge",
    "APIBridge",
    "StdioBridge",
    "MockHostBridge",
    "ChallengeSpec",
    "SolveResult",
    "run_hosted",
]
