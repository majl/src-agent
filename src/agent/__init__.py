"""SRC-Hunter 标准 Agent 包：对齐 tsecbench 三种接入形态的封装。

对外暴露：
- ``BaseAgent`` / ``SRC_HunterAgent``：SDK 接入核心解题器（实现 solve）。
- ``Bridge`` / ``APIBridge`` / ``StdioBridge`` / ``HostChannel`` / ``HostHarness``：
  平台交互桥与托管运行通道（对齐官方 Host Bridge 协议）。
- ``ChallengeSpec`` / ``SolveResult``：标准数据契约。
- ``run_hosted``：托管运行主循环。
- ``hosted_solver``：托管 Solver 子进程入口（平台以子进程方式运行）。
"""
from .base import BaseAgent
from .bridge import (
    APIBridge,
    Bridge,
    HostChannel,
    HostHarness,
    MockHostBridge,
    StdioBridge,
)
from .challenge import ChallengeSpec, SolveResult
from .runner import run_hosted
from .src_hunter_agent import SRC_HunterAgent

__all__ = [
    "BaseAgent",
    "SRC_HunterAgent",
    "Bridge",
    "APIBridge",
    "StdioBridge",
    "HostChannel",
    "HostHarness",
    "MockHostBridge",
    "ChallengeSpec",
    "SolveResult",
    "run_hosted",
    "hosted_solver",
]
