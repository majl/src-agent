"""tsecbench 平台标准题目与解题结果数据结构。

字段尽量对齐 tsecbench ``/openapi/v1/challenges`` 返回结构与 Host Bridge 协议
（challenge_get_state 返回的元数据），保证 agent 在「SDK 接入」与「API 接入」
两种形态下使用同一份数据契约。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ChallengeSpec:
    """平台下发给 Solver 的题目规格（标准输入契约）。

    平台「托管运行」时由 Host Bridge 的 ``challenge_get_state`` 返回；
    「API 接入」时由客户端 ``start`` 后拼装。两者归一为同一结构。
    """

    unique_code: str
    description: str = ""
    difficulty: str = ""           # easy / medium / hard
    level: int = 0
    total_score: int = 0
    flag_count: int = 0            # 题目含 flag 数量（多 flag 题需全部提交）
    correct_flag_count: int = 0
    is_completed: bool = False
    container_addr: list[str] = field(default_factory=list)  # 靶机入口地址列表
    hint: Optional[str] = None

    @property
    def target_url(self) -> str:
        """默认入口地址（靶机根 URL）。多入口时取第一个。"""
        for addr in self.container_addr:
            return addr
        return ""

    def to_dict(self) -> dict:
        return {
            "unique_code": self.unique_code,
            "description": self.description,
            "difficulty": self.difficulty,
            "level": self.level,
            "total_score": self.total_score,
            "flag_count": self.flag_count,
            "correct_flag_count": self.correct_flag_count,
            "is_completed": self.is_completed,
            "container_addr": self.container_addr,
            "hint": self.hint,
        }


@dataclass
class SolveResult:
    """Solver（解题器）的标准输出契约：返回所有发现的 flag 候选。

    是否真正得分由平台裁定（通过 bridge 的 submit_flag 返回 correct）。
    """

    flags: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    success: bool = False
    log: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    llm_calls: int = 0
    llm_cost_usd: float = 0.0

    def to_dict(self) -> dict:
        return {
            "flags": self.flags,
            "findings": self.findings,
            "success": self.success,
            "log": self.log,
            "duration_s": self.duration_s,
            "llm_calls": self.llm_calls,
            "llm_cost_usd": self.llm_cost_usd,
        }
