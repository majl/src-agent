"""SRC-Hunter 标准解题器：实现 tsecbench SDK 接入的核心 solve 流程。

职责边界（对齐平台托管范式）：
- 只解题、收集 flag 候选，**不**自行调用平台提交接口；
- 提交交由上层 bridge（APIBridge / StdioBridge）→ 宿主代理转发竞赛 API。
"""
from __future__ import annotations

from typing import Optional

from ..agents.redteam import RedTeamAgent
from ..llm.client import HY3Client
from .base import BaseAgent
from .challenge import ChallengeSpec, SolveResult


class SRC_HunterAgent(BaseAgent):
    """黑盒自主渗透解题器，HY3 驱动三决策点（资产排序/利用规划/flag 判定）+ 杀伤链叙事合成。

    覆盖 tsecbench 六大维度中的 WEB / EXPLOIT / CLOUD / BINARY / KILLCHAIN 五维：
    侦察 → Web 漏洞扫描 → 云维度检测 → 二进制检测 → 杀伤链多阶段游走 → 优先级排序 →
    按序 PoC 真实利用提取 flag → 返回全部候选（由 bridge 提交）。
    """

    name = "SRC-Hunter"
    version = "1.0.0"
    author = "BSRC-Agent+ Challenge Team"
    description = (
        "自动化红队渗透 Agent：HY3 驱动决策，覆盖 WEB/EXPLOIT/CLOUD/BINARY/KILLCHAIN 维度，"
        "纯 Python 工具链 + 分级 LLM 调用 + 成本护栏。"
    )

    def __init__(
        self,
        llm: Optional[HY3Client] = None,
        use_llm: Optional[bool] = None,
        budget_usd: float = 5.0,
    ):
        self.llm = llm
        self.use_llm = use_llm
        self.budget_usd = budget_usd
        # RedTeamAgent 不持有平台 client：解题阶段不提交，提交交给 bridge
        self._rt = RedTeamAgent(
            client=None, llm=llm, use_llm=use_llm, budget_usd=budget_usd
        )

    def solve(self, challenge: ChallengeSpec) -> SolveResult:
        target_url = challenge.target_url
        if not target_url:
            return SolveResult(
                success=False,
                log=["[错误] 题目未提供可用入口地址 container_addr"],
            )

        raw = self._rt.solve_target(
            target_url=target_url,
            unique_code=challenge.unique_code,
            break_on_flag=False,   # 多 flag 题：遍历所有发现，收集全部候选
            submit=False,          # 关键：不自行提交，交给 bridge
        )

        flags = raw.get("flags_all") or []
        if raw.get("flag") and raw["flag"] not in flags:
            flags.append(raw["flag"])
        # 二次兜底：从 findings 的 evidence 里再扫一遍 flag 字面量
        import re
        for fd in raw.get("findings_detail", []):
            ev = (fd.get("evidence") or "") + (fd.get("llm_exploit_hint") or "")
            for m in re.findall(r"flag\{[^}]+\}", ev):
                if m not in flags:
                    flags.append(m)

        return SolveResult(
            flags=flags,
            findings=raw.get("findings_detail", []),
            success=bool(flags),
            log=raw.get("log", []),
            duration_s=raw.get("elapsed_s", 0.0),
            llm_calls=raw.get("llm_calls", 0),
            llm_cost_usd=raw.get("llm_cost_usd", 0.0),
        )
