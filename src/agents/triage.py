"""Triage（合并与降误报）Agent。

将 SAST 静态扫描命中与 LLM 审计发现合并、按 (文件, 行, 类型) 去重，
并据"是否双向佐证"调整置信度与最终 verdict——这是压制 SAST 高误报率的关键环节，
也是比赛量化指标"误报率"的优化点。
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import PurePath
from typing import Iterable

from ..models import Finding, FindingSource, Severity

_SEV_RANK = {Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def _key(f: Finding):
    # 行号近似聚合（±5 行视为同处漏洞），避免 SAST 与 LLM 重复计数
    base_line = (f.line // 5) * 5
    return (PurePath(f.file).name, base_line, f.vuln_type.value)


class TriageAgent:
    def __init__(self, drop_llm_below: float = 0.5, drop_sast_below: float = 0.4):
        self.drop_llm_below = drop_llm_below
        self.drop_sast_below = drop_sast_below

    def merge(self, findings: Iterable[Finding]) -> list[Finding]:
        groups: dict[tuple, list[Finding]] = defaultdict(list)
        for f in findings:
            groups[_key(f)].append(f)

        final: list[Finding] = []
        for key, items in groups.items():
            sources = {i.source for i in items}
            base_conf = max(i.confidence for i in items)
            base_sev = max((i.severity for i in items), key=lambda s: _SEV_RANK[s])
            title = next((i.title for i in items if i.title), items[0].title)
            desc = max((i.description for i in items), key=len) if any(i.description for i in items) else ""
            evidence = max((i.evidence for i in items), key=len) if any(i.evidence for i in items) else ""
            line = next((i.line for i in items if i.line), items[0].line)
            file = items[0].file

            if FindingSource.SAST in sources and FindingSource.LLM in sources:
                source = FindingSource.HYBRID
                conf = min(1.0, base_conf + 0.2)
                verdict = "keep"
            elif FindingSource.SAST in sources:
                source = FindingSource.SAST
                conf = base_conf
                verdict = "keep" if conf >= self.drop_sast_below else "drop"
            else:
                source = FindingSource.LLM
                conf = base_conf
                verdict = "keep" if conf >= self.drop_llm_below else "drop"

            if verdict == "drop":
                continue

            merged = items[0].model_copy(deep=True)
            merged.source = source
            merged.confidence = round(conf, 2)
            merged.severity = base_sev
            merged.title = title
            merged.description = desc
            merged.evidence = evidence
            merged.line = line
            merged.file = file
            final.append(merged)

        # 按严重度降序，便于报告
        final.sort(key=lambda f: _SEV_RANK[f.severity], reverse=True)
        return final
