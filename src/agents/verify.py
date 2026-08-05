"""Verify（PoC 生成与验证）Agent。

对高置信度/高危发现自动生成 PoC；仅在显式开启 verify_poc 且提供 target_url 时真打，
否则仅产出 PoC 文本（安全默认，符合脱敏与合规要求）。
"""
from __future__ import annotations

from typing import Optional

from ..models import Finding
from ..tools.poc import build_poc, verify as poc_verify


class VerifyAgent:
    def __init__(self, verify_enabled: bool = False, target_url: Optional[str] = None):
        self.verify_enabled = verify_enabled
        self.target_url = target_url

    def run(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            if f.confidence < 0.5 and f.severity not in (f.severity.CRITICAL, f.severity.HIGH):
                continue
            f.poc = build_poc(f, self.target_url)
            f.verified = poc_verify(f, self.target_url, self.verify_enabled)
        return findings
