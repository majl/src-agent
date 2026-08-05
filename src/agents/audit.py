"""审计 Agent：对单文件做"初筛 → 请求上下文 → 多轮深挖"的 LLM 审计。

核心：模拟安全专家的思维——先粗筛可疑点，再按需补齐跨文件上下文，最后类型化确认。
借鉴 vulnhuntr 的两段式（initial + secondary with context），并做去重合并。
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

from ..llm.client import HY3Client
from ..llm.prompts import SYSTEM_AUDITOR, INITIAL_USER, CONTEXT_USER
from ..models import Finding, FindingSource, Severity, VulnType
from ..tools.context import ContextExtractor

_SEV_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
            "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
_VT_MAP = {v.value: v for v in VulnType}


def parse_json_block(text: str) -> Optional[dict]:
    """从 LLM 返回中稳健地抽取首个 JSON 对象。"""
    if not text:
        return None
    # 去 ```json 围栏
    cleaned = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    # 截取到最后一个 } 的合法对象
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", cleaned, flags=re.S)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _to_finding(item: dict, file_path: str, source: FindingSource) -> Optional[Finding]:
    vt_raw = str(item.get("vuln_type", "其他"))
    vt = _VT_MAP.get(vt_raw, VulnType.OTHER)
    if vt == VulnType.OTHER and vt_raw:
        # 允许英文/别名
        for k, v in _VT_MAP.items():
            if vt_raw.lower() in k.lower() or k in vt_raw:
                vt = v
                break
    sev = _SEV_MAP.get(str(item.get("severity", "medium")).lower(), Severity.MEDIUM)
    return Finding(
        vuln_type=vt,
        severity=sev,
        file=file_path,
        line=int(item.get("line", 0) or 0),
        function=item.get("function"),
        title=item.get("title") or vt.value,
        description=item.get("description", ""),
        evidence=item.get("evidence", ""),
        confidence=float(item.get("confidence", 0.5) or 0.5),
        source=source,
    )


class AuditAgent:
    def __init__(self, client: HY3Client, ctx: ContextExtractor, max_rounds: int = 4):
        self.client = client
        self.ctx = ctx
        self.max_rounds = max_rounds

    def audit_file(self, file_path: str, project: str = "target") -> list[Finding]:
        path = Path(file_path)
        try:
            code = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        messages = [
            {"role": "system", "content": SYSTEM_AUDITOR},
            {"role": "user", "content": INITIAL_USER.format(project=project, code=code[:12000])},
        ]

        collected: list[Finding] = []
        seen = set()
        for _ in range(self.max_rounds):
            resp = self.client.chat(messages, tier="deep")
            data = parse_json_block(resp.content)
            if data:
                for item in data.get("findings", []):
                    f = _to_finding(item, file_path, FindingSource.LLM)
                    key = (f.file, f.line, f.vuln_type.value)
                    if key not in seen:
                        seen.add(key)
                        collected.append(f)
            needs = bool(data.get("needs_context")) if data else False
            symbols = data.get("context_symbols", []) if data else []
            if not needs or not symbols:
                break
            blocks = []
            for s in symbols[:8]:
                snip = self.ctx.extract_symbol(s)
                if snip:
                    blocks.append(f"# 符号 {s}\n{snip}")
            if not blocks:
                break
            messages.append({"role": "assistant", "content": resp.content})
            messages.append({"role": "user", "content": CONTEXT_USER.format(
                context_block="\n\n".join(blocks), code=code[:12000])})
        return collected
