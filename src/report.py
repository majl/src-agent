"""报告生成：Markdown（人读） + JSON（机读） + SARIF（工具链兼容）。"""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding, Metrics, ScanResult, Severity


def to_markdown(result: ScanResult, metrics: Metrics, project: str = "target") -> str:
    lines = []
    lines.append(f"# SRC 漏洞挖掘报告 · {project}\n")
    lines.append(f"- 审计文件数：{result.files_analyzed}")
    lines.append(f"- 审计代码行数：{result.lines_analyzed}")
    lines.append(f"- 发现漏洞数：{len(result.findings)}")
    lines.append(f"- LLM 调用：{result.llm_calls} 次，成本 ${result.llm_cost_usd:.4f}")
    lines.append(f"- 端到端耗时：{result.wall_clock_seconds:.1f}s\n")

    lines.append("## 量化指标对比（Agent vs 传统）\n")
    lines.append("| 指标 | Agent | 传统模式 |")
    lines.append("|------|-------|----------|")
    for row in metrics.to_compare_table():
        lines.append(f"| {row['指标']} | {row['Agent']} | {row['传统']} |")
    lines.append("")

    lines.append("## 漏洞清单\n")
    if not result.findings:
        lines.append("_未发现（或 mock 模式未启用真实 LLM 审计）。_\n")
    for i, f in enumerate(result.findings, 1):
        lines.append(f"### {i}. {f.vuln_type.value} — {f.severity.value.upper()}")
        lines.append(f"- 位置：`{f.file}:{f.line}`（函数：{f.function or '—'}）")
        lines.append(f"- 置信度：{f.confidence} · 来源：{f.source.value} · 已验证：{f.verified}")
        if f.description:
            lines.append(f"- 说明：{f.description}")
        if f.evidence:
            lines.append(f"- 证据：\n```\n{f.evidence[:600]}\n```")
        if f.poc:
            lines.append(f"- PoC：\n```\n{f.poc[:600]}\n```")
        lines.append("")
    return "\n".join(lines)


def to_json(result: ScanResult, metrics: Metrics) -> str:
    return json.dumps({
        "scan": result.model_dump(mode="json"),
        "metrics": metrics.model_dump(mode="json"),
    }, ensure_ascii=False, indent=2)


def to_sarif(result: ScanResult, tool: str = "src-hunter") -> dict:
    rules = {}
    results = []
    for f in result.findings:
        rid = f.rule_id or f"SRCH-{f.vuln_type.value}"
        rules.setdefault(rid, {
            "id": rid,
            "name": f.vuln_type.value,
            "shortDescription": {"text": f.title or f.vuln_type.value},
            "fullDescription": {"text": f.description or ""},
            "helpUri": "",
        })
        results.append({
            "ruleId": rid,
            "level": "error" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
            "message": {"text": f"{f.vuln_type.value}: {f.description}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.file},
                "region": {"startLine": f.line or 1},
            }}],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": tool, "rules": list(rules.values())}},
            "results": results,
        }],
    }


def write_all(result: ScanResult, metrics: Metrics, out_dir: str, project: str = "target"):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.md").write_text(to_markdown(result, metrics, project), encoding="utf-8")
    (out / "report.json").write_text(to_json(result, metrics), encoding="utf-8")
    (out / "report.sarif").write_text(json.dumps(to_sarif(result), ensure_ascii=False, indent=2), encoding="utf-8")
    return out
