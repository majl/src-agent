"""量化指标采集：比赛评审核心的六项指标 + 与传统模式对比。

指标说明：
- discovery_rate    漏洞发现率：命中的已知漏洞 / ground truth 总数
- false_positive_rate 误报率：未被确认的发现占比（有 ground truth 时按真实标注计算）
- audit_volume_loc  代码审计量级：审计的代码行数
- high_severity_find_time_s 单高危漏洞发现时长：总耗时 / 高危数
- llm_cost_usd      大模型运行成本
- human_ratio       人机验证时间比例：人工介入耗时 / 总耗时
baseline_* 为传统人工/工具模式基线（来自团队经验估算或历史数据），用于凸显 AI 增益。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .models import Metrics, ScanResult, Finding, Severity


def _load_ground_truth(path: Optional[str]) -> list[dict]:
    if not path or not Path(path).exists():
        return []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data if isinstance(data, list) else data.get("vulnerabilities", [])
    except Exception:
        return []


class MetricsCollector:
    def __init__(self, baseline: Optional[dict] = None):
        # 代表性格线（传统人工审计，单位与上面一致）；可由配置文件覆盖
        self.baseline = baseline or {
            "discovery_rate": 0.55,
            "false_positive_rate": 0.42,
            "audit_volume_loc": 8000,
            "high_severity_find_time_s": 5400,   # ~1.5h/高危
            "llm_cost_usd": 0.0,
            "human_ratio": 1.0,                    # 纯人工，100% 人工时间
        }

    def compute(self, result: ScanResult, ground_truth_path: Optional[str] = None) -> Metrics:
        gt = _load_ground_truth(ground_truth_path)
        findings = result.findings

        m = Metrics()
        m.audit_volume_loc = result.lines_analyzed
        m.llm_cost_usd = result.llm_cost_usd
        # 人机验证时间比例 = 人工耗时 / (人工耗时 + 自动化耗时)；越低越自动化
        denom = result.human_seconds + result.wall_clock_seconds
        m.human_ratio = (result.human_seconds / denom) if denom > 0 else 0.0

        high_count = sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))
        m.high_severity_find_time_s = (result.wall_clock_seconds / high_count) if high_count else result.wall_clock_seconds

        if gt:
            matched = self._match(findings, gt)
            m.discovery_rate = matched / len(gt) if gt else 0.0
            tp = matched
            fp = max(0, len(findings) - tp)
            m.false_positive_rate = (fp / len(findings)) if findings else 0.0
        else:
            # 无基线标注时，以"置信度<0.7 且未 verified"估计为疑似误报
            suspect = sum(1 for f in findings if f.confidence < 0.7 and not f.verified)
            m.false_positive_rate = (suspect / len(findings)) if findings else 0.0
            m.discovery_rate = 0.0  # 无 ground truth 无法计算，留待人工标注

        # 基线
        m.baseline_discovery_rate = float(self.baseline.get("discovery_rate", 0))
        m.baseline_fp_rate = float(self.baseline.get("false_positive_rate", 0))
        m.baseline_audit_loc = int(self.baseline.get("audit_volume_loc", 0))
        m.baseline_high_find_time_s = float(self.baseline.get("high_severity_find_time_s", 0))
        m.baseline_llm_cost_usd = float(self.baseline.get("llm_cost_usd", 0))
        m.baseline_human_ratio = float(self.baseline.get("human_ratio", 1))
        return m

    @staticmethod
    def _match(findings: list[Finding], gt: list[dict]) -> int:
        gt_set = {(g.get("file", "").split("/")[-1], int(g.get("line", 0) or 0), g.get("vuln_type", "")) for g in gt}
        matched = 0
        for f in findings:
            fn = f.file.split("/")[-1]
            for (gf, gl, gv) in gt_set:
                if fn == gf and abs(f.line - gl) <= 5 and (gv == "" or f.vuln_type.value == gv):
                    matched += 1
                    break
        return matched
