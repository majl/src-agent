"""编排器：把 SAST → LLM 审计 → Triage → Verify → Metrics 串成全链路自动化。

设计目标：单条命令跑完一个目标，输出结构化结果 + 量化指标，尽量零人工介入
（从而降低量化指标中的"人机验证时间比例"）。
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from .config import Settings
from .llm.client import HY3Client
from .models import Finding, ScanResult
from .tools.sast import SemgrepRunner
from .tools.context import ContextExtractor
from .agents.audit import AuditAgent
from .agents.triage import TriageAgent
from .agents.verify import VerifyAgent
from .metrics import MetricsCollector


class Orchestrator:
    def __init__(self, settings: Settings, human_overhead_s: float = 30.0):
        self.s = settings
        self.client = HY3Client(settings.llm)
        self.sast = SemgrepRunner(settings.sast)
        self.ctx = ContextExtractor(settings.pipeline.target)
        self.audit = AuditAgent(self.client, self.ctx, max_rounds=settings.pipeline.max_rounds_per_file)
        self.triage = TriageAgent()
        self.verify = VerifyAgent(settings.pipeline.verify_poc, settings.pipeline.target_url)
        self.metrics = MetricsCollector()
        self.human_overhead_s = human_overhead_s

    def _collect_files(self, target: str) -> list[str]:
        p = Path(target)
        if p.is_file():
            return [str(p)]
        exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".php", ".rb", ".cs"}
        files = [str(f) for f in p.rglob("*") if f.is_file() and f.suffix.lower() in exts]
        return files[: self.s.pipeline.max_files]

    def run(self, target: Optional[str] = None) -> tuple[ScanResult, object]:
        target = target or self.s.pipeline.target
        self.ctx = ContextExtractor(target)
        self.audit.ctx = self.ctx

        result = ScanResult(target=target)
        t0 = time.time()

        # 1) SAST
        sast_findings, warnings = self.sast.scan(target)
        for w in warnings:
            print(f"[sast] {w}")
        result.findings.extend(sast_findings)

        # 2) LLM 审计（仅白盒代码模式；活靶模式此处替换为侦察+扫描）
        files = self._collect_files(target)
        result.files_analyzed = len(files)
        result.lines_analyzed = sum(self._count_lines(f) for f in files)

        if self.client.mode != "mock":  # 真实 HY3 才逐文件审计，省成本
            for f in files:
                llm = self.audit.audit_file(f, project=Path(target).name)
                result.findings.extend(llm)
                # 预算硬上限保护
                if self.client.meter.cost_usd >= self.s.pipeline.budget_usd:
                    print(f"[budget] 已达成本预算 ${self.s.pipeline.budget_usd}，停止 LLM 审计。")
                    break
        else:
            print("[audit] mock 模式跳过真实 LLM 审计（请配置 HY3_API_KEY）。")

        # 3) Triage 合并降误报
        final = self.triage.merge(result.findings)
        result.findings = final

        # 4) Verify / PoC
        result.findings = self.verify.run(final)

        # 5) 计量 & 指标
        usage = self.client.meter.snapshot()
        result.llm_calls = usage["calls"]
        result.llm_tokens_prompt = usage["prompt_tokens"]
        result.llm_tokens_completion = usage["completion_tokens"]
        result.llm_cost_usd = usage["cost_usd"]
        result.wall_clock_seconds = time.time() - t0
        result.human_seconds = self.human_overhead_s  # 仅初始化等非审计人工

        metrics = self.metrics.compute(result, self.s.pipeline.ground_truth)
        return result, metrics

    @staticmethod
    def _count_lines(path: str) -> int:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
