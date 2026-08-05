"""配置中心：LLM（HY3）接入、SAST、流水线参数、分级调用预设。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLMTier:
    """分级调用预设：快慢思考 + 预算。"""

    name: str
    model: str
    reasoning: bool = False       # 是否启用 HY3 思考链
    temperature: float = 0.2
    max_tokens: int = 4096
    note: str = ""


@dataclass
class LLMConfig:
    provider: str = "hy3"                       # hy3 | mock
    api_key: str = field(default_factory=lambda: os.getenv("HY3_API_KEY", ""))
    base_url: str = field(default_factory=lambda: os.getenv("HY3_BASE_URL", "https://tokenhub.tencentmaas.com/v1"))
    timeout: int = 120

    # 分级策略：便宜快模型做初筛/分类，强思考模型做深度审计
    tiers: dict = field(default_factory=lambda: {
        "fast": LLMTier("fast", model="hy3", reasoning=False, temperature=0.2, max_tokens=2048,
                        note="初筛/分类/SAST结果摘要，低成本"),
        "deep": LLMTier("deep", model="hy3", reasoning=True, temperature=0.3, max_tokens=8192,
                        note="深度审计/复杂逻辑/降误报，高成本但仅用于高价值环节"),
    })

    # 成本计量（USD / 1K tokens），HY3 价格便宜，留可配置口子
    price_per_1k_prompt: float = 0.0005
    price_per_1k_completion: float = 0.002


@dataclass
class SASTConfig:
    enabled: bool = True
    engine: str = "semgrep"
    config: str = "p/ci"          # 或 auto / 自定义规则目录
    max_findings: int = 200
    fallback_regex: bool = True   # semgrep 不可用时启用内置正则兜底引擎


@dataclass
class PipelineConfig:
    target: str = ""
    mode: str = "whitebox"        # whitebox（代码审计） | graybox（活靶）
    max_files: int = 200          # 单次审计文件上限（成本控制）
    max_rounds_per_file: int = 4  # 多轮上下文分析轮次上限
    verify_poc: bool = False      # 是否真打（默认演示/脱敏环境才开）
    target_url: Optional[str] = None   # graybox 模式下的被测地址
    budget_usd: float = 5.0       # 单次运行 LLM 成本预算硬上限
    ground_truth: Optional[str] = None  # 已知漏洞清单路径（用于算发现率）


@dataclass
class Settings:
    llm: LLMConfig = field(default_factory=LLMConfig)
    sast: SASTConfig = field(default_factory=SASTConfig)
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Settings":
        s = cls()
        if path and os.path.exists(path):
            import yaml
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            # 简单覆盖，不递归合并
            if "llm" in data:
                for k, v in data["llm"].items():
                    if k == "tiers":
                        continue
                    setattr(s.llm, k, v)
            if "sast" in data:
                for k, v in data["sast"].items():
                    setattr(s.sast, k, v)
            if "pipeline" in data:
                for k, v in data["pipeline"].items():
                    setattr(s.pipeline, k, v)
        return s
