"""核心数据模型：漏洞、扫描结果、量化指标。"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnType(str, Enum):
    SQLI = "SQL注入"
    XSS = "XSS跨站脚本"
    SSRF = "SSRF服务端请求伪造"
    RCE = "远程代码执行"
    IDOR = "越权访问/IDOR"
    AUTH_BYPASS = "认证绕过"
    PATH_TRAVERSAL = "路径遍历"
    XXE = "XXE"
    SENSITIVE_DATA = "敏感信息泄露"
    INSECure_DESERIAL = "不安全反序列化"
    COMMAND_INJECTION = "命令注入"
    LOGIC_FLAW = "业务逻辑缺陷"
    SECRET_LEAK = "硬编码凭据"
    CLOUD_METADATA = "云元数据服务暴露(IMDS)"
    CLOUD_UNAUTH_API = "未授权云API"
    CLOUD_CONTAINER_ESCAPE = "容器逃逸线索"
    # 二进制维度（对应 tsecbench BINARY 评分维度，权重 15%）：pwn / 逆向题自动分析
    BINARY_STACK_OVERFLOW = "二进制栈溢出"
    BINARY_FORMAT_STRING = "格式化字符串漏洞"
    BINARY_DANGEROUS_FUNC = "二进制危险函数调用"
    BINARY_HARDCODED_SECRET = "二进制硬编码凭据/后门"
    # 杀伤链维度（对应 tsecbench KILLCHAIN 评分维度，权重 20%）：把分散漏洞点串成连贯攻击链
    KILLCHAIN_RECON = "杀伤链-侦察发现"
    KILLCHAIN_INITIAL_ACCESS = "杀伤链-初始立足"
    KILLCHAIN_PRIV_ESC = "杀伤链-权限提升"
    KILLCHAIN_LATERAL = "杀伤链-横向移动"
    KILLCHAIN_CRED_ACCESS = "杀伤链-凭据访问"
    KILLCHAIN_COLLECTION = "杀伤链-信息收集"
    KILLCHAIN_IMPACT = "杀伤链-影响/渗出"
    # 规避维度（对应 tsecbench EVASION 评分维度，权重 10%）：防御规避 / 反取证
    EVASION_DEFENSE_DETECTED = "防御机制侦测(规避前置)"
    EVASION_WAF_BYPASS = "WAF/签名规避(编码绕过)"
    EVASION_ANTI_FORENSICS = "反取证/痕迹清除"
    OTHER = "其他"


class FindingSource(str, Enum):
    SAST = "sast"          # 纯静态扫描命中
    LLM = "llm"            # 纯 LLM 审计发现
    HYBRID = "hybrid"      # SAST 命中后经 LLM 确认


class Finding(BaseModel):
    """单条漏洞发现。"""

    id: str = Field(default_factory=lambda: "F-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")[:17])
    vuln_type: VulnType
    severity: Severity
    file: str
    line: int = 0
    function: Optional[str] = None
    title: str = ""
    description: str = ""
    evidence: str = ""          # 关键代码片段
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    poc: Optional[str] = None
    verified: bool = False
    source: FindingSource = FindingSource.LLM
    rule_id: Optional[str] = None   # SAST 规则 ID（如有）
    cwe: Optional[str] = None
    remediation: str = ""
    llm_exploit_hint: Optional[str] = None   # HY3 给出的利用手法/路径建议（黑盒决策）
    killchain_phase: Optional[str] = None    # 该发现所属杀伤链阶段 id（KILLCHAIN 维度）
    chain_order: int = 0                     # 在杀伤链中的顺序（多阶段靶机游走时填充）


class ScanResult(BaseModel):
    """一次扫描的整体结果。"""

    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    files_analyzed: int = 0
    lines_analyzed: int = 0
    findings: list[Finding] = Field(default_factory=list)
    llm_calls: int = 0
    llm_tokens_prompt: int = 0
    llm_tokens_completion: int = 0
    llm_cost_usd: float = 0.0
    human_seconds: float = 0.0       # 人工介入耗时
    wall_clock_seconds: float = 0.0   # 端到端耗时


class Metrics(BaseModel):
    """六项量化指标 + 与基线对比。"""

    discovery_rate: float = 0.0          # 漏洞发现率（命中已知漏洞数 / ground truth）
    false_positive_rate: float = 0.0     # 误报率
    audit_volume_loc: int = 0            # 代码审计量级（行）
    high_severity_find_time_s: float = 0.0  # 单高危漏洞发现时长
    llm_cost_usd: float = 0.0            # 大模型运行成本
    human_ratio: float = 0.0             # 人机验证时间比例（人工/总）

    # 对比传统模式的增益
    baseline_discovery_rate: float = 0.0
    baseline_fp_rate: float = 0.0
    baseline_audit_loc: int = 0
    baseline_high_find_time_s: float = 0.0
    baseline_llm_cost_usd: float = 0.0
    baseline_human_ratio: float = 0.0

    def to_compare_table(self) -> list[dict]:
        return [
            {"指标": "漏洞发现率", "Agent": f"{self.discovery_rate:.1%}", "传统": f"{self.baseline_discovery_rate:.1%}"},
            {"指标": "误报率", "Agent": f"{self.false_positive_rate:.1%}", "传统": f"{self.baseline_fp_rate:.1%}"},
            {"指标": "代码审计量级(行)", "Agent": self.audit_volume_loc, "传统": self.baseline_audit_loc},
            {"指标": "单高危发现时长(s)", "Agent": round(self.high_severity_find_time_s, 1), "传统": round(self.baseline_high_find_time_s, 1)},
            {"指标": "大模型成本($)", "Agent": round(self.llm_cost_usd, 3), "传统": round(self.baseline_llm_cost_usd, 3)},
            {"指标": "人机验证时间比", "Agent": f"{self.human_ratio:.1%}", "传统": f"{self.baseline_human_ratio:.1%}"},
        ]
