"""攻击杀伤链（Kill Chain）分析模块（对应 tsecbench KILLCHAIN 评分维度，权重 20%）。

KILLCHAIN 维度衡量 Agent 能否把"分散的孤立漏洞点"串成一条**连贯、可递进、抵达目标**
的多阶段攻击链，而非只会单点爆破。典型阶段（对齐 Lockheed Martin + MITRE ATT&CK）：

    0 侦察(recon) → 1 初始立足(initial_access) → 2 执行(execution) →
    3 权限提升(priv_esc) → 4 横向移动(lateral) → 5 凭据访问(cred_access) →
    6 信息收集(collection) → 7 影响/渗出(impact)

本模块提供两类能力：
  1) 通用杀伤链合成 ``build_killchain``：把一次解题产生的所有 Finding 映射到阶段、
     排序、计算"阶段覆盖率 / 抵达影响阶段 / 链深度"，并产出可追责的攻击叙事
     （可被 HY3 决策点⑤进一步润色）。该能力对 WEB/CLOUD/BINARY 的发现同样适用——
     例如一个 RCE 发现会被归入 execution 阶段。
  2) 多阶段靶机游走器 ``scan_killchain_stage``：针对 mock 靶场的"三跳链"
     （entry 侦察 → internal 凭据 → flag 影响）自动推进并产出带 chain_order 的
     Finding，使 KILLCHAIN 维度可在本地离线跑通完整闭环。

接入：redteam.solve_target 在侦察/扫描后调用 scan_killchain_stage，并在利用结束后
调用 build_killchain 生成 killchain 报告并入结果；LLM 决策点⑤负责把报告润色为
连贯叙事（无 HY3 时退化为启发式叙事）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from ..models import Finding, FindingSource, Severity, VulnType
from .recon import http_get
from .exploit import extract_flag


# ============================================================================
# 1. 标准杀伤链阶段 taxonomy
# ============================================================================
@dataclass
class _Phase:
    idx: int
    pid: str          # 阶段 id
    name: str         # 中文名
    en: str           # 英文名


KILLCHAIN_PHASES: list[_Phase] = [
    _Phase(0, "recon", "侦察", "Reconnaissance"),
    _Phase(1, "initial_access", "初始立足", "Initial Access"),
    _Phase(2, "execution", "执行", "Execution"),
    _Phase(3, "priv_esc", "权限提升", "Privilege Escalation"),
    _Phase(4, "lateral", "横向移动", "Lateral Movement"),
    _Phase(5, "cred_access", "凭据访问", "Credential Access"),
    _Phase(6, "collection", "信息收集", "Collection"),
    _Phase(7, "impact", "影响/渗出", "Impact / Exfiltration"),
]
_PHASE_BY_ID = {p.pid: p for p in KILLCHAIN_PHASES}
_PHASE_BY_IDX = {p.idx: p for p in KILLCHAIN_PHASES}
TOTAL_PHASES = len(KILLCHAIN_PHASES)


# 漏洞类型 → 杀伤链阶段（单主阶段，用于排序；多种类型可指向同一阶段）
_VULN_TO_PHASE: dict[VulnType, str] = {
    VulnType.SSRF: "lateral",
    VulnType.IDOR: "initial_access",
    VulnType.AUTH_BYPASS: "initial_access",
    VulnType.SENSITIVE_DATA: "collection",
    VulnType.SECRET_LEAK: "cred_access",
    VulnType.COMMAND_INJECTION: "execution",
    VulnType.RCE: "execution",
    VulnType.SQLI: "execution",
    VulnType.XSS: "execution",
    VulnType.PATH_TRAVERSAL: "collection",
    VulnType.XXE: "execution",
    VulnType.INSECure_DESERIAL: "execution",
    VulnType.LOGIC_FLAW: "initial_access",
    VulnType.CLOUD_METADATA: "cred_access",
    VulnType.CLOUD_UNAUTH_API: "initial_access",
    VulnType.CLOUD_CONTAINER_ESCAPE: "priv_esc",
    VulnType.BINARY_STACK_OVERFLOW: "execution",
    VulnType.BINARY_FORMAT_STRING: "execution",
    VulnType.BINARY_DANGEROUS_FUNC: "execution",
    VulnType.BINARY_HARDCODED_SECRET: "cred_access",
    # 杀伤链显式阶段类型
    VulnType.KILLCHAIN_RECON: "recon",
    VulnType.KILLCHAIN_INITIAL_ACCESS: "initial_access",
    VulnType.KILLCHAIN_PRIV_ESC: "priv_esc",
    VulnType.KILLCHAIN_LATERAL: "lateral",
    VulnType.KILLCHAIN_CRED_ACCESS: "cred_access",
    VulnType.KILLCHAIN_COLLECTION: "collection",
    VulnType.KILLCHAIN_IMPACT: "impact",
}


def phase_of(vt: VulnType) -> str:
    """返回漏洞类型对应的杀伤链阶段 id（未知 → 'execution' 兜底）。"""
    return _VULN_TO_PHASE.get(vt, "execution")


# ============================================================================
# 2. 杀伤链报告数据结构
# ============================================================================
@dataclass
class KillChainStep:
    phase_idx: int
    phase_id: str
    phase_name: str
    vuln_type: str
    finding_id: str
    action: str          # 该步的攻击动作描述
    evidence: str
    order: int = 0       # chain_order（多阶段靶机）；单点发现为 0


@dataclass
class KillChainReport:
    steps: list[KillChainStep] = field(default_factory=list)
    phases_covered: int = 0
    coverage_ratio: float = 0.0       # phases_covered / TOTAL_PHASES
    deepest_phase_idx: int = -1
    deepest_phase_name: str = ""
    reached_impact: bool = False       # 是否抵达"影响/渗出"阶段（KILLCHAIN 维度的关键正信号）
    narrative: str = ""                # 连贯攻击叙事（启发式或 LLM 润色）
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "steps": [s.__dict__ for s in self.steps],
            "phases_covered": self.phases_covered,
            "coverage_ratio": round(self.coverage_ratio, 3),
            "deepest_phase_idx": self.deepest_phase_idx,
            "deepest_phase_name": self.deepest_phase_name,
            "reached_impact": self.reached_impact,
            "narrative": self.narrative,
            "flags": self.flags,
        }


# ============================================================================
# 3. 通用杀伤链合成（对一次解题的全部发现生效）
# ============================================================================
def build_killchain(
    findings: list[Finding],
    flags: Optional[list[str]] = None,
    narrative: str = "",
) -> KillChainReport:
    """把发现映射到杀伤链阶段、排序、计算覆盖率与链深度，产出报告。

    findings 中的每条会被赋予 ``killchain_phase``（副作用，供上层复用）。
    narrative 由调用方（或 HY3 决策点⑤）提供；为空则生成启发式叙事。
    """
    flags = flags or []
    steps: list[KillChainStep] = []
    for f in findings:
        pid = phase_of(f.vuln_type)
        f.killchain_phase = pid
        ph = _PHASE_BY_ID.get(pid, _PHASE_BY_IDX[2])
        steps.append(KillChainStep(
            phase_idx=ph.idx, phase_id=ph.pid, phase_name=ph.name,
            vuln_type=f.vuln_type.value, finding_id=f.id,
            action=_action_verb(f.vuln_type, pid),
            evidence=(f.evidence or f.title)[:160],
            order=getattr(f, "chain_order", 0) or 0,
        ))

    # 排序：先按 chain_order（多阶段链显式顺序），再按阶段 idx，最后 severity
    _SEV = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4}
    steps.sort(key=lambda s: (s.order != 0, s.order, s.phase_idx, _SEV.get(_sev_of(findings, s.finding_id), 4)))

    covered = sorted({s.phase_id for s in steps}, key=lambda p: _PHASE_BY_ID[p].idx)
    deepest = max((_PHASE_BY_ID[p].idx for p in covered), default=-1)
    reached_impact = "impact" in covered
    rep = KillChainReport(
        steps=steps,
        phases_covered=len(covered),
        coverage_ratio=round(len(covered) / TOTAL_PHASES, 3),
        deepest_phase_idx=deepest,
        deepest_phase_name=_PHASE_BY_IDX[deepest].name if deepest >= 0 else "",
        reached_impact=reached_impact,
        flags=flags,
    )
    rep.narrative = narrative or _heuristic_narrative(rep)
    return rep


def _sev_of(findings: list[Finding], fid: str) -> Optional[Severity]:
    for f in findings:
        if f.id == fid:
            return f.severity
    return None


def _action_verb(vt: VulnType, pid: str) -> str:
    return {
        "recon": "侦察并发现攻击面/入口",
        "initial_access": "利用入口获取初始立足点",
        "execution": "执行代码/命令取得运行期控制",
        "priv_esc": "利用配置/漏洞提升权限",
        "lateral": "借助可达内部服务横向移动",
        "cred_access": "窃取凭据/临时凭证",
        "collection": "收集敏感文件/数据",
        "impact": "达成影响（渗出 flag / 控制目标）",
    }.get(pid, "实施攻击动作")


def _heuristic_narrative(rep: KillChainReport) -> str:
    if not rep.steps:
        return "未构造出有效杀伤链（无可用发现）。"
    parts = []
    for s in rep.steps:
        parts.append(f"[{s.phase_name}] {s.action}（{s.vuln_type}）")
    tail = ""
    if rep.reached_impact:
        tail = " → 已抵达影响/渗出阶段，杀伤链闭环成立。"
    else:
        tail = f" → 当前最深处为「{rep.deepest_phase_name}」，尚未抵达影响阶段。"
    return "攻击杀伤链：" + " → ".join(parts) + tail


# ============================================================================
# 4. 多阶段靶机游走器（mock 三跳链：entry→internal→flag）
# ============================================================================
_FLAG_RE = re.compile(r"flag\{[^}]+\}", re.I)


def scan_killchain_stage(target_url: str) -> list[Finding]:
    """针对实现了三跳链的靶机自动推进，产出带 chain_order 的 Finding。

    端点约定（base_url 已是靶机根，如 http://x:port/range）：
      · GET /kc/entry    → 暴露内部端点线索（侦察阶段）
      · GET /kc/internal → 泄露服务凭据/令牌（凭据访问阶段）
      · GET /kc/flag     → 返回最终 flag（影响/渗出阶段）
    若靶机未实现该链（纯 Web 题等），返回空列表，不影响其他维度。
    """
    if not target_url:
        return []
    base = target_url.rstrip("/")
    findings: list[Finding] = []

    # 阶段 1：侦察 entry
    st1, h1, b1 = http_get(base + "/kc/entry", timeout=10)
    entry_note = ""
    if st1 == 200 and b1:
        entry_note = b1[:200]
        findings.append(Finding(
            vuln_type=VulnType.KILLCHAIN_RECON, severity=Severity.INFO,
            file=base + "/kc/entry", title="杀伤链-侦察发现内部入口",
            description="靶机暴露内部服务入口线索，可作为多阶段攻击链的侦察起点。",
            evidence="entry response: " + entry_note,
            confidence=0.8, source=FindingSource.LLM, chain_order=1,
            remediation="收敛内部接口暴露面，避免向未授权客户端泄露内部拓扑。",
        ))

    # 阶段 2：凭据访问 internal
    st2, h2, b2 = http_get(base + "/kc/internal", timeout=10)
    token = ""
    if st2 == 200 and b2:
        m = re.search(r"(token|secret|ak|sk)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./]{6,})", b2, re.I)
        token = m.group(2) if m else ""
        findings.append(Finding(
            vuln_type=VulnType.KILLCHAIN_CRED_ACCESS, severity=Severity.HIGH,
            file=base + "/kc/internal", title="杀伤链-凭据访问（泄露服务令牌）",
            description="通过已发现入口提取到内部服务凭据/令牌，可用于推进至影响阶段。",
            evidence="internal response: " + (b2[:200]),
            confidence=0.85, source=FindingSource.LLM, chain_order=2,
            remediation="服务令牌应经鉴权下发、设置短期有效期与最小权限；禁止未授权读取。",
        ))

    # 阶段 3：影响 flag（靶机直出 flag，链叙事体现前置依赖）
    st3, h3, b3 = http_get(base + "/kc/flag", timeout=10)
    flag = extract_flag(b3) if st3 == 200 and b3 else None
    if flag:
        findings.append(Finding(
            vuln_type=VulnType.KILLCHAIN_IMPACT, severity=Severity.CRITICAL,
            file=base + "/kc/flag", title="杀伤链-影响/渗出（取得最终 flag）",
            description="沿杀伤链推进至影响阶段，提取到目标 flag，杀伤链闭环成立。",
            evidence="flag=" + flag,
            confidence=0.95, source=FindingSource.LLM, chain_order=3,
            poc=base + "/kc/flag",
            remediation="在影响阶段前设置多道防线（分段鉴权、行为审计、敏感操作二次确认）。",
        ))
    return findings
