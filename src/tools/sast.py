"""SAST 工具封装：以 Semgrep 为核心静态扫描引擎。

职责：调用 semgrep CLI（或二进制），解析 JSON 输出，归一化为 Finding 列表。
无 semgrep 环境时优雅降级（返回空结果 + 告警），保证流水线不中断。
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ..config import SASTConfig
from ..models import Finding, FindingSource, Severity, VulnType


_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# rule_id 关键词 → VulnType（粗粒度，LLM 会再精细化）
_TYPE_HINTS = [
    ("sqli", VulnType.SQLI), ("sql-injection", VulnType.SQLI),
    ("xss", VulnType.XSS),
    ("ssrf", VulnType.SSRF),
    ("rce", VulnType.RCE), ("command-injection", VulnType.COMMAND_INJECTION),
    ("code-injection", VulnType.RCE), ("eval", VulnType.RCE),
    ("idor", VulnType.IDOR), ("auth", VulnType.AUTH_BYPASS), ("auth-bypass", VulnType.AUTH_BYPASS),
    ("path-traversal", VulnType.PATH_TRAVERSAL), ("traversal", VulnType.PATH_TRAVERSAL),
    ("xxe", VulnType.XXE),
    ("deserial", VulnType.INSECure_DESERIAL),
    ("secret", VulnType.SECRET_LEAK), ("credentials", VulnType.SECRET_LEAK),
    ("hardcoded", VulnType.SECRET_LEAK),
    ("insecure", VulnType.INSECure_DESERIAL),
    ("sensitive", VulnType.SENSITIVE_DATA),
]

# 正则兜底规则（semgrep 不可用时）： (漏洞类型, 严重度, 正则)
_REGEX_RULES = [
    (VulnType.SQLI, Severity.HIGH, re.compile(r"(execute|raw)\s*\([^)]*(\+|\%|\.format|f[\"'])", re.I)),
    (VulnType.XSS, Severity.MEDIUM, re.compile(r"render_template_string\s*\([^)]*\+", re.I)),
    (VulnType.SSRF, Severity.HIGH, re.compile(r"requests\.(get|post|put|delete)\s*\(", re.I)),
    (VulnType.COMMAND_INJECTION, Severity.HIGH, re.compile(r"(os\.system|subprocess\.[A-Za-z]+\(|eval\(|exec\()\s*\([^)]*(\+|\%|\.format|f[\"'])", re.I)),
    (VulnType.SECRET_LEAK, Severity.MEDIUM, re.compile(r"(password|api_key|secret|token|pwd|ak|sk)\s*=\s*[\"'][^\"'\n]{4,}[\"']", re.I)),
    (VulnType.IDOR, Severity.HIGH, re.compile(r"(execute|raw)\s*\([^)]*id\s*=\s*[\"']?\s*\+", re.I)),
]


def _guess_type(check_id: str, message: str) -> VulnType:
    blob = (check_id + " " + message).lower()
    for kw, vt in _TYPE_HINTS:
        if kw in blob:
            return vt
    return VulnType.OTHER


class SemgrepRunner:
    def __init__(self, cfg: SASTConfig):
        self.cfg = cfg
        self.bin = shutil.which("semgrep") or shutil.which("semgrep-cli")

    def available(self) -> bool:
        return self.bin is not None

    def scan(self, target: str) -> tuple[list[Finding], list[str]]:
        warnings: list[str] = []
        if not self.cfg.enabled:
            return [], warnings
        if self.available():
            return self._scan_semgrep(target)
        if self.cfg.fallback_regex:
            warnings.append("semgrep 未安装，启用内置正则兜底引擎（建议 brew install semgrep 获得更全覆盖）。")
            return self._scan_regex(target), warnings
        warnings.append("semgrep 未安装且未启用兜底，跳过 SAST（仅 LLM 审计模式）。")
        return [], warnings

    def _scan_regex(self, target: str) -> list[Finding]:
        """轻量正则 SAST：semgrep 不可用时的兜底，覆盖常见注入/XSS/SSRF/命令/硬编码。"""
        exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".php", ".rb", ".cs"}
        root = Path(target)
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in exts]
        findings: list[Finding] = []
        used = 0
        for f in files:
            try:
                lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines, 1):
                if used >= self.cfg.max_findings:
                    return findings
                for vt, sev, pat in _REGEX_RULES:
                    if pat.search(line):
                        findings.append(Finding(
                            vuln_type=vt, severity=sev, file=str(f), line=i,
                            title=f"regex:{vt.value}", description=f"正则命中：{line.strip()[:120]}",
                            evidence=line.strip(), confidence=0.55, source=FindingSource.SAST,
                        ))
                        used += 1
                        break
        return findings

    def _scan_semgrep(self, target: str) -> tuple[list[Finding], list[str]]:
        warnings: list[str] = []
        cmd = [
            self.bin, "--config", self.cfg.config,
            "--json", "--metrics", "off", "--quiet", target,
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            warnings.append("semgrep 扫描超时。")
            return [], warnings
        except Exception as e:  # noqa
            warnings.append(f"semgrep 执行异常：{e}")
            return [], warnings

        if not proc.stdout.strip():
            return [], warnings

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            warnings.append("semgrep 输出非 JSON，已忽略。")
            return [], warnings

        findings: list[Finding] = []
        for r in data.get("results", [])[: self.cfg.max_findings]:
            extra = r.get("extra", {})
            sev_raw = str(extra.get("severity", "INFO")).upper()
            severity = _SEVERITY_MAP.get(sev_raw, Severity.MEDIUM)
            check_id = r.get("check_id", "unknown")
            message = extra.get("message", "")
            vt = _guess_type(check_id, message)
            findings.append(Finding(
                vuln_type=vt,
                severity=severity,
                file=r.get("path", target),
                line=r.get("start", {}).get("line", 0),
                title=check_id,
                description=message,
                evidence=(extra.get("lines") or "").strip(),
                confidence=0.6,  # SAST 命中需 LLM 确认，初值中等
                source=FindingSource.SAST,
                rule_id=check_id,
                cwe=extra.get("metadata", {}).get("cwe"),
            ))
        return findings, warnings
