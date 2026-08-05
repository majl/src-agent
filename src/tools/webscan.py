"""Web 漏洞扫描模块。

- 纯 Python 自实现常见 Web 漏洞检测：敏感信息/flag 未授权访问、命令注入、
  SQL 注入（报错型）、反射型 XSS。
- 可选封装 nuclei（若环境中已安装，自动启用，补充 CVE/暴露面模板）。
- 输出标准化 ``Finding``，与白盒 SAST 结果共用同一数据模型。
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Optional

from ..models import Finding, FindingSource, Severity, VulnType
from .recon import Asset, http_get, http_post

FLAG_RE = re.compile(r"flag\{[^}]+\}", re.I)
SENSITIVE_KW = ["password", "secret", "api_key", "apikey", "token", "private_key", "aws_access_key"]

# 疑似命令注入端点
INJECT_PATHS = ["/cmd", "/exec", "/shell", "/run", "/ping", "/api/cmd", "/api/exec", "/cgi-bin/test"]
CMD_PAYLOADS = [";id", "|id", "$(id)", ";cat /flag", "|cat flag.txt", ";cat flag.txt"]
CMD_HIT = ["uid=", "root:", "flag{"]

# 疑似 SQLi 登录/查询端点
SQLI_PATHS = ["/login", "/user/login", "/api/login", "/search", "/api/search", "/product"]
SQLI_PAYLOADS = ["' OR '1'='1", "admin'--", "' UNION SELECT 1,2,3--"]
SQLI_HIT = ["sql syntax", "mysql_fetch", "ora-01756", "unclosed quotation", "sqlite_error"]

# 疑似 XSS 端点（带参数反射）
XSS_PATHS = ["/search", "/s", "/q", "/api/search"]
XSS_PAYLOAD = "<script>srcHunterXss</script>"
XSS_HIT = "srcHunterXss"


def _detect_sensitive(asset: Asset) -> Optional[Finding]:
    st, h, b = http_get(asset.url, timeout=8)
    if not st:
        return None
    m = FLAG_RE.search(b)
    if m:
        return Finding(
            vuln_type=VulnType.SENSITIVE_DATA,
            severity=Severity.HIGH,
            file=asset.url,
            title="敏感信息/flag 未授权访问",
            description=f"路径 {asset.url} 直接返回 flag 内容，疑似未授权访问或敏感接口暴露。",
            evidence=f"flag={m.group(0)}",
            confidence=0.95,
            source=FindingSource.LLM,
            poc=f"GET {asset.url}",
        )
    low = b.lower()
    for kw in SENSITIVE_KW:
        if kw in low and asset.status == 200:
            return Finding(
                vuln_type=VulnType.SENSITIVE_DATA,
                severity=Severity.MEDIUM,
                file=asset.url,
                title=f"疑似敏感信息泄露（{kw}）",
                description=f"路径 {asset.url} 响应中包含关键字 {kw}。",
                confidence=0.6,
                source=FindingSource.LLM,
                poc=f"GET {asset.url}",
            )
    return None


def _probe_cmd_injection(base: str) -> list[Finding]:
    out: list[Finding] = []
    for p in INJECT_PATHS:
        u = base.rstrip("/") + p
        for payload in CMD_PAYLOADS:
            target = u + ("?input=" + payload if "?" not in u else "&input=" + payload)
            st, h, b = http_get(target, timeout=6)
            if st and any(k in b for k in CMD_HIT):
                out.append(
                    Finding(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        severity=Severity.CRITICAL,
                        file=u,
                        title="命令注入",
                        description=f"端点 {u} 对参数 input 拼接命令执行，payload={payload} 在响应中可见执行结果。",
                        evidence=payload,
                        confidence=0.9,
                        source=FindingSource.LLM,
                        poc=f"GET {target}",
                    )
                )
                break
    return out


def _probe_sqli(base: str) -> list[Finding]:
    out: list[Finding] = []
    for p in SQLI_PATHS:
        u = base.rstrip("/") + p
        for payload in SQLI_PAYLOADS:
            target = u + ("?user=" + payload + "&pwd=x") if "?" not in u else u + "&user=" + payload
            st, h, b = http_post(target, data={"user": payload, "pwd": "x"}, timeout=6) if "?" not in u else http_get(target, timeout=6)
            if st and any(k in b.lower() for k in SQLI_HIT):
                out.append(
                    Finding(
                        vuln_type=VulnType.SQLI,
                        severity=Severity.HIGH,
                        file=u,
                        title="SQL 注入（报错型）",
                        description=f"端点 {u} 对注入 payload 返回数据库报错特征。",
                        evidence=payload,
                        confidence=0.85,
                        source=FindingSource.LLM,
                        poc=f"POST {target}",
                    )
                )
                break
    return out


def _probe_xss(base: str) -> list[Finding]:
    out: list[Finding] = []
    for p in XSS_PATHS:
        u = base.rstrip("/") + p
        target = u + ("?q=" + XSS_PAYLOAD) if "?" not in u else u + "&q=" + XSS_PAYLOAD
        st, h, b = http_get(target, timeout=6)
        if st and XSS_HIT in b:
            out.append(
                Finding(
                    vuln_type=VulnType.XSS,
                    severity=Severity.MEDIUM,
                    file=u,
                    title="反射型 XSS",
                    description=f"端点 {u} 未过滤反射参数，注入脚本原样回显。",
                    evidence=XSS_PAYLOAD,
                    confidence=0.8,
                    source=FindingSource.LLM,
                    poc=f"GET {target}",
                )
            )
            break
    return out


def _nuclei(base: str) -> list[Finding]:
    if not shutil.which("nuclei"):
        return []
    try:
        out = subprocess.run(
            ["nuclei", "-u", base, "-silent", "-j", "-rate-limit", "50"],
            capture_output=True, text=True, timeout=180,
        )
        findings: list[Finding] = []
        for line in out.stdout.splitlines():
            try:
                j = json.loads(line)
            except Exception:
                continue
            findings.append(
                Finding(
                    vuln_type=VulnType.OTHER,
                    severity=Severity.MEDIUM,
                    file=base,
                    title=j.get("template-id", "nuclei"),
                    description=j.get("info", {}).get("name", ""),
                    confidence=0.7,
                    source=FindingSource.SAST,
                    rule_id=j.get("template-id"),
                )
            )
        return findings
    except Exception:
        return []


def scan_assets(assets: list[Asset], base_url: str = "") -> list[Finding]:
    findings: list[Finding] = []
    for a in assets:
        f = _detect_sensitive(a)
        if f:
            findings.append(f)
    if base_url:
        findings += _probe_cmd_injection(base_url)
        findings += _probe_sqli(base_url)
        findings += _probe_xss(base_url)
        findings += _nuclei(base_url)
    return findings
