"""云安全维度检测模块（对应 tsecbench CLOUD 评分维度，权重 15%）。

覆盖三类云上攻击面：
  1. 云元数据服务 IMDS（169.254.169.254）——可通过 SSRF 或实例内直连获取
     临时凭证 / 用户数据中的敏感信息（含 flag）；
  2. 未授权云 API——K8s API server、Docker API（2375）、etcd（2379）
     等未鉴权暴露，可直接列举资源或拿到 flag；
  3. 容器逃逸线索——/.dockerenv 存在、docker.sock 挂载可读、特权容器 cap
     等逃逸前置信号。

输出与 Web 扫描共用同一 Finding 模型，可直接并入红队利用闭环：
  Finding.file / poc 设为可访问 URL，run_exploit_full 会 GET 提取 flag{...}。
优先外部工具（httpx/naabu），缺失时纯 Python（requests）兜底，零依赖可运行。
"""
from __future__ import annotations

import re
from typing import Optional

from ..models import Finding, FindingSource, Severity, VulnType
from .recon import http_get

FLAG_RE = re.compile(r"flag\{[^}]+\}", re.I)

# 真实云元数据服务地址（链路本地，仅实例内可达；靶场内通常通过 SSRF 打到）
IMDS_HOST = "http://169.254.169.254"
IMDS_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/iam/security-credentials/role",
    "/latest/user-data/",
    "/latest/dynamic/instance-identity/document",
]

# 未授权云 API 探测路径（相对 container_addr；真实场景为独立端口 / 独立路径）
UNAUTH_API_TARGETS = [
    ("k8s-pods", "/k8s/api/v1/pods", "K8s API server 未授权访问(/api/v1/pods)"),
    ("k8s-healthz", "/k8s/healthz", "K8s API server 未授权 healthz"),
    ("docker-containers", "/docker/containers/json", "Docker API 未授权(/containers/json)"),
    ("docker-version", "/docker/version", "Docker API 未授权(/version)"),
    ("etcd-v2", "/etcd/v2/keys/", "etcd 未授权访问(/v2/keys)"),
    ("etcd-v3", "/etcd/v3/kv/range", "etcd v3 未授权访问"),
]

# 容器逃逸线索探测路径（相对 container_addr）
ESCAPE_TARGETS = [
    ("dockerenv", "/escape/dockerenv", "存在 /.dockerenv（容器内运行线索）"),
    ("dockersock", "/escape/docker.sock", "docker.sock 挂载可读（高危逃逸前置）"),
    ("priv-cap", "/escape/cap", "特权容器 cap 线索(SYS_ADMIN 等)"),
    ("cgroup", "/escape/cgroup", "cgroup 命名空间线索"),
]

_IMDS_HINTS = ("instance-id", "accessKeyId", "ami-id", "security-credentials",
               "SecretAccessKey", "sessionToken", "availability-zone")


def check_imds(base_url: str = "", direct: bool = False) -> list[Finding]:
    """探测云元数据服务（IMDS）。

    - direct=True：直接访问链路本地 169.254.169.254（Agent 自身处于云实例/容器中）；
    - 否则：通过 base_url 下的模拟元数据端点（靶场把 IMDS 挂在 /range/metadata）。
    """
    out: list[Finding] = []
    if direct:
        targets = [IMDS_HOST + p for p in IMDS_PATHS]
    else:
        if not base_url:
            return out
        targets = [base_url.rstrip("/") + "/metadata/"]

    for u in targets:
        st, h, b = http_get(u, timeout=8)
        if not st:
            continue
        fl = FLAG_RE.search(b)
        exposed = fl or any(k in b for k in _IMDS_HINTS)
        if exposed:
            out.append(Finding(
                vuln_type=VulnType.CLOUD_METADATA, severity=Severity.CRITICAL,
                file=u, title="云元数据服务 IMDS 暴露",
                description=f"IMDS 可未经授权访问（{u}），可能泄露临时凭证/用户数据。",
                evidence=f"flag={fl.group(0)}" if fl else b[:120],
                confidence=0.9, source=FindingSource.LLM, poc=f"GET {u}",
            ))
            if not direct:  # 靶场单一模拟端点，命中即止
                break
    return out


def check_unauthorized_cloud_api(base_url: str) -> list[Finding]:
    out: list[Finding] = []
    if not base_url:
        return out
    for name, path, desc in UNAUTH_API_TARGETS:
        url = base_url.rstrip("/") + path
        st, h, b = http_get(url, timeout=8)
        if not st:
            continue
        fl = FLAG_RE.search(b)
        # 未授权判定：拿到 flag，或返回非空集群信息，或无需鉴权的 healthz/version
        looks_open = fl or (
            st == 200 and b.strip()
            and ("flag" in b.lower() or name in ("docker-version", "k8s-healthz", "etcd-v2", "etcd-v3"))
        )
        if looks_open:
            out.append(Finding(
                vuln_type=VulnType.CLOUD_UNAUTH_API, severity=Severity.HIGH,
                file=url, title=f"未授权云 API：{name}",
                description=desc + " 接口无需鉴权即可访问。",
                evidence=f"flag={fl.group(0)}" if fl else b[:120],
                confidence=0.85, source=FindingSource.LLM, poc=f"GET {url}",
            ))
    return out


def detect_container_escape(base_url: str) -> list[Finding]:
    out: list[Finding] = []
    if not base_url:
        return out
    for name, path, desc in ESCAPE_TARGETS:
        url = base_url.rstrip("/") + path
        st, h, b = http_get(url, timeout=8)
        if not st:
            continue
        if st == 200 and b.strip():  # 命中非空响应即视为逃逸线索
            fl = FLAG_RE.search(b)
            sev = Severity.CRITICAL if name == "dockersock" else Severity.HIGH
            out.append(Finding(
                vuln_type=VulnType.CLOUD_CONTAINER_ESCAPE, severity=sev,
                file=url, title=f"容器逃逸线索：{name}",
                description=desc,
                evidence=f"flag={fl.group(0)}" if fl else b[:120],
                confidence=0.8, source=FindingSource.LLM, poc=f"GET {url}",
            ))
    return out


def scan_cloud(base_url: str, direct_imds: bool = False) -> list[Finding]:
    """云维度汇总扫描，返回标准化 Finding 列表。"""
    if not base_url:
        return []
    findings: list[Finding] = []
    findings += check_imds(base_url, direct=direct_imds)
    findings += check_unauthorized_cloud_api(base_url)
    findings += detect_container_escape(base_url)
    return findings
