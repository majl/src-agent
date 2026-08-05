"""黑盒侦察模块 + 共享 HTTP 工具。

- 共享 ``http_get`` / ``http_post``：自动为 localhost/127.0.0.1 关闭系统代理（避免 502），
  统一重试与超时，供 webscan / exploit / redteam 复用。
- ``recon_target``：资产发现。优先调用外部工具（subfinder / httpx / naabu），
  缺失时纯 Python（requests）兜底，保证零依赖可运行。

输出结构化 ``Asset`` 列表，作为 Web 漏洞扫描与利用的输入。
"""
from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 常见敏感/可疑路径，目录爆破用（前缀为公网靶场高频暴露点）
COMMON_PATHS = [
    "/", "/api", "/api/flag", "/api/flags", "/flag", "/flags",
    "/admin", "/admin/", "/login", "/console", "/dashboard",
    "/robots.txt", "/.git/config", "/.env", "/config", "/config.json",
    "/api/v1", "/api/user", "/api/users", "/actuator", "/phpinfo.php",
    "/.aws/credentials", "/backup.zip", "/api/debug",
]

USER_AGENT = "SRC-Hunter/1.0"


@dataclass
class Asset:
    url: str
    status: int = 0
    server: str = ""
    title: str = ""
    tech: list[str] = field(default_factory=list)
    note: str = ""


def _session_for(url: str) -> requests.Session:
    s = requests.Session()
    # 访问本地 mock 平台时绕过系统代理，避免 502
    if "127.0.0.1" in url or "localhost" in url:
        s.trust_env = False
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def http_get(url: str, timeout: int = 8, headers: Optional[dict] = None) -> tuple[int, dict, str]:
    s = _session_for(url)
    try:
        r = s.get(url, timeout=timeout, headers=headers or {"User-Agent": USER_AGENT}, allow_redirects=False)
        return r.status_code, dict(r.headers), r.text
    except requests.RequestException:
        return 0, {}, ""


def http_get_bytes(url: str, timeout: int = 10) -> tuple[int, bytes]:
    """同 ``http_get``，但返回原始响应字节（用于二进制端点 / 非文本载荷）。"""
    s = _session_for(url)
    try:
        r = s.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT}, allow_redirects=False)
        return r.status_code, r.content
    except requests.RequestException:
        return 0, b""


def http_post(url: str, data=None, json=None, timeout: int = 8, headers: Optional[dict] = None) -> tuple[int, dict, str]:
    s = _session_for(url)
    try:
        r = s.post(url, data=data, json=json, timeout=timeout, headers=headers or {"User-Agent": USER_AGENT}, allow_redirects=False)
        return r.status_code, dict(r.headers), r.text
    except requests.RequestException:
        return 0, {}, ""


def _title(html: str) -> str:
    m = re.search(r"<title>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:80] if m else ""


def _port_open(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


# 常见 Web 服务端口（探针默认扫描集合）；可经 --ports 覆盖
WEB_PORTS = [80, 443, 8080, 8000, 3000, 8800, 9000, 8443, 8888, 5000, 8081, 9090, 7000, 9200]


def probe_ports(host: str, ports: Optional[list[int]] = None, timeout: float = 0.6) -> list[str]:
    """对目标主机探测开放的 Web 服务端口，返回可达的 http/https 入口 URL 列表。

    https 优先；80/443 省略端口号，其余带 :port。
    """
    ports = ports or WEB_PORTS
    urls: list[str] = []
    for p in ports:
        if not _port_open(host, p, timeout):
            continue
        for scheme in ("https", "http"):
            if p == 443 and scheme == "http":
                continue
            if p == 80 and scheme == "https":
                continue
            base = f"{scheme}://{host}" if p in (80, 443) else f"{scheme}://{host}:{p}"
            st, h, b = http_get(base, timeout=4)
            if st:
                urls.append(base)
                break
    return urls


def _subdomain_enum(domain: str) -> list[str]:
    """可选：调用 subfinder（若已安装）。"""
    import shutil
    import subprocess

    if not shutil.which("subfinder"):
        return []
    try:
        out = subprocess.run(
            ["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, timeout=60
        )
        return [l.strip() for l in out.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def recon_target(target: str) -> list[Asset]:
    """对目标做黑盒资产发现，返回可达的 Web 资产列表。

    target 可为 ``http(s)://host:port/path`` 或裸 ``host``。
    """
    if not target.startswith("http"):
        target = "http://" + target

    assets: list[Asset] = []
    status, headers, body = http_get(target, timeout=8)
    if status:
        assets.append(
            Asset(url=target, status=status, server=headers.get("Server", ""), title=_title(body))
        )

    # 子域枚举（可选增强）
    from urllib.parse import urlparse

    host = urlparse(target).hostname or target
    if "." in host and host != "127.0.0.1" and host != "localhost":
        for sub in _subdomain_enum(host):
            su = "http://" + sub
            st, h, b = http_get(su, timeout=6)
            if st:
                assets.append(Asset(url=su, status=st, server=h.get("Server", ""), title=_title(b), note="subdomain"))

    # 目录/路径爆破（基于已确认基址）
    base = target.rstrip("/")
    for p in COMMON_PATHS:
        u = base + (p if p.startswith("/") else "/" + p)
        st, h, b = http_get(u, timeout=5)
        if st in (200, 201, 203, 204, 301, 302, 307, 308, 401, 403):
            assets.append(
                Asset(url=u, status=st, server=h.get("Server", ""), title=_title(b), note="path-probe")
            )

    return assets
