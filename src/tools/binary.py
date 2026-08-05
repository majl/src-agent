"""二进制漏洞自动分析模块（对应 tsecbench BINARY 评分维度，权重 15%）。

覆盖对给定二进制程序（ELF，pwn / 逆向题）的自动化静态分析能力：
  1. 保护机制 checksec：RELRO / Canary / NX / PIE / 架构；
  2. 危险函数识别：gets/strcpy/strcat/sprintf/scanf/system/popen/execve 等
     无边界拷贝或命令执行风险函数；
  3. 敏感字符串扫描：flag{...}（硬编码 flag / 后门）、/bin/sh、cat flag、password/secret；
  4. 启发式漏洞判定：
     - 栈溢出：存在无边界检查危险函数（gets/strcpy/strcat）且未开 stack canary → 高置信；
     - 格式化字符串：存在 printf/sprintf/fprintf 且格式串可能来自输入 → 中高置信；
     - 命令执行：存在 system/popen/execve 等 → 高风险（常直接 getshell）；
     - 硬编码凭据 / 后门：二进制内直接含 flag{...} → 直接可利用（静态提取 flag）。

工具链优先级（增强层，非必需）：
  pwntools(ELF.checksec) → 系统 strings/nm/objdump 命令 → 纯 Python 字节扫描（跨平台兜底，零依赖）。
真实评测靶机（Linux）上会自动启用 pwntools 拿权威 checksec；本地 macOS 演示走纯 Python 兜底，
二者产出统一 Finding，可直接并入红队利用闭环。

与闭环对接：
  - BINARY_HARDCODED_SECRET 的 poc 指向靶场「利用后 flag 端点」，run_exploit_full 会优先从
    evidence 提取静态 flag，否则 GET 该端点；若静态分析已直接提取到 flag，则无需 HTTP 交互即可提交。
"""
from __future__ import annotations

import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Union

from ..models import Finding, FindingSource, Severity, VulnType

FLAG_RE = re.compile(r"flag\{[^}]+\}", re.I)

# 危险函数 → 风险说明
_DANGEROUS_FUNCS = {
    "gets": "无边界输入读取，确定栈溢出风险",
    "strcpy": "无边界字符串拷贝，栈溢出风险",
    "strcat": "无边界字符串拼接，栈溢出风险",
    "sprintf": "格式化输出至栈缓冲，溢出 / 格式串风险",
    "scanf": "格式化输入至栈缓冲，溢出风险",
    "system": "执行系统命令，命令注入 / 后门风险",
    "popen": "执行系统命令，命令注入 / 后门风险",
    "execve": "执行程序，参数可控可 getshell",
    "execl": "执行程序，参数可控可 getshell",
    "WinExec": "Windows 执行程序，参数可控可 getshell",
    "memcpy": "内存拷贝，长度可控时溢出风险",
}
# 格式化字符串相关函数
_FMT_FUNCS = {"printf", "sprintf", "fprintf", "snprintf", "syslog"}
# 命令执行相关（高危）
_CMD_FUNCS = {"system", "popen", "execve", "execl", "WinExec"}
# 无边界拷贝 / 输入（确定性栈溢出）
_BOUNDSLESS_FUNCS = {"gets", "strcpy", "strcat"}
# 敏感字符串线索
_SENSITIVE_HINTS = ("/bin/sh", "cat flag", "/flag", "password", "secret", "admin", "token", "apikey")
# canary 符号（动态引用栈保护函数即视为开启 -fstack-protector）
_CANARY_SIGNS = (b".stack_chk_fail", b"__stack_chk_fail", b"stack_chk_guard")

_ARCH_MAP = {0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64",
             0x08: "MIPS", 0x16: "S390", 0x32: "IA-64", 0x14: "PowerPC"}


def _read_input(path_or_bytes) -> tuple[bytes, Optional[str]]:
    """统一输入：返回 (data, tmp_path_or_None)。bytes 会落临时文件供 pwntools/strings 复用。"""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        data = bytes(path_or_bytes)
        try:
            fd, tmp = tempfile.mkstemp(suffix=".bin", prefix="srchunter_")
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            return data, tmp
        except Exception:
            return data, None
    p = Path(path_or_bytes)
    return p.read_bytes(), str(p)


def _extract_strings_py(data: bytes, min_len: int = 4) -> list[str]:
    """纯 Python 提取可打印 ASCII 字符串（跨平台兜底）。"""
    out: list[str] = []
    buf: list[str] = []
    for b in data:
        if 0x20 <= b < 0x7F:
            buf.append(chr(b))
        else:
            if len(buf) >= min_len:
                out.append("".join(buf))
            buf = []
    if len(buf) >= min_len:
        out.append("".join(buf))
    return out


def _extract_strings_tool(tmp_path: Optional[str], fallback_data: bytes) -> list[str]:
    """优先用系统 strings 命令提取（更全，能跨 ELF 段），否则纯 Python。"""
    import shutil
    strings_bin = shutil.which("strings")
    if tmp_path and strings_bin:
        try:
            r = subprocess.run(
                [strings_bin, "-n", "4", tmp_path],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0 and r.stdout.strip():
                lines = [ln.strip() for ln in r.stdout.splitlines() if len(ln.strip()) >= 4]
                if lines:
                    return lines
        except Exception:
            pass
    return _extract_strings_py(fallback_data)


def _parse_elf(data: bytes) -> dict:
    """纯 Python 解析 ELF header / program headers，提取基础保护属性。"""
    props = {
        "is_elf": False, "arch": "unknown", "bits": 0, "endian": "unknown",
        "pie": None, "nx": None, "canary": None, "relro": "unknown",
    }
    if data[:4] != b"\x7fELF":
        return props
    props["is_elf"] = True
    ei_class = data[4]            # 1=32bit, 2=64bit
    ei_data = data[5]             # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"
    props["bits"] = 32 if ei_class == 1 else 64
    props["endian"] = "little" if ei_data == 1 else "big"
    try:
        (e_type,) = struct.unpack_from(endian + "H", data, 16)
        (e_machine,) = struct.unpack_from(endian + "H", data, 18)
        props["pie"] = (e_type == 3)  # ET_DYN
        props["arch"] = _ARCH_MAP.get(e_machine, f"e_machine=0x{e_machine:x}")
        if ei_class == 1:  # ELF32
            (e_phoff,) = struct.unpack_from(endian + "I", data, 28)
            (e_phentsize,) = struct.unpack_from(endian + "H", data, 42)
            (e_phnum,) = struct.unpack_from(endian + "H", data, 44)
        else:  # ELF64
            (e_phoff,) = struct.unpack_from(endian + "Q", data, 32)
            (e_phentsize,) = struct.unpack_from(endian + "H", data, 54)
            (e_phnum,) = struct.unpack_from(endian + "H", data, 56)
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            if base + 8 > len(data):
                break
            (p_type,) = struct.unpack_from(endian + "I", data, base)
            if p_type == 0x6474E551:  # PT_GNU_STACK
                # ELF32 p_flags @ +24；ELF64 p_flags @ +4
                off = (base + 24) if ei_class == 1 else (base + 4)
                (p_flags,) = struct.unpack_from(endian + "I", data, off)
                props["nx"] = not bool(p_flags & 0x1)  # PF_X=0x1
                break
    except Exception:
        pass
    # canary：扫描栈保护符号引用
    props["canary"] = any(s in data for s in _CANARY_SIGNS)
    return props


def _checksec_pwn(tmp_path: Optional[str]) -> Optional[dict]:
    """用 pwntools 拿权威 checksec（Linux 真实靶机增强层）。"""
    if not tmp_path:
        return None
    try:
        from pwn import ELF
        elf = ELF(tmp_path, checksec=True)
        cs = getattr(elf, "checksec", None)
        if not isinstance(cs, dict):
            return None
        relro = str(cs.get("relro", "")).lower()
        return {
            "relro": "full" if "full" in relro else ("partial" if "partial" in relro else "unknown"),
            "canary": bool(cs.get("canary")),
            "nx": bool(cs.get("nx")),
            "pie": bool(cs.get("pie")),
            "fortify": bool(cs.get("fortify_source")),
        }
    except Exception:
        return None


def analyze_binary_file(path_or_bytes) -> list[Finding]:
    """对二进制做静态脆弱性分析，返回标准化 Finding 列表（供红队闭环并入）。"""
    data, tmp = _read_input(path_or_bytes)
    props = _parse_elf(data)
    pwn_props = _checksec_pwn(tmp)
    if pwn_props:
        props.update({k: v for k, v in pwn_props.items() if v is not None or k == "relro"})

    strings = _extract_strings_tool(tmp, data)
    joined = "\n".join(strings)

    findings: list[Finding] = []
    flag = FLAG_RE.search(joined)
    if flag:
        findings.append(Finding(
            vuln_type=VulnType.BINARY_HARDCODED_SECRET, severity=Severity.CRITICAL,
            file=(tmp or "binary"),
            title="二进制内硬编码 flag / 后门",
            description="二进制程序中直接包含 flag{...} 字符串，疑似硬编码凭据或后门，可静态提取利用。",
            evidence=f"硬编码flag={flag.group(0)}",
            confidence=0.95, source=FindingSource.LLM,
            poc=(tmp or "binary"),
            remediation="移除二进制中的硬编码凭据 / 后门；flag 改为运行时从安全配置或环境变量注入。",
        ))

    found_funcs = {fn: desc for fn, desc in _DANGEROUS_FUNCS.items() if re.search(r"\b" + re.escape(fn) + r"\b", joined)}
    canary = bool(props.get("canary"))

    # 栈溢出（无边界拷贝函数 + 无 canary → 高置信）
    if any(fn in found_funcs for fn in _BOUNDSLESS_FUNCS):
        hits = [fn for fn in _BOUNDSLESS_FUNCS if fn in found_funcs]
        conf = 0.85 if not canary else 0.55
        sev = Severity.CRITICAL if not canary else Severity.HIGH
        findings.append(Finding(
            vuln_type=VulnType.BINARY_STACK_OVERFLOW, severity=sev,
            file=(tmp or "binary"),
            title="潜在栈溢出（无边界拷贝函数）",
            description=("检测到无边界检查的危险函数 " + ", ".join(hits) +
                         ("；目标未开启 stack canary，可直接构造溢出利用（如 ret2libc / ROP）。"
                          if not canary else "；目标已开启 stack canary，仍需寻找泄露或其他溢出路径。")),
            evidence="危险函数: " + ", ".join(f"{h}({found_funcs[h]})" for h in hits),
            confidence=conf, source=FindingSource.LLM,
            poc=(tmp or "binary"),
            remediation="使用有界拷贝函数（strncpy/snprintf 等）；开启 FORTIFY_SOURCE / stack canary；关键路径加长度校验。",
        ))

    # 格式化字符串
    if any(fn in found_funcs for fn in _FMT_FUNCS):
        hits = [fn for fn in _FMT_FUNCS if fn in found_funcs]
        findings.append(Finding(
            vuln_type=VulnType.BINARY_FORMAT_STRING, severity=Severity.HIGH,
            file=(tmp or "binary"),
            title="潜在格式化字符串漏洞",
            description="检测到格式化输出函数 " + ", ".join(hits) +
                        "，若格式串可被用户输入控制，可造成任意地址读 / 写（泄露 canary / GOT 劫持）。",
            evidence="危险函数: " + ", ".join(hits),
            confidence=0.55, source=FindingSource.LLM,
            poc=(tmp or "binary"),
            remediation="禁止格式串来自用户输入；使用固定格式串（如 printf(\"%s\", buf)）。",
        ))

    # 命令执行（system/popen/execve 等）
    if any(fn in found_funcs for fn in _CMD_FUNCS):
        hits = [fn for fn in _CMD_FUNCS if fn in found_funcs]
        findings.append(Finding(
            vuln_type=VulnType.BINARY_DANGEROUS_FUNC, severity=Severity.HIGH,
            file=(tmp or "binary"),
            title="命令执行类危险函数",
            description="检测到命令执行函数 " + ", ".join(hits) +
                        "，若其参数部分可控，可造成任意命令执行（直接 getshell）。",
            evidence="危险函数: " + ", ".join(f"{h}({found_funcs[h]})" for h in hits),
            confidence=0.7, source=FindingSource.LLM,
            poc=(tmp or "binary"),
            remediation="避免将用户输入拼接进命令；改用 exec 族 + 参数数组，或对输入做严格白名单校验。",
        ))

    # 清理临时文件
    if tmp:
        try:
            os.remove(tmp)
        except Exception:
            pass
    return findings


def analyze_binary(path_or_bytes, detail: bool = False) -> dict:
    """详细分析入口（供 CLI / 脚本）：返回 {props, strings_sample, findings, flag}。"""
    data, tmp = _read_input(path_or_bytes)
    props = _parse_elf(data)
    pwn_props = _checksec_pwn(tmp)
    if pwn_props:
        props.update({k: v for k, v in pwn_props.items() if v is not None or k == "relro"})
    strings = _extract_strings_tool(tmp, data)
    findings = analyze_binary_file(data)  # analyze_binary_file 内部会清理 tmp
    flag = FLAG_RE.search("\n".join(strings))
    if tmp and os.path.exists(tmp):
        try:
            os.remove(tmp)
        except Exception:
            pass
    result = {
        "props": props,
        "strings_count": len(strings),
        "strings_sample": strings[:40],
        "findings": findings,
        "flag": flag.group(0) if flag else None,
    }
    return result


def scan_binary(base_url: str, flag_endpoint: str = "/pwn/flag") -> list[Finding]:
    """靶场模式：下载靶机二进制并执行自动分析，返回标准化 Finding 列表。

    - 二进制端点：base_url + /pwn/binary；
    - 利用后 flag 端点：base_url + flag_endpoint（供 run_exploit_full 提取 / 提交）。
    若靶机不存在二进制端点（如纯 Web 题），返回空列表，不影响其他维度。
    """
    from .recon import http_get_bytes
    if not base_url:
        return []
    bin_url = base_url.rstrip("/") + "/pwn/binary"
    st, b = http_get_bytes(bin_url, timeout=10)
    if not st or len(b) < 4:
        return []
    findings = analyze_binary_file(b)
    if not findings:
        return []
    flag_url = base_url.rstrip("/") + flag_endpoint
    for f in findings:
        # poc 统一指向靶场「利用后 flag 端点」；file 指向二进制端点
        f.poc = flag_url
        f.file = bin_url
    return findings
