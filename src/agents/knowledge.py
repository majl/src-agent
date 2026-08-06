"""RAG 知识增强层：把 CyberSecurity-Skills 安全技能库接入红队决策主循环。

来源：Hi-FullHouse/CyberSecurity-Skills（39 模块 / 195 技能），经
``cybersec-skills-retriever`` 专家技能封装（检索器 retriever.py）。

本模块做薄封装：
  - 定位知识库根目录（含 index.json），优先环境变量 CYBERSEC_SKILLS_DIR，
    其次默认专家技能路径；
  - 按当前漏洞类型 / 杀伤链阶段检索相关技能，产出可注入 LLM system 上下文的
    RAG 文本块；
  - 知识库缺失或检索失败时**优雅降级**为返回空串，绝不阻断解题流水线。

合规边界：检索仅在本地读取授权知识库，不向任何靶场写入数据；注入的提示词
自带「严格限于授权靶场」声明。
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import Dict, List, Optional

# 默认专家技能根目录（retriever.py 同目录，其下含 CyberSecurity-Skills/）
_DEFAULT_SKILL_DIR = os.path.expanduser(
    "~/.workbuddy/skills/cybersec-skills-retriever"
)

# VulnType 枚举成员名 -> 知识库检索关键词（中文，契合知识库语言）。
# 键使用枚举 .name（稳定），而非 .value（中文串，易因模型改动漂移）。
_VULN_QUERY: Dict[str, str] = {
    "COMMAND_INJECTION": "命令注入 远程代码执行 RCE 利用 反弹shell",
    "RCE": "远程代码执行 RCE 漏洞利用 反弹shell 内存马",
    "SQLI": "SQL注入利用 SQLMap 联合查询 报错注入 盲注",
    "XSS": "XSS 跨站脚本 利用 存储型 反射型 钓鱼",
    "SSRF": "SSRF 服务端请求伪造 内网探测 元数据 169.254.169.254",
    "PATH_TRAVERSAL": "路径遍历 目录穿越 任意文件读取 ../../../",
    "XXE": "XXE 外部实体注入 利用 读文件 内网请求",
    "AUTH_BYPASS": "认证绕过 登录绕过 JWT 会话伪造",
    "IDOR": "越权访问 IDOR 水平越权 垂直越权 改ID",
    "SENSITIVE_DATA": "敏感信息泄露 配置暴露 备份文件 源码泄露",
    "INSECURE_DESERIAL": "不安全反序列化 反序列化漏洞 利用链",
    "LOGIC_FLAW": "业务逻辑缺陷 支付绕过 薅羊毛 短信轰炸",
    "SECRET_LEAK": "硬编码凭据 密钥泄露 配置文件 环境变量",
    "CLOUD_METADATA": "云安全 元数据服务 IMDS 169.254.169.254 SSRF 取角色",
    "CLOUD_UNAUTH_API": "云安全 未授权 API 访问 对象存储 公有桶 列举",
    "CLOUD_CONTAINER_ESCAPE": "容器逃逸 特权容器 挂载逃逸 内核漏洞 Docker",
    "BINARY_STACK_OVERFLOW": "栈溢出 缓冲区溢出 ROP PWN 利用 控制流劫持",
    "BINARY_FORMAT_STRING": "格式化字符串漏洞 利用 %n 任意写",
    "BINARY_DANGEROUS_FUNC": "危险函数 系统调用 缓冲区 漏洞 逆向",
    "BINARY_HARDCODED_SECRET": "二进制 硬编码密钥 字符串提取 逆向 脱壳",
    "KILLCHAIN_RECON": "信息搜集 侦察 资产发现 子域名 端口扫描",
    "KILLCHAIN_INITIAL_ACCESS": "初始访问 边界突破 Web 漏洞利用 钓鱼",
    "KILLCHAIN_PRIV_ESC": "权限提升 本地提权 Linux Windows sudo 计划任务",
    "KILLCHAIN_LATERAL": "横向移动 内网横向 远程服务 口令复用 票据",
    "KILLCHAIN_CRED_ACCESS": "凭据访问 凭证窃取 哈希 dump 票据 浏览器密码",
    "KILLCHAIN_COLLECTION": "信息收集 目标枚举 数据定位 屏幕抓取",
    "KILLCHAIN_IMPACT": "影响 渗出 数据外传 目标达成 勒索 清除",
}


def _resolve_skill_dir() -> Optional[str]:
    """返回含 retriever.py 的专家技能目录（用于加入 sys.path）。"""
    candidates: List[str] = []
    env = os.environ.get("CYBERSEC_SKILLS_DIR")
    if env:
        # env 可能直接指向 KB 目录，也可能指向技能根目录
        candidates.append(env)
        candidates.append(os.path.dirname(env))
    candidates.append(_DEFAULT_SKILL_DIR)
    for d in candidates:
        if d and os.path.isdir(d) and os.path.isfile(os.path.join(d, "retriever.py")):
            return d
    return None


def _resolve_kb_root() -> Optional[str]:
    """返回含 index.json 的知识库根目录。"""
    env = os.environ.get("CYBERSEC_SKILLS_DIR")
    if env:
        kb = os.path.join(env, "CyberSecurity-Skills") if not os.path.isfile(
            os.path.join(env, "index.json")
        ) else env
        if os.path.isfile(os.path.join(kb, "index.json")):
            return kb
    # 默认技能目录下的 CyberSecurity-Skills 子目录
    kb = os.path.join(_DEFAULT_SKILL_DIR, "CyberSecurity-Skills")
    if os.path.isfile(os.path.join(kb, "index.json")):
        return kb
    return None


@lru_cache(maxsize=1)
def _get_retriever():
    """懒加载并返回一个 CyberSecSkills 检索器；缺失则返回 None（降级）。"""
    try:
        skill_dir = _resolve_skill_dir()
        kb_root = _resolve_kb_root()
        if not skill_dir or not kb_root:
            return None
        if skill_dir not in sys.path:
            sys.path.insert(0, skill_dir)
        from retriever import CyberSecSkills
        return CyberSecSkills(kb_root)
    except Exception:
        return None


def knowledge_available() -> bool:
    """知识库是否可接入（用于状态日志）。"""
    return _get_retriever() is not None


def retrieve(query: str, top: int = 3) -> str:
    """检索知识库，返回可注入 LLM 上下文的 RAG 文本块；失败/无命中返回空串。"""
    try:
        r = _get_retriever()
        if r is None:
            return ""
        out = r.retrieve(query, top=top)
        if not out or out.startswith("(未检索到"):
            return ""
        return out
    except Exception:
        return ""


def retrieve_for_vuln(vuln_type_name: str, top: int = 2) -> str:
    """按 VulnType 枚举成员名检索对应攻击知识。"""
    q = _VULN_QUERY.get(vuln_type_name)
    if not q:
        return ""
    return retrieve(q, top=top)


def retrieve_for_findings(findings, per_type: int = 1, max_blocks: int = 4) -> str:
    """针对一组 finding 的漏洞类型集合做去重聚合检索（用于利用规划 / 杀伤链叙事）。"""
    seen: List[str] = []
    for f in findings:
        v = getattr(f.vuln_type, "name", None) or getattr(
            f.vuln_type, "value", str(f.vuln_type)
        )
        q = _VULN_QUERY.get(v)
        if q and q not in seen:
            seen.append(q)
    blocks: List[str] = []
    for q in seen[:max_blocks]:
        r = retrieve(q, top=per_type)
        if r:
            blocks.append(r)
    return "\n\n".join(blocks)
