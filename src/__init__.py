"""SRC-Hunter: 面向 SRC 的 AI 漏洞挖掘 Agent。

核心能力：白盒代码审计（SAST + LLM 多轮上下文分析）、误报压制、PoC 自动生成与验证、
量化指标采集。LLM 后端默认使用腾讯混元 HY3（OpenAI 兼容协议），可降级为 mock 离线运行。
"""
__version__ = "0.1.0"
