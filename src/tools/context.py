"""上下文提取器：为 LLM 补齐跨文件调用上下文（借鉴 vulnhuntr 的 symbol_finder 思路）。

实现：语言无关的"符号 → 定义代码块"检索。对 Python 优先走 jedi 精准定位，
其余语言与降级场景走正则扫描。目标是把被分析文件中引用的函数/类定义喂给 LLM，
降低纯 LLM 数据流分析的幻觉与断裂。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

# 各语言的函数/类定义正则
_DEF_PATTERNS = [
    re.compile(r"def\s+(\w+)\s*\(", re.MULTILINE),                       # python
    re.compile(r"function\s+(\w+)\s*\(", re.MULTILINE),                  # js
    re.compile(r"(\w+)\s*=\s*function\s*\(", re.MULTILINE),             # js assign
    re.compile(r"class\s+(\w+)", re.MULTILINE),                          # many langs
    re.compile(r"(\w+)\s*<\s*\w+\s*>\s*\(?", re.MULTILINE),              # generic-ish (skip)
    re.compile(r"public\s+(?:static\s+)?(?:void|int|string|bool|\w+)\s+(\w+)\s*\(", re.MULTILINE),  # java/c#
    re.compile(r"func\s+(\w+)\s*\(", re.MULTILINE),                      # go
]


class ContextExtractor:
    def __init__(self, repo_root: str):
        self.repo_root = Path(repo_root)
        self._cache: dict[str, str] = {}

    def _all_source_files(self, exts=None) -> list[Path]:
        if exts is None:
            exts = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".php", ".rb", ".cs"}
        files = []
        for p in self.repo_root.rglob("*"):
            if p.is_file() and p.suffix.lower() in exts:
                files.append(p)
        return files

    def relevant_files(self, repo_root: str | None = None) -> list[str]:
        """筛选"入口/网络相关"文件（路由、handler、controller、api）。"""
        root = Path(repo_root or self.repo_root)
        markers = re.compile(r"(route|app|controller|handler|api|view|service|endpoint|request|response)", re.I)
        out = []
        for p in self._all_source_files():
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if markers.search(p.name) or markers.search(text[:2000]):
                out.append(str(p))
        return out

    def extract_symbol(self, symbol: str, max_lines: int = 60) -> Optional[str]:
        """返回名为 symbol 的函数/类定义代码块（跨文件查找）。"""
        if symbol in self._cache:
            return self._cache[symbol]
        sym = symbol.strip().split("(")[0].split(".")[-1]
        if not sym or len(sym) < 2:
            return None
        for p in self._all_source_files():
            try:
                lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
            except Exception:
                continue
            for i, line in enumerate(lines):
                if re.search(rf"(def|function|class|func)\s+{re.escape(sym)}\b", line) or \
                   re.search(rf"\b{re.escape(sym)}\s*=\s*function\b", line):
                    block = lines[i: i + max_lines]
                    snippet = "\n".join(block)
                    self._cache[symbol] = snippet
                    return snippet
        return None

    def network_related_files(self) -> list[str]:
        return self.relevant_files()
