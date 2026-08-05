"""tsecbench 平台接入客户端（Python SDK 风格）。

封装官方 /openapi/v1 全部端点（反推自公开对接实现）：
  GET  /challenges           列出题目（含 unique_code / container_addr / flag_count 等）
  POST /challenges/start     启动靶机，返回容器地址 container_addr（靶场入口 URL）
  GET  /challenges/hint      获取提示（注意：可能扣分）
  POST /challenges/submit    提交 flag，返回 correct / awarded / cumulative_score
  POST /challenges/close     关闭靶机容器

鉴权：请求头 ``BENCHMARK_TOKEN``；base_url 默认 https://tsecbench.zc.tencent.com

该客户端同时兼容本地 mock_server（base_url 指向 localhost 即可无缝切换），
便于离线跑通"拉题→打靶→提交"闭环。
"""
from __future__ import annotations

import os
from typing import Optional

import requests
from pydantic import BaseModel, Field
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class Challenge(BaseModel):
    unique_code: str
    description: str = ""
    difficulty: str = ""
    level: int = 0
    total_score: int = 0
    flag_count: int = 0
    correct_flag_count: int = 0
    is_completed: bool = False
    container_status: str = ""
    container_addr: list[str] = Field(default_factory=list)


class SubmitResult(BaseModel):
    correct: bool = False
    awarded: int = 0
    cumulative_score: int = 0
    correct_flag_count: int = 0
    total_flag_count: int = 0
    matched_flag_index: Optional[int] = None
    raw: dict = Field(default_factory=dict)


class TsecBenchError(RuntimeError):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(f"TsecBench API error HTTP {status}: {message}")


class TsecBenchClient:
    """tsecbench 评测平台 HTTP 客户端。"""

    DEFAULT_BASE = "https://tsecbench.zc.tencent.com"

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        timeout: int = 60,
    ):
        self.base_url = (
            base_url or os.getenv("BENCHMARK_BASE_URL") or self.DEFAULT_BASE
        ).rstrip("/")
        self.token = token or os.getenv("BENCHMARK_TOKEN") or ""
        self.timeout = timeout
        self.session = requests.Session()
        # 访问本地 mock 平台（127.0.0.1/localhost）时绕过系统代理，避免 502
        if "127.0.0.1" in self.base_url or "localhost" in self.base_url:
            self.session.trust_env = False
        retry = Retry(
            total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504]
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    # ---------- low-level ----------
    def _request(self, method: str, path: str, query=None, json=None):
        if not self.token:
            raise TsecBenchError(
                401, "未配置 BENCHMARK_TOKEN（请设置环境变量 BENCHMARK_TOKEN 或从参数传入）"
            )
        url = self.base_url + path
        headers = {"BENCHMARK_TOKEN": self.token, "User-Agent": "SRC-Hunter/1.0"}
        try:
            r = self.session.request(
                method, url, params=query, json=json, headers=headers, timeout=self.timeout
            )
        except requests.RequestException as e:
            raise TsecBenchError(0, f"网络错误: {e}") from e
        if not (200 <= r.status_code < 300):
            try:
                err = r.json()
                msg = err.get("message") or str(err.get("detail") or r.text)
            except Exception:
                msg = r.text
            raise TsecBenchError(r.status_code, msg)
        return r

    # ---------- high-level ----------
    def list_challenges(self) -> list[Challenge]:
        r = self._request("GET", "/openapi/v1/challenges")
        return [Challenge(**c) for c in r.json()]

    def start(self, unique_code: str) -> list[str]:
        r = self._request(
            "POST", "/openapi/v1/challenges/start", json={"unique_code": unique_code}
        )
        data = r.json()
        return data.get("container_addr") or data.get("container_addrs") or []

    def hint(self, unique_code: str) -> Optional[str]:
        r = self._request(
            "GET", "/openapi/v1/challenges/hint", query={"unique_code": unique_code}
        )
        data = r.json()
        h = data.get("hint")
        return h if h else None

    def submit(self, unique_code: str, flag: str) -> SubmitResult:
        r = self._request(
            "POST",
            "/openapi/v1/challenges/submit",
            json={"unique_code": unique_code, "flag": flag},
        )
        data = r.json()
        return SubmitResult(
            correct=bool(data.get("correct", False)),
            awarded=int(data.get("awarded", 0) or 0),
            cumulative_score=int(data.get("cumulative_score", 0) or 0),
            correct_flag_count=int(data.get("correct_flag_count", 0) or 0),
            total_flag_count=int(data.get("total_flag_count", 0) or 0),
            matched_flag_index=data.get("matched_flag_index"),
            raw=data,
        )

    def close(self, unique_code: str) -> bool:
        r = self._request(
            "POST", "/openapi/v1/challenges/close", json={"unique_code": unique_code}
        )
        data = r.json()
        return bool(data.get("closed", True))
