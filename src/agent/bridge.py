"""平台交互 Bridge 层：对齐 tsecbench 官方 Host Bridge 协议。

tsecbench「托管运行 + SDK 接入」的本质是：Solver 运行在隔离环境内，只能通过
标准 bridge 动作与宿主（平台代理）通信，由宿主统一转发竞赛 API。官方四个标准
动作为（参考真实榜首 agent BreachWeave 的 Host Bridge 设计）：

    challenge_get_state    读取当前题目元数据与完成状态
    challenge_get_hint     获取/读取持久化提示
    challenge_submit_flag  提交发现的 flag
    challenge_is_completed 检查题目是否已全部完成

本模块提供两套实现：
- ``APIBridge``      ：直接包裹 TsecBenchClient（openapi），用于「API 接入」自测
                        与本地 mock 验证，进程内完成拉题/启动/提交/关闭。
- ``StdioBridge``    ：实现 JSONL over stdin/stdout 协议（agent 侧），写出
                        HostBridgeRequestEvent、读入 host_bridge_response，
                        用于真机「托管运行」对接平台。
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from abc import ABC, abstractmethod
from typing import Optional, TextIO

from ..platform.tsecbench_client import TsecBenchClient
from .challenge import ChallengeSpec


class Bridge(ABC):
    """平台交互契约：Solver 只能通过这四个动作与外界通信。"""

    @abstractmethod
    def get_state(self, unique_code: str) -> ChallengeSpec:
        ...

    @abstractmethod
    def get_hint(self, unique_code: str) -> Optional[str]:
        ...

    @abstractmethod
    def submit_flag(self, unique_code: str, flag: str) -> dict:
        """提交 flag。返回至少含 ``correct``(bool) 的字典。"""

    @abstractmethod
    def is_completed(self, unique_code: str) -> bool:
        ...

    # 容器生命周期（API 接入形态需要；托管形态由平台负责）
    def start(self, unique_code: str) -> list[str]:
        return []

    def close(self, unique_code: str) -> bool:
        return True


class APIBridge(Bridge):
    """进程内 API 接入实现：直接调用 TsecBenchClient（兼容本地 mock_server）。"""

    def __init__(self, client: TsecBenchClient):
        self.client = client

    def start(self, unique_code: str) -> list[str]:
        return self.client.start(unique_code)

    def get_state(self, unique_code: str) -> ChallengeSpec:
        # openapi 没有单题 GET，这里用 list 过滤；mock 返回完整字段
        for c in self.client.list_challenges():
            if c.unique_code == unique_code:
                return ChallengeSpec(
                    unique_code=c.unique_code,
                    description=c.description,
                    difficulty=c.difficulty,
                    level=c.level,
                    total_score=c.total_score,
                    flag_count=c.flag_count,
                    correct_flag_count=c.correct_flag_count,
                    is_completed=c.is_completed,
                    container_addr=c.container_addr,
                )
        return ChallengeSpec(unique_code=unique_code)

    def get_hint(self, unique_code: str) -> Optional[str]:
        try:
            return self.client.hint(unique_code)
        except Exception:
            return None

    def submit_flag(self, unique_code: str, flag: str) -> dict:
        res = self.client.submit(unique_code, flag)
        return {"correct": res.correct, "awarded": res.awarded,
                "cumulative_score": res.cumulative_score}

    def is_completed(self, unique_code: str) -> bool:
        return self.get_state(unique_code).is_completed

    def close(self, unique_code: str) -> bool:
        return self.client.close(unique_code)


# ---------------------------------------------------------------------------
# StdioBridge —— 对齐官方 Host Bridge 的 JSONL over stdin/stdout 协议
# ---------------------------------------------------------------------------
class StdioBridge(Bridge):
    """agent 侧 bridge：通过 stdin/stdout 与宿主（平台）通信。

    写出（到 stdout，每行一个 JSON）：:
        {"request_id": "...", "action": "challenge_get_state",
         "params": {"unique_code": "WEB-DEMO-001"}}

    读入（从 stdin，每行一个 JSON）：:
        {"request_id": "...", "type": "host_bridge_response",
         "ok": true, "data": {...}}

    动作名与官方 Host Bridge 完全一致：challenge_get_state /
    challenge_get_hint / challenge_submit_flag / challenge_is_completed。
    """

    def __init__(self, stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None,
                 timeout: float = 30.0):
        self._in = stdin or sys.stdin
        self._out = stdout or sys.stdout
        self._timeout = timeout
        self._pending: dict[str, float] = {}

    # ---- 内部 RPC ----
    def _call(self, action: str, params: dict) -> dict:
        rid = uuid.uuid4().hex
        req = {"request_id": rid, "action": action, "params": params}
        self._out.write(json.dumps(req, ensure_ascii=False) + "\n")
        self._out.flush()
        # 读取响应直到匹配 request_id
        deadline = time.time() + self._timeout
        while time.time() < deadline:
            line = self._in.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("request_id") == rid and msg.get("type") == "host_bridge_response":
                if not msg.get("ok", False):
                    raise RuntimeError(f"bridge error for {action}: {msg.get('error')}")
                return msg.get("data", {})
        raise TimeoutError(f"bridge timeout waiting for {action}")

    # ---- 标准动作 ----
    def get_state(self, unique_code: str) -> ChallengeSpec:
        d = self._call("challenge_get_state", {"unique_code": unique_code})
        return ChallengeSpec(
            unique_code=d.get("unique_code", unique_code),
            description=d.get("description", ""),
            difficulty=d.get("difficulty", ""),
            level=int(d.get("level", 0)),
            total_score=int(d.get("total_score", 0)),
            flag_count=int(d.get("flag_count", 0)),
            correct_flag_count=int(d.get("correct_flag_count", 0)),
            is_completed=bool(d.get("is_completed", False)),
            container_addr=list(d.get("container_addr", [])),
            hint=d.get("hint"),
        )

    def get_hint(self, unique_code: str) -> Optional[str]:
        d = self._call("challenge_get_hint", {"unique_code": unique_code})
        h = d.get("hint")
        return h if h else None

    def submit_flag(self, unique_code: str, flag: str) -> dict:
        d = self._call("challenge_submit_flag",
                       {"unique_code": unique_code, "flag": flag})
        return {"correct": bool(d.get("correct", False)),
                "awarded": int(d.get("awarded", 0) or 0),
                "cumulative_score": int(d.get("cumulative_score", 0) or 0)}

    def is_completed(self, unique_code: str) -> bool:
        d = self._call("challenge_is_completed", {"unique_code": unique_code})
        return bool(d.get("completed", False))


class MockHostBridge:
    """宿主侧模拟：读 StdioBridge 的请求、调用 TsecBenchClient、回写响应。

    用于本地验证 StdioBridge 协议 roundtrip（无需真实平台）。把 StdioBridge 的
    stdin/stdout 与该对象的 stdout/stdin 配成一对即可。
    """

    def __init__(self, client: TsecBenchClient, stdin: TextIO, stdout: TextIO,
                 timeout: float = 30.0):
        self.client = client
        self._in = stdin
        self._out = stdout
        self._timeout = timeout

    def serve(self, unique_code: str) -> None:
        """持续读取 agent 的请求并响应，直到题目完成或 stdin 关闭。"""
        while True:
            line = self._in.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            rid = req.get("request_id")
            action = req.get("action")
            params = req.get("params", {}) or {}
            try:
                data = self._dispatch(action, params, unique_code)
                resp = {"request_id": rid, "type": "host_bridge_response",
                        "ok": True, "data": data}
            except Exception as e:  # noqa
                resp = {"request_id": rid, "type": "host_bridge_response",
                        "ok": False, "error": str(e)}
            self._out.write(json.dumps(resp, ensure_ascii=False) + "\n")
            self._out.flush()
            if action == "challenge_is_completed" and data.get("completed"):
                break

    def _dispatch(self, action: str, params: dict, unique_code: str) -> dict:
        if action == "challenge_get_state":
            spec = APIBridge(self.client).get_state(unique_code)
            return spec.to_dict()
        if action == "challenge_get_hint":
            return {"hint": self.client.hint(unique_code) or ""}
        if action == "challenge_submit_flag":
            res = self.client.submit(unique_code, params.get("flag", ""))
            return {"correct": res.correct, "awarded": res.awarded,
                    "cumulative_score": res.cumulative_score}
        if action == "challenge_is_completed":
            done = self.client.list_challenges()
            completed = any(c.unique_code == unique_code and c.is_completed
                            for c in done)
            return {"completed": completed}
        raise ValueError(f"unknown bridge action: {action}")
