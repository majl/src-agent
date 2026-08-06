"""平台交互 Bridge 层：对齐 tsecbench 官方 Host Bridge 协议。

tsecbench「托管运行 + SDK 接入」的本质是：Solver 运行在隔离环境内，只能通过
标准 bridge 动作与宿主（平台代理）通信，由宿主统一转发竞赛 API。官方四个标准
动作为（参考真实榜首 agent BreachWeave 的 Host Bridge 设计，腾讯同一竞赛生态）：

    challenge_get_state    读取当前题目元数据与完成状态
    challenge_get_hint     获取/读取持久化提示
    challenge_submit_flag  提交发现的 flag
    challenge_is_completed 检查题目是否已全部完成

双向 JSONL 通道（Host Bridge）：
- 平台（宿主）→ Solver（stdin）：控制命令 prompt / steer / follow_up / abort
- Solver → 平台（stdout）：host_bridge_request（四个动作）+ agent_end 生命周期事件
- 平台 → Solver（stdin）：host_bridge_response（动作响应，按 request_id 匹配）
- 题号由平台通过环境变量 TCH_CHALLENGE_ID（兼容 TSEC_CHALLENGE_ID /
  BENCHMARK_CHALLENGE_ID / CHALLENGE_ID）注入启动环境。

本模块提供：
- ``APIBridge``     ：进程内 API 接入实现（直接调用 TsecBenchClient），用于自测与
                      本地 mock 验证，串起拉题/启动/提交/关闭。
- ``HostChannel``   ：托管运行模式下 Solver 侧的 JSONL 双向通道（单读线程复用
                      stdin，区分 host_bridge_response 与控制命令）。
- ``StdioBridge``   ：基于 HostChannel 的 agent 侧 bridge，写出 host_bridge_request、
                      读入 host_bridge_response。
- ``HostHarness``   ：宿主侧模拟（mock / 自测用），下发 prompt、分发四类动作、
                      处理 agent_end——等价于平台托管运行时做的事。
"""
from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from typing import Callable, Optional, TextIO

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
# HostChannel —— 托管运行模式的 JSONL 双向通道（对齐 BreachWeave Host Bridge）
# ---------------------------------------------------------------------------
class HostChannel:
    """Solver 侧与宿主进程的 JSONL 通道（单读线程复用一个 stdin）。

    读线程把 stdin 上的两类消息分开处理：
    - ``host_bridge_response``：按 request_id 唤醒阻塞在 :meth:`request` 的调用方；
    - 控制命令（prompt / steer / follow_up / abort）：交给 ``on_command`` 回调。

    Solver 向 stdout 写出 ``host_bridge_request`` 事件（四个挑战动作），宿主处理
    后回 ``host_bridge_response``。由于 stdout 兼作协议流，**调用方禁止往 stdout
    打印任何非协议内容**（诊断日志一律走 stderr）。
    """

    def __init__(
        self,
        stdin: TextIO,
        stdout: TextIO,
        timeout: float = 120.0,
        on_command: Optional[Callable[[dict], None]] = None,
    ):
        self._in = stdin
        self._out = stdout
        self._timeout = timeout
        self._on_command = on_command or (lambda msg: None)
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def request(self, action: str, params: dict) -> dict:
        """发出一个 host_bridge_request 并阻塞等待对应 response。"""
        rid = uuid.uuid4().hex
        req = {"type": "host_bridge_request", "request_id": rid,
               "action": action, "params": params}
        with self._lock:
            self._pending[rid] = {"event": threading.Event(),
                                  "data": None, "error": None}
        self._out.write(json.dumps(req, ensure_ascii=False) + "\n")
        self._out.flush()
        entry = self._pending[rid]
        if not entry["event"].wait(self._timeout):
            with self._lock:
                self._pending.pop(rid, None)
            raise TimeoutError(f"host bridge timeout waiting for {action}")
        if entry["error"]:
            raise RuntimeError(f"host bridge error for {action}: {entry['error']}")
        return entry["data"]

    def send_event(self, msg: dict) -> None:
        """向 stdout 发送任意协议事件（如 agent_end 生命周期事件）。"""
        self._out.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self._out.flush()

    def _read_loop(self) -> None:
        while True:
            try:
                line = self._in.readline()
            except Exception:
                break
            if not line:
                break  # stdin 关闭（宿主退出）
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = msg.get("type")
            if t == "host_bridge_response":
                rid = msg.get("request_id")
                with self._lock:
                    entry = self._pending.pop(rid, None)
                if entry:
                    if not msg.get("ok", False):
                        entry["error"] = msg.get("error")
                    else:
                        entry["data"] = msg.get("data", {})
                    entry["event"].set()
            else:
                # prompt / steer / follow_up / abort —— 控制命令
                try:
                    self._on_command(msg)
                except Exception:
                    pass


class StdioBridge(Bridge):
    """agent 侧 bridge：基于 ``HostChannel``，写出 host_bridge_request、读 host_bridge_response。

    动作名与官方 Host Bridge 完全一致：challenge_get_state /
    challenge_get_hint / challenge_submit_flag / challenge_is_completed。
    """

    def __init__(self, channel: HostChannel):
        self.ch = channel

    # ---- 标准动作 ----
    def get_state(self, unique_code: str) -> ChallengeSpec:
        d = self.ch.request("challenge_get_state", {"unique_code": unique_code})
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
        d = self.ch.request("challenge_get_hint", {"unique_code": unique_code})
        h = d.get("hint")
        return h if h else None

    def submit_flag(self, unique_code: str, flag: str) -> dict:
        d = self.ch.request("challenge_submit_flag",
                            {"unique_code": unique_code, "flag": flag})
        return {"correct": bool(d.get("correct", False)),
                "awarded": int(d.get("awarded", 0) or 0),
                "cumulative_score": int(d.get("cumulative_score", 0) or 0)}

    def is_completed(self, unique_code: str) -> bool:
        d = self.ch.request("challenge_is_completed", {"unique_code": unique_code})
        return bool(d.get("completed", False))


# ---------------------------------------------------------------------------
# HostHarness —— 宿主侧：模拟 tsecbench 平台驱动 Solver 子进程的托管运行
# ---------------------------------------------------------------------------
class HostHarness:
    """宿主侧：模拟平台托管运行时，驱动托管 Solver 子进程。

    - 向 Solver stdin 下发 ``prompt`` 控制命令（触发解题）；
    - 读取 Solver stdout 的 ``host_bridge_request`` 并分发到 TsecBenchClient；
    - 回写 ``host_bridge_response``；
    - 收到 ``agent_end`` 或 stdin 关闭后结束。

    本地自测（selftest_stdio）用它与真实 ``hosted_solver.py`` 子进程配对，从而
    在不上真实平台的情况下端到端验证「托管运行」协议接线。
    """

    def __init__(self, client: TsecBenchClient, stdin: TextIO, stdout: TextIO,
                 timeout: float = 120.0):
        self.client = client
        self._in = stdin
        self._out = stdout
        self._timeout = timeout

    def _send(self, msg: dict) -> None:
        self._out.write(json.dumps(msg, ensure_ascii=False) + "\n")
        self._out.flush()

    def serve(self, challenge_id: str, prompt_text: str = "please solve the challenge") -> dict:
        """驱动单题托管运行，返回该 Solver 上报的 agent_end 载荷（若有）。"""
        # 1) 下发 prompt 控制命令：平台由此触发 Solver 开始解题
        self._send({"type": "prompt", "prompt": prompt_text,
                    "challenge_id": challenge_id})
        # 2) 读取 Solver 事件直到 agent_end / EOF
        last_end: dict = {}
        while True:
            line = self._in.readline()
            if not line:
                break  # Solver 进程退出 / stdin 关闭
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            t = msg.get("type")
            if t == "host_bridge_request":
                rid = msg.get("request_id")
                action = msg.get("action")
                params = msg.get("params", {}) or {}
                code = params.get("unique_code") or challenge_id
                try:
                    data = self._dispatch(action, params, code)
                    resp = {"request_id": rid, "type": "host_bridge_response",
                            "ok": True, "data": data}
                except Exception as e:  # noqa
                    resp = {"request_id": rid, "type": "host_bridge_response",
                            "ok": False, "error": str(e)}
                self._send(resp)
            elif t == "agent_end":
                last_end = msg
                break
            # 其它事件（如 steer/follow_up 回显）忽略
        return last_end

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


# 向后兼容别名：早期版本使用 MockHostBridge，现统一为 HostHarness
MockHostBridge = HostHarness
