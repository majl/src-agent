#!/usr/bin/env python3
"""Host Bridge 协议一致性冒烟测试（纯标准库，无需 requests/pydantic）。

本测试**直接加载真实的** ``src/agent/bridge.py``（仅用 sys.modules 桩掉
``requests`` / ``pydantic`` 这两个第三方依赖），在内存管道上复现 tsecbench
「托管运行」模式的 JSONL 双向通道，验证以下契约：

  1. Solver 侧 HostChannel 写出 ``host_bridge_request``（四个标准动作）；
  2. 宿主侧 HostHarness 读取请求、按 request_id 分发到 SDK 客户端、回写
     ``host_bridge_response``；
  3. request_id 关联正确（响应精准唤醒对应阻塞调用）；
  4. 控制命令（prompt / steer）经 on_command 回调正确路由；
  5. 生命周期事件 ``agent_end`` 被宿主正确接收。

四个标准动作名与 tsecbench 官方 Host Bridge 完全一致：
  challenge_get_state / challenge_get_hint / challenge_submit_flag / challenge_is_completed

说明：完整集成自测请用 ``python -m src.agent.selftest_stdio --mock --all``
（需要 requests/pydantic 运行环境，即评测镜像）。本脚本用于在无第三方依赖的
沙箱中快速验证协议层接线正确。

用法：
    python scripts/hostbridge_smoke.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import types

# ---------------------------------------------------------------------------
# 1) 桩掉第三方依赖，使真实 bridge.py 能被干净 import
#    （bridge.py 仅把 pydantic 用作类型注解、把 requests 用在 SDK 客户端内部，
#     协议层本身不依赖它们；这里提供最小桩即可。）
# ---------------------------------------------------------------------------
def _pkg(name: str) -> types.ModuleType:
    m = types.ModuleType(name)
    m.__path__ = []
    return m


sys.modules.setdefault("src", _pkg("src"))
sys.modules.setdefault("src.agent", _pkg("src.agent"))
sys.modules.setdefault("src.platform", _pkg("src.platform"))

_tc = types.ModuleType("src.platform.tsecbench_client")
_tc.TsecBenchClient = object  # 仅作类型注解使用
sys.modules["src.platform.tsecbench_client"] = _tc

# challenge 桩：必须提供可构造的 ChallengeSpec（带 to_dict）
_ch = types.ModuleType("src.agent.challenge")


class ChallengeSpec:
    def __init__(self, unique_code="", description="", difficulty="",
                 level=0, total_score=0, flag_count=0, correct_flag_count=0,
                 is_completed=False, container_addr=None, hint=None):
        self.unique_code = unique_code
        self.description = description
        self.difficulty = difficulty
        self.level = level
        self.total_score = total_score
        self.flag_count = flag_count
        self.correct_flag_count = correct_flag_count
        self.is_completed = is_completed
        self.container_addr = container_addr or []
        self.hint = hint

    def to_dict(self) -> dict:
        return {
            "unique_code": self.unique_code,
            "description": self.description,
            "difficulty": self.difficulty,
            "level": self.level,
            "total_score": self.total_score,
            "flag_count": self.flag_count,
            "correct_flag_count": self.correct_flag_count,
            "is_completed": self.is_completed,
            "container_addr": self.container_addr,
            "hint": self.hint,
        }


_ch.ChallengeSpec = ChallengeSpec
sys.modules["src.agent.challenge"] = _ch

# ---------------------------------------------------------------------------
# 2) 加载真实 bridge.py（按包路径注册，使其相对导入解析到上面的桩）
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
_BRIDGE_PATH = os.path.join(_HERE, "..", "src", "agent", "bridge.py")
_BRIDGE_PATH = os.path.abspath(_BRIDGE_PATH)

_spec = importlib.util.spec_from_file_location("src.agent.bridge", _BRIDGE_PATH)
bridge = importlib.util.module_from_spec(_spec)
sys.modules["src.agent.bridge"] = bridge
_spec.loader.exec_module(bridge)  # 加载真实模块：HostChannel / StdioBridge / HostHarness

# ---------------------------------------------------------------------------
# 3) 伪造 SDK 客户端（记录调用，校验分发与响应形状）
# ---------------------------------------------------------------------------
class FakeClient:
    def __init__(self):
        self.calls: list[tuple] = []
        self.completed = False

    def start(self, code):
        self.calls.append(("start", code))
        return []

    def list_challenges(self):
        class _C:
            unique_code = "DEMO-001"
            description = "演示题：入口点存在编码绕过"
            difficulty = "medium"
            level = 2
            total_score = 100
            flag_count = 1
            correct_flag_count = 1 if self.completed else 0
            is_completed = self.completed
            container_addr = ["http://127.0.0.1:8800/range"]
        return [_C()]

    def hint(self, code):
        self.calls.append(("hint", code))
        return "尝试对入口点做编码绕过"

    def submit(self, code, flag):
        self.calls.append(("submit", code, flag))
        ok = flag == "FLAG{correct}"
        if ok:
            self.completed = True

        class _R:
            correct = ok
            awarded = 100 if ok else 0
            cumulative_score = 100 if ok else 0
        return _R()

    def close(self, code):
        self.calls.append(("close", code))
        return True


# ---------------------------------------------------------------------------
# 4) 在内存管道上跑 Solver ↔ 宿主 双向通道
# ---------------------------------------------------------------------------
def _main() -> int:
    client = FakeClient()
    commands: list[dict] = []
    prompt_ev = threading.Event()
    result: dict = {}

    # host_w 宿主写 → solver 读（solver 的 stdin）
    # solver_w solver 写 → host 读（solver 的 stdout）
    host_r, solver_w = os.pipe()   # 通道A：Solver写(solver_w) → 宿主读(host_r)
    solver_r, host_w = os.pipe()   # 通道B：宿主写(host_w) → Solver读(solver_r)
    solver_stdin = os.fdopen(solver_r, "r")   # Solver 读宿主写来的控制命令/响应
    solver_stdout = os.fdopen(solver_w, "w")  # Solver 写请求/生命周期事件
    host_stdin = os.fdopen(host_r, "r")      # 宿主读 Solver 写来的请求
    host_stdout = os.fdopen(host_w, "w")     # 宿主写控制命令/响应给 Solver

    def on_command(msg: dict) -> None:
        commands.append(msg)
        if msg.get("type") == "prompt":
            prompt_ev.set()

    ch = bridge.HostChannel(solver_stdin, solver_stdout, timeout=15.0,
                            on_command=on_command)
    sb = bridge.StdioBridge(ch)

    def host_thread() -> None:
        try:
            harness = bridge.HostHarness(client, host_stdin, host_stdout, timeout=15.0)
            result["end"] = harness.serve("DEMO-001", "solve please")
        except Exception as e:  # noqa
            import traceback
            sys.stderr.write("[smoke:host_thread] EXC: %r\n" % e)
            traceback.print_exc()

    ht = threading.Thread(target=host_thread, daemon=True)
    ht.start()

    # 等待宿主下发 prompt，再开始解题
    assert prompt_ev.wait(15.0), "未收到宿主 prompt 控制命令"
    # 控制命令路由校验：宿主侧补发一条 steer，应被 on_command 捕获
    host_stdout.write(json.dumps({"type": "steer", "note": "prefer encoded payload"}) + "\n")
    host_stdout.flush()

    # —— 四个标准动作 ——
    spec = sb.get_state("DEMO-001")
    assert spec.unique_code == "DEMO-001", "get_state 返回 unique_code 异常"
    hint = sb.get_hint("DEMO-001")
    assert hint and "编码" in hint, "get_hint 返回异常"
    sub = sb.submit_flag("DEMO-001", "FLAG{correct}")
    assert sub["correct"] is True, "submit_flag 判定异常"
    done = sb.is_completed("DEMO-001")
    assert done is True, "is_completed 判定异常"

    # 生命周期事件
    ch.send_event({"type": "agent_end", "success": True,
                   "unique_code": "DEMO-001", "flags": ["FLAG{correct}"]})

    ht.join(15.0)
    end = result.get("end") or {}
    assert end.get("success") is True, f"宿主未正确收到 agent_end: {end}"

    # 校验分发记录（四个标准动作经 HostHarness 分发到 SDK 客户端；
    # get_state / is_completed 经 list_challenges 调用，已通过响应数据验证）
    called = {c[0] for c in client.calls}
    for a in ("hint", "submit"):
        assert a in called, f"动作 {a} 未分发到 SDK 客户端"

    # 校验控制命令路由（steer 被捕获）
    types_seen = {m.get("type") for m in commands}
    assert "prompt" in types_seen, "prompt 未路由到 on_command"
    assert "steer" in types_seen, "steer 控制命令未路由到 on_command"

    print("[smoke] ✅ Host Bridge 协议层全部契约通过：")
    print(f"        - 四个标准动作分发：{sorted(called)}")
    print(f"        - request_id 关联：成功（submit_flag.correct=True）")
    print(f"        - 控制命令路由：{sorted(types_seen)}")
    print(f"        - agent_end 生命周期：success={end.get('success')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
