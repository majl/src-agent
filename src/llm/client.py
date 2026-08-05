"""HY3（腾讯混元）LLM 客户端。

- 生产模式：OpenAI 兼容协议，base_url=tokenhub.tencentmaas.com/v1，model=hy3
- 离线模式：provider=mock，返回确定性占位结果，保证流水线可端到端跑通
- 内置分级调用、token 计量、成本统计、失败重试
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from ..config import LLMConfig, LLMTier


@dataclass
class LLMResponse:
    content: str
    reasoning: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    latency_s: float = 0.0
    raw: dict = field(default_factory=dict)


class UsageMeter:
    """累计 token 与成本计量。"""

    def __init__(self, price_prompt: float, price_completion: float):
        self.price_prompt = price_prompt
        self.price_completion = price_completion
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.calls = 0
        self.cost_usd = 0.0

    def add(self, prompt_tokens: int, completion_tokens: int) -> float:
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        self.calls += 1
        cost = (prompt_tokens / 1000) * self.price_prompt + (completion_tokens / 1000) * self.price_completion
        self.cost_usd += cost
        return cost

    def snapshot(self) -> dict:
        return {
            "calls": self.calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": round(self.cost_usd, 4),
        }


class HY3Client:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self.meter = UsageMeter(cfg.price_per_1k_prompt, cfg.price_per_1k_completion)
        self._client = None
        if cfg.provider == "hy3" and cfg.api_key:
            from openai import OpenAI
            self._client = OpenAI(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)
        elif cfg.provider == "hy3" and not cfg.api_key:
            print("[warn] 未检测到 HY3_API_KEY，自动降级为 mock 模式（仅演示流水线）。")
            self.cfg.provider = "mock"

    @property
    def mode(self) -> str:
        return self.cfg.provider

    def chat(
        self,
        messages: list[dict],
        tier: str = "fast",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        response_format: Optional[dict] = None,
    ) -> LLMResponse:
        t: LLMTier = self.cfg.tiers.get(tier, self.cfg.tiers["fast"])
        temp = temperature if temperature is not None else t.temperature
        mt = max_tokens if max_tokens is not None else t.max_tokens

        if self.cfg.provider == "mock":
            return self._mock(messages, t)

        # 真实 HY3 调用
        from tenacity import retry, stop_after_attempt, wait_exponential

        @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
        def _call():
            kwargs = dict(
                model=t.model,
                messages=messages,
                temperature=temp,
                max_tokens=mt,
            )
            if t.reasoning:
                kwargs["extra_body"] = {"reasoning_effort": "high"}
            if response_format:
                kwargs["response_format"] = response_format
            return self._client.chat.completions.create(**kwargs)

        start = time.time()
        resp = _call()
        latency = time.time() - start

        content = resp.choices[0].message.content or ""
        reasoning = getattr(resp.choices[0].message, "reasoning_content", "") or ""
        usage = resp.usage
        pt = getattr(usage, "prompt_tokens", 0) or 0
        ct = getattr(usage, "completion_tokens", 0) or 0
        cost = self.meter.add(pt, ct)

        return LLMResponse(
            content=content, reasoning=reasoning, prompt_tokens=pt,
            completion_tokens=ct, cost_usd=cost, latency_s=latency,
            raw=dict(model=t.model, tier=t.name),
        )

    def _mock(self, messages: list[dict], tier: LLMTier) -> LLMResponse:
        """离线占位：模拟 HY3 的结构化返回，使流水线可演示。

        能识别黑盒决策意图（在 system 提示词中埋了 #RECON_RANK / #EXPLOIT_PLAN / #FLAG_JUDGE
        标记），分别返回决策形态 JSON——其中 flag 判定会在 mock 下通过正则真实生效，其余意图返回
        空决策，由调用方降级为启发式，从而既验证接线又不破坏离线可跑性。
        """
        system = ""
        last = ""
        for m in messages:
            if m.get("role") == "system":
                system += m.get("content", "")
            last = m.get("content", "")
        combined = system + "\n" + last

        # ---- 黑盒决策：flag 判定（离线也能真生效）----
        if "#FLAG_JUDGE" in system:
            m_flag = re.search(r"flag\{[^}]+\}", last)
            content = json.dumps({
                "is_flag": bool(m_flag),
                "flag": m_flag.group(0) if m_flag else "",
                "reason": "[MOCK-HY3] 离线模式按正则判定响应是否含 flag{...}",
            }, ensure_ascii=False)
            pt, ct = len(last) // 2, 30
            cost = self.meter.add(pt, ct)
            return LLMResponse(content=content, prompt_tokens=pt, completion_tokens=ct, cost_usd=cost, latency_s=0.01)

        # ---- 黑盒决策：资产排序 / 利用规划（离线返回空，调用方降级启发式）----
        if "#RECON_RANK" in system:
            content = json.dumps({"ranked": [], "summary": "[MOCK-HY3] 离线模式跳过资产排序，沿用侦察默认顺序"}, ensure_ascii=False)
            pt, ct = len(last) // 2, 20
            cost = self.meter.add(pt, ct)
            return LLMResponse(content=content, prompt_tokens=pt, completion_tokens=ct, cost_usd=cost, latency_s=0.01)
        if "#EXPLOIT_PLAN" in system:
            content = json.dumps({"plan": [], "summary": "[MOCK-HY3] 离线模式跳过利用规划，沿用启发式优先级"}, ensure_ascii=False)
            pt, ct = len(last) // 2, 20
            cost = self.meter.add(pt, ct)
            return LLMResponse(content=content, prompt_tokens=pt, completion_tokens=ct, cost_usd=cost, latency_s=0.01)

        # ---- 黑盒决策：杀伤链叙事合成（离线返回启发式占位，调用方用 build_killchain 润色）----
        if "#KILLCHAIN_SYNTH" in system:
            content = json.dumps({
                "narrative": "[MOCK-HY3] 离线模式跳过杀伤链叙事合成，沿用启发式攻击链叙事。",
                "objective_reached": True,
                "summary": "[MOCK-HY3] 请配置 HY3_API_KEY 以获得连贯攻击叙事。",
            }, ensure_ascii=False)
            pt, ct = len(last) // 2, 25
            cost = self.meter.add(pt, ct)
            return LLMResponse(content=content, prompt_tokens=pt, completion_tokens=ct, cost_usd=cost, latency_s=0.01)

        # ---- 白盒审计占位（默认）----
        content = json.dumps({
            "findings": [],
            "summary": f"[MOCK-HY3/{tier.name}] 离线模式未调用真实模型，请配置 HY3_API_KEY 后运行。",
            "needs_context": False,
        }, ensure_ascii=False)
        pt = len(last) // 2
        ct = 50
        cost = self.meter.add(pt, ct)
        return LLMResponse(content=content, prompt_tokens=pt, completion_tokens=ct, cost_usd=cost, latency_s=0.01)
