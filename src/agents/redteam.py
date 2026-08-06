"""红队解题编排 Agent（黑盒自主渗透闭环，HY3 驱动决策）。

流程：侦察资产 → [LLM 资产排序] → Web 漏洞扫描 → 启发式优先级 → [LLM 利用规划]
→ 按序 PoC 真实利用提取 flag → [LLM 判定 flag] → 调用 tsecbench 提交 → 返回结构化结果。

三个决策点由 HY3 驱动（无 key 时降级为启发式，保证离线可跑）：
  1) _llm_rank_assets  —— fast 档，对侦察资产按攻击价值排序（命中 WEB 维度）；
  2) _llm_plan_exploit —— deep 档（开思考链），对漏洞候选排序并给出利用手法；
  3) _llm_judge_flag   —— fast 档，判定响应是否含有效 flag，抑制误提交；
  额外：标准模板未命中时 _llm_craft_exploit 让 HY3 构造自定义利用请求。

成本护栏：累计 LLM 成本超过 budget_usd 后，后续决策自动降级启发式，直接对应评分项
"大模型运行成本"的可控性。
"""
from __future__ import annotations

import json
import time
from typing import Optional

from ..llm.client import HY3Client
from ..llm.prompts import (
    RECON_RANK_SYSTEM, RECON_RANK_USER,
    EXPLOIT_PLAN_SYSTEM, EXPLOIT_PLAN_USER,
    FLAG_JUDGE_SYSTEM, FLAG_JUDGE_USER,
    EXPLOIT_CRAFT_SYSTEM, EXPLOIT_CRAFT_USER,
    KILLCHAIN_SYNTH_SYSTEM, KILLCHAIN_SYNTH_USER,
)
from ..models import Finding, VulnType
from ..platform.tsecbench_client import TsecBenchClient
from ..tools.exploit import run_exploit_full, extract_flag
from ..tools.recon import Asset, recon_target
from ..tools.webscan import scan_assets
from ..tools.cloud import scan_cloud
from ..tools.binary import scan_binary
from ..tools.killchain import scan_killchain_stage, build_killchain, TOTAL_PHASES
from .knowledge import (
    retrieve_for_findings,
    retrieve_for_vuln,
    retrieve as _kb_retrieve,
    knowledge_available,
)

# 优先级：命令注入/RCE 最优先，其次未授权/越权，再次业务逻辑
_PRIORITY = {
    VulnType.COMMAND_INJECTION: 0,
    VulnType.RCE: 0,
    VulnType.SENSITIVE_DATA: 1,
    VulnType.AUTH_BYPASS: 1,
    VulnType.IDOR: 1,
    VulnType.SQLI: 2,
    VulnType.XSS: 3,
    VulnType.PATH_TRAVERSAL: 2,
    VulnType.XXE: 2,
    # 云维度：高价值（常直接拿凭证/flag），优先于一般 Web 漏洞
    VulnType.CLOUD_METADATA: 1,
    VulnType.CLOUD_UNAUTH_API: 1,
    VulnType.CLOUD_CONTAINER_ESCAPE: 1,
    # 二进制维度：常直接拿 shell/flag，最高优先级
    VulnType.BINARY_HARDCODED_SECRET: 0,
    VulnType.BINARY_STACK_OVERFLOW: 0,
    VulnType.BINARY_DANGEROUS_FUNC: 1,
    VulnType.BINARY_FORMAT_STRING: 1,
    # 杀伤链维度：影响阶段（最终 flag）最高优先级；凭据访问/初始立足次之；侦察兜底
    VulnType.KILLCHAIN_IMPACT: 0,
    VulnType.KILLCHAIN_CRED_ACCESS: 1,
    VulnType.KILLCHAIN_INITIAL_ACCESS: 1,
    VulnType.KILLCHAIN_PRIV_ESC: 1,
    VulnType.KILLCHAIN_LATERAL: 1,
    VulnType.KILLCHAIN_RECON: 2,
    VulnType.KILLCHAIN_COLLECTION: 2,
}


class RedTeamAgent:
    def __init__(
        self,
        client: Optional[TsecBenchClient] = None,
        llm: Optional[HY3Client] = None,
        use_llm: Optional[bool] = None,
        budget_usd: float = 5.0,
        use_rag: bool = True,
    ):
        self.client = client
        self.llm = llm
        self.budget_usd = budget_usd
        # RAG 知识增强：默认开启；知识库缺失时自动降级为无增强（不阻断）。
        self.use_rag = bool(use_rag)
        # 只要注入了 HY3 客户端（含 mock 离线模式）即开启 LLM 决策路径；
        # 仅当显式 use_llm=False 时强制纯启发式。
        if use_llm is None:
            self.use_llm = llm is not None
        else:
            self.use_llm = bool(use_llm) and llm is not None

    # ---------- 成本护栏 ----------
    def _within_budget(self) -> bool:
        if not self.llm:
            return False
        return self.llm.meter.cost_usd < self.budget_usd

    def _llm_on(self) -> bool:
        return self.use_llm and self.llm is not None and self._within_budget()

    # ---------- RAG 知识增强助手 ----------
    @staticmethod
    def _augment_system(base: str, kb_ctx: str) -> str:
        """把离线安全技能知识拼接到 system 提示词尾部（缺失则原样返回）。"""
        if not kb_ctx:
            return base
        return (
            base
            + "\n\n# 参考攻击知识（检索自离线安全技能库 CyberSecurity-Skills，仅用于启发利用手法；"
            + "严格限于授权靶场使用，不得用于未授权目标）\n"
            + kb_ctx
        )

    # ---------- 单靶解题 ----------
    def solve_target(
        self,
        target_url: str,
        unique_code: Optional[str] = None,
        break_on_flag: bool = True,
        submit: bool = True,
    ) -> dict:
        """对单一靶机地址执行自主渗透，返回结构化结果。

        submit=True（默认，兼容 cli）：命中 flag 后由内部 client 直接提交。
        submit=False（SDK/托管模式）：只解题、收集全部 flag 候选，**不**自行提交，
        交由上层 bridge（宿主代理）统一提交——对齐 tsecbench「Solver 只能通过
        bridge 动作提交」的托管运行范式。
        """
        t0 = time.time()
        log: list[str] = []

        assets = recon_target(target_url)
        log.append(f"[侦察] 发现 {len(assets)} 个可达资产")

        # RAG 知识增强状态（接入失败则自动降级，不阻断流水线）
        if self.use_rag:
            log.append(
                f"[RAG] 安全技能知识增强：{'已接入 CyberSecurity-Skills' if knowledge_available() else '知识库缺失，已降级为无增强'}"
            )

        # 决策点①：LLM 资产攻击价值排序（fast 档）
        if self._llm_on():
            assets = self._llm_rank_assets(assets, target_url)
            log.append(f"[LLM-决策] 资产排序完成（fast），当前顺序：")
            for a in assets[:5]:
                log.append(f"    · {a.url} [{a.status}]")
        else:
            log.append("[决策] 启发式默认顺序（未启用/超预算 LLM）")

        findings = scan_assets(assets, base_url=target_url)
        log.append(f"[扫描] 命中 {len(findings)} 个疑似漏洞")

        # 云维度检测（CLOUD 评分维度：IMDS 元数据 / 未授权云 API / 容器逃逸线索）
        cloud_findings = scan_cloud(target_url)
        if cloud_findings:
            findings += cloud_findings
            log.append(f"[云检测] 命中 {len(cloud_findings)} 个云维度疑似风险")

        # 二进制维度检测（BINARY 评分维度，权重 15%：栈溢出 / 格式化字符串 /
        # 危险函数 / 硬编码 flag）。靶机若提供 /pwn/binary 端点则自动分析，否则跳过。
        binary_findings = scan_binary(target_url)
        if binary_findings:
            findings += binary_findings
            log.append(f"[二进制检测] 命中 {len(binary_findings)} 个二进制维度疑似风险")

        # 杀伤链维度检测（KILLCHAIN 评分维度，权重 20%）：多阶段靶机游走，
        # 自动推进 entry→internal→flag 三段链，产出带 chain_order 的 Finding。
        killchain_findings = scan_killchain_stage(target_url)
        if killchain_findings:
            findings += killchain_findings
            log.append(f"[杀伤链检测] 命中 {len(killchain_findings)} 个多阶段链节点（KILLCHAIN 维度）")

        # 启发式优先级（始终先排一遍，作为 LLM 规划的兜底基线）
        findings = self._prioritize(findings)

        # 决策点②：LLM 利用规划（deep 档，开思考链）
        if self._llm_on():
            findings = self._llm_plan_exploit(findings, target_url)
            hints = [f"{f.id}:{f.llm_exploit_hint}" for f in findings if f.llm_exploit_hint]
            log.append(f"[LLM-决策] 利用规划完成（deep），手法建议：{len(hints)} 条")
        else:
            log.append("[决策] 启发式利用优先级（未启用/超预算 LLM）")

        flag = None
        flags_all: list[str] = []   # 所有提取到的 flag 候选（交给 bridge 统一提交）
        for f in findings:
            fl, body = run_exploit_full(f, target_url)
            if not fl and f.llm_exploit_hint and self._llm_on():
                # 决策点④：标准模板未命中 → HY3 构造自定义利用
                fl = self._llm_craft_exploit(f, target_url, body)

            if fl:
                flags_all.append(fl)   # 收集所有候选，不依赖 LLM 判定（由平台最终裁定）
                accepted = fl
                # 决策点③：LLM 判定响应是否含有效 flag（抑制误提交）
                if self._llm_on():
                    accepted = self._llm_judge_flag(body, target_url) or fl
                    if accepted:
                        log.append(f"[利用] 提取并经 LLM 判定 flag：{accepted} （{f.vuln_type.value}）")
                else:
                    if accepted:
                        log.append(f"[利用] 提取并确认 flag：{accepted} （{f.vuln_type.value}）")
                if accepted:
                    flag = accepted
                    f.verified = True
                    if break_on_flag:
                        break
            else:
                log.append(f"[利用] {f.id}({f.vuln_type.value}) 标准模板未拿到 flag，跳过")
        if not flag:
            log.append("[利用] 未发现可直接提取的 flag，建议人工/LLM 深度介入")

        # 杀伤链维度（KILLCHAIN，权重 20%）：把全部发现串成连贯攻击链并评估链深度
        kc_report = build_killchain(findings, flags=sorted(set(flags_all)))
        # 决策点⑤：LLM 把攻击链润色为连贯叙事（无 HY3 时沿用启发式叙事）
        if self._llm_on():
            kc_narr = self._llm_synth_killchain(findings, target_url, sorted(set(flags_all)))
            if kc_narr:
                kc_report.narrative = kc_narr
                log.append("[LLM-决策] 杀伤链叙事合成完成（fast）")
        else:
            log.append("[决策] 启发式杀伤链叙事（未启用/超预算 LLM）")
        log.append(
            f"[杀伤链] 覆盖 {kc_report.phases_covered}/{TOTAL_PHASES} "
            f"阶段，最深处={kc_report.deepest_phase_name}，抵达影响={kc_report.reached_impact}"
        )

        submitted_ok = None
        if submit and flag and self.client and unique_code:
            res = self.client.submit(unique_code, flag)
            submitted_ok = bool(res.correct)
            log.append(f"[提交] correct={res.correct} awarded={res.awarded} cumulative={res.cumulative_score}")

        llm_info = self.llm.meter.snapshot() if self.llm else {"calls": 0, "cost_usd": 0.0}
        return {
            "target": target_url,
            "unique_code": unique_code,
            "assets": len(assets),
            "findings": len(findings),
            "flag": flag,
            "flags_all": sorted(set(flags_all)),   # 去重后的全部候选，供 bridge 提交
            "submitted_ok": submitted_ok,
            "elapsed_s": round(time.time() - t0, 2),
            "llm_calls": llm_info["calls"],
            "llm_cost_usd": round(llm_info["cost_usd"], 4),
            "log": log,
            "findings_detail": [f.dict() for f in findings],
            "killchain": kc_report.to_dict(),
        }

    # ---------- 平台全流程（拉题→启动→解题→提交→关闭） ----------
    def solve_challenge(self, unique_code: Optional[str] = None, close: bool = True) -> dict:
        if not self.client:
            raise RuntimeError("solve_challenge 需要传入 TsecBenchClient")
        if not unique_code:
            chs = self.client.list_challenges()
            if not chs:
                raise RuntimeError("平台无可用题目")
            unique_code = chs[0].unique_code
        addrs = self.client.start(unique_code)
        if not addrs:
            raise RuntimeError(f"启动靶机失败：{unique_code}")
        target = addrs[0]
        result = self.solve_target(target, unique_code)
        if close:
            try:
                self.client.close(unique_code)
            except Exception:
                pass
        return result

    # ---------- 优先级（启发式基线） ----------
    def _prioritize(self, findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: (_PRIORITY.get(f.vuln_type, 9), -f.confidence))

    # ---------- 决策点①：资产排序 ----------
    def _llm_rank_assets(self, assets: list[Asset], target_url: str) -> list[Asset]:
        try:
            lines = "\n".join(
                f"{a.url} | {a.status} | {','.join(a.tech) or '-'} | {a.note or '-'}"
                for a in assets
            )
            kb_ctx = _kb_retrieve("信息搜集 侦察 资产发现 攻击面 入口识别", top=2) if self.use_rag else ""
            msgs = [
                {"role": "system", "content": self._augment_system(RECON_RANK_SYSTEM, kb_ctx)},
                {"role": "user", "content": RECON_RANK_USER.format(target=target_url, assets=lines)},
            ]
            resp = self.llm.chat(msgs, tier="fast")
            data = json.loads(_safe_json(resp.content))
            ranked = data.get("ranked") or []
            if not ranked:
                return assets
            order = [r.get("url") for r in ranked if r.get("url")]
            by_url = {a.url: a for a in assets}
            reordered = [by_url[u] for u in order if u in by_url]
            reordered += [a for a in assets if a.url not in order]  # 未提及的补充在末尾
            return reordered
        except Exception as e:
            return assets  # 解析失败 → 启发式兜底

    # ---------- 决策点②：利用规划 ----------
    def _llm_plan_exploit(self, findings: list[Finding], target_url: str) -> list[Finding]:
        try:
            items = "\n".join(
                f"{f.id} | {f.vuln_type.value} | {f.severity.value} | conf={f.confidence:.2f} | "
                f"{f.file} | {f.evidence[:60] or '-'}"
                for f in findings
            )
            kb_ctx = retrieve_for_findings(findings, max_blocks=3) if self.use_rag else ""
            msgs = [
                {"role": "system", "content": self._augment_system(EXPLOIT_PLAN_SYSTEM, kb_ctx)},
                {"role": "user", "content": EXPLOIT_PLAN_USER.format(target=target_url, findings=items)},
            ]
            resp = self.llm.chat(msgs, tier="deep")
            data = json.loads(_safe_json(resp.content))
            plan = data.get("plan") or []
            if not plan:
                return findings
            order = [p.get("id") for p in plan if p.get("id")]
            by_id = {f.id: f for f in findings}
            for p in plan:  # 写入利用手法建议
                fid = p.get("id")
                if fid in by_id and p.get("technique"):
                    by_id[fid].llm_exploit_hint = p.get("technique")
            reordered = [by_id[i] for i in order if i in by_id]
            reordered += [f for f in findings if f.id not in order]
            return reordered
        except Exception:
            return findings

    # ---------- 决策点③：flag 判定 ----------
    def _llm_judge_flag(self, response_text: str, target_url: str) -> Optional[str]:
        try:
            snippet = (response_text or "")[:4000]
            msgs = [
                {"role": "system", "content": FLAG_JUDGE_SYSTEM},
                {"role": "user", "content": FLAG_JUDGE_USER.format(target=target_url, response=snippet)},
            ]
            resp = self.llm.chat(msgs, tier="fast")
            data = json.loads(_safe_json(resp.content))
            if data.get("is_flag") and data.get("flag"):
                return data["flag"]
            return None
        except Exception:
            # 判定失败 → 退回到正则提取（不阻断）
            return extract_flag(response_text)

    # ---------- 决策点④：自定义利用构造 ----------
    def _llm_craft_exploit(self, finding: Finding, target_url: str, last_body: str) -> Optional[str]:
        try:
            kb_ctx = retrieve_for_vuln(finding.vuln_type.name, top=2) if self.use_rag else ""
            msgs = [
                {"role": "system", "content": self._augment_system(EXPLOIT_CRAFT_SYSTEM, kb_ctx)},
                {"role": "user", "content": EXPLOIT_CRAFT_USER.format(
                    target=target_url,
                    vuln_type=finding.vuln_type.value,
                    severity=finding.severity.value,
                    entry=finding.file,
                    evidence=(finding.evidence or "")[:120],
                    hint=finding.llm_exploit_hint or "-",
                )},
            ]
            resp = self.llm.chat(msgs, tier="deep")
            data = json.loads(_safe_json(resp.content))
            if data.get("flag"):
                return data["flag"]
            eu = data.get("exploit_url")
            if eu:
                from ..tools.recon import http_get
                st, h, b = http_get(eu, timeout=8)
                return extract_flag(b)
            return None
        except Exception:
            return None

    # ---------- 决策点⑤：杀伤链叙事合成 ----------
    def _llm_synth_killchain(self, findings: list[Finding], target_url: str, flags: list[str]) -> Optional[str]:
        try:
            from ..tools.killchain import phase_of, _PHASE_BY_ID
            chain_lines = "\n".join(
                f"{_PHASE_BY_ID[phase_of(f.vuln_type)].name} | {f.vuln_type.value} | "
                f"{f.title} | {(f.evidence or '')[:80]}"
                for f in findings
            )
            kb_ctx = retrieve_for_findings(findings, max_blocks=3) if self.use_rag else ""
            msgs = [
                {"role": "system", "content": self._augment_system(KILLCHAIN_SYNTH_SYSTEM, kb_ctx)},
                {"role": "user", "content": KILLCHAIN_SYNTH_USER.format(
                    target=target_url, chain=chain_lines,
                    flags="; ".join(flags) or "（无）",
                )},
            ]
            resp = self.llm.chat(msgs, tier="fast")
            data = json.loads(_safe_json(resp.content))
            return data.get("narrative") or None
        except Exception:
            return None


def _safe_json(text: str) -> str:
    """从 LLM 返回里尽量抠出首个 JSON 对象（容忍代码围栏/前后噪点）。"""
    if not text:
        return "{}"
    s = text.find("{")
    e = text.rfind("}")
    if s != -1 and e != -1 and e > s:
        return text[s:e + 1]
    return "{}"
