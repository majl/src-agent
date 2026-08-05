#!/usr/bin/env python3
"""SRC-Hunter CLI：一行命令完成 SRC 定向漏洞挖掘全流程。

白盒（代码审计）形态：
    python cli.py demo                                   # 内置脱敏样例，离线跑通
    HY3_API_KEY=sk-xxx python cli.py scan -t ./repo      # 真实 HY3 白盒审计

黑盒（自主渗透 / 平台评测）形态：
    python cli.py bench --mock                           # 本地 mock 平台全闭环（无需 token）
    BENCHMARK_TOKEN=xxx python cli.py bench --base-url https://tsecbench.zc.tencent.com
    python cli.py tsecbench list  --base-url ... --token ...
    python cli.py web                                     # 启动 Web 控制台
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from src.agents.redteam import RedTeamAgent
from src.config import Settings
from src.llm.client import HY3Client
from src.metrics import Metrics
from src.orchestrator import Orchestrator
from src.platform.tsecbench_client import TsecBenchClient
from src.report import write_all, to_markdown


def build_settings(args) -> Settings:
    s = Settings.load(args.config)
    s.pipeline.target = args.target or s.pipeline.target
    s.pipeline.mode = getattr(args, "mode", "whitebox")
    s.pipeline.verify_poc = getattr(args, "verify", False)
    s.pipeline.ground_truth = getattr(args, "ground_truth", None)
    s.pipeline.budget_usd = getattr(args, "budget", 5.0)
    if getattr(args, "llm", None):
        s.llm.provider = args.llm
    if getattr(args, "api_key", None):
        s.llm.api_key = args.api_key
    if getattr(args, "max_files", None):
        s.pipeline.max_files = args.max_files
    return s


# ---------------- 白盒（保留） ----------------
def cmd_whitebox(args):
    if args.cmd == "demo":
        demo_dir = Path(__file__).parent / "demo" / "vuln_sample"
        args.target = str(demo_dir)
        args.mode = "whitebox"
        args.ground_truth = str(demo_dir / "ground_truth.json")
        args.llm = args.llm or "mock"
        args.max_files = 50
        args.verify = getattr(args, "verify", False)
        args.budget = getattr(args, "budget", 5.0)
        args.config = getattr(args, "config", None)

    s = build_settings(args)
    orch = Orchestrator(s)
    print(f"[*] 模式={s.pipeline.mode}  LLM={orch.client.mode}  目标={s.pipeline.target}")
    result, metrics = orch.run()

    out_dir = args.out if hasattr(args, "out") else "./out"
    write_all(result, metrics, out_dir, project=Path(s.pipeline.target).name)
    print(to_markdown(result, metrics, project=Path(s.pipeline.target).name))
    print(f"\n[+] 报告已写出：{out_dir}/ (report.md / report.json / report.sarif)")
    return 0


# ---------------- 黑盒：平台一键跑分 ----------------
def cmd_bench(args):
    if args.mock:
        from src.platform.mock_server import run_mock_server
        run_mock_server(8800)
        args.base_url = "http://127.0.0.1:8800"
        args.token = args.token or "mock-token"

    if not args.base_url or not args.token:
        print("[!] 需提供 --base-url 与 --token，或使用 --mock 启动本地平台")
        return 1

    client = TsecBenchClient(base_url=args.base_url, token=args.token)
    # 构建 HY3 客户端（自动读 HY3_API_KEY 环境变量；无 key 时降级 mock 离线模式）
    llm = HY3Client(Settings().llm)
    use_llm = not getattr(args, "no_llm", False)
    agent = RedTeamAgent(client=client, llm=llm, use_llm=use_llm)
    print(f"[*] 对接平台 {args.base_url}  LLM决策={agent.use_llm} (mode={llm.mode}) …")
    res = agent.solve_challenge(unique_code=args.code, close=not args.no_close)

    # 六项量化指标（黑盒场景映射）
    m = Metrics()
    m.discovery_rate = 1.0 if res.get("flag") else 0.0
    m.false_positive_rate = 0.0
    m.audit_volume_loc = 0
    m.high_severity_find_time_s = float(res.get("elapsed_s", 0.0))
    m.llm_cost_usd = float(res.get("llm_cost_usd", 0.0))
    m.human_ratio = 0.0

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "bench_result.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "report.json").write_text(
        json.dumps({"metrics": m.dict(), "bench": res}, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(json.dumps(res, ensure_ascii=False, indent=2))
    print("\n=== 量化指标（黑盒映射） ===")
    for row in m.to_compare_table():
        print(f"  {row['指标']:<16} Agent={row['Agent']}")
    print(f"\n[+] 发现 flag: {res.get('flag')}  提交结果: {res.get('submitted_ok')}")
    print(f"[+] LLM 调用: {res.get('llm_calls')} 次  成本: ${res.get('llm_cost_usd', 0.0)}")
    print(f"[+] 产物：{out}/bench_result.json , {out}/report.json")
    return 0


# ---------------- 平台操作 ----------------
def cmd_tsecbench(args):
    if not args.base_url or not args.token:
        print("[!] 需提供 --base-url 与 --token（或设置环境变量 BENCHMARK_BASE_URL / BENCHMARK_TOKEN）")
        return 1
    client = TsecBenchClient(base_url=args.base_url, token=args.token)
    if args.action == "list":
        for c in client.list_challenges():
            print(json.dumps(c.dict(), ensure_ascii=False))
    elif args.action == "start":
        print(json.dumps(client.start(args.code), ensure_ascii=False))
    elif args.action == "submit":
        print(json.dumps(client.submit(args.code, args.flag).dict(), ensure_ascii=False))
    elif args.action == "close":
        print(json.dumps({"closed": client.close(args.code)}, ensure_ascii=False))
    elif args.action == "hint":
        print(json.dumps({"hint": client.hint(args.code)}, ensure_ascii=False))
    else:
        print("[!] action 仅支持 list/start/submit/close/hint")
        return 1
    return 0


# ---------------- Web 控制台 ----------------
def cmd_web(args):
    from src.web.app import run_web
    srv = run_web(args.port)
    print(f"[*] Web 控制台: http://0.0.0.0:{args.port}  (Ctrl+C 停止)")
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()
    return 0


# ---------------- 黑盒：输入 IP/域名 自动漏洞挖掘 ----------------
def cmd_target(args):
    print("=" * 64)
    print("⚠️  合规声明：本工具仅可用于你拥有合法授权的目标——")
    print("    自有资产 / 授权渗透测试 / SRC 平台范围内的目标。")
    print("    严禁对未授权设备进行任何扫描或攻击。")
    print("=" * 64)

    entries: list[str] = []
    if getattr(args, "entry", None):
        entries = [args.entry]
    else:
        if not getattr(args, "target", None):
            print("[!] 需提供 --target <IP/域名> 或 --entry <完整URL>")
            return 1
        from src.tools.recon import probe_ports
        ports = None
        if getattr(args, "ports", None):
            try:
                ports = [int(x) for x in args.ports.split(",") if x.strip()]
            except ValueError:
                print("[!] --ports 格式错误（示例：80,443,8080）")
                return 1
        print(f"[*] 探测 {args.target} 的开放 Web 端口 …")
        entries = probe_ports(args.target, ports=ports)
        if not entries:
            print("[!] 未发现开放的可达 Web 端口（可用 --ports 指定更多端口）")
            return 1
        for e in entries:
            print(f"    · {e}")

    llm = HY3Client(Settings().llm)
    agent = RedTeamAgent(llm=llm, use_llm=not getattr(args, "no_llm", False))

    all_findings: list[dict] = []
    flags: list[str] = []
    for entry in entries:
        print(f"\n[*] 入口 {entry}：自动化侦察 → 漏洞扫描 → 利用验证 …")
        res = agent.solve_target(entry, break_on_flag=False)
        all_findings.extend(res.get("findings_detail", []))
        if res.get("flag"):
            flags.append(res["flag"])
        print(f"    资产 {res.get('assets')}  疑似漏洞 {res.get('findings')}  "
              f"耗时 {res.get('elapsed_s')}s  LLM调用 {res.get('llm_calls')}")

    # 去重（按 类型 + URL）
    seen = set()
    uniq = []
    for f in all_findings:
        key = (f.get("vuln_type"), f.get("file"))
        if key in seen:
            continue
        seen.add(key)
        uniq.append(f)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    report = {
        "target": getattr(args, "target", None) or args.entry,
        "entries": entries,
        "flags": flags,
        "findings": uniq,
        "llm_calls": llm.meter.calls if llm else 0,
        "llm_cost_usd": round(llm.meter.cost_usd, 4) if llm else 0.0,
    }
    (out / "target_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n=== 漏洞清单（按严重程度） ===")
    order = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "信息": 4}
    for f in sorted(uniq, key=lambda x: order.get(x.get("severity"), 9)):
        mark = "✅已验证" if f.get("verified") else "待验证"
        print(f"  [{f.get('severity')}] {f.get('vuln_type')}  {f.get('file')}  ({mark})")
        if f.get("evidence"):
            print(f"       证据: {f.get('evidence')[:80]}")
    print(f"\n[+] 提取 flag: {flags}")
    print(f"[+] 产物：{out}/target_report.json")
    return 0


# ---------------- 二进制静态分析（本地 ELF） ----------------
def cmd_binary(args):
    from src.tools.binary import analyze_binary

    print(f"[*] 分析二进制：{args.path}")
    res = analyze_binary(args.path, detail=True)
    props = res["props"]

    print("\n=== 保护机制 (checksec) ===")
    print(f"  ELF       : {props.get('is_elf')}")
    print(f"  架构      : {props.get('arch')}  {props.get('bits')}bit  {props.get('endian')}")
    print(f"  PIE       : {props.get('pie')}")
    print(f"  NX        : {props.get('nx')}")
    print(f"  Canary    : {props.get('canary')}")
    print(f"  RELRO     : {props.get('relro')}")
    print(f"  字符串数  : {res['strings_count']}")
    if res["flag"]:
        print(f"  硬编码flag: {res['flag']}")

    findings = res["findings"]
    print(f"\n=== 漏洞发现 ({len(findings)}) ===")
    if not findings:
        print("  [+] 未发现明显二进制漏洞特征")
    for f in findings:
        print(f"  [{f.severity.value}] {f.vuln_type.value}")
        print(f"      说明: {f.description}")
        print(f"      证据: {f.evidence[:160]}")
        print(f"      修复: {f.remediation[:120]}")
        print()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    payload = {"props": props, "flag": res["flag"], "findings": [f.model_dump() for f in findings]}
    (out / "binary_findings.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] 结果已写出：{out}/binary_findings.json")
    return 0


def _ensure_mock():
    """若本地 8800 端口无 mock 平台则启动一个（仅在 --mock 时使用）。"""
    import socket
    from src.platform.mock_server import run_mock_server
    try:
        with socket.create_connection(("127.0.0.1", 8800), timeout=0.4):
            return  # 已在运行
    except OSError:
        pass
    run_mock_server(8800)


def cmd_killchain(args):
    """杀伤链维度分析：对目标 / 题目跑全闭环，重点输出攻击杀伤链报告（KILLCHAIN 维度）。"""
    from src.agents.redteam import RedTeamAgent
    from src.llm.client import HY3Client, LLMConfig
    from src.config import LLMTier
    from src.platform.tsecbench_client import TsecBenchClient
    from src.tools.killchain import TOTAL_PHASES

    use_llm = not args.no_llm
    llm = None
    if use_llm:
        llm = HY3Client(LLMConfig(
            provider="mock",
            api_key="mock",
            base_url="https://tokenhub.tencentmaas.com/v1",
            tiers={"fast": LLMTier("fast", model="hy3", reasoning=False, temperature=0.2, max_tokens=2048),
                   "deep": LLMTier("deep", model="hy3", reasoning=True, temperature=0.4, max_tokens=4096)},
        ))

    if args.mock:
        _ensure_mock()
        client = TsecBenchClient(base_url="http://127.0.0.1:8800", token="mock", timeout=60)
        agent = RedTeamAgent(client=client, llm=llm, use_llm=use_llm)
        if args.code:
            print(f"[*] 杀伤链分析（mock 题目 {args.code}）")
            result = agent.solve_challenge(args.code, close=not args.no_close)
        else:
            print("[*] 杀伤链分析（mock 全部题目逐一）")
            results = []
            for ch in client.list_challenges():
                results.append(agent.solve_challenge(ch.unique_code, close=not args.no_close))
            result = results[-1] if results else {}
    else:
        if not args.target:
            print("[!] 请提供 --target <range根URL> 或 --mock --code <题目>")
            return 1
        print(f"[*] 杀伤链分析目标：{args.target}")
        agent = RedTeamAgent(client=None, llm=llm, use_llm=use_llm)
        result = agent.solve_target(args.target, submit=False)

    kc = result.get("killchain", {})
    print("\n=== 攻击杀伤链报告 (KILLCHAIN) ===")
    print(f"  阶段覆盖   : {kc.get('phases_covered')} / {TOTAL_PHASES}")
    print(f"  覆盖率     : {kc.get('coverage_ratio')}")
    print(f"  最深处阶段 : {kc.get('deepest_phase_name')} (idx={kc.get('deepest_phase_idx')})")
    print(f"  抵达影响   : {kc.get('reached_impact')}")
    print(f"  flag 候选  : {kc.get('flags')}")
    print("\n  攻击链：")
    for s in kc.get("steps", []):
        print(f"    [{s.get('phase_name')}] {s.get('action')}  ({s.get('vuln_type')})")
    print(f"\n  叙事：{kc.get('narrative')}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "killchain_report.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] 完整结果已写出：{out}/killchain_report.json")
    return 0


def main():
    ap = argparse.ArgumentParser(prog="src-hunter", description="SRC 定向漏洞挖掘 Agent (HY3 + 黑盒红队)")
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan", help="白盒审计指定目标")
    sp.add_argument("--target", "-t", required=True)
    sp.add_argument("--config", "-c")
    sp.add_argument("--mode", default="whitebox", choices=["whitebox", "graybox"])
    sp.add_argument("--out", "-o", default="./out")
    sp.add_argument("--llm", choices=["hy3", "mock"])
    sp.add_argument("--api-key", default=None)
    sp.add_argument("--verify", action="store_true", help="真打验证（仅脱敏/授权环境）")
    sp.add_argument("--ground-truth", default=None)
    sp.add_argument("--budget", type=float, default=5.0)
    sp.add_argument("--max-files", type=int, default=200)

    dp = sub.add_parser("demo", help="白盒：用内置脱敏样例靶机跑通流水线")
    dp.add_argument("--config", "-c")
    dp.add_argument("--out", "-o", default="./out-demo")
    dp.add_argument("--llm", choices=["hy3", "mock"], default="mock")
    dp.add_argument("--api-key", default=None)
    dp.add_argument("--verify", action="store_true")
    dp.add_argument("--budget", type=float, default=5.0)

    bp = sub.add_parser("bench", help="黑盒：对接 tsecbench 平台一键跑分（含 mock 模式）")
    bp.add_argument("--mock", action="store_true", help="启动本地 mock 平台全闭环")
    bp.add_argument("--base-url", default=None)
    bp.add_argument("--token", default=None)
    bp.add_argument("--code", default=None, help="题目 unique_code，缺省取第一题")
    bp.add_argument("--no-close", action="store_true", help="解题后不关闭靶机")
    bp.add_argument("--no-llm", action="store_true", help="关闭 HY3 决策（纯启发式，用于对比）")
    bp.add_argument("--out", "-o", default="./out-bench")

    tp = sub.add_parser("tsecbench", help="平台直接操作（list/start/submit/close/hint）")
    tp.add_argument("--action", required=True, choices=["list", "start", "submit", "close", "hint"])
    tp.add_argument("--base-url", default=None)
    tp.add_argument("--token", default=None)
    tp.add_argument("--code", default=None)
    tp.add_argument("--flag", default=None)

    wp = sub.add_parser("web", help="启动 Web 控制台")
    wp.add_argument("--port", type=int, default=7700)

    gp = sub.add_parser("target", help="黑盒：输入目标 IP/域名，自动化漏洞挖掘（出漏洞报告，不提交平台）")
    gp.add_argument("target", nargs="?", default=None, help="目标 IP 或域名（如 1.2.3.4 / example.com）；省略时须用 --entry 指定入口")
    gp.add_argument("--entry", default=None, help="直接指定入口 URL，跳过端口探测（如 http://host:port/path）")
    gp.add_argument("--ports", default=None, help="自定义端口列表，逗号分隔（如 80,443,8080）")
    gp.add_argument("--no-llm", action="store_true", help="关闭 HY3 决策（纯启发式，用于对比）")
    gp.add_argument("--out", "-o", default="./out-target")

    xp = sub.add_parser("binary", help="二进制漏洞静态分析（本地 ELF，对应 BINARY 评分维度）")
    xp.add_argument("path", help="二进制文件路径（ELF）")
    xp.add_argument("--out", "-o", default="./out-binary")

    kp = sub.add_parser("killchain", help="攻击杀伤链分析（对应 KILLCHAIN 评分维度，权重 20%）")
    kp.add_argument("--target", default=None, help="靶机根 URL（如 http://host:port/range），分析其杀伤链")
    kp.add_argument("--mock", action="store_true", help="使用本地 mock 平台")
    kp.add_argument("--code", default=None, help="mock 题目 unique_code（如 KILLCHAIN-DEMO-001）")
    kp.add_argument("--no-close", action="store_true", help="解题后不关闭靶机")
    kp.add_argument("--no-llm", action="store_true", help="关闭 HY3 决策（纯启发式叙事）")
    kp.add_argument("--out", "-o", default="./out-killchain")

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return 1

    if args.cmd in ("scan", "demo"):
        return cmd_whitebox(args)
    if args.cmd == "bench":
        return cmd_bench(args)
    if args.cmd == "tsecbench":
        return cmd_tsecbench(args)
    if args.cmd == "web":
        return cmd_web(args)
    if args.cmd == "target":
        return cmd_target(args)
    if args.cmd == "binary":
        return cmd_binary(args)
    if args.cmd == "killchain":
        return cmd_killchain(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
