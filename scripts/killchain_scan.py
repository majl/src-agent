#!/usr/bin/env python3
"""独立脚本：攻击杀伤链（KILLCHAIN）维度扫描（对应 tsecbench KILLCHAIN 评分维度，权重 20%）。

仅做「侦察 + 多阶段链游走 + 杀伤链合成与覆盖率评估」，不提交平台，便于快速验证
Agent 的杀伤链能力。

用法：
    # 分析本地 mock 靶机的杀伤链（需先有 mock 平台在 8800，或用 --mock 自动起）
    python scripts/killchain_scan.py --target http://127.0.0.1:8800/range

    # 一键起 mock 并分析 KILLCHAIN 题目
    python scripts/killchain_scan.py --mock --code KILLCHAIN-DEMO-001

    # 指定输出
    python scripts/killchain_scan.py --mock --code KILLCHAIN-DEMO-001 --out ./out-killchain
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# 允许以脚本方式直接运行（python scripts/killchain_scan.py）
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.tools.killchain import scan_killchain_stage, build_killchain, TOTAL_PHASES  # noqa: E402
from src.tools.exploit import extract_flag  # noqa: E402


def _ensure_mock():
    import socket
    from src.platform.mock_server import run_mock_server
    try:
        with socket.create_connection(("127.0.0.1", 8800), timeout=0.4):
            return
    except OSError:
        pass
    run_mock_server(8800)


def _range_root(base: str) -> str:
    """把平台容器地址统一成 /range 根（mock 靶场挂在 /range 下）。"""
    base = base.rstrip("/")
    if base.endswith("/range"):
        return base
    return base + "/range"


def main():
    ap = argparse.ArgumentParser(description="KILLCHAIN 维度独立扫描（不提交）")
    ap.add_argument("--target", default=None, help="靶机根 URL，如 http://127.0.0.1:8800/range")
    ap.add_argument("--mock", action="store_true", help="自动启动本地 mock 平台")
    ap.add_argument("--code", default="KILLCHAIN-DEMO-001", help="mock 题目 unique_code")
    ap.add_argument("--base-url", default="http://127.0.0.1:8800", help="mock 平台地址")
    ap.add_argument("--out", "-o", default="./out-killchain")
    args = ap.parse_args()

    if args.mock:
        _ensure_mock()
        # 从平台拉题，拿到容器地址（/range 根）
        try:
            from src.platform.tsecbench_client import TsecBenchClient
            client = TsecBenchClient(base_url=args.base_url, token="mock", timeout=60)
            chs = [c for c in client.list_challenges() if c.unique_code == args.code]
            if not chs:
                print(f"[!] mock 平台无题目 {args.code}")
                return 1
            ch = client.start(args.code)
            target = _range_root(ch[0])
            print(f"[*] mock 题目 {args.code} 容器地址：{target}")
        except Exception as e:
            print(f"[!] 拉题失败：{e}")
            return 1
    elif args.target:
        target = _range_root(args.target)
    else:
        print("[!] 需提供 --target <url> 或 --mock")
        return 1

    findings = scan_killchain_stage(target)
    if not findings:
        print(f"[*] {target} 未实现多阶段杀伤链（无 /kc/* 端点），无可分析链节点。")
        return 0

    flags = [extract_flag(f.evidence or "") for f in findings if extract_flag(f.evidence or "")]
    report = build_killchain(findings, flags=sorted(set(flags)))

    print("\n=== 攻击杀伤链报告 (KILLCHAIN) ===")
    print(f"  阶段覆盖   : {report.phases_covered} / {TOTAL_PHASES}")
    print(f"  覆盖率     : {report.coverage_ratio}")
    print(f"  最深处阶段 : {report.deepest_phase_name} (idx={report.deepest_phase_idx})")
    print(f"  抵达影响   : {report.reached_impact}")
    print(f"  flag 候选  : {report.flags}")
    print("\n  攻击链：")
    for s in report.steps:
        print(f"    [{s.phase_name}] {s.action}  ({s.vuln_type})")
    print(f"\n  叙事：{report.narrative}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    payload = {"target": target, **report.to_dict()}
    (out / "killchain_report.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[+] 结果已写出：{out}/killchain_report.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
