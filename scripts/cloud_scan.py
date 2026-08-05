#!/usr/bin/env python3
"""云维度独立扫描脚本：对目标执行 CLOUD 维度检测（IMDS / 未授权云 API / 容器逃逸线索）。

覆盖 tsecbench 的 CLOUD 评分维度（权重 15%）。仅做检测与发现输出，不做 flag 提交，
可单独用于云上攻击面排查或靶场自检。

用法：
    # 对 mock 靶场的云维度端点扫描
    python scripts/cloud_scan.py --target http://127.0.0.1:8800/range

    # 直连链路本地 IMDS（Agent 自身运行于云实例/容器内时）
    python scripts/cloud_scan.py --target http://127.0.0.1:8800/range --direct-imds

    # 真实目标
    python scripts/cloud_scan.py --target http://target:8080
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.cloud import scan_cloud


def main():
    ap = argparse.ArgumentParser(description="SRC-Hunter 云维度扫描（IMDS/未授权云API/容器逃逸）")
    ap.add_argument("--target", "-t", required=True, help="靶场基址，如 http://127.0.0.1:8800/range")
    ap.add_argument("--direct-imds", action="store_true",
                    help="同时直连链路本地 169.254.169.254 探测 IMDS（实例内场景）")
    args = ap.parse_args()

    findings = scan_cloud(args.target, direct_imds=args.direct_imds)

    print(f"[*] 云维度扫描：{args.target}  direct_imds={args.direct_imds}")
    if not findings:
        print("[+] 未发现云维度风险")
        return

    print(f"[+] 发现 {len(findings)} 个云维度疑似风险：\n")
    payload = []
    for f in findings:
        payload.append(f.model_dump())
        print(f"  · [{f.severity.value}] {f.vuln_type.value}")
        print(f"      URL : {f.file}")
        print(f"      说明: {f.description}")
        print(f"      证据: {f.evidence[:160]}")
        print(f"      PoC : {f.poc}")
        print()

    out = Path_out()
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"[+] 结果已写出：{out}")


def Path_out() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out-cloud", "cloud_findings.json")


if __name__ == "__main__":
    main()
