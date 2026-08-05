#!/usr/bin/env python3
"""二进制维度独立分析脚本：对本地 ELF 文件或靶场二进制端点做自动漏洞分析。

覆盖 tsecbench 的 BINARY 评分维度（权重 15%）。仅做检测与发现输出，不做 flag 提交，
可单独用于二进制加固排查、pwn 题静态侦察或靶场自检。

用法：
    # 分析本地 ELF 文件
    python scripts/binary_scan.py --file ./vuln_pwn

    # 对 mock 靶场的二进制端点分析（自动走 scan_binary 靶场模式）
    python scripts/binary_scan.py --target http://127.0.0.1:8800/range

    # 真实靶机（Linux，自动启用 pwntools checksec 增强）
    python scripts/binary_scan.py --file ./chal --detail
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.binary import analyze_binary, scan_binary


def main():
    ap = argparse.ArgumentParser(description="SRC-Hunter 二进制维度分析（栈溢出/格式化字符串/危险函数/硬编码flag）")
    ap.add_argument("--file", "-f", default=None, help="本地 ELF 文件路径")
    ap.add_argument("--target", "-t", default=None, help="靶场基址，如 http://127.0.0.1:8800/range（走 scan_binary 靶场模式）")
    ap.add_argument("--detail", action="store_true", help="输出保护机制详情与字符串样例")
    args = ap.parse_args()

    if args.file:
        res = analyze_binary(args.file, detail=args.detail)
        props = res["props"]
        flag = res["flag"]
        binary_findings = res["findings"]
        print(f"[*] 分析本地 ELF：{args.file}")
        print(f"    ELF={props.get('is_elf')} arch={props.get('arch')} {props.get('bits')}bit "
              f"PIE={props.get('pie')} NX={props.get('nx')} Canary={props.get('canary')} RELRO={props.get('relro')}")
        if flag:
            print(f"    硬编码 flag: {flag}")
    elif args.target:
        binary_findings = scan_binary(args.target)
        props, flag = {}, None
        print(f"[*] 靶场二进制模式：{args.target}/pwn/binary")
    else:
        print("[!] 需提供 --file 或 --target")
        return 1

    if not binary_findings:
        print("[+] 未发现二进制维度风险特征")
        return 0

    print(f"[+] 发现 {len(binary_findings)} 个二进制疑似风险：\n")
    payload = []
    for f in binary_findings:
        payload.append(f.model_dump())
        print(f"  · [{f.severity.value}] {f.vuln_type.value}")
        print(f"      文件: {f.file}")
        print(f"      说明: {f.description}")
        print(f"      证据: {f.evidence[:160]}")
        print(f"      PoC : {f.poc}")
        print()

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "out-binary", "binary_findings.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    print(f"[+] 结果已写出：{out}")


if __name__ == "__main__":
    main()
