#!/usr/bin/env python3
"""独立侦察脚本：对目标做黑盒资产发现并打印可达资产。

用法：
    python scripts/recon.py http://127.0.0.1:8800/range
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tools.recon import recon_target


def main():
    ap = argparse.ArgumentParser(description="SRC-Hunter 黑盒侦察脚本")
    ap.add_argument("target", help="目标 URL 或 host")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出")
    args = ap.parse_args()

    assets = recon_target(args.target)
    if args.json:
        import json
        print(json.dumps([a.__dict__ for a in assets], ensure_ascii=False, indent=2))
    else:
        print(f"共发现 {len(assets)} 个可达资产：")
        for a in assets:
            print(f"  [{a.status}] {a.server or '-':<20} {a.url}  {a.note}")


if __name__ == "__main__":
    main()
