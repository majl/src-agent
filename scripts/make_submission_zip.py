#!/usr/bin/env python3
"""生成 SRC-Hunter 参赛提交压缩包（排除缓存/密钥/中间产物，保留验证证据）。"""
import os
import zipfile

SRC = "/Users/malong/WorkBuddy/2026-08-05-20-12-40/src-agent"
OUT_ZIP = "/Users/malong/WorkBuddy/2026-08-05-20-12-40/src-agent-submission.zip"

EXCLUDE_DIRS = {
    "__pycache__", ".venv", "venv", "env", ".git", ".idea", ".vscode",
}
EXCLUDE_EXT = {".pyc", ".egg-info"}
EXCLUDE_FILES = {
    ".DS_Store", "*.swp", ".env", "src-agent-submission.zip",
}
# 运行输出目录整体排除，但 out-verify（验证证据）保留
EXCLUDE_OUT_DIRS = {
    "out-agent", "out-agent-kc", "out-bench", "out-bench-nollm",
    "out-bench-regress", "out-binary", "out-binary-bench", "out-cloud",
    "out-demo", "out-killchain", "out-regress", "out-target", "out-target-range",
}


def keep(path: str) -> bool:
    rel = os.path.relpath(path, SRC)
    parts = rel.split(os.sep)
    # 排除特定缓存/环境目录
    if any(p in EXCLUDE_DIRS for p in parts):
        return False
    # 排除运行输出目录（out-verify 除外）
    if parts[0] in EXCLUDE_OUT_DIRS:
        return False
    # 排除扩展名
    _, ext = os.path.splitext(path)
    if ext in EXCLUDE_EXT:
        return False
    # 排除具体文件名
    base = os.path.basename(path)
    if base in EXCLUDE_FILES:
        return False
    if base.startswith(".env."):  # .env.local 等真实密钥变体
        return False
    return True


def main():
    count = 0
    size = 0
    with zipfile.ZipFile(OUT_ZIP, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(SRC):
            # 原地剪枝目录遍历
            dirs[:] = [d for d in dirs if keep(os.path.join(root, d))]
            for f in files:
                fp = os.path.join(root, f)
                if not keep(fp):
                    continue
                rel = os.path.relpath(fp, SRC)
                z.write(fp, rel)
                count += 1
                size += os.path.getsize(fp)
    mb = size / 1024 / 1024
    print(f"生成提交包：{OUT_ZIP}")
    print(f"包含文件数：{count}  总大小：{mb:.2f} MB")


if __name__ == "__main__":
    main()
