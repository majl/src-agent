# SRC-Hunter tsecbench 托管运行镜像
# 平台以子进程方式运行 Solver：python -m src.agent.hosted_solver
FROM python:3.11-slim

WORKDIR /app

# 依赖（含编译型仅在需要时安装；纯 Python 工具链）
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 源码
COPY . /app

# 平台托管运行时通过环境变量注入（切勿硬编码凭证）：
#   TCH_CHALLENGE_ID  当前题目码（平台注入；兼容 TSEC_CHALLENGE_ID / BENCHMARK_CHALLENGE_ID / CHALLENGE_ID）
#   BENCHMARK_BASE_URL 平台地址（默认 https://tsecbench.zc.tencent.com）
#   BENCHMARK_TOKEN    评测凭证
#   HY3_API_KEY        HY3 大模型密钥（可选；缺失时自动降级为启发式 mock）
ENV PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# 托管 Solver 入口（平台子进程形态）。stdout 仅协议 JSONL，日志走 stderr。
ENTRYPOINT ["python", "-m", "src.agent.hosted_solver"]
