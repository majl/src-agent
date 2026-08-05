#!/usr/bin/env bash
# 三种接入形态端到端验证脚本
set -u
cd /Users/malong/WorkBuddy/2026-08-05-20-12-40/src-agent
source /Users/malong/.workbuddy/binaries/python/envs/src-agent/bin/activate
OUT=out-verify
mkdir -p "$OUT"

kill_mock() {
  pkill -f "mock_server" 2>/dev/null
  pkill -f "cli.py bench" 2>/dev/null
  pkill -f "src.agent.selftest_stdio" 2>/dev/null
  pkill -f "main.py" 2>/dev/null
  # 兜底：释放 8800 端口占用
  PIDS=$(lsof -ti :8800 2>/dev/null)
  [ -n "$PIDS" ] && kill -9 $PIDS 2>/dev/null
  sleep 1.5
}

echo "===== VERIFY START $(date) =====" | tee "$OUT/verify.log"

# ---------- 形态一：bench 黑盒跑分 ----------
echo "########## FORM 1: cli.py bench --mock ##########" | tee -a "$OUT/verify.log"
for code in WEB-DEMO-001 CLOUD-DEMO-001 BINARY-DEMO-001 KILLCHAIN-DEMO-001; do
  kill_mock
  echo "----- bench $code -----" | tee -a "$OUT/verify.log"
  python cli.py bench --mock --code "$code" --out "$OUT/bench_$code" 2>&1 | tee -a "$OUT/verify.log"
done

# ---------- 形态二：main.py API 接入（封装 Agent） ----------
kill_mock
echo "########## FORM 2: main.py --mock --all ##########" | tee -a "$OUT/verify.log"
python main.py --mock --all --out "$OUT/api" 2>&1 | tee -a "$OUT/verify.log"

# ---------- 形态三：selftest_stdio 托管形态 ----------
for code in BINARY-DEMO-001 KILLCHAIN-DEMO-001; do
  kill_mock
  echo "########## FORM 3: selftest_stdio --mock $code ##########" | tee -a "$OUT/verify.log"
  python -m src.agent.selftest_stdio --mock --code "$code" 2>&1 | tee -a "$OUT/verify.log"
done

echo "===== VERIFY DONE $(date) =====" | tee -a "$OUT/verify.log"
