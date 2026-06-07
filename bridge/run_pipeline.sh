#!/bin/bash
# ============================================================
# ADGFuzz + Sleuth End-to-End Pipeline
# ============================================================
# 用法:
#   ./run_pipeline.sh [copter|plane|rover|px4] [fuzz_time_seconds]
#
# 示例:
#   ./run_pipeline.sh copter 3600    # 对ArduCopter进行1小时fuzzing+分析
# ============================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$SCRIPT_DIR/.."
ADGFUZZ_DIR="$WORK_DIR/ADGFuzz-main"
SLEUTH_DIR="$WORK_DIR/Sleuth_code"
BRIDGE_DIR="$WORK_DIR/bridge"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 参数
RVTYPE="${1:-copter}"
FUZZ_TIME="${2:-3600}"
OUTPUT_ROOT="$WORK_DIR/output/$TIMESTAMP"

echo "============================================"
echo "  ADGFuzz + Sleuth Pipeline"
echo "  RV Type: $RVTYPE"
echo "  Fuzz Time: ${FUZZ_TIME}s"
echo "  Output: $OUTPUT_ROOT"
echo "============================================"

# 检查环境变量
if [ -z "$ARDUPILOT_HOME" ]; then
    echo "[!] ARDUPILOT_HOME not set!"
    echo "    Run: source ~/.bashrc"
    exit 1
fi

if [ -z "$SLEUTH_PATH" ]; then
    export SLEUTH_PATH="$SLEUTH_DIR"
fi

# ---------- Phase 1: ADGFuzz Fuzzing ----------
echo ""
echo "============================================"
echo " Phase 1: ADGFuzz Bug Discovery"
echo "============================================"

ADGFUZZ_OUT="$OUTPUT_ROOT/phase1_adgfuzz"
mkdir -p "$ADGFUZZ_OUT"

cd "$ADGFUZZ_DIR"

case $RVTYPE in
    copter|plane|rover)
        INITFILE="static/initpath/ArduCopter/ static/initpath/libraries/"
        if [ "$RVTYPE" = "plane" ]; then
            INITFILE="static/initpath/ArduPlane/ static/initpath/libraries/"
        elif [ "$RVTYPE" = "rover" ]; then
            INITFILE="static/initpath/Rover/ static/initpath/libraries/"
        fi

        echo "[+] Running ADGFuzz on ArduPilot $RVTYPE..."
        python adgfuzz.py \
            --initfile $INITFILE \
            --rvtype "$RVTYPE" \
            --time "$FUZZ_TIME" \
            --out_path "$ADGFUZZ_OUT/"
        ;;
    px4)
        echo "[+] Running ADGFuzz on PX4..."
        python adgfuzz.py \
            --initfile static/px4path/lib/ static/px4path/modules/ \
            --rvtype px4 \
            --time "$FUZZ_TIME" \
            --out_path "$ADGFUZZ_OUT/"
        ;;
    *)
        echo "[!] Unknown RV type: $RVTYPE"
        exit 1
        ;;
esac

echo "[+] Phase 1 complete. Bugs saved to $ADGFUZZ_OUT"

# 统计发现的bug
BUG_COUNT=$(ls -1 "$ADGFUZZ_OUT"/bug*.txt 2>/dev/null | wc -l)
echo "[+] Found $BUG_COUNT bugs"

if [ "$BUG_COUNT" -eq 0 ]; then
    echo "[!] No bugs found. Exiting."
    exit 0
fi

# ---------- Phase 2: Bridge - Convert to Sleuth Format ----------
echo ""
echo "============================================"
echo " Phase 2: ADGFuzz → Sleuth Bridge"
echo "============================================"

SLEUTH_INPUT="$OUTPUT_ROOT/phase2_sleuth_input"
mkdir -p "$SLEUTH_INPUT"

cd "$BRIDGE_DIR"
python adg_to_sleuth.py \
    --bug_dir "$ADGFUZZ_OUT" \
    --output_dir "$SLEUTH_INPUT" \
    --project_path "$WORK_DIR"

echo "[+] Phase 2 complete. Sleuth inputs generated."

# ---------- Phase 3: Per-Bug Sleuth Analysis ----------
echo ""
echo "============================================"
echo " Phase 3: Sleuth Deep Impact Analysis"
echo "============================================"

SLEUTH_OUTPUT="$OUTPUT_ROOT/phase3_sleuth_output"
mkdir -p "$SLEUTH_OUTPUT"

# 只对 software crash bugs (ArithmException) 进行深度分析
# 这些是最适合 Sleuth 分析的 bug 类型
for harness_file in "$SLEUTH_INPUT/harnesses"/harness_bug*.c; do
    if [ ! -f "$harness_file" ]; then
        echo "[!] No harness files found"
        continue
    fi

    BUG_ID=$(basename "$harness_file" .c | sed 's/harness_bug//')
    BUG_DIR="$SLEUTH_OUTPUT/bug_$BUG_ID"
    mkdir -p "$BUG_DIR"

    echo ""
    echo "----------------------------------------"
    echo " Processing Bug #$BUG_ID"
    echo "----------------------------------------"

    # 3a: 检查是否有对应的 ArithmException bug
    BUG_FILE=$(ls "$ADGFUZZ_OUT"/bug${BUG_ID}_ArithmException_*.txt 2>/dev/null | head -1)
    if [ -z "$BUG_FILE" ]; then
        echo "[+] Bug #$BUG_ID is not ArithmException, skipping Sleuth analysis"
        continue
    fi

    # 3b: 编译 harness (需要先提取漏洞代码)
    echo "[+] Building harness for bug #$BUG_ID..."
    cd "$BUG_DIR"

    # 使用 wllvm 编译以支持 bitcode 提取
    clang -g -O0 -emit-llvm -S -o "harness_bug${BUG_ID}.ll" "$harness_file" 2>&1 || {
        echo "[!] Harness compilation failed (expected - needs ArduPilot code extraction)"
        echo "[+] Creating placeholder for manual completion"
        continue
    }

    # 3c: 运行 DDGAnalysis
    echo "[+] Running DDGAnalysis on bug #$BUG_ID..."
    if [ -f "$SLEUTH_DIR/ddgAnalysis/build/tools/static-dua" ]; then
        "$SLEUTH_DIR/ddgAnalysis/build/tools/static-dua" \
            --ander "harness_bug${BUG_ID}.bc" \
            --out="$BUG_DIR/target.json" 2>&1 || {
            echo "[!] DDGAnalysis failed (may need full code)"
        }
    fi

    # 3d: 使用 DDG_INSTR 重新编译
    echo "[+] Recompiling with Sleuth instrumentation..."
    DDG_INSTR=1 AFL_LLVM_INSTRUMENT=classic clang -g -O0 \
        -o "harness_bug${BUG_ID}_cov" "$harness_file" 2>&1 || {
        echo "[!] Instrumented build failed"
        continue
    }

    # 3e: 准备输入目录
    IN_DIR="$BUG_DIR/in"
    OUT_DIR="$BUG_DIR/out"
    mkdir -p "$IN_DIR" "$OUT_DIR"

    # 复制种子文件
    SEED_FILE="$SLEUTH_INPUT/seeds/seed_bug${BUG_ID}.bin"
    if [ -f "$SEED_FILE" ]; then
        cp "$SEED_FILE" "$IN_DIR/"
    fi

    # 3f: 运行 Sleuth
    echo "[+] Running Sleuth on bug #$BUG_ID (10 minutes)..."
    timeout 10m "$SLEUTH_DIR/Sleuth/afl-fuzz" \
        -m none -C \
        -i "$IN_DIR" \
        -o "$OUT_DIR" \
        -k "$SEED_FILE" \
        -- "./harness_bug${BUG_ID}_cov" @@ 2>&1 &

    SLEUTH_PID=$!
    echo "[+] Sleuth started (PID: $SLEUTH_PID)"

    # 只分析第一个 ArithmException bug 作为演示
    # 完整分析可以去掉 break
    break
done

# ---------- Phase 4: Result Analysis ----------
echo ""
echo "============================================"
echo " Phase 4: Result Analysis"
echo "============================================"

cd "$SLEUTH_OUTPUT"
for bug_dir in bug_*/; do
    if [ -d "$bug_dir/out" ]; then
        echo "[+] Analyzing $bug_dir..."
        # 统计发现的 crash
        if [ -d "$bug_dir/out/default/crashes" ]; then
            CRASH_COUNT=$(ls -1 "$bug_dir/out/default/crashes"/id:* 2>/dev/null | wc -l)
            echo "    Crashes found: $CRASH_COUNT"
        fi
    fi
done

echo ""
echo "============================================"
echo " Pipeline Complete!"
echo " Results saved to: $OUTPUT_ROOT"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Review harness files and extract actual ArduPilot code"
echo "  2. Re-run Phase 3 with complete harness"
echo "  3. Run crash analysis: cd \$SLEUTH_PATH/src/exec/crash_analysis && ./crash_run.sh"
echo "  4. Generate impact report: python \$SLEUTH_PATH/src/exec/generate_result/impact_deal.py"
echo "============================================"
