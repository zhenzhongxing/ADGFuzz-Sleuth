#!/bin/bash
# ============================================================
# Sleuth Bug Setup Script
# 为单个 ADGFuzz 发现的 bug 设置 Sleuth 分析环境
#
# 用法:
#   ./sleuth_setup_bug.sh <bug_id> <harness_dir> <ardupilot_src_dir>
#
# 示例:
#   ./sleuth_setup_bug.sh 1 ./output/harnesses /home/user/work/ArduPilot
# ============================================================

set -e

BUG_ID="${1:?Usage: $0 <bug_id> <harness_dir> <ardupilot_src>}"
HARNESS_DIR="${2:?Usage: $0 <bug_id> <harness_dir> <ardupilot_src>}"
ARDUPILOT_SRC="${3:?Usage: $0 <bug_id> <harness_dir> <ardupilot_src>}"
SLEUTH_PATH="${SLEUTH_PATH:?SLEUTH_PATH not set. Run: source ~/.bashrc}"

HARNESS_FILE="$HARNESS_DIR/harness_bug${BUG_ID}.c"
BUG_DIR="$SLEUTH_PATH/src/project/adgfuzz_bugs/ADGFUZZ-BUG-${BUG_ID}"
WORK_DIR="$PWD"

echo "============================================"
echo " Sleuth Setup for ADGFuzz Bug #$BUG_ID"
echo " Harness: $HARNESS_FILE"
echo " ArduPilot: $ARDUPILOT_SRC"
echo " Bug Dir: $BUG_DIR"
echo "============================================"

# ---------- Step 1: Create bug directory structure ----------
echo "[+] Creating Sleuth bug directory..."
mkdir -p "$BUG_DIR"/{poc,build,logs}

# ---------- Step 2: Find and extract vulnerable code ----------
echo "[+] Analyzing bug to identify vulnerable code..."

# 读取 harness 中的模块信息
if [ -f "$HARNESS_FILE" ]; then
    MODULES=$(grep "Affected module:" "$HARNESS_FILE" | awk '{print $3}')
    echo "    Affected modules: $MODULES"

    # 在 ArduPilot 源码中搜索相关文件
    for module in $MODULES; do
        echo "    Searching for $module in ArduPilot source..."
        find "$ARDUPILOT_SRC/libraries" -name "*.cpp" -o -name "*.h" | \
            xargs grep -l "$module" 2>/dev/null | head -5
    done
else
    echo "[!] Harness file not found: $HARNESS_FILE"
    echo "    Run bridge/adg_to_sleuth.py first"
    exit 1
fi

# ---------- Step 3: Copy harness and add ArduPilot includes ----------
echo "[+] Preparing harness with ArduPilot integration..."

FULL_HARNESS="$BUG_DIR/harness_full_bug${BUG_ID}.c"

cat > "$FULL_HARNESS" << 'HARNESS_HEADER'
/**
 * Full harness for Sleuth - includes ArduPilot library code
 * Bug ID: BUG_ID_PLACEHOLDER
 *
 * Build instructions:
 *   cd ARDUPILOT_PLACEHOLDER
 *   DDG_INSTR=1 AFL_LLVM_INSTRUMENT=classic gcc -I libraries/ \
 *       -o fuzz_bugID_cov harness_full_bugID.c -lm
 */

/* ArduPilot core headers needed by most modules */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

/* ============================================================
 * Minimal ArduPilot compatibility layer
 * This simulates the AP_HAL and AP_Param infrastructure enough
 * for the vulnerable code to compile and run.
 * ============================================================ */

/* Simulated HAL */
typedef struct {
    void (*console_printf)(const char *, ...);
} HAL_SIMPLE;

static HAL_SIMPLE hal_simple;

/* Simulated parameter storage */
#define AP_PARAM_MAX_PARAMS 256

typedef struct {
    const char *name;
    float value;
    float default_value;
    float min_value;
    float max_value;
} ap_param_t;

static ap_param_t param_store[AP_PARAM_MAX_PARAMS];
static int param_count = 0;

/* Parameter access functions */
static float get_param_value(const char *name) {
    for (int i = 0; i < param_count; i++) {
        if (strcmp(param_store[i].name, name) == 0) {
            return param_store[i].value;
        }
    }
    return 0.0f;
}

static void set_param_value(const char *name, float value) {
    for (int i = 0; i < param_count; i++) {
        if (strcmp(param_store[i].name, name) == 0) {
            param_store[i].value = value;
            return;
        }
    }
    if (param_count < AP_PARAM_MAX_PARAMS) {
        param_store[param_count].name = name;
        param_store[param_count].value = value;
        param_store[param_count].default_value = value;
        param_store[param_count].min_value = value / 2.0f;
        param_store[param_count].max_value = value * 2.0f;
        param_count++;
    }
}

/* Math helpers */
#ifndef M_PI
#define M_PI 3.14159265358979323846f
#endif

#define radians(deg) ((deg) * M_PI / 180.0f)
#define degrees(rad) ((rad) * 180.0f / M_PI)

HARNESS_HEADER

# 替换占位符
sed -i "s/BUG_ID_PLACEHOLDER/$BUG_ID/g" "$FULL_HARNESS"
sed -i "s|ARDUPILOT_PLACEHOLDER|$ARDUPILOT_SRC|g" "$FULL_HARNESS"

# 追加实际 harness 内容（跳过 include 和 main 声明部分）
tail -n +13 "$HARNESS_FILE" | head -n -1 >> "$FULL_HARNESS"

echo "[+] Full harness written: $FULL_HARNESS"

# ---------- Step 4: Build with DDG instrumentation ----------
echo "[+] Building harness with DDG instrumentation..."

cd "$BUG_DIR/build"

# Step 4a: Generate LLVM bitcode for DDG analysis
clang -g -O0 -emit-llvm -S \
    -I "$ARDUPILOT_SRC/libraries" \
    -o "harness_bug${BUG_ID}.ll" \
    "$FULL_HARNESS" 2>&1 || {
    echo "[!] Bitcode generation failed."
    echo "    This is expected if ArduPilot dependencies are not fully resolved."
    echo "    See: $BUG_DIR/logs/build_bc.log"
}

# Step 4b: Full LLVM bitcode
if [ -f "harness_bug${BUG_ID}.ll" ]; then
    llvm-as "harness_bug${BUG_ID}.ll" -o "harness_bug${BUG_ID}.bc" 2>&1 || true
fi

# Step 4c: Run DDGAnalysis
if [ -f "harness_bug${BUG_ID}.bc" ] && \
   [ -f "$SLEUTH_PATH/ddgAnalysis/build/tools/static-dua" ]; then
    echo "[+] Running DDGAnalysis..."
    "$SLEUTH_PATH/ddgAnalysis/build/tools/static-dua" \
        --ander "harness_bug${BUG_ID}.bc" \
        --out="$BUG_DIR/target.json" 2>&1 | tee "$BUG_DIR/logs/ddg_analysis.log" || {
        echo "[!] DDGAnalysis had issues (see log)"
    }
fi

# Step 4d: Build instrumented binary for Sleuth
echo "[+] Building instrumented binary..."
DDG_INSTR=1 AFL_LLVM_INSTRUMENT=classic clang -g -O0 \
    -I "$ARDUPILOT_SRC/libraries" \
    -o "fuzz_bug${BUG_ID}_cov" \
    "$FULL_HARNESS" -lm 2>&1 | tee "$BUG_DIR/logs/build_instr.log" || {
    echo "[!] Instrumented build failed (may need manual ArduPilot code integration)"
}

# ---------- Step 5: Set up seed input ----------
echo "[+] Setting up initial seeds..."

# 如果 bridge 已生成种子文件，复制它
SEED_DIR="$WORK_DIR/bridge/test/output/seeds"
if [ -f "$SEED_DIR/seed_bug${BUG_ID}.bin" ]; then
    mkdir -p "$BUG_DIR/poc/in"
    cp "$SEED_DIR/seed_bug${BUG_ID}.bin" "$BUG_DIR/poc/"
    cp "$SEED_DIR/seed_bug${BUG_ID}.bin" "$BUG_DIR/poc/in/"
    echo "[+] Seed copied from bridge output"
else
    # 从 ADGFuzz bug 输出生成种子
    echo "[!] No pre-generated seed found."
    echo "    Run: python bridge/adg_to_sleuth.py --bug_dir <path> --output_dir <path>"
fi

# ---------- Step 6: Update VulnTable ----------
echo "[+] Updating VulnTable..."
VULNTABLE="$SLEUTH_PATH/src/vulnInfo/VulnTable.txt"
ENTRY="/src/project/adgfuzz_bugs/ADGFUZZ-BUG-${BUG_ID}\t$WORK_DIR\tfuzz_bug${BUG_ID}_cov\t@@"

if ! grep -q "ADGFUZZ-BUG-${BUG_ID}" "$VULNTABLE" 2>/dev/null; then
    echo -e "$ENTRY" >> "$VULNTABLE"
    echo "[+] VulnTable entry added"
else
    echo "[+] VulnTable entry already exists"
fi

echo ""
echo "============================================"
echo " Setup complete for Bug #$BUG_ID!"
echo ""
echo "Next steps:"
echo "  1. Edit $FULL_HARNESS to add actual vulnerable code"
echo "  2. Run: cd $BUG_DIR/build && make"
echo "  3. Run Sleuth:"
echo "     \$SLEUTH_PATH/Sleuth/afl-fuzz -m none -C \\"
echo "       -i $BUG_DIR/poc/in -o $BUG_DIR/poc/out \\"
echo "       -k $BUG_DIR/poc/seed_bug${BUG_ID}.bin -- \\"
echo "       $BUG_DIR/build/fuzz_bug${BUG_ID}_cov @@"
echo "  4. Analyze: cd \$SLEUTH_PATH/src/exec/crash_analysis && ./crash_run.sh ADGFUZZ-BUG-${BUG_ID}"
echo "============================================"
