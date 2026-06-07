#!/usr/bin/env python3
"""
ADGFuzz → Sleuth Bridge Module
================================
将 ADGFuzz 发现的 RV 漏洞转换为 Sleuth 可用的 PoC 和 harness。

工作流程:
1. 解析 ADGFuzz 的 bug 输出文件
2. 分析漏洞参数，定位可能受影响的 ArduPilot 模块
3. 生成独立的 C harness 程序
4. 将参数集转换为二进制种子文件
5. 生成 Sleuth VulnTable 条目
6. 创建 DDGAnalysis 配置
"""

import os
import sys
import re
import json
import argparse
import struct
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set


# ============================================================
# Data Structures
# ============================================================

class BugInput:
    """表示 ADGFuzz 发现的一个 bug 输入"""
    def __init__(self, bug_id: int, bug_type: str, timestamp: float):
        self.bug_id = bug_id
        self.bug_type = bug_type  # ArithmException, StatusError, WpDeviation
        self.timestamp = timestamp
        self.init_path: str = ""
        self.rv_path: List[List[str]] = []
        self.inputs: List[Tuple[str, str, str]] = []  # (type, name, value)
        self.param_sets: List[Tuple[str, str]] = []    # (param_name, value)
        self.mav_cmds: List[Tuple[str, List]] = []     # (cmd_name, params)
        self.rc_channels: List[Tuple[str, str]] = []   # (channel, pwm)
        self.mode_sets: List[str] = []

    def categorize_inputs(self):
        """将输入按类型分类"""
        for itype, iname, ivalue in self.inputs:
            if itype == 'paramset':
                self.param_sets.append((iname, ivalue))
            elif itype == 'mavcmd':
                self.mav_cmds.append((iname, eval(ivalue) if isinstance(ivalue, str) else ivalue))
            elif itype == 'rc':
                self.rc_channels.append((iname, ivalue))
            elif itype == 'modeset':
                self.mode_sets.append(iname)

    def get_affected_params(self) -> List[str]:
        """获取所有受影响的参数名"""
        return [p[0] for p in self.param_sets]

    def get_affected_modules(self) -> Set[str]:
        """根据参数名推断受影响的 ArduPilot 模块"""
        module_map = {
            'ACRO': 'AC_AttitudeControl',
            'AHRS': 'AP_AHRS',
            'ATC': 'AC_AttitudeControl',
            'ATC_ACCEL': 'AC_AttitudeControl',
            'ATC_RAT': 'AC_AttitudeControl',
            'ATC_ANG': 'AC_AttitudeControl',
            'ANGLE': 'AC_AttitudeControl',
            'BATT': 'AP_BattMonitor',
            'BARO': 'AP_Baro',
            'COMPASS': 'AP_Compass',
            'EK2': 'AP_NavEKF2',
            'EK3': 'AP_NavEKF3',
            'GPS': 'AP_GPS',
            'INS': 'AP_InertialSensor',
            'MOT': 'AP_Motors',
            'PSC': 'AC_PosControl',
            'RC': 'RC_Channel',
            'RTL': 'AC_WPNav',
            'SERIAL': 'AP_SerialManager',
            'SIM': 'SIM_',
            'SR0': 'AP_SerialManager',
            'SR1': 'AP_SerialManager',
            'TERRAIN': 'AP_Terrain',
            'WPNAV': 'AC_WPNav',
            'WP': 'AC_WPNav',
            'PILOT': 'AC_AttitudeControl',
        }

        modules = set()
        for param_name, _ in self.param_sets:
            for prefix, module in module_map.items():
                if param_name.upper().startswith(prefix):
                    modules.add(module)
                    break
            else:
                # 尝试基于前缀推断
                parts = param_name.split('_')
                if len(parts) > 0:
                    modules.add(f"AP_Unknown_{parts[0]}")

        return modules if modules else {"Unknown"}


# ============================================================
# Bug File Parser
# ============================================================

def parse_bug_file(filepath: str) -> Optional[BugInput]:
    """解析 ADGFuzz bug 输出文件"""
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return None

    # 从文件名提取信息
    basename = os.path.basename(filepath)
    # 格式: bug{N}_{BugType}_{timestamp}.txt
    match = re.match(r'bug(\d+)_(\w+)_([\d.]+)\.txt', basename)
    if not match:
        print(f"[!] Cannot parse filename: {basename}")
        return None

    bug_id = int(match.group(1))
    bug_type = match.group(2)
    timestamp = float(match.group(3))

    bug = BugInput(bug_id, bug_type, timestamp)

    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            if line.startswith('init_path:'):
                bug.init_path = line[len('init_path:'):].strip()
            elif line.startswith('RVpath:'):
                rvpath_str = line[len('RVpath:'):].strip()
                try:
                    bug.rv_path = eval(rvpath_str)
                except:
                    pass
            else:
                # 输入行格式: type name value
                parts = line.split(' ', 2)
                if len(parts) >= 2:
                    itype = parts[0]
                    iname = parts[1]
                    ivalue = parts[2] if len(parts) > 2 else ''
                    bug.inputs.append((itype, iname, ivalue))

    bug.categorize_inputs()
    return bug


# ============================================================
# Harness Generator
# ============================================================

HARNESS_TEMPLATE = r"""
/**
 * Auto-generated harness for Sleuth fuzzing
 * Bug ID: {bug_id}
 * Bug Type: {bug_type}
 * Affected Parameters: {param_list}
 * Generated by: adg_to_sleuth.py
 *
 * This harness wraps the vulnerable function extracted from ArduPilot
 * to enable Sleuth-based deep impact analysis.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>

/* ============================================================
 * Simulation of ArduPilot types needed by the vulnerable code
 * ============================================================ */

typedef float AP_Float;
typedef int16_t AP_Int16;
typedef uint16_t AP_UInt16;
typedef int32_t AP_Int32;
typedef uint32_t AP_UInt32;
typedef uint8_t AP_Int8;

/* Parameter container - simplified from AP_Param */
typedef struct {{
    AP_Float value;
    AP_Float default_val;
    AP_Float min_val;
    AP_Float max_val;
}} ParamFloat;

typedef struct {{
    AP_Int32 value;
    AP_Int32 default_val;
    AP_Int32 min_val;
    AP_Int32 max_val;
}} ParamInt32;

/* ============================================================
 * Parameter Definitions - generated from bug input
 * ============================================================ */
{param_defs}

/* ============================================================
 * Forward declarations of vulnerable functions
 * (These should be extracted from ArduPilot source)
 * ============================================================ */
{forward_decls}

/* ============================================================
 * Input reading - reads binary fuzz input and sets parameters
 * ============================================================ */
static int read_input(const char *filename) {{
    unsigned char buf[4096];
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {{
        perror("open");
        return -1;
    }}

    ssize_t n = read(fd, buf, sizeof(buf));
    if (n < 0) {{
        perror("read");
        close(fd);
        return -1;
    }}
    close(fd);

    if (n < {min_input_size}) {{
        fprintf(stderr, "Input too small: %zd bytes (need at least {min_input_size})\\n", n);
        return -1;
    }}

    /* Parse input and set parameters */
    size_t offset = 0;
{input_parsers}

    return 0;
}}

/* ============================================================
 * Main - AFL/Sleuth entry point
 * ============================================================ */
int main(int argc, char **argv) {{
    const char *input_file = NULL;

    if (argc > 1) {{
        input_file = argv[1];
    }} else {{
        /* When run by AFL/Sleuth, input is passed as argument or via stdin */
        input_file = getenv("AFL_FILE");
        if (!input_file) {{
            input_file = "/dev/stdin";
        }}
    }}

    if (read_input(input_file) < 0) {{
        return 1;
    }}

    /* ============================================================
     * Trigger the vulnerable code path
     * ============================================================ */
{trigger_code}

    return 0;
}}
"""


def generate_harness(bug: BugInput, output_dir: str) -> str:
    """生成独立 harness C 程序"""
    os.makedirs(output_dir, exist_ok=True)

    # 生成参数定义
    param_defs = []
    input_parsers = []
    min_input_size = 0

    for i, (param_name, param_value) in enumerate(bug.param_sets):
        try:
            val = float(param_value)
            # 判断是 int 还是 float
            if val == int(val) and abs(val) < 2**31:
                param_defs.append(
                    f"static ParamInt32 param_{i} = {{ .value = {int(val)}, "
                    f".default_val = {int(val)}, .min_val = {int(val)//2}, "
                    f".max_val = {int(val)*2} }};"
                )
                input_parsers.append(
                    f"    memcpy(&param_{i}.value, buf + offset, sizeof(AP_Int32));\n"
                    f"    offset += sizeof(AP_Int32);\n"
                    f"    fprintf(stderr, \"[{param_name}] = %d\\n\", param_{i}.value);"
                )
                min_input_size += 4
            else:
                param_defs.append(
                    f"static ParamFloat param_{i} = {{ .value = {val}f, "
                    f".default_val = {val}f, .min_val = {val/2:.1f}f, "
                    f".max_val = {val*2:.1f}f }};"
                )
                input_parsers.append(
                    f"    memcpy(&param_{i}.value, buf + offset, sizeof(AP_Float));\n"
                    f"    offset += sizeof(AP_Float);\n"
                    f"    fprintf(stderr, \"[{param_name}] = %f\\n\", param_{i}.value);"
                )
                min_input_size += 4
        except (ValueError, OverflowError):
            continue

    # 生成前向声明和触发代码（占位 - 需要从 ArduPilot 提取实际函数）
    affected_modules = bug.get_affected_modules()
    forward_decls = "/* TODO: Extract and include actual ArduPilot function declarations */\n"
    for module in affected_modules:
        forward_decls += f"/* Affected module: {module} */\n"

    trigger_code = "    /* TODO: Call the vulnerable function(s) with the parsed parameters */\n"
    trigger_code += "    /* Example pattern:\n"
    trigger_code += "     *   1. Initialize the subsystem with parameters\n"
    trigger_code += "     *   2. Call the function that caused the crash\n"
    trigger_code += "     *   3. The crash should be reproduced here\n"
    trigger_code += "     */\n"

    for i, (param_name, _) in enumerate(bug.param_sets):
        trigger_code += f"    fprintf(stderr, \"Setting {param_name} = %d/%f\\n\", "
        trigger_code += f"param_{i}.value, (float)param_{i}.value);\n"

    trigger_code += "\n    /* === VULNERABLE CODE PATH === */\n"
    trigger_code += "    /* TODO: Insert the actual vulnerable function call */\n"
    trigger_code += "    /* abort() is a placeholder - replace with actual code */\n"
    trigger_code += "    // abort();\n"

    harness_code = HARNESS_TEMPLATE.format(
        bug_id=bug.bug_id,
        bug_type=bug.bug_type,
        param_list=', '.join(bug.get_affected_params()),
        param_defs='\n'.join(param_defs) if param_defs else '/* No parameters */',
        forward_decls=forward_decls,
        min_input_size=max(min_input_size, 4),
        input_parsers='\n'.join(input_parsers) if input_parsers else '    /* No parameters to parse */',
        trigger_code=trigger_code,
    )

    harness_path = os.path.join(output_dir, f"harness_bug{bug.bug_id}.c")
    with open(harness_path, 'w') as f:
        f.write(harness_code)

    print(f"[+] Generated harness: {harness_path}")
    return harness_path


# ============================================================
# Seed Generator
# ============================================================

def generate_seed(bug: BugInput, output_dir: str) -> str:
    """将 ADGFuzz 参数转换为二进制种子文件（供 AFL/Sleuth 使用）"""
    os.makedirs(output_dir, exist_ok=True)
    seed_path = os.path.join(output_dir, f"seed_bug{bug.bug_id}.bin")

    data = bytearray()

    for param_name, param_value in bug.param_sets:
        try:
            val = float(param_value)
            if val == int(val) and abs(val) < 2**31:
                # 整数参数 - 4字节 little-endian
                data.extend(struct.pack('<i', int(val)))
            else:
                # 浮点参数 - 4字节 float
                data.extend(struct.pack('<f', val))
        except (ValueError, OverflowError):
            # 跳过无法转换的值
            continue

    # 为 MAVLink 命令添加额外字节
    for cmd_name, cmd_params in bug.mav_cmds:
        for p in cmd_params:
            if isinstance(p, (int, float)):
                data.extend(struct.pack('<i', int(p)))

    with open(seed_path, 'wb') as f:
        f.write(data)

    print(f"[+] Generated seed ({len(data)} bytes): {seed_path}")
    return seed_path


# ============================================================
# VulnTable Generator
# ============================================================

def generate_vulntable_entry(bug: BugInput, harness_dir: str,
                             project_path: str) -> str:
    """生成 Sleuth VulnTable 条目"""
    bug_id = f"ADGFUZZ-BUG-{bug.bug_id}"

    # 格式: /path/to/CVE-info \t /path/to/project \t target/binary \t parameters
    entry = (
        f"/src/project/adgfuzz_bugs/{bug_id}\t"
        f"{project_path}\t"
        f"harness_bug{bug.bug_id}\t"
        f"@@"
    )

    return entry


# ============================================================
# Main Pipeline
# ============================================================

def process_bug_directory(bug_dir: str, output_dir: str,
                          project_path: str = "/home/user/work/ADGFuzz-Sleuth") -> Dict:
    """处理整个 bug 目录"""
    results = {
        'total': 0,
        'processed': 0,
        'harnesses': [],
        'seeds': [],
        'vulntable_entries': [],
        'errors': []
    }

    harness_dir = os.path.join(output_dir, "harnesses")
    seed_dir = os.path.join(output_dir, "seeds")
    os.makedirs(harness_dir, exist_ok=True)
    os.makedirs(seed_dir, exist_ok=True)

    for filename in sorted(os.listdir(bug_dir)):
        if not filename.endswith('.txt'):
            continue

        filepath = os.path.join(bug_dir, filename)
        results['total'] += 1

        try:
            bug = parse_bug_file(filepath)
            if bug is None:
                results['errors'].append(f"Failed to parse: {filename}")
                continue

            print(f"\n[+] Processing Bug #{bug.bug_id}: {bug.bug_type}")
            print(f"    Parameters: {bug.get_affected_params()}")
            print(f"    Modules: {bug.get_affected_modules()}")

            # 生成 harness
            harness_path = generate_harness(bug, harness_dir)
            results['harnesses'].append(harness_path)

            # 生成种子
            seed_path = generate_seed(bug, seed_dir)
            results['seeds'].append(seed_path)

            # 生成 VulnTable 条目
            entry = generate_vulntable_entry(bug, harness_dir, project_path)
            results['vulntable_entries'].append(entry)

            results['processed'] += 1

        except Exception as e:
            results['errors'].append(f"Error processing {filename}: {e}")

    # 写入汇总文件
    # VulnTable
    vulntable_path = os.path.join(output_dir, "VulnTable_adgfuzz.txt")
    with open(vulntable_path, 'w') as f:
        f.write('\n'.join(results['vulntable_entries']))
    print(f"\n[+] VulnTable written: {vulntable_path}")

    # 汇总 JSON
    summary_path = os.path.join(output_dir, "bridge_summary.json")
    with open(summary_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"[+] Summary written: {summary_path}")

    return results


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='ADGFuzz → Sleuth Bridge - Convert RV bugs to Sleuth-compatible format'
    )
    parser.add_argument('--bug_dir', type=str, required=True,
                        help='Directory containing ADGFuzz bug output files')
    parser.add_argument('--output_dir', type=str, default='./sleuth_input',
                        help='Output directory for Sleuth inputs')
    parser.add_argument('--project_path', type=str,
                        default='/home/user/work/ADGFuzz-Sleuth',
                        help='Project path for VulnTable entries')
    parser.add_argument('--single', type=str,
                        help='Process a single bug file instead of a directory')

    args = parser.parse_args()

    if args.single:
        bug = parse_bug_file(args.single)
        if bug:
            print(f"Bug #{bug.bug_id}: {bug.bug_type}")
            print(f"Parameters: {bug.get_affected_params()}")
            print(f"Affected modules: {bug.get_affected_modules()}")
            harness_dir = os.path.join(args.output_dir, "harnesses")
            seed_dir = os.path.join(args.output_dir, "seeds")
            generate_harness(bug, harness_dir)
            generate_seed(bug, seed_dir)
    else:
        results = process_bug_directory(
            args.bug_dir, args.output_dir, args.project_path
        )
        print(f"\n{'='*50}")
        print(f"Total bugs: {results['total']}")
        print(f"Processed: {results['processed']}")
        print(f"Errors: {len(results['errors'])}")
        print(f"Harnesses generated: {len(results['harnesses'])}")
        print(f"Seeds generated: {len(results['seeds'])}")


if __name__ == '__main__':
    main()
