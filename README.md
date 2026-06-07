# ADGFuzz + Sleuth 适配项目

使用 **ADGFuzz** 挖掘 RV（Robotic Vehicle）系统的漏洞，再用 **Sleuth** 进行深入的漏洞影响能力挖掘。

---

## 目录

- [项目背景](#项目背景)
- [项目结构](#项目结构)
- [环境要求](#环境要求)
- [快速开始](#快速开始)
- [编译指南](#编译指南)
- [详细使用说明](#详细使用说明)
- [修改说明](#修改说明)
- [Bridge 桥接模块 API](#bridge-桥接模块-api)
- [测试](#测试)
- [常见问题](#常见问题)
- [Git 提交历史](#git-提交历史)

---

## 项目背景

### ADGFuzz（漏洞发现）
ADGFuzz 是一个针对 RV 控制软件的模糊测试框架。它通过**静态分析**从源码中构建赋值依赖图（ADG），再通过同义词表和关联规则将变量映射为 RV 输入子集（MIS），最后使用信息熵引导的策略在 SITL 模拟器上进行模糊测试。

- 目标系统：ArduPilot（Copter/Plane/Rover）、PX4
- 检测能力：软件崩溃（算术异常）、路径偏离、坠地
- 论文：NDSS 2026

### Sleuth（漏洞影响深度挖掘）
Sleuth 是一个基于 AFLplusplus 的 bug 影响探索工具。它通过**数据依赖图（DDG）静态分析**生成内存相关图，并以此引导模糊测试来探索漏洞的深层影响。

- 目标程序：C/C++ 程序
- 分析能力：新 crash 类型发现、影响范围评估、严重性评分
- 论文：ISSTA 2024

### 适配目标
将 ADGFuzz 发现的 RV 漏洞作为 Sleuth 的初始种子，利用 Sleuth 的内存图引导能力深入挖掘漏洞影响。

**核心挑战**：ADGFuzz 通过 MAVLink 协议与 SITL 模拟器交互（参数→MAVLink→SITL），而 Sleuth 通过文件输入与独立二进制交互（文件→stdin→二进制）。需要桥接这两种完全不同的交互模式。

---

## 项目结构

```
ADGFuzz-Sleuth/
│
├── ADGFuzz-main/                    # ADGFuzz 模糊测试框架
│   ├── adgfuzz.py                   # ★ 主入口（已修改：新增 --sleuth_export）
│   ├── fuzzer/
│   │   ├── fuzz.py                  # ★ ArduPilot fuzzer（已修改：集成 SleuthExporter）
│   │   ├── fuzzpx4.py               # ★ PX4 fuzzer（已修改：集成 SleuthExporter）
│   │   ├── oracle.py                # Bug 检测预言（3种：软件崩溃/路径偏离/坠地）
│   │   ├── runtimedict.py           # 运行时参数字典（参数值生成）
│   │   ├── rvmethod.py              # MAVLink 通信方法
│   │   └── postprocess.py           # Bug 后处理（最小化/去重）
│   ├── model/
│   │   ├── Mapping.py               # ADG → MIS 映射转换
│   │   ├── constant.py              # 常量定义
│   │   └── parsefile.py             # 文件解析
│   ├── static/
│   │   ├── initpath/                # ArduPilot 静态分析结果（ADG 图）
│   │   ├── px4path/                 # PX4 静态分析结果
│   │   └── tree_parse.py            # 静态分析主程序
│   ├── data/                        # 参数/命令数据 CSV
│   ├── map/                         # 同义词表和物理耦合表
│   ├── missiondata/                 # 航点任务文件
│   ├── paths/                       # 路径配置和快速测试
│   └── outfile/                     # Fuzzing 输出目录
│
├── Sleuth_code/                     # Sleuth 漏洞影响分析框架
│   ├── Sleuth/                      # 修改版 AFLplusplus（DDG 引导变异）
│   ├── ddgAnalysis/                 # 静态分析器（基于 SVF + Z3）
│   │   ├── tools/
│   │   │   ├── dataflow-cc          # 将源码编译为 LLVM bitcode
│   │   │   └── static-dua           # 生成内存依赖图（DDG）
│   │   └── ext/                     # 依赖（SVF, Z3, LLVM）
│   ├── src/
│   │   ├── exec/
│   │   │   ├── autoRun.py           # 自动化模糊测试入口
│   │   │   ├── crash_analysis/      # Crash 结果分析脚本
│   │   │   └── generate_result/     # 影响评估和报告生成
│   │   ├── script/                  # 构建和运行脚本
│   │   ├── vulnInfo/                # 漏洞信息（VulnTable, target.json）
│   │   └── vuln_tool/               # 漏洞分析工具
│   └── benchmark/                   # 测试用例集
│
├── bridge/                          # ★ 桥接模块（本次核心开发）
│   ├── adg_to_sleuth.py             # ADGFuzz → Sleuth 转换器主程序
│   ├── adgfuzz_sleuth_export.py     # SleuthExporter：集成到 ADGFuzz 的实时导出
│   ├── sleuth_impact_analysis.py    # Sleuth 影响分析集成
│   ├── sleuth_setup_bug.sh          # 单 Bug Sleuth 分析环境配置
│   ├── setup_ubuntu.sh              # Ubuntu 环境一键安装脚本
│   ├── run_pipeline.sh              # 端到端自动化流水线
│   ├── CHANGES.md                   # 详细修改清单
│   └── test/                        # 测试数据和验证输出
│
├── 资料/                            # 论文 PDF 和参考资料
│   ├── ADGFUZZ介绍PPT.pdf
│   ├── ISSTA24 Sleuth.pdf
│   └── NDSS2026-ADGFuzz.pdf
│
├── PROJECT_PLAN.md                  # 详细工作计划
├── 工作要求.txt                     # 原始工作需求
└── README.md                        # 本文件
```

★ 标记 = 本次修改或新建的文件

---

## 环境要求

| 组件 | 要求 |
|------|------|
| 操作系统 | Ubuntu 20.04 或 22.04（SITL 模拟器必需） |
| Python | 3.8.10+（推荐 3.8.10） |
| 内存 | ≥ 16 GB（SITL + fuzzer 同时运行） |
| 磁盘 | ≥ 60 GB（ArduPilot 构建 + 依赖） |
| GCC/Clang | GCC 9+ / Clang 12（用于 Sleuth） |
| LLVM | 12.x（DDGAnalysis 依赖） |
| Java | JDK 17（PX4 jMAVSim 需要） |

---

## 快速开始

### 步骤 1：克隆项目

```bash
git clone https://github.com/<your-username>/ADGFuzz-Sleuth.git
cd ADGFuzz-Sleuth
```

### 步骤 2：一键安装环境

```bash
bash bridge/setup_ubuntu.sh
source ~/.bashrc
```

此脚本会自动完成：
- 安装系统依赖（包括 LLVM 12、Clang、Z3）
- 安装 Python 依赖（pymavlink、numpy、pandas、geopy 等）
- 克隆并构建 ArduPilot SITL（指定 commit）
- 克隆并构建 PX4 SITL（指定 commit）
- 构建 Sleuth DDGAnalysis（z3 + SVF + static-dua）
- 构建 Sleuth fuzzer（AFLplusplus 修改版）
- 设置环境变量（`ARDUPILOT_HOME`、`PX4_HOME`、`SLEUTH_PATH`）

### 步骤 3：运行 ADGFuzz 挖掘漏洞

```bash
cd ADGFuzz-main

# 快速测试（~5 分钟，验证环境正常）
python adgfuzz.py \
    --initfile paths/testcopter/quicktest/ \
    --rvtype copter \
    --time 300 \
    --out_path outfile/quicktest/ \
    --sleuth_export

# 正式运行（~1 小时，ArduCopter）
python adgfuzz.py \
    --initfile static/initpath/ArduCopter/ static/initpath/libraries/ \
    --rvtype copter \
    --time 3600 \
    --out_path outfile/copter/ \
    --sleuth_export

# 其他 RV 类型
python adgfuzz.py --initfile static/initpath/ArduPlane/ static/initpath/libraries/ \
    --rvtype plane --time 3600 --out_path outfile/plane/

python adgfuzz.py --initfile static/initpath/Rover/ static/initpath/libraries/ \
    --rvtype rover --time 3600 --out_path outfile/rover/

# PX4
python adgfuzz.py --initfile static/px4path/lib/ static/px4path/modules/ \
    --rvtype px4 --time 3600 --out_path outfile/px4_copter/
```

### 步骤 4：桥接转换

```bash
cd bridge

# 批量处理所有发现的 bug
python adg_to_sleuth.py \
    --bug_dir ../ADGFuzz-main/outfile/copter/ \
    --output_dir ./sleuth_input/

# 处理单个 bug 文件
python adg_to_sleuth.py \
    --single ../ADGFuzz-main/outfile/copter/bug1_ArithmException_xxx.txt \
    --output_dir ./sleuth_input/
```

输出：
- `sleuth_input/harnesses/harness_bugN.c` — 独立 harness C 程序
- `sleuth_input/seeds/seed_bugN.bin` — 二进制模糊测试种子
- `sleuth_input/VulnTable_adgfuzz.txt` — Sleuth VulnTable 条目
- `sleuth_input/bridge_summary.json` — 处理汇总

### 步骤 5：Sleuth 深度影响分析

```bash
# 为单个 bug 设置完整的 Sleuth 分析环境
bash sleuth_setup_bug.sh 1 ./sleuth_input/harnesses ~/work/ArduPilot

# 运行 Sleuth 模糊测试（10 分钟）
cd $SLEUTH_PATH/src/exec
python autoRun.py ADGFUZZ-BUG-1 10m 1 SLEUTH

# 分析 crash
cd crash_analysis
./crash_run.sh ADGFUZZ-BUG-1

# 生成影响评估
cd ../generate_result
python impact_deal.py ADGFUZZ-BUG-1
python severity_score.py
```

### 步骤 6：使用端到端流水线

```bash
cd bridge
bash run_pipeline.sh copter 3600
```

自动完成：ADGFuzz fuzzing → Bridge 转换 → Sleuth 分析 → 结果汇总

---

## 编译指南

### ADGFuzz

ADGFuzz 本身是 Python 项目，无需编译。但需要 ArduPilot/PX4 SITL 环境：

```bash
# ArduPilot SITL
cd ~/work/ArduPilot
git checkout 564879594ebb8d31c6400461b96f5dc442f14533
git submodule update --init --recursive
Tools/environment_install/install-prereqs-ubuntu.sh -y

# 测试 SITL
./Tools/autotest/sim_vehicle.py -v ArduCopter --console --map -w
```

### Sleuth DDGAnalysis

```bash
cd Sleuth_code/ddgAnalysis

# 构建 Z3
git clone https://github.com/z3prover/z3
git -C z3 checkout z3-4.8.8
mkdir -p z3/build && cd z3/build
cmake .. -DCMAKE_INSTALL_PREFIX=$(realpath ../install) -DZ3_BUILD_LIBZ3_SHARED=False
make -j$(nproc) && make install

# 构建 DDGAnalysis
cd ../../ && mkdir -p build && cd build
cmake .. \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DLLVM_DIR=$(llvm-config --cmakedir) \
    -DZ3_DIR=$(realpath ../z3/install)
make -j$(nproc)
```

### Sleuth Fuzzer

```bash
cd Sleuth_code/Sleuth
make source-only NO_SPLICING=1
```

### Harness（桥接模块生成的 C 程序）

```bash
# 基本编译（不含 ArduPilot 代码）
clang -g -O0 -o harness_bug1 harness_bug1.c -lm

# 带 DDG 插桩编译
DDG_INSTR=1 AFL_LLVM_INSTRUMENT=classic clang -g -O0 \
    -I ~/work/ArduPilot/libraries \
    -o harness_bug1_cov harness_bug1.c -lm

# 生成 LLVM bitcode（供 DDGAnalysis 使用）
clang -g -O0 -emit-llvm -S -o harness_bug1.ll harness_bug1.c
llvm-as harness_bug1.ll -o harness_bug1.bc

# 运行 DDG 静态分析
$SLEUTH_PATH/ddgAnalysis/build/tools/static-dua \
    --ander harness_bug1.bc \
    --out=target.json
```

---

## 详细使用说明

### ADGFuzz 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--initfile` | ADG 路径目录（静态分析结果） | `paths` |
| `--rvtype` | RV 类型：copter/plane/rover/px4 | `copter` |
| `--time` | 模糊测试时间（秒） | `3600` |
| `--out_path` | 输出目录 | 无（必填） |
| `--log_path` | 日志文件路径 | 无 |
| `--log_level` | 日志级别：error/info/debug | `info` |
| `--bugpost` | 跳过模糊测试，直接后处理 | `False` |
| `--sleuth_export` | 🆕 启用 Sleuth 兼容导出 | `False` |

### Bridge 桥接模块命令行

```bash
# adg_to_sleuth.py - 批量转换
python adg_to_sleuth.py \
    --bug_dir <ADGFuzz输出目录> \
    --output_dir <Sleuth输入目录> \
    [--project_path <项目根路径>] \
    [--single <单个bug文件>]

# adgfuzz_sleuth_export.py - 处理已有结果
python adgfuzz_sleuth_export.py \
    --bug_dir <ADGFuzz输出目录> \
    --output_dir <导出目录>

# sleuth_impact_analysis.py - 影响分析
python sleuth_impact_analysis.py \
    --sleuth_path <Sleuth_code路径> \
    --bug_ids ADGFUZZ-BUG-1 ADGFUZZ-BUG-2 \
    [--register <bug_id,project,binary,params>] \
    [--compare] \
    [--output <结果文件>]
```

### Bug 输出文件格式

ADGFuzz 生成的 bug 文件格式：

```
init_path: (源函数, 变量名, [依赖变量列表])
RVpath: [['paramset', '参数名', 匹配数], ['mavcmd', '命令名', ...]]
paramset PARAM_NAME value
mavcmd MAV_CMD_NAME [param1, param2, ..., param7]
rc channel_id pwm_value
```

### Sleuth 分析输出

分析完成后，在 `$SLEUTH_PATH/Experiment/result/` 目录下：

| 文件 | 内容 |
|------|------|
| `New_Impact_Table-2.json` | 新发现的影响（对应论文 Table 2） |
| `Overall_NewBugImpact.png` | 影响总览图（对应论文 Figure 4） |
| `NewImpact_Overtime.png` | 新影响随时间发现图 |
| `SameImpact_Overtime.png` | 相同影响随时间发现图 |
| `NewImpact_Efficiency.xls` | 影响发现效率（对应论文 Table 3） |
| `Severity_score_Table-4.json` | 严重性评分（对应论文 Table 4） |

---

## 修改说明

### 修改动机

原始 ADGFuzz 只能将发现的 bug 保存为文本文件，无法直接供 Sleuth 使用。Sleuth 需要：
1. 独立的 C/C++ 目标程序（而非 SITL 模拟器）
2. 文件格式的 PoC 输入（而非 MAVLink 参数）
3. VulnTable 注册条目
4. DDG 静态分析配置

### ADGFuzz-main/adgfuzz.py

```diff
+ arg_parser.add_argument("--sleuth_export", ...)
- adgfuzz = PX4fuzzer(m.paths, ...)
+ adgfuzz = PX4fuzzer(m.paths, ..., sleuth_export=args.sleuth_export)
- adgfuzz = ADGfuzzer(m.paths, ...)
+ adgfuzz = ADGfuzzer(m.paths, ..., sleuth_export=args.sleuth_export)
```

**作用**：新增 `--sleuth_export` 命令行参数，将开关传递给 fuzzer 构造函数。

### ADGFuzz-main/fuzzer/fuzz.py（ADGfuzzer 类）

```diff
+ # Sleuth integration: import SleuthExporter (with graceful fallback)
+ try:
+     from adgfuzz_sleuth_export import SleuthExporter
+     SLEUTH_EXPORT_AVAILABLE = True
+ except ImportError:
+     SLEUTH_EXPORT_AVAILABLE = False

  class ADGfuzzer:
-     def __init__(self, paths, rvtype, ..., time_budget = 300):
+     def __init__(self, paths, rvtype, ..., time_budget = 300, sleuth_export: bool = False):

+     # Sleuth export integration
+     self.sleuth_exporter = None
+     if sleuth_export and SLEUTH_EXPORT_AVAILABLE:
+         self.sleuth_exporter = SleuthExporter(...)

  def save_bug(self, ...):
      # ...原有保存逻辑...
+     if self.sleuth_exporter is not None:
+         self.sleuth_exporter.export_bug(bug_id=..., ...)
```

**作用**：在 fuzzer 发现 bug 时自动同步导出 Sleuth 兼容格式（种子文件 + 元数据 JSON）。

### ADGFuzz-main/fuzzer/fuzzpx4.py（PX4fuzzer 类）

与 fuzz.py 相同的修改模式，确保 PX4 也能使用 Sleuth 导出功能。

### 桥接模块（bridge/）- 全新开发

详见 [Bridge 桥接模块 API](#bridge-桥接模块-api) 章节。

---

## Bridge 桥接模块 API

### 核心类：`SleuthExporter`

```python
from adgfuzz_sleuth_export import SleuthExporter

exporter = SleuthExporter(output_dir="./sleuth_export/")

# 导出一个 bug
seed_path = exporter.export_bug(
    bug_id=1,                          # Bug 编号
    bug_type="ArithmException",        # Bug 类型
    init_path="('func', 'var', [...])", # ADG 路径
    rv_path=[['paramset', 'PARAM']],   # RV 输入路径
    temp_value=[('paramset', 'NAME', '0.5')],  # 输入值列表
    timestamp=100.5                    # 发现时间戳
)
# → 生成 seeds/bug1_ArithmException.bin + metadata/bug1.json

# 获取统计
stats = exporter.get_statistics()
# → {'total_bugs': 1, 'by_type': {'ArithmException': 1}, ...}
```

### 核心函数：`parse_bug_file()`

```python
from adg_to_sleuth import parse_bug_file

bug = parse_bug_file("bug1_ArithmException_100.5.txt")
print(bug.bug_id)          # 1
print(bug.bug_type)        # "ArithmException"
print(bug.get_affected_params())    # ['AHRS_TRIM_X', 'EK2_ENABLE']
print(bug.get_affected_modules())   # {'AP_AHRS', 'AP_NavEKF2'}
```

### 核心函数：`generate_harness()` 和 `generate_seed()`

```python
from adg_to_sleuth import generate_harness, generate_seed

# 生成独立 harness C 程序
harness_path = generate_harness(bug, output_dir="./harnesses/")
# → harnesses/harness_bug1.c

# 生成二进制种子文件
seed_path = generate_seed(bug, output_dir="./seeds/")
# → seeds/seed_bug1.bin (二进制格式，可直接供 AFL/Sleuth 使用)
```

### 核心类：`SleuthImpactAnalyzer`

```python
from sleuth_impact_analysis import SleuthImpactAnalyzer

analyzer = SleuthImpactAnalyzer(sleuth_path="/path/to/Sleuth_code")

# 注册 bug 到 VulnTable
analyzer.register_bug("ADGFUZZ-BUG-1", "/path/to/project", "harness_bug1", "@@")

# 运行 crash 分析
analyzer.run_crash_analysis("ADGFUZZ-BUG-1")

# 生成影响报告
impact = analyzer.generate_impact_report("ADGFUZZ-BUG-1")

# 批量分析 + 对比报告
results = analyzer.batch_analyze(["ADGFUZZ-BUG-1", "ADGFUZZ-BUG-2"])
```

### 二进制种子格式

ADGFuzz 参数到二进制种子的编码：

| 字节偏移 | 内容 |
|---------|------|
| 0 | 类型标记 (0x01=paramset, 0x02=mavcmd, 0x03=rc, 0x04=modeset) |
| 1 | 参数名长度 (N) |
| 2~2+N | 参数名 (UTF-8) |
| 2+N~2+N+4 | 参数值 (float32, little-endian) |

---

## 测试

### 测试桥接模块

```bash
cd bridge

# 使用提供的样本数据测试
python adg_to_sleuth.py --bug_dir test/ --output_dir test/output/

# 预期输出：
# ==================================================
# Total bugs: 2
# Processed: 2
# Errors: 0
# Harnesses generated: 2
# Seeds generated: 2

# 单独测试 SleuthExporter
python adgfuzz_sleuth_export.py --bug_dir test/ --output_dir test/sleuth_export/

# Python 语法验证
python -m py_compile adg_to_sleuth.py && echo "OK"
python -m py_compile adgfuzz_sleuth_export.py && echo "OK"
python -m py_compile sleuth_impact_analysis.py && echo "OK"
```

### 验证 ADGFuzz 修改

```bash
cd ADGFuzz-main
python -c "import adgfuzz"  # 验证语法
python adgfuzz.py --help    # 应显示 --sleuth_export 选项
```

---

## 常见问题

### Q: 运行 setup_ubuntu.sh 时出现 "E: Unmet dependencies"

A: 这通常是 gazebo 包冲突。执行：
```bash
sudo apt-get -o Dpkg::Options::="--force-overwrite" install gazebo11 gazebo11-plugin-base
bash bridge/setup_ubuntu.sh  # 重试
```

### Q: ArduPilot SITL 显示 "Arm: Need Position Estimate"

A: SITL 初始化时间不足。在 adgfuzz.py 中增大 `time.sleep(50)` 的值（第 280 行附近）。

### Q: PX4 编译失败 "Java JDK 15+ required"

A: 安装 JDK 17：
```bash
sudo apt install openjdk-17-jdk
```

### Q: 桥接模块导入失败 "No module named 'adgfuzz_sleuth_export'"

A: 确保 bridge/ 目录在 Python 路径中：
```bash
export PYTHONPATH=$PYTHONPATH:$(pwd)/bridge
```

### Q: DDGAnalysis 构建失败

A: 确认 LLVM 12 已安装：
```bash
llvm-config --version  # 应输出 12.x.x
```

### Q: Sleuth harness 编译失败（缺少 ArduPilot 头文件）

A: harness 模板需要手动提取 ArduPilot 源码中的漏洞函数。模板只是框架，需要：
1. 从 ArduPilot 源码中复制漏洞函数到 harness
2. 添加必要的 `#include` 和类型定义
3. 重新编译

---

## Git 提交历史

```
e7187a7 Step 6-9: Sleuth impact analysis integration and project README
29ac90c Step 2-5: ADGFuzz modifications and bridge integration complete
3e2ce62 Step 1: Bridge module and environment setup complete
92cd836 Initial commit: project plan and work requirements
```

---

## 引用

如果使用本项目，请引用原始论文：

```bibtex
@inproceedings{adgfuzz2026wang,
  title={ADGFUZZ: Assignment Dependency-Guided Fuzzing for Robotic Vehicles},
  author={Yuncheng Wang and Yaowen Zheng and Puzhuo Liu and Dongliang Fang 
          and Jiaxing Cheng and Dingyi Shi and Limin Sun},
  booktitle={NDSS},
  year={2026}
}

@inproceedings{sleuth2024,
  title={Sleuth: Bug Impact Exploration via Memory-Graph-Guided Fuzzing},
  booktitle={ISSTA},
  year={2024}
}
```
