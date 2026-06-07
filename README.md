# ADGFuzz + Sleuth 适配项目

使用 ADGFuzz 挖掘 RV（Robotic Vehicle）系统的漏洞，再用 Sleuth 进行深入的漏洞影响能力挖掘。

## 项目结构

```
.
├── ADGFuzz-main/          # ADGFuzz 模糊测试框架（含修改）
│   ├── adgfuzz.py         # 主入口（新增 --sleuth_export 选项）
│   ├── fuzzer/
│   │   ├── fuzz.py        # ArduPilot fuzzer（集成 SleuthExporter）
│   │   ├── fuzzpx4.py     # PX4 fuzzer（集成 SleuthExporter）
│   │   ├── oracle.py      # Bug 检测预言
│   │   ├── runtimedict.py # 参数字典
│   │   └── rvmethod.py    # MAVLink 通信
│   ├── model/             # ADG → MIS 映射
│   ├── static/            # 静态分析结果(ADG)
│   └── data/              # 参数和命令数据
├── Sleuth_code/           # Sleuth 漏洞影响分析框架
│   ├── Sleuth/            # AFLplusplus 修改版
│   ├── ddgAnalysis/       # 静态内存依赖图分析
│   └── src/               # 分析和评估脚本
├── bridge/                # 🆕 桥接模块（核心适配代码）
│   ├── adg_to_sleuth.py           # ADGFuzz → Sleuth 转换器
│   ├── adgfuzz_sleuth_export.py   # SleuthExporter 实时导出类
│   ├── sleuth_impact_analysis.py  # Sleuth 影响分析集成
│   ├── sleuth_setup_bug.sh        # 单Bug分析环境设置
│   ├── setup_ubuntu.sh            # Ubuntu 环境一键安装
│   ├── run_pipeline.sh            # 端到端自动化流水线
│   ├── CHANGES.md                 # 修改清单
│   └── test/                      # 测试数据和输出
├── 资料/                  # 论文和介绍资料
├── PROJECT_PLAN.md        # 详细工作计划
└── README.md              # 本文件
```

## 快速开始

### 前置条件
- Ubuntu 20.04 或 22.04（需要运行 SITL 模拟器）
- Python 3.8+
- 至少 20GB 磁盘空间

### 1. 环境安装

```bash
# 克隆项目
git clone <repo-url>
cd ADGFuzz-Sleuth

# 一键安装所有依赖
bash bridge/setup_ubuntu.sh
source ~/.bashrc
```

### 2. 运行 ADGFuzz（启用 Sleuth 导出）

```bash
cd ADGFuzz-main

# 快速测试 (~5 分钟)
python adgfuzz.py \
    --initfile paths/testcopter/quicktest/ \
    --rvtype copter \
    --time 300 \
    --out_path outfile/quicktest/ \
    --sleuth_export

# 小规模运行 (~1 小时)
python adgfuzz.py \
    --initfile static/initpath/ArduCopter/ static/initpath/libraries/ \
    --rvtype copter \
    --time 3600 \
    --out_path outfile/copter/ \
    --sleuth_export
```

### 3. 桥接转换

```bash
cd bridge

# 处理 ADGFuzz 发现的所有 bug
python adg_to_sleuth.py \
    --bug_dir ../ADGFuzz-main/outfile/copter/ \
    --output_dir ./sleuth_input/
```

### 4. Sleuth 深度分析

```bash
# 为单个 bug 设置分析环境
bash sleuth_setup_bug.sh 1 ./sleuth_input/harnesses ~/work/ArduPilot

# 运行 Sleuth fuzzing
cd $SLEUTH_PATH/src/exec
python autoRun.py ADGFUZZ-BUG-1 10m 1 SLEUTH

# 分析结果
cd crash_analysis && ./crash_run.sh ADGFUZZ-BUG-1
cd ../generate_result
python impact_deal.py ADGFUZZ-BUG-1
```

## 工作流程

```
┌─────────────────────────────────────────────────────────────┐
│                    ADGFuzz + Sleuth 流水线                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  [ArduPilot 源码]                                            │
│       │                                                     │
│       ▼                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │ 静态分析  │───▶│  ADG → MIS   │───▶│  SITL Fuzzing │      │
│  │ (ADGs)   │    │  (Mapping)   │    │  (ADGFuzz)   │      │
│  └──────────┘    └──────────────┘    └──────┬───────┘      │
│                                             │               │
│                                    ┌────────▼──────────┐   │
│                                    │  Bug 输出文件      │   │
│                                    │  + Sleuth 导出    │   │
│                                    └────────┬──────────┘   │
│                                             │               │
│                           ┌─────────────────▼───────────┐  │
│                           │  Bridge 桥接模块            │  │
│                           │  - 解析 bug → harneess     │  │
│                           │  - 参数 → 二进制种子       │  │
│                           │  - 模块 → 代码定位         │  │
│                           └─────────────────┬───────────┘  │
│                                             │               │
│                    ┌────────────────────────▼───────────┐  │
│                    │  Sleuth 影响分析                    │  │
│                    │  - DDG 静态分析 → target.json      │  │
│                    │  - DDG_INSTR 编译 → *_cov 二进制   │  │
│                    │  - 内存图引导 Fuzzing               │  │
│                    │  - Crash 分析 → 影响评估           │  │
│                    └────────────────┬───────────────────┘  │
│                                     │                       │
│                            ┌────────▼──────────┐           │
│                            │  影响分析报告      │           │
│                            │  - 新 crash 类型   │           │
│                            │  - 严重性评分      │           │
│                            │  - 影响范围评估    │           │
│                            └───────────────────┘           │
└─────────────────────────────────────────────────────────────┘
```

## 修改说明

### ADGFuzz 修改
- `adgfuzz.py`: 新增 `--sleuth_export` 参数
- `fuzzer/fuzz.py`: ADGfuzzer 集成 SleuthExporter
- `fuzzer/fuzzpx4.py`: PX4fuzzer 集成 SleuthExporter

详见 `bridge/CHANGES.md`

## 当前进度

| 步骤 | 状态 | 说明 |
|------|------|------|
| 1. 环境搭建 | ✅ | 安装脚本完成，代码修改完成 |
| 2. ADGFuzz 运行 | ⏳ | 需要在 Ubuntu 上执行 |
| 3. 漏洞定位 | ⏳ | 需要 bug 输出数据 |
| 4. Harness 构建 | 🔧 | 模板已生成，需实际代码 |
| 5. 桥接模块 | ✅ | 测试通过（2/2 sample bugs） |
| 6. DDG 分析 | ⏳ | 需要在 Ubuntu 上执行 |
| 7. Sleuth Fuzzing | ⏳ | 需要编译后的 harness |
| 8. 结果分析 | ⏳ | 分析脚本已准备 |
| 9. 端到端流水线 | 🔧 | 脚本已完成，待集成测试 |

## Git 提交历史

```
92cd836 Initial commit: project plan and work requirements
3e2ce62 Step 1: Bridge module and environment setup complete
29ac90c Step 2-5: ADGFuzz modifications and bridge integration complete
```

## 下一步操作（在 Ubuntu 上）

1. 运行 `bash bridge/setup_ubuntu.sh` 安装环境
2. 运行 `python adgfuzz.py --sleuth_export ...` 开始 fuzzing
3. 使用 `python bridge/adg_to_sleuth.py` 转换结果
4. 使用 `bash bridge/sleuth_setup_bug.sh` 设置 Sleuth 分析
5. 运行 Sleuth 进行深度影响挖掘
