# ADGFuzz + Sleuth 适配修改清单

## 修改的文件

### ADGFuzz-main/fuzzer/fuzz.py (ADGfuzzer)
- **Line 19-28**: 添加 SleuthExporter 导入逻辑，自动检测 bridge 模块是否可用
- **Line 24-25**: `__init__` 增加 `sleuth_export: bool = False` 参数
- **Line 81-87**: `__init__` 中初始化 SleuthExporter（当 sleuth_export=True 时）
- **Line 543-556**: `save_bug` 方法中增加 Sleuth 导出调用

### ADGFuzz-main/fuzzer/fuzzpx4.py (PX4fuzzer)
- **Line 21-28**: 添加 SleuthExporter 导入逻辑
- **Line 26-27**: `__init__` 增加 `sleuth_export` 参数
- **Line 83-89**: `__init__` 中初始化 SleuthExporter
- **Line 523-536**: `save_bug` 方法中增加 Sleuth 导出调用

### ADGFuzz-main/adgfuzz.py (主入口)
- **Line 165**: 新增 `--sleuth_export` 命令行参数
- **Line 285-287**: 将 sleuth_export 传递给 PX4fuzzer/ADGfuzzer 构造函数

## 新增的文件

### bridge/ 目录
| 文件 | 用途 |
|------|------|
| `adg_to_sleuth.py` | 核心桥接模块：解析 ADGFuzz bug → 生成 harness + 种子 + VulnTable |
| `adgfuzz_sleuth_export.py` | SleuthExporter 类：集成到 ADGFuzz 实时导出 |
| `setup_ubuntu.sh` | Ubuntu 环境一键安装脚本 |
| `run_pipeline.sh` | 端到端自动化流水线 |
| `sleuth_setup_bug.sh` | 为单个 bug 设置 Sleuth 分析环境 |
| `CHANGES.md` | 本文件 |

## 使用方式

### 1. 运行 ADGFuzz 并启用 Sleuth 导出
```bash
python adgfuzz.py \
    --initfile static/initpath/ArduCopter/ static/initpath/libraries/ \
    --rvtype copter \
    --time 3600 \
    --out_path outfile/copter/ \
    --sleuth_export
```

### 2. 后处理已有结果
```bash
python bridge/adg_to_sleuth.py \
    --bug_dir outfile/copter/ \
    --output_dir sleuth_input/
```

### 3. 设置单个 Bug 的 Sleuth 分析
```bash
./bridge/sleuth_setup_bug.sh 1 sleuth_input/harnesses ~/work/ArduPilot
```

### 4. 运行完整流水线
```bash
./bridge/run_pipeline.sh copter 3600
```
