# ADGFuzz + Sleuth 适配项目计划

## 项目目标
使用 ADGFuzz 挖掘 RV（Robotic Vehicle）系统的漏洞，再用 Sleuth 进行深入的漏洞影响能力挖掘。

## 适配策略：提取-桥接方案

### 核心思路
```
ADGFuzz → 发现RV系统bug → 定位漏洞代码 → 提取为独立harness → Sleuth深度分析
```

### 为什么选择这个方案？

1. **可行性最高**：ADGFuzz通过MAVLink协议与SITL模拟器交互，Sleuth通过文件输入与独立二进制交互。直接集成Sleuth到SITL中需要大量修改两个工具的核心架构。

2. **保留各自优势**：
   - ADGFuzz擅长在完整系统环境中通过参数fuzzing发现bug
   - Sleuth擅长通过内存依赖图引导fuzzing来探索bug的深层影响

3. **桥接点清晰**：
   - ADGFuzz输出：参数触发的bug（软件崩溃、路径偏离、坠地）
   - Sleuth输入：PoC文件 + 目标二进制
   - 桥接：提取漏洞函数 → 封装为独立程序 → 转换参数为文件输入

### 9步工作计划

| 步骤 | 内容 | 预计耗时 | 关键产出 |
|------|------|---------|---------|
| 1 | Ubuntu环境搭建 | 2-4h | 两个工具独立运行成功 |
| 2 | 运行ADGFuzz | 1-2h | bug触发输入文件 |
| 3 | 漏洞分析与定位 | 2-4h | 漏洞函数定位报告 |
| 4 | 构建提取Harness | 4-8h | 独立harness程序 |
| 5 | 桥接模块开发 | 2-4h | adg_to_sleuth.py |
| 6 | DDG静态分析 | 1-2h | target.json |
| 7 | Sleuth fuzzing | 4-12h | 新的crash发现 |
| 8 | 结果分析汇总 | 2-4h | 影响分析报告 |
| 9 | 端到端自动化 | 2-4h | 自动化流水线 |

### 关键技术挑战

1. **漏洞代码提取**：ArduPilot是大型C++项目，函数依赖复杂。需要最小化提取，保留漏洞触发路径。

2. **输入格式转换**：ADGFuzz的参数集(MIS)是key-value对通过MAVLink发送的，需要转换为文件字节流供Sleuth使用。

3. **DDG分析适配**：DDGAnalysis基于SVF(指针分析)，需要确保提取的代码能被正确分析。

4. **可复现性**：提取的harness需要能复现与SITL中相同的crash行为。
