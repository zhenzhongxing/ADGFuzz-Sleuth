#!/usr/bin/env python3
"""
ADGFuzz Sleuth Export Module
=============================
集成到 ADGFuzz 中，在发现 bug 时同时导出 Sleuth 兼容格式的数据。

使用方法1: 作为独立脚本处理已有结果
    python adgfuzz_sleuth_export.py --bug_dir outfile/copter/

使用方法2: 作为模块导入到 ADGFuzz
    from bridge.adgfuzz_sleuth_export import SleuthExporter
    exporter = SleuthExporter(output_dir="./sleuth_ready/")
    exporter.export_bug(bug_id, bug_type, path, temp_value)
"""

import os
import json
import struct
import time
import re
from typing import List, Tuple, Optional, Dict
from pathlib import Path


class SleuthExporter:
    """在 ADGFuzz 运行时同步导出 Sleuth 兼容格式"""

    def __init__(self, output_dir: str = "./sleuth_export/"):
        self.output_dir = output_dir
        self.manifest: List[Dict] = []
        self.bug_count = 0
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "seeds"), exist_ok=True)
        os.makedirs(os.path.join(output_dir, "metadata"), exist_ok=True)

    def export_bug(self, bug_id: int, bug_type: str,
                   init_path: str, rv_path: List,
                   temp_value: List[Tuple[str, str, str]],
                   timestamp: float = None) -> str:
        """
        导出一个 bug 为 Sleuth 兼容格式

        参数:
            bug_id: bug 编号
            bug_type: ArithmException, StatusError, WpDeviation
            init_path: ADG 路径信息
            rv_path: RV 输入路径
            temp_value: [(type, name, value), ...]
            timestamp: 发现时间

        返回: 种子文件路径
        """
        if timestamp is None:
            timestamp = time.time()

        self.bug_count += 1

        # 1. 保存元数据 (JSON格式，包含完整信息供后续分析)
        metadata = {
            'bug_id': bug_id,
            'bug_type': bug_type,
            'timestamp': timestamp,
            'init_path': str(init_path),
            'rv_path': [[str(x) for x in node] for node in rv_path],
            'inputs': [
                {'type': t, 'name': n, 'value': str(v)}
                for t, n, v in temp_value
            ],
        }

        meta_path = os.path.join(
            self.output_dir, "metadata", f"bug{bug_id}.json"
        )
        with open(meta_path, 'w') as f:
            json.dump(metadata, f, indent=2)

        # 2. 生成二进制种子（供 AFL/Sleuth 变异）
        seed_path = os.path.join(
            self.output_dir, "seeds", f"bug{bug_id}_{bug_type}.bin"
        )
        seed_data = self._generate_seed_data(temp_value)
        with open(seed_path, 'wb') as f:
            f.write(seed_data)

        # 3. 更新 manifest
        self.manifest.append({
            'bug_id': bug_id,
            'bug_type': bug_type,
            'seed': seed_path,
            'metadata': meta_path,
            'param_count': len([x for x in temp_value if x[0] == 'paramset']),
            'cmd_count': len([x for x in temp_value if x[0] == 'mavcmd']),
        })

        # 4. 更新 manifest 文件
        manifest_path = os.path.join(self.output_dir, "manifest.json")
        with open(manifest_path, 'w') as f:
            json.dump(self.manifest, f, indent=2)

        return seed_path

    def _generate_seed_data(self,
                            temp_value: List[Tuple[str, str, str]]
                            ) -> bytes:
        """将 ADGFuzz 输入转换为二进制种子"""
        data = bytearray()

        for itype, iname, ivalue in temp_value:
            # 写入类型标记 (1 byte)
            if itype == 'paramset':
                data.append(0x01)
                # 参数名长度 + 参数名
                name_bytes = iname.encode('utf-8')[:64]
                data.append(len(name_bytes))
                data.extend(name_bytes)
                # 参数值 (4 bytes float)
                try:
                    data.extend(struct.pack('<f', float(ivalue)))
                except (ValueError, OverflowError):
                    data.extend(b'\x00\x00\x00\x00')

            elif itype == 'mavcmd':
                data.append(0x02)
                # 命令名长度 + 命令名
                name_bytes = iname.encode('utf-8')[:64]
                data.append(len(name_bytes))
                data.extend(name_bytes)
                # 参数数量 + 参数值
                try:
                    params = eval(ivalue) if isinstance(ivalue, str) else ivalue
                    if isinstance(params, list):
                        data.append(len(params))
                        for p in params:
                            data.extend(struct.pack('<f', float(p)))
                except:
                    data.append(0)

            elif itype == 'rc':
                data.append(0x03)
                # RC 通道 + PWM 值
                try:
                    data.append(int(iname))
                    data.extend(struct.pack('<H', int(ivalue)))
                except (ValueError, OverflowError):
                    data.extend(b'\x00\x00\x00')

            elif itype == 'modeset':
                data.append(0x04)
                name_bytes = iname.encode('utf-8')[:32]
                data.append(len(name_bytes))
                data.extend(name_bytes)

        return bytes(data)

    def get_statistics(self) -> Dict:
        """获取导出统计信息"""
        bug_types = {}
        for item in self.manifest:
            bt = item['bug_type']
            bug_types[bt] = bug_types.get(bt, 0) + 1

        return {
            'total_bugs': len(self.manifest),
            'by_type': bug_types,
            'total_params': sum(m['param_count'] for m in self.manifest),
            'total_cmds': sum(m['cmd_count'] for m in self.manifest),
        }


# ============================================================
# ADGFuzz Monkey-Patch 集成点
# ============================================================
#
# 在 ADGFuzz 的 fuzz.py 中，在 save_bug() 方法调用后添加:
#
#   from bridge.adgfuzz_sleuth_export import SleuthExporter
#   # 在 ADGfuzzer.__init__() 中:
#   self.sleuth_exporter = SleuthExporter(
#       output_dir=os.path.join(bug_out_path, "sleuth_export")
#   )
#   # 在 save_bug() 调用后:
#   self.sleuth_exporter.export_bug(
#       bug_id=self.bug_count,
#       bug_type=bugtype,
#       init_path=str(i_path),
#       rv_path=path,
#       temp_value=self.temp_value,
#       timestamp=time_stamp
#   )


# ============================================================
# CLI - 处理已有结果
# ============================================================

def process_existing_results(bug_dir: str, output_dir: str):
    """处理 ADGFuzz 已生成的结果目录"""
    from adg_to_sleuth import parse_bug_file

    exporter = SleuthExporter(output_dir)

    bug_files = sorted([
        f for f in os.listdir(bug_dir)
        if f.startswith('bug') and f.endswith('.txt')
    ])

    print(f"[+] Found {len(bug_files)} bug files in {bug_dir}")

    for filename in bug_files:
        filepath = os.path.join(bug_dir, filename)
        bug = parse_bug_file(filepath)

        if bug is None:
            continue

        seed_path = exporter.export_bug(
            bug_id=bug.bug_id,
            bug_type=bug.bug_type,
            init_path=bug.init_path,
            rv_path=bug.rv_path,
            temp_value=bug.inputs,
            timestamp=bug.timestamp,
        )
        print(f"  Bug #{bug.bug_id}: {bug.bug_type} → {seed_path}")

    stats = exporter.get_statistics()
    print(f"\n[+] Export complete:")
    print(f"    Total: {stats['total_bugs']}")
    for bt, count in stats['by_type'].items():
        print(f"    {bt}: {count}")

    return stats


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(
        description='Export ADGFuzz results to Sleuth-compatible format'
    )
    parser.add_argument('--bug_dir', type=str, required=True,
                        help='Directory containing ADGFuzz bug files')
    parser.add_argument('--output_dir', type=str,
                        default='./sleuth_export/',
                        help='Output directory')

    args = parser.parse_args()

    if not os.path.isdir(args.bug_dir):
        print(f"[!] Bug directory not found: {args.bug_dir}")
        exit(1)

    process_existing_results(args.bug_dir, args.output_dir)
