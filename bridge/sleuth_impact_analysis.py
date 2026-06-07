#!/usr/bin/env python3
"""
Sleuth Impact Analysis Integration
===================================
将 Sleuth 的 bug 影响分析能力适配到 ADGFuzz 发现的 RV 漏洞上。

功能:
1. 注册 ADGFuzz bug 到 Sleuth VulnTable
2. 运行 crash 分析
3. 生成影响对比报告
4. 评估严重性评分
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from collections import defaultdict


class SleuthImpactAnalyzer:
    """Sleuth 影响分析器 - 为 ADGFuzz bug 提供深度分析"""

    def __init__(self, sleuth_path: str):
        self.sleuth_path = sleuth_path
        self.vulntable_path = os.path.join(sleuth_path, 'src/vulnInfo/VulnTable.txt')
        self.exec_path = os.path.join(sleuth_path, 'src/exec')
        self.result_path = os.path.join(sleuth_path, 'Experiment/result')

    def register_bug(self, bug_id: str, project_path: str,
                     binary_name: str, parameters: str = "@@") -> bool:
        """注册一个 ADGFuzz bug 到 Sleuth 的 VulnTable"""
        entry = f"/src/project/adgfuzz_bugs/{bug_id}\t{project_path}\t{binary_name}\t{parameters}"

        # 检查是否已存在
        if os.path.exists(self.vulntable_path):
            with open(self.vulntable_path, 'r') as f:
                if bug_id in f.read():
                    print(f"[+] Bug {bug_id} already registered")
                    return True

        # 追加条目
        with open(self.vulntable_path, 'a') as f:
            f.write(f"\n{entry}")

        print(f"[+] Registered {bug_id} in VulnTable")
        return True

    def run_crash_analysis(self, bug_id: str) -> bool:
        """运行 Sleuth crash 分析"""
        crash_script = os.path.join(
            self.exec_path, 'crash_analysis/crash_run.sh'
        )

        if not os.path.exists(crash_script):
            print(f"[!] Crash analysis script not found: {crash_script}")
            return False

        print(f"[+] Running crash analysis for {bug_id}...")
        try:
            result = subprocess.run(
                ['bash', crash_script, bug_id],
                cwd=os.path.join(self.exec_path, 'crash_analysis'),
                capture_output=True, text=True, timeout=300
            )
            print(result.stdout)
            if result.returncode != 0:
                print(f"[!] Crash analysis had errors:\n{result.stderr}")
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            print("[!] Crash analysis timed out")
            return False
        except Exception as e:
            print(f"[!] Crash analysis failed: {e}")
            return False

    def generate_impact_report(self, bug_id: str) -> Optional[Dict]:
        """生成单个 bug 的影响报告"""
        impact_script = os.path.join(
            self.exec_path, 'generate_result/impact_deal.py'
        )

        if not os.path.exists(impact_script):
            print(f"[!] Impact script not found: {impact_script}")
            return None

        print(f"[+] Generating impact report for {bug_id}...")
        try:
            result = subprocess.run(
                ['python', impact_script, bug_id],
                cwd=os.path.join(self.exec_path, 'generate_result'),
                capture_output=True, text=True, timeout=120
            )
            print(result.stdout)
        except Exception as e:
            print(f"[!] Impact report generation failed: {e}")
            return None

        # 尝试读取生成的结果
        result_file = os.path.join(
            self.result_path, 'New_Impact_Table-2.json'
        )
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                data = json.load(f)
                # 筛选当前 bug 的结果
                for entry in data:
                    if isinstance(entry, dict) and bug_id in str(entry):
                        return entry
        return None

    def compare_impacts(self, adgfuzz_bugs: List[str]) -> Dict:
        """
        比较 ADGFuzz 原始发现 vs Sleuth 深度分析结果

        返回对比报告:
        - ADGFuzz: 发现的 bug 类型
        - Sleuth: 新发现的影响类型
        - 严重性变化
        """
        comparison = {
            'adgfuzz_findings': defaultdict(list),
            'sleuth_new_impacts': defaultdict(list),
            'severity_changes': [],
            'summary': {}
        }

        for bug_id in adgfuzz_bugs:
            # 读取 ADGFuzz 元数据
            meta_path = os.path.join(
                self.sleuth_path,
                f'src/project/adgfuzz_bugs/{bug_id}',
                'metadata.json'
            )

            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
                bug_type = meta.get('bug_type', 'Unknown')
                comparison['adgfuzz_findings'][bug_type].append(bug_id)

            # 读取 Sleuth 分析结果
            sleuth_result = os.path.join(
                self.result_path, 'Unique_Impact',
                f'{bug_id}_impacts.json'
            )
            if os.path.exists(sleuth_result):
                with open(sleuth_result, 'r') as f:
                    impacts = json.load(f)
                for impact in impacts if isinstance(impacts, list) else [impacts]:
                    impact_type = impact.get('type', 'Unknown')
                    comparison['sleuth_new_impacts'][impact_type].append(bug_id)

        # 汇总统计
        comparison['summary'] = {
            'total_bugs_analyzed': len(adgfuzz_bugs),
            'adgfuzz_bug_types': dict(comparison['adgfuzz_findings']),
            'sleuth_impact_types': dict(comparison['sleuth_new_impacts']),
            'new_impacts_found': sum(
                len(v) for v in comparison['sleuth_new_impacts'].values()
            ),
        }

        return comparison

    def batch_analyze(self, bug_ids: List[str]) -> Dict:
        """批量分析所有 ADGFuzz bug"""
        results = {
            'analyzed': [],
            'failed': [],
            'comparison': None,
        }

        for bug_id in bug_ids:
            print(f"\n{'='*50}")
            print(f" Analyzing {bug_id}")
            print(f"{'='*50}")

            success = self.run_crash_analysis(bug_id)
            if success:
                impact = self.generate_impact_report(bug_id)
                results['analyzed'].append({
                    'bug_id': bug_id,
                    'impact': impact,
                })
            else:
                results['failed'].append(bug_id)

        # 生成对比报告
        if results['analyzed']:
            results['comparison'] = self.compare_impacts(
                [r['bug_id'] for r in results['analyzed']]
            )

        return results


def main():
    parser = argparse.ArgumentParser(
        description='Sleuth Impact Analysis for ADGFuzz Bugs'
    )
    parser.add_argument('--sleuth_path', type=str,
                        default=os.getenv('SLEUTH_PATH', '.'),
                        help='Path to Sleuth_code directory')
    parser.add_argument('--bug_ids', type=str, nargs='+',
                        help='Bug IDs to analyze (e.g., ADGFUZZ-BUG-1)')
    parser.add_argument('--register', type=str,
                        help='Register a bug: bug_id,project_path,binary,params')
    parser.add_argument('--compare', action='store_true',
                        help='Generate comparison report')
    parser.add_argument('--output', type=str, default='impact_report.json',
                        help='Output file for results')

    args = parser.parse_args()

    analyzer = SleuthImpactAnalyzer(args.sleuth_path)

    if args.register:
        parts = args.register.split(',')
        if len(parts) >= 3:
            bug_id, project, binary = parts[0], parts[1], parts[2]
            params = parts[3] if len(parts) > 3 else "@@"
            analyzer.register_bug(bug_id, project, binary, params)

    if args.bug_ids:
        results = analyzer.batch_analyze(args.bug_ids)
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Results saved to {args.output}")

        if args.compare and results.get('comparison'):
            comp = results['comparison']['summary']
            print(f"\n{'='*50}")
            print(f" Impact Comparison Summary")
            print(f"{'='*50}")
            print(f" Total bugs analyzed: {comp['total_bugs_analyzed']}")
            print(f" ADGFuzz bug types: {comp['adgfuzz_bug_types']}")
            print(f" Sleuth new impact types: {comp['sleuth_impact_types']}")
            print(f" New impacts found: {comp['new_impacts_found']}")


if __name__ == '__main__':
    main()
