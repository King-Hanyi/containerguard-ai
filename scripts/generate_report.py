#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ContainerGuard AI — CI 报告生成入口脚本。

在 GitHub Actions 中以独立进程调用，从 baseline_results.json 读取扫描数据，
调用 report_generator.generate_markdown_report() 生成 Markdown 报告并写入文件。

用法:
    python scripts/generate_report.py [--input PATH] [--output PATH] [--target IMAGE]
"""

import argparse
import json
import sys
from pathlib import Path

# 将项目 src 目录加入路径，确保在 CI 环境中也能找到模块
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from vuln_analysis.report_generator import generate_markdown_report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="生成 ContainerGuard AI 漏洞分析 Markdown 报告"
    )
    parser.add_argument(
        "--input",
        default="docs/baseline_results.json",
        help="扫描结果 JSON 文件路径 (默认: docs/baseline_results.json)",
    )
    parser.add_argument(
        "--output",
        default="pr_report.md",
        help="输出 Markdown 报告路径 (默认: pr_report.md)",
    )
    parser.add_argument(
        "--target",
        default="",
        help="被扫描的容器镜像名称，写入报告摘要",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] 扫描结果文件不存在: {input_path}", file=sys.stderr)
        sys.exit(1)

    with open(input_path, encoding="utf-8") as f:
        scan_data = json.load(f)

    markdown_content = generate_markdown_report(scan_data=scan_data, target=args.target)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)

    print(f"[OK] Markdown 报告已写入: {output_path}")


if __name__ == "__main__":
    main()
