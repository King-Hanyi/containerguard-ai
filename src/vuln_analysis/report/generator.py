# Copyright 2024 ContainerGuard AI Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
generator.py - 报告生成主入口

ReportGenerator 聚合 MarkdownReport、JsonReport 和 OpenVEXReport，
提供 generate_all() 一键生成三种格式报告并保存到指定目录的能力。
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from .json_report import JsonReport
from .markdown_report import MarkdownReport
from .openvex_report import OpenVEXReport

logger = logging.getLogger(__name__)


@dataclass
class GeneratedReports:
    """保存三种格式报告的输出路径。"""

    markdown_path: str = ""
    json_path: str = ""
    openvex_path: str = ""
    errors: list[str] = field(default_factory=list)


class ReportGenerator:
    """安全报告生成主入口，聚合三种格式的报告生成器。

    Usage::

        from vuln_analysis.report import ReportGenerator

        generator = ReportGenerator()
        result = generator.generate_all(data, output_dir="./reports")
        print(result.markdown_path)
        print(result.json_path)
        print(result.openvex_path)
    """

    # 输出文件名模板（不含后缀的基础名）
    _REPORT_BASENAME = "containerguard_report"

    def __init__(
        self,
        markdown_gen: MarkdownReport | None = None,
        json_gen: JsonReport | None = None,
        openvex_gen: OpenVEXReport | None = None,
    ) -> None:
        """初始化报告生成器。

        Args:
            markdown_gen: 可注入的 MarkdownReport 实例（用于测试替换）。
            json_gen:     可注入的 JsonReport 实例。
            openvex_gen:  可注入的 OpenVEXReport 实例。
        """
        self._markdown_gen = markdown_gen or MarkdownReport()
        self._json_gen = json_gen or JsonReport()
        self._openvex_gen = openvex_gen or OpenVEXReport()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_all(
        self,
        data: dict,
        output_dir: str = ".",
        base_name: str | None = None,
    ) -> GeneratedReports:
        """一次性生成 Markdown、JSON 和 OpenVEX 三种格式报告并写入磁盘。

        Args:
            data:       包含扫描结果的标准化字典（参见各子报告类的 docstring）。
            output_dir: 报告输出目录路径（如不存在则自动创建）。
            base_name:  输出文件的基础名（不含后缀），默认为 "containerguard_report"。

        Returns:
            GeneratedReports dataclass，包含三个文件的绝对路径以及错误列表。
        """
        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        base = base_name or self._REPORT_BASENAME

        result = GeneratedReports()

        # ---- Markdown ----
        try:
            md_content = self._markdown_gen.generate(data)
            md_path = out_dir / f"{base}.md"
            md_path.write_text(md_content, encoding="utf-8")
            result.markdown_path = str(md_path)
            logger.info("Markdown report saved → %s", md_path)
        except Exception as exc:  # pylint: disable=broad-except
            msg = f"Markdown report generation failed: {exc}"
            logger.error(msg)
            result.errors.append(msg)

        # ---- JSON ----
        try:
            json_content = self._json_gen.generate(data)
            json_path = out_dir / f"{base}.json"
            json_path.write_text(json_content, encoding="utf-8")
            result.json_path = str(json_path)
            logger.info("JSON report saved → %s", json_path)
        except Exception as exc:  # pylint: disable=broad-except
            msg = f"JSON report generation failed: {exc}"
            logger.error(msg)
            result.errors.append(msg)

        # ---- OpenVEX ----
        try:
            vex_content = self._openvex_gen.generate(data)
            vex_path = out_dir / f"{base}.vex.json"
            vex_path.write_text(vex_content, encoding="utf-8")
            result.openvex_path = str(vex_path)
            logger.info("OpenVEX report saved → %s", vex_path)
        except Exception as exc:  # pylint: disable=broad-except
            msg = f"OpenVEX report generation failed: {exc}"
            logger.error(msg)
            result.errors.append(msg)

        # 汇总日志
        if result.errors:
            logger.warning(
                "%d report(s) failed to generate. Errors: %s",
                len(result.errors),
                result.errors,
            )
        else:
            logger.info(
                "All 3 reports generated successfully in %s", out_dir
            )

        return result

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def generate_markdown(self, data: dict) -> str:
        """仅生成 Markdown 字符串（不写文件）。"""
        return self._markdown_gen.generate(data)

    def generate_json(self, data: dict) -> str:
        """仅生成 JSON 字符串（不写文件）。"""
        return self._json_gen.generate(data)

    def generate_openvex(self, data: dict) -> str:
        """仅生成 OpenVEX 字符串（不写文件）。"""
        return self._openvex_gen.generate(data)
