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
markdown_report.py - Markdown 格式安全报告生成器

结构化展示扫描摘要、CVE 详细分析以及修复建议。
"""

from datetime import datetime, timezone


# 风险等级对应的 Markdown 标记前缀
_SEVERITY_EMOJI: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "UNKNOWN": "⚪",
}


class MarkdownReport:
    """将漏洞分析结果渲染为结构化 Markdown 报告。"""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, data: dict) -> str:
        """生成 Markdown 格式的安全报告。

        Args:
            data: 包含扫描结果和 CVE 分析数据的字典。结构示例:
                {
                    "image": str,
                    "scan_time": str,
                    "summary": {
                        "total": int,
                        "critical": int,
                        "high": int,
                        "medium": int,
                        "low": int,
                        "unknown": int,
                    },
                    "cve_details": [
                        {
                            "cve_id": str,
                            "severity": str,
                            "cvss_score": float,
                            "description": str,
                            "affected_package": str,
                            "fixed_version": str,
                            "intel": str,           # 威胁情报摘要
                            "agent_verdict": str,   # Agent 判定结论
                            "verdict_basis": str,   # 判定依据
                        }
                    ],
                    "remediation_suggestions": [str],
                }

        Returns:
            完整的 Markdown 字符串。
        """
        sections = [
            self._render_header(data),
            self._render_summary(data),
            self._render_cve_details(data),
            self._render_remediation(data),
            self._render_footer(),
        ]
        return "\n\n".join(filter(None, sections))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _render_header(self, data: dict) -> str:
        image = data.get("image", "N/A")
        scan_time = data.get("scan_time", "N/A")
        generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"# 🛡️ ContainerGuard AI — 安全分析报告\n\n"
            f"| 字段 | 值 |\n"
            f"|------|----|\n"
            f"| **目标镜像** | `{image}` |\n"
            f"| **扫描时间** | {scan_time} |\n"
            f"| **报告生成** | {generated_at} |"
        )

    def _render_summary(self, data: dict) -> str:
        summary = data.get("summary", {})
        total = summary.get("total", 0)
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        unknown = summary.get("unknown", 0)

        lines = [
            "## 📊 扫描摘要",
            "",
            f"共发现 **{total}** 个 CVE 漏洞，风险分布如下：",
            "",
            "| 风险等级 | 数量 |",
            "|----------|------|",
            f"| 🔴 CRITICAL | **{critical}** |",
            f"| 🟠 HIGH     | **{high}** |",
            f"| 🟡 MEDIUM   | **{medium}** |",
            f"| 🔵 LOW      | **{low}** |",
            f"| ⚪ UNKNOWN  | **{unknown}** |",
        ]
        return "\n".join(lines)

    def _render_cve_details(self, data: dict) -> str:
        cve_list = data.get("cve_details", [])
        if not cve_list:
            return "## 🔍 CVE 详细分析\n\n*未发现漏洞。*"

        lines = ["## 🔍 CVE 详细分析"]

        for cve in cve_list:
            cve_id = cve.get("cve_id", "N/A")
            severity = cve.get("severity", "UNKNOWN").upper()
            cvss = cve.get("cvss_score", "N/A")
            description = cve.get("description", "无描述")
            pkg = cve.get("affected_package", "N/A")
            fixed = cve.get("fixed_version", "暂无修复版本")
            intel = cve.get("intel", "暂无情报")
            verdict = cve.get("agent_verdict", "N/A")
            basis = cve.get("verdict_basis", "N/A")

            emoji = _SEVERITY_EMOJI.get(severity, "⚪")

            lines += [
                "",
                f"### {emoji} {cve_id}  `{severity}` · CVSS {cvss}",
                "",
                f"**影响组件：** `{pkg}`　**修复版本：** `{fixed}`",
                "",
                f"**描述：** {description}",
                "",
                "#### 威胁情报",
                f"> {intel}",
                "",
                "#### Agent 判定",
                f"- **结论：** {verdict}",
                f"- **依据：** {basis}",
                "",
                "---",
            ]

        return "\n".join(lines)

    def _render_remediation(self, data: dict) -> str:
        suggestions = data.get("remediation_suggestions", [])
        if not suggestions:
            return ""

        lines = ["## 🔧 修复建议", ""]
        for i, suggestion in enumerate(suggestions, start=1):
            lines.append(f"{i}. {suggestion}")
        return "\n".join(lines)

    def _render_footer(self) -> str:
        return (
            "> **免责声明：** 本报告由 ContainerGuard AI 自动生成，仅供参考。"
            "请结合实际业务场景进行人工复核后再做决策。"
        )
