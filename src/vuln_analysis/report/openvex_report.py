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
openvex_report.py - OpenVEX v0.2.0 格式安全报告生成器

严格遵循 OpenVEX v0.2.0 规范（https://github.com/openvex/spec）输出 VEX 文档，
包含 @context, @id, statements（vulnerability / products / status / justification）。

OpenVEX Status 取值（v0.2.0）:
  - not_affected        : 产品不受该漏洞影响
  - affected            : 产品受该漏洞影响
  - fixed               : 漏洞已在该版本修复
  - under_investigation : 正在评估中

OpenVEX Justification 仅在 status=not_affected 时可用，取值:
  - component_not_present
  - vulnerable_code_not_present
  - vulnerable_code_cannot_be_controlled_by_adversary
  - vulnerable_code_not_in_execute_path
  - inline_mitigations_already_exist
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Any

# OpenVEX v0.2.0 规范 @context URI
_OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# Agent 判定结论 → OpenVEX status 的映射
_VERDICT_TO_STATUS: dict[str, str] = {
    "not_affected": "not_affected",
    "affected": "affected",
    "fixed": "fixed",
    "under_investigation": "under_investigation",
    # 中文别名（宽容匹配）
    "不受影响": "not_affected",
    "受影响": "affected",
    "已修复": "fixed",
    "调查中": "under_investigation",
}

# 允许的 justification 取值集合
_VALID_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "vulnerable_code_not_in_execute_path",
    "inline_mitigations_already_exist",
}


class OpenVEXReport:
    """将漏洞分析结果序列化为符合 OpenVEX v0.2.0 规范的 VEX 文档。"""

    def generate(self, data: dict) -> str:
        """生成 OpenVEX v0.2.0 格式报告。

        Args:
            data: 包含扫描结果和 CVE 分析数据的字典。结构示例:
                {
                    "image": str,           # 如 "nginx:1.25.3"
                    "scan_time": str,
                    "cve_details": [
                        {
                            "cve_id": str,          # 如 "CVE-2023-36632"
                            "agent_verdict": str,   # 对应 OpenVEX status
                            "justification": str,   # 可选，仅在 not_affected 时有效
                            "impact_statement": str,# 可选，影响说明
                        }
                    ],
                }

        Returns:
            符合 OpenVEX v0.2.0 规范的 JSON 字符串。
        """
        image = data.get("image", "unknown-image")
        scan_time = data.get("scan_time", datetime.now(tz=timezone.utc).isoformat())
        cve_list = data.get("cve_details", [])

        doc_id = f"https://containerguard.ai/vex/{uuid.uuid4()}"

        statements = [
            self._build_statement(cve, image) for cve in cve_list
        ]

        vex_doc: dict[str, Any] = {
            "@context": _OPENVEX_CONTEXT,
            "@id": doc_id,
            "author": "ContainerGuard AI",
            "timestamp": scan_time,
            "last_updated": datetime.now(tz=timezone.utc).isoformat(),
            "version": "1",
            "tooling": "ContainerGuard AI v1.0.0",
            "statements": statements,
        }
        return json.dumps(vex_doc, indent=2, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_statement(self, cve: dict, image: str) -> dict[str, Any]:
        """将单条 CVE 数据转换为 OpenVEX statement 对象。"""
        cve_id = cve.get("cve_id", "CVE-UNKNOWN")
        raw_verdict = cve.get("agent_verdict", "under_investigation")
        status = _VERDICT_TO_STATUS.get(raw_verdict, "under_investigation")

        statement: dict[str, Any] = {
            "vulnerability": {
                "@id": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "name": cve_id,
                "description": cve.get("description", ""),
            },
            "products": [
                {
                    "@id": f"pkg:oci/{image}",
                    "identifiers": {
                        "purl": f"pkg:oci/{image}",
                    },
                }
            ],
            "status": status,
        }

        # justification 仅在 not_affected 时有意义
        if status == "not_affected":
            justification = cve.get("justification", "")
            if justification in _VALID_JUSTIFICATIONS:
                statement["justification"] = justification
            else:
                # 回退到最通用的 justification
                statement["justification"] = "vulnerable_code_not_present"

        # impact_statement（可选注释）
        impact = cve.get("impact_statement") or cve.get("verdict_basis", "")
        if impact:
            statement["impact_statement"] = impact

        return statement
