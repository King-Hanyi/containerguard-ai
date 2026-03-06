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
json_report.py - JSON 格式安全报告生成器

将分析结果数据字典标准化输出为格式优美的 JSON 字符串（缩进 2 个空格）。
"""

import json
from datetime import datetime, timezone
from typing import Any


class JsonReport:
    """将漏洞分析结果序列化为标准 JSON 格式报告。"""

    def generate(self, data: dict) -> str:
        """生成 JSON 格式的安全报告。

        Args:
            data: 包含扫描结果和 CVE 分析数据的字典。结构示例:
                {
                    "image": str,
                    "scan_time": str,
                    "summary": {"total": int, "critical": int, ...},
                    "cve_details": [{"cve_id": str, "severity": str, ...}],
                }

        Returns:
            格式化后的 JSON 字符串（缩进 2 个空格，确保 Unicode 字符正常输出）。
        """
        report: dict[str, Any] = {
            "report_meta": {
                "format": "ContainerGuard-JSON",
                "version": "1.0.0",
                "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            },
            "scan_target": data.get("image", "unknown"),
            "scan_time": data.get("scan_time", ""),
            "summary": data.get("summary", {}),
            "cve_details": data.get("cve_details", []),
            "remediation_suggestions": data.get("remediation_suggestions", []),
        }
        return json.dumps(report, indent=2, ensure_ascii=False)
