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
report - 安全报告生成模块

提供三种格式的安全报告生成能力：
  - Markdown (.md)
  - JSON (.json)
  - OpenVEX v0.2.0 (.vex.json)
"""

from .generator import ReportGenerator
from .markdown_report import MarkdownReport
from .json_report import JsonReport
from .openvex_report import OpenVEXReport

__all__ = [
    "ReportGenerator",
    "MarkdownReport",
    "JsonReport",
    "OpenVEXReport",
]
