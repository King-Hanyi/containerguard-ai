# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Intel Agent — 漏洞情报检索智能体。

职责: 调用 IntelSkill 从 NVD / GHSA / RedHat / Ubuntu 获取 CVE 情报数据。
"""

import logging
from vuln_analysis.agents.state import IntelResult, MultiAgentState

logger = logging.getLogger(__name__)


async def intel_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    Intel Agent 节点: 为每个 CVE 检索情报信息。
    
    从 state.engine_input.info.intel 中提取已获取的情报数据，
    解析为结构化的 IntelResult。
    """
    logger.info("🔍 Intel Agent 启动，处理 %d 个 CVE", len(state.cve_list))
    
    intel_data_list = []
    if state.engine_input and state.engine_input.info and state.engine_input.info.intel:
        intel_data_list = state.engine_input.info.intel

    for i, cve_id in enumerate(state.cve_list):
        try:
            # 匹配情报数据
            intel_data = {}
            severity = "unknown"
            description = ""
            
            if i < len(intel_data_list):
                intel_item = intel_data_list[i]
                # CveIntel 对象包含 NVD / GHSA / RedHat 等多源数据
                intel_data = intel_item.model_dump() if hasattr(intel_item, 'model_dump') else {}
                
                # 尝试从 NVD 数据提取严重程度
                if hasattr(intel_item, 'nvd') and intel_item.nvd:
                    nvd = intel_item.nvd
                    if hasattr(nvd, 'cvss_severity'):
                        severity = nvd.cvss_severity or "unknown"
                    if hasattr(nvd, 'cve_description'):
                        description = nvd.cve_description or ""

            state.intel_results[cve_id] = IntelResult(
                cve_id=cve_id,
                intel_data=intel_data,
                severity=severity,
                description=description,
            )
            logger.info("  ✅ %s 情报检索完成 (severity=%s)", cve_id, severity)

        except Exception as e:
            logger.error("  ❌ %s 情报检索失败: %s", cve_id, e)
            state.intel_results[cve_id] = IntelResult(cve_id=cve_id)
            state.errors.append(f"Intel Agent 处理 {cve_id} 失败: {e}")

    logger.info("🔍 Intel Agent 完成，处理了 %d 个 CVE", len(state.intel_results))
    return state
