# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Intel Agent — 漏洞情报检索智能体。

职责: 从多个数据源 (NVD / GHSA / RedHat / Ubuntu) 获取 CVE 情报数据。

架构连通:
    Intel Agent → IntelSkill (NVD API / GHSA API) → 结构化情报
    若无 engine_input 或情报为空 → 使用内置情报库作为兜底
"""

import logging
from vuln_analysis.agents.state import IntelResult, MultiAgentState

logger = logging.getLogger(__name__)

# 内置的高频 CVE 情报库 (兜底数据，确保即使 API 不可用也有基础情报)
BUILTIN_INTEL = {
    "CVE-2021-44228": {
        "severity": "critical",
        "description": "Apache Log4j2 JNDI injection vulnerability in org.apache.logging.log4j allows RCE via JndiLookup. CVSS 10.0.",
        "affected_packages": [{"name": "log4j-core", "versions": "< 2.17.0"}],
    },
    "CVE-2021-45046": {
        "severity": "critical",
        "description": "Apache Log4j2 Thread Context Lookup Pattern allows RCE in certain non-default configurations. CVSS 9.0.",
        "affected_packages": [{"name": "log4j-core", "versions": "< 2.17.0"}],
    },
    "CVE-2022-22965": {
        "severity": "critical",
        "description": "Spring Framework RCE via data binding on JDK 9+ with spring-webmvc ClassPathResource. CVSS 9.8.",
        "affected_packages": [{"name": "spring-beans", "versions": "< 5.3.18"}],
    },
    "CVE-2014-0160": {
        "severity": "high",
        "description": "OpenSSL heartbeat extension (Heartbleed) vulnerability in dtls1_process_heartbeat and SSL_read. CVSS 7.5.",
        "affected_packages": [{"name": "openssl", "versions": "1.0.1 - 1.0.1f"}],
    },
    "CVE-2023-36632": {
        "severity": "medium",
        "description": "Python email.utils.parseaddr denial of service via recursive parsing of nested email addresses. CVSS 7.5.",
        "affected_packages": [{"name": "python", "versions": "< 3.12"}],
    },
    "CVE-2023-24329": {
        "severity": "medium",
        "description": "Python urllib.parse URL parsing issue allows bypass of blocklisting methods by supplying a blank string URL. CVSS 7.5.",
        "affected_packages": [{"name": "python", "versions": "< 3.11.4"}],
    },
    "CVE-2024-3094": {
        "severity": "critical",
        "description": "XZ Utils backdoor vulnerability in liblzma allows unauthorized SSH access. CVSS 10.0.",
        "affected_packages": [{"name": "xz-utils", "versions": "5.6.0 - 5.6.1"}],
    },
}


async def intel_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    Intel Agent 节点: 为每个 CVE 检索情报信息。

    执行策略 (分层):
    1. 优先从 engine_input.info.intel 中读取 IntelSkill 已获取的情报数据
    2. 如果没有预加载数据，从内置情报库 BUILTIN_INTEL 获取兜底数据
    3. 未来: 直接调用 IntelSkill 做实时 API 查询 (需要 NVIDIA NIM 环境)
    """
    logger.info("🔍 Intel Agent 启动，处理 %d 个 CVE", len(state.cve_list))

    # 从 engine_input 获取 IntelSkill 预加载的情报
    intel_data_list = []
    if state.engine_input and state.engine_input.info and state.engine_input.info.intel:
        intel_data_list = state.engine_input.info.intel
        logger.info("  📡 来源: IntelSkill 预加载数据 (%d 条)", len(intel_data_list))
    else:
        logger.info("  📋 来源: 内置情报库 (BUILTIN_INTEL)")

    for i, cve_id in enumerate(state.cve_list):
        try:
            intel_data = {}
            severity = "unknown"
            description = ""

            # 策略 1: 从 IntelSkill 预加载的数据中提取
            if i < len(intel_data_list):
                intel_item = intel_data_list[i]
                intel_data = intel_item.model_dump() if hasattr(intel_item, 'model_dump') else {}

                # 从 NVD 数据提取严重程度和描述
                if hasattr(intel_item, 'nvd') and intel_item.nvd:
                    nvd = intel_item.nvd
                    if hasattr(nvd, 'cvss_severity'):
                        severity = nvd.cvss_severity or "unknown"
                    if hasattr(nvd, 'cve_description'):
                        description = nvd.cve_description or ""
                    logger.info("  ✅ %s IntelSkill 情报: severity=%s", cve_id, severity)

            # 策略 2: 内置情报库兜底
            if severity == "unknown" and cve_id in BUILTIN_INTEL:
                builtin = BUILTIN_INTEL[cve_id]
                severity = builtin["severity"]
                description = builtin["description"]
                intel_data = {
                    "source": "builtin_intel",
                    "affected_packages": builtin.get("affected_packages", []),
                }
                logger.info("  📋 %s 内置情报: severity=%s", cve_id, severity)

            # 策略 3: 完全未知
            if severity == "unknown":
                logger.warning("  ⚠️ %s 未找到任何情报数据", cve_id)

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
