# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Intel Agent — 漏洞情报检索智能体。

职责: 从多个数据源 (NVD / GHSA / RedHat / Ubuntu / BRON 知识图谱) 获取 CVE 情报数据。

架构连通:
    Intel Agent → IntelSkill (NVD API / GHSA API) → 结构化情报
    Intel Agent → KnowledgeGraph (BRON) → CWE/CAPEC/ATT&CK 攻击链
    若无 engine_input 或情报为空 → 使用内置情报库作为兜底
"""

import logging
from typing import Optional
from vuln_analysis.agents.state import IntelResult, MultiAgentState

logger = logging.getLogger(__name__)

# ============================================================
# 内置高频 CVE 情报库 — 覆盖 5 种语言生态 (13 个 CVE)
# ============================================================
BUILTIN_INTEL = {
    # ---- Java 生态 ----
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
    "CVE-2017-5638": {
        "severity": "critical",
        "description": "Apache Struts2 RCE via Content-Type header Jakarta Multipart parser exploitation. CVSS 10.0.",
        "affected_packages": [{"name": "struts2-core", "versions": "< 2.3.32 / < 2.5.10.1"}],
    },
    "CVE-2022-42889": {
        "severity": "critical",
        "description": "Apache Commons Text StringSubstitutor interpolation allows RCE via script, dns, url lookups (Text4Shell). CVSS 9.8.",
        "affected_packages": [{"name": "commons-text", "versions": "< 1.10.0"}],
    },
    # ---- C/C++ 生态 ----
    "CVE-2014-0160": {
        "severity": "high",
        "description": "OpenSSL heartbeat extension (Heartbleed) vulnerability in dtls1_process_heartbeat and SSL_read. CVSS 7.5.",
        "affected_packages": [{"name": "openssl", "versions": "1.0.1 - 1.0.1f"}],
    },
    "CVE-2021-3449": {
        "severity": "high",
        "description": "OpenSSL NULL pointer dereference in ssl3_read_bytes during TLS renegotiation allows DoS. CVSS 7.5.",
        "affected_packages": [{"name": "openssl", "versions": "1.1.1 - 1.1.1j"}],
    },
    "CVE-2024-3094": {
        "severity": "critical",
        "description": "XZ Utils backdoor vulnerability in liblzma allows unauthorized SSH access. CVSS 10.0.",
        "affected_packages": [{"name": "xz-utils", "versions": "5.6.0 - 5.6.1"}],
    },
    # ---- Python 生态 ----
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
    "CVE-2023-32681": {
        "severity": "medium",
        "description": "Python Requests library leaks Proxy-Authorization header to destination server on HTTP redirect (SSRF). CVSS 6.1.",
        "affected_packages": [{"name": "requests", "versions": "< 2.31.0"}],
    },
    # ---- Go 生态 ----
    "CVE-2023-44487": {
        "severity": "high",
        "description": "HTTP/2 Rapid Reset attack enables DDoS by sending RST_STREAM frames. Affects Go net/http2, nginx, Apache. CVSS 7.5.",
        "affected_packages": [{"name": "golang.org/x/net", "versions": "< 0.17.0"}],
    },
    # ---- Node.js 生态 ----
    "CVE-2021-44906": {
        "severity": "critical",
        "description": "Minimist prototype pollution allows property injection on Object.prototype via --constructor arguments. CVSS 9.8.",
        "affected_packages": [{"name": "minimist", "versions": "< 1.2.6"}],
    },
}


# ============================================================
# 知识图谱集成 (BRON)
# ============================================================
_knowledge_graph = None

def _get_knowledge_graph():
    """懒加载 KnowledgeGraph — 从 BRON 数据构建图索引。"""
    global _knowledge_graph
    if _knowledge_graph is not None:
        return _knowledge_graph

    try:
        from pathlib import Path
        from vuln_analysis.knowledge.bron_loader import BRONLoader
        from vuln_analysis.knowledge.knowledge_graph import KnowledgeGraph

        # 尝试从常见位置加载 BRON 数据
        project_root = Path(__file__).resolve().parent.parent.parent.parent
        bron_candidates = [
            project_root / "BRON",
            project_root / "data" / "BRON",
            Path.home() / "BRON",
        ]
        for bron_path in bron_candidates:
            if bron_path.exists():
                loader = BRONLoader()
                cve_data = loader.load(str(bron_path))
                if cve_data:
                    _knowledge_graph = KnowledgeGraph(cve_data)
                    logger.info("  🧠 BRON 知识图谱加载完成: %d CVEs", len(cve_data))
                    return _knowledge_graph

        logger.debug("  BRON 数据目录未找到，知识图谱功能跳过")
    except ImportError:
        logger.debug("  KnowledgeGraph 模块未安装，跳过")
    except Exception as e:
        logger.warning("  知识图谱加载失败: %s", e)

    return None


async def intel_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    Intel Agent 节点: 为每个 CVE 检索情报信息。

    执行策略 (分层):
    1. 优先从 engine_input.info.intel 中读取 IntelSkill 已获取的情报数据
    2. 如果没有预加载数据，从内置情报库 BUILTIN_INTEL 获取兜底数据
    3. 调用 KnowledgeGraph 获取 CWE/CAPEC/ATT&CK 攻击链 (如果 BRON 可用)
    """
    logger.info("🔍 Intel Agent 启动，处理 %d 个 CVE", len(state.cve_list))

    # 从 engine_input 获取 IntelSkill 预加载的情报
    intel_data_list = []
    if state.engine_input and state.engine_input.info and state.engine_input.info.intel:
        intel_data_list = state.engine_input.info.intel
        logger.info("  📡 来源: IntelSkill 预加载数据 (%d 条)", len(intel_data_list))
    else:
        logger.info("  📋 来源: 内置情报库 (BUILTIN_INTEL, %d 条)", len(BUILTIN_INTEL))

    # 懒加载知识图谱
    kg = _get_knowledge_graph()

    for i, cve_id in enumerate(state.cve_list):
        try:
            intel_data = {}
            severity = "unknown"
            description = ""

            # 策略 1: 从 IntelSkill 预加载的数据中提取
            if i < len(intel_data_list):
                intel_item = intel_data_list[i]
                intel_data = intel_item.model_dump() if hasattr(intel_item, 'model_dump') else {}

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

            # 策略 3: 知识图谱攻击链增强
            if kg is not None:
                chain = kg.query_attack_chain(cve_id)
                if chain.get("found"):
                    intel_data["attack_chain"] = {
                        "cwes": chain.get("cwes", []),
                        "capecs": chain.get("capecs", []),
                        "attack_techniques": chain.get("attack_techniques", []),
                    }
                    logger.info("  🧠 %s 攻击链: CWE=%s, CAPEC=%s, ATT&CK=%s",
                                cve_id,
                                chain.get("cwes", []),
                                chain.get("capecs", []),
                                chain.get("attack_techniques", []))

            # 策略 4: 完全未知
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
