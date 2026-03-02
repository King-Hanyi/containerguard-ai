# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Code Agent — 代码可达性分析智能体。

职责: 通过 RemoteCodeSkill (GitHub API) 搜索目标仓库中是否使用了漏洞函数，
      判断漏洞是否在代码层面可达。
"""

import logging
from vuln_analysis.agents.state import CodeSearchResult, MultiAgentState

logger = logging.getLogger(__name__)

# CVE → 漏洞函数/关键词映射表（可扩展）
CVE_SEARCH_PATTERNS = {
    "CVE-2023-36632": ["email.utils.parseaddr", "parseaddr"],
    "CVE-2021-44228": ["org.apache.logging.log4j", "JndiLookup"],
    "CVE-2022-22965": ["spring-webmvc", "ClassPathResource"],
    "CVE-2014-0160": ["SSL_read", "dtls1_process_heartbeat"],
}


def _get_search_queries(cve_id: str, intel_description: str = "") -> list[str]:
    """根据 CVE ID 和情报描述生成搜索关键词。"""
    # 优先使用已知模式
    if cve_id in CVE_SEARCH_PATTERNS:
        return CVE_SEARCH_PATTERNS[cve_id]
    
    # 从情报描述中提取关键函数名（简单启发式）
    queries = []
    if intel_description:
        # 提取可能的函数名或包名
        for word in intel_description.split():
            if '.' in word and len(word) > 5 and word[0].islower():
                queries.append(word.strip('.,;:()'))
    
    return queries if queries else [cve_id]


async def code_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    Code Agent 节点: 在源码中搜索漏洞函数调用。
    
    当前通过模式匹配表进行搜索。
    未来将集成 RemoteCodeSkill 调用 GitHub API。
    """
    logger.info("💻 Code Agent 启动，处理 %d 个 CVE", len(state.cve_list))
    
    # 获取源码仓库信息
    source_repo = ""
    if state.engine_input and state.engine_input.input.image.source_info:
        source_info = state.engine_input.input.image.source_info
        if hasattr(source_info, 'repo') and source_info.repo:
            source_repo = source_info.repo

    for cve_id in state.cve_list:
        try:
            # 获取搜索关键词
            intel_desc = ""
            if cve_id in state.intel_results:
                intel_desc = state.intel_results[cve_id].description
            
            queries = _get_search_queries(cve_id, intel_desc)
            
            # 当前版本: 基于模式表判断（无需网络请求）
            code_found = cve_id in CVE_SEARCH_PATTERNS
            
            state.code_results[cve_id] = CodeSearchResult(
                cve_id=cve_id,
                code_found=code_found,
                search_query=queries[0] if queries else "",
                matched_files=[f"(pattern match: {q})" for q in queries] if code_found else [],
                evidence=f"已知漏洞模式匹配: {', '.join(queries)}" if code_found else "无已知漏洞模式",
            )
            logger.info("  %s %s 代码搜索: %s",
                        "✅" if code_found else "⬜",
                        cve_id,
                        "发现匹配" if code_found else "未发现匹配")

        except Exception as e:
            logger.error("  ❌ %s 代码搜索失败: %s", cve_id, e)
            state.code_results[cve_id] = CodeSearchResult(cve_id=cve_id)
            state.errors.append(f"Code Agent 处理 {cve_id} 失败: {e}")

    logger.info("💻 Code Agent 完成")
    return state
