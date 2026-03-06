# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Code Agent — 代码可达性分析智能体。

职责: 通过 RemoteCodeSkill (GitHub API) 搜索目标仓库中是否使用了漏洞函数，
      判断漏洞是否在代码层面可达。

架构连通:
    Code Agent → RemoteCodeSkill → GitHub Code Search API
    若无 GitHub Token 或 API 不可用 → 回退到本地模式表匹配
"""

import logging
import os
from typing import Optional

import aiohttp

from vuln_analysis.agents.state import CodeSearchResult, MultiAgentState

logger = logging.getLogger(__name__)

# CVE → 漏洞函数/关键词映射表（可扩展）
CVE_SEARCH_PATTERNS = {
    # Python 系列
    "CVE-2023-36632": ["email.utils.parseaddr", "parseaddr"],
    "CVE-2023-24329": ["urllib.parse", "urlparse"],
    "CVE-2022-45061": ["idna", "decode"],
    # Java 系列
    "CVE-2021-44228": ["org.apache.logging.log4j", "JndiLookup", "log4j-core"],
    "CVE-2021-45046": ["org.apache.logging.log4j", "JndiLookup"],
    "CVE-2022-22965": ["spring-webmvc", "ClassPathResource", "spring-beans"],
    "CVE-2022-22947": ["spring-cloud-gateway", "RouteDefinitionLocator"],
    # C/C++ 系列
    "CVE-2014-0160": ["SSL_read", "dtls1_process_heartbeat", "tls1_process_heartbeat"],
    "CVE-2021-3449": ["ssl3_read_bytes", "SSL_do_handshake"],
    "CVE-2024-3094": ["xz", "liblzma"],
    # JavaScript / Node.js
    "CVE-2021-44906": ["minimist", "prototype pollution"],
    "CVE-2022-0235": ["node-fetch", "authorization header"],
}


def _get_search_queries(cve_id: str, intel_description: str = "") -> list[str]:
    """根据 CVE ID 和情报描述生成搜索关键词。"""
    # 优先使用已知模式
    if cve_id in CVE_SEARCH_PATTERNS:
        return CVE_SEARCH_PATTERNS[cve_id]

    # 从情报描述中提取关键函数名（改进的启发式）
    queries = []
    if intel_description:
        for word in intel_description.split():
            cleaned = word.strip('.,;:()"\'')
            # 匹配 Java/Python 包名 (含 .) 或 C 函数名 (含 _)
            if '.' in cleaned and len(cleaned) > 5 and cleaned[0].islower():
                queries.append(cleaned)
            elif '_' in cleaned and len(cleaned) > 5 and cleaned[0].islower():
                queries.append(cleaned)

    return queries if queries else [cve_id]


async def _search_github_api(query: str, repo: str, token: Optional[str] = None) -> dict:
    """
    调用 GitHub Code Search API 搜索代码。

    这是 RemoteCodeSkill 核心逻辑的直接集成，
    避免了 NAT Builder 实例化依赖，使 Agent 可独立运行。

    Returns:
        {"found": bool, "files": list[str], "total": int, "error": str|None}
    """
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "ContainerGuard-AI",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    search_query = f"{query}+repo:{repo}"
    url = f"https://api.github.com/search/code?q={search_query}&per_page=5"

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    files = [item.get("path", "") for item in data.get("items", [])]
                    total = data.get("total_count", 0)
                    return {"found": total > 0, "files": files, "total": total, "error": None}
                else:
                    return {"found": False, "files": [], "total": 0,
                            "error": f"GitHub API 返回 {response.status}"}
    except Exception as e:
        return {"found": False, "files": [], "total": 0, "error": str(e)}


def _extract_repo_from_state(state: MultiAgentState) -> str:
    """从 engine_input 提取 GitHub 仓库名。"""
    if state.engine_input and state.engine_input.input.image.source_info:
        source_info = state.engine_input.input.image.source_info
        # source_info 可能是列表
        sources = source_info if isinstance(source_info, list) else [source_info]
        for src in sources:
            git_repo = ""
            if isinstance(src, dict):
                git_repo = src.get("git_repo", "")
            elif hasattr(src, "git_repo"):
                git_repo = src.git_repo or ""
            # 从 URL 提取 owner/repo 格式
            if git_repo and "github.com" in git_repo:
                parts = git_repo.rstrip("/").rstrip(".git").split("github.com/")
                if len(parts) > 1:
                    return parts[1]
    return ""


async def code_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    Code Agent 节点: 在源码中搜索漏洞函数调用。

    执行策略 (分层):
    1. 如果有 GitHub 仓库信息 + Token → 调用 GitHub API 实时搜索 (RemoteCodeSkill 逻辑)
    2. 否则 → 回退到本地模式表匹配
    """
    logger.info("💻 Code Agent 启动，处理 %d 个 CVE", len(state.cve_list))

    # 提取源码仓库 + GitHub Token
    source_repo = _extract_repo_from_state(state)
    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GHSA_API_KEY")
    use_api = bool(source_repo and github_token)

    if use_api:
        logger.info("  📡 模式: GitHub API 实时搜索 (repo: %s)", source_repo)
    else:
        reason = "无仓库信息" if not source_repo else "无 GitHub Token"
        logger.info("  📋 模式: 本地模式表匹配 (%s)", reason)

    for cve_id in state.cve_list:
        try:
            # 获取搜索关键词
            intel_desc = ""
            if cve_id in state.intel_results:
                intel_desc = state.intel_results[cve_id].description

            queries = _get_search_queries(cve_id, intel_desc)

            if use_api:
                # 策略 1: 调用 GitHub Code Search API (RemoteCodeSkill 核心逻辑)
                code_found = False
                all_files = []
                evidence_parts = []

                for query in queries[:3]:  # 最多搜 3 个关键词，避免触发限速
                    result = await _search_github_api(query, source_repo, github_token)
                    if result["error"]:
                        logger.warning("  ⚠️ GitHub API 查询 '%s' 失败: %s", query, result["error"])
                        continue
                    if result["found"]:
                        code_found = True
                        all_files.extend(result["files"][:3])
                        evidence_parts.append(f"'{query}' 命中 {result['total']} 个结果")

                state.code_results[cve_id] = CodeSearchResult(
                    cve_id=cve_id,
                    code_found=code_found,
                    search_query=queries[0] if queries else "",
                    matched_files=all_files,
                    evidence=("GitHub API 搜索: " + ", ".join(evidence_parts))
                    if evidence_parts else "GitHub API 搜索: 未发现匹配",
                )

            else:
                # 策略 2: 本地模式表匹配 (兜底)
                code_found = cve_id in CVE_SEARCH_PATTERNS

                state.code_results[cve_id] = CodeSearchResult(
                    cve_id=cve_id,
                    code_found=code_found,
                    search_query=queries[0] if queries else "",
                    matched_files=[f"(pattern match: {q})" for q in queries] if code_found else [],
                    evidence=f"本地模式匹配: {', '.join(queries)}" if code_found else "无已知漏洞模式",
                )

            logger.info("  %s %s 代码搜索: %s",
                        "✅" if state.code_results[cve_id].code_found else "⬜",
                        cve_id,
                        state.code_results[cve_id].evidence[:60])

        except Exception as e:
            logger.error("  ❌ %s 代码搜索失败: %s", cve_id, e)
            state.code_results[cve_id] = CodeSearchResult(cve_id=cve_id)
            state.errors.append(f"Code Agent 处理 {cve_id} 失败: {e}")

    logger.info("💻 Code Agent 完成")
    return state
