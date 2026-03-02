# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Config Agent — 配置与依赖分析智能体。

职责: 分析 SBOM，检查漏洞包是否存在于容器依赖中，
      判断漏洞是否在配置/依赖层面可达。
"""

import logging
from vuln_analysis.agents.state import ConfigResult, MultiAgentState

logger = logging.getLogger(__name__)


async def config_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    Config Agent 节点: 检查 SBOM 中是否包含漏洞包。
    
    从 state.engine_input.info.sbom 读取已解析的包列表，
    结合情报数据判断是否存在受影响的依赖。
    """
    logger.info("⚙️ Config Agent 启动，处理 %d 个 CVE", len(state.cve_list))
    
    # 获取 SBOM 包列表
    packages = []
    if (state.engine_input and state.engine_input.info 
            and state.engine_input.info.sbom and state.engine_input.info.sbom.packages):
        packages = state.engine_input.info.sbom.packages
    
    package_names = {pkg.name.lower() for pkg in packages}
    logger.info("  SBOM 包含 %d 个软件包", len(packages))

    for cve_id in state.cve_list:
        try:
            # 从情报数据中提取受影响的包名
            affected_package = ""
            affected_version = ""
            package_found = False
            is_vulnerable = False
            
            intel_result = state.intel_results.get(cve_id)
            if intel_result and intel_result.intel_data:
                # 尝试从情报数据中提取包信息
                intel = intel_result.intel_data
                if 'affected_packages' in intel:
                    for pkg in intel['affected_packages']:
                        pkg_name = pkg.get('name', '').lower()
                        if pkg_name in package_names:
                            affected_package = pkg_name
                            package_found = True
                            is_vulnerable = True
                            break

            # 如果情报数据没有包信息，尝试简单匹配 CVE 相关的包名
            if not package_found and intel_result:
                desc = intel_result.description.lower()
                for pkg in packages:
                    if pkg.name.lower() in desc:
                        affected_package = pkg.name
                        affected_version = pkg.version
                        package_found = True
                        is_vulnerable = True
                        break

            state.config_results[cve_id] = ConfigResult(
                cve_id=cve_id,
                package_found=package_found,
                package_name=affected_package,
                package_version=affected_version,
                is_vulnerable_version=is_vulnerable,
            )
            logger.info("  %s %s 依赖检查: %s",
                        "✅" if package_found else "⬜",
                        cve_id,
                        f"发现 {affected_package}" if package_found else "未在 SBOM 中发现")

        except Exception as e:
            logger.error("  ❌ %s 依赖检查失败: %s", cve_id, e)
            state.config_results[cve_id] = ConfigResult(cve_id=cve_id)
            state.errors.append(f"Config Agent 处理 {cve_id} 失败: {e}")

    logger.info("⚙️ Config Agent 完成")
    return state
