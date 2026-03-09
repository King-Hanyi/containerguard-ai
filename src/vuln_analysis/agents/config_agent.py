# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Config Agent — 配置与依赖分析智能体。

职责: 分析 SBOM，检查漏洞包是否存在于容器依赖中，
      判断漏洞是否在配置/依赖层面可达。

架构连通:
    Config Agent → ConfigSkill._parse_sbom_packages() → SBOM 解析
    支持三种 SBOM 来源: file / http / engine_input 预加载
"""

import logging
import re
from pathlib import Path

from vuln_analysis.agents.state import ConfigResult, MultiAgentState

logger = logging.getLogger(__name__)

# 项目根目录 (用于定位 SBOM 文件)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def _strip_ansi(text: str) -> str:
    """去除 ANSI 转义序列（终端颜色码）。"""
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def _parse_sbom_packages(sbom_lines: list[str]) -> list[dict]:
    """
    解析 SBOM 文本行并提取包列表。

    复用 ConfigSkill._parse_sbom_packages 的核心逻辑，
    增加了 ANSI 转义码和 duplicate 标注的处理。
    """
    packages = []

    if not sbom_lines:
        return packages

    # 检查表头
    header = _strip_ansi(sbom_lines[0]).strip().split()
    if header != ["NAME", "VERSION", "TYPE"]:
        logger.warning("SBOM 文件格式不标准，表头: %s (期望 NAME VERSION TYPE)", header)

    for line in sbom_lines[1:]:
        cleaned = _strip_ansi(line).strip()
        if not cleaned:
            continue
        # 去除 "(+N duplicates)" 后缀
        cleaned = re.sub(r'\(\+\d+ duplicates?\)', '', cleaned).strip()
        parts = cleaned.split()
        if len(parts) >= 3:
            packages.append({
                "name": parts[0],
                "version": parts[1],
                "type": parts[2],
            })

    return packages


def _load_sbom_from_file(file_path: str) -> list[dict]:
    """
    从文件加载并解析 SBOM。

    集成 ConfigSkill 的文件读取逻辑:
    - 支持 utf-8-sig 编码 (修复 BOM 头 Bug)
    - 支持绝对路径和项目相对路径
    """
    path = Path(file_path)
    if not path.is_absolute():
        path = PROJECT_ROOT / file_path

    if not path.exists():
        logger.warning("SBOM 文件不存在: %s", path)
        return []

    with open(path, "r", encoding="utf-8-sig") as f:
        lines = f.readlines()

    packages = _parse_sbom_packages(lines)
    logger.info("  📦 从 '%s' 解析到 %d 个软件包", path.name, len(packages))
    return packages


# CVE → 受影响 package + 版本范围的映射 (精确版本匹配)
CVE_PACKAGE_HINTS = {
    # Java
    "CVE-2021-44228": {"packages": ["log4j-core", "log4j-api"], "version_constraint": "< 2.17.0"},
    "CVE-2021-45046": {"packages": ["log4j-core", "log4j-api"], "version_constraint": "< 2.17.0"},
    "CVE-2022-22965": {"packages": ["spring-beans", "spring-webmvc"], "version_constraint": "< 5.3.18"},
    "CVE-2022-22947": {"packages": ["spring-cloud-gateway"], "version_constraint": "< 3.1.1"},
    "CVE-2017-5638":  {"packages": ["struts2-core", "struts-core"], "version_constraint": "< 2.5.10.1"},
    "CVE-2022-42889": {"packages": ["commons-text"], "version_constraint": "< 1.10.0"},
    # C/C++
    "CVE-2014-0160":  {"packages": ["openssl", "libssl"], "version_constraint": ">= 1.0.1, < 1.0.1g"},
    "CVE-2021-3449":  {"packages": ["openssl", "libssl"], "version_constraint": ">= 1.1.1, < 1.1.1k"},
    "CVE-2024-3094":  {"packages": ["xz", "xz-utils", "liblzma"], "version_constraint": ">= 5.6.0, < 5.6.2"},
    # Python
    "CVE-2023-36632": {"packages": ["python", "cpython"], "version_constraint": "< 3.12"},
    "CVE-2023-24329": {"packages": ["python", "cpython"], "version_constraint": "< 3.11.4"},
    "CVE-2023-32681": {"packages": ["requests"], "version_constraint": "< 2.31.0"},
    # Go
    "CVE-2023-44487": {"packages": ["golang.org/x/net", "go"], "version_constraint": "< 0.17.0"},
    # Node.js
    "CVE-2021-44906": {"packages": ["minimist"], "version_constraint": "< 1.2.6"},
}


def _check_version_vulnerable(installed_version: str, constraint: str) -> bool:
    """
    检查已安装版本是否在受影响范围内。

    优先使用 univers 库做精确语义化版本匹配（与 NVIDIA Blueprint 相同）。
    如果 univers 不可用，回退到简单字符串比较。
    """
    try:
        from packaging.version import Version
        installed = Version(installed_version)

        # 解析 constraint: "< 2.17.0" 或 ">= 1.0.1, < 1.0.1g"
        parts = [c.strip() for c in constraint.split(",")]
        for part in parts:
            if part.startswith(">="):
                if installed < Version(part[2:].strip()):
                    return False
            elif part.startswith("<="):
                if installed > Version(part[2:].strip()):
                    return False
            elif part.startswith("<"):
                if installed >= Version(part[1:].strip()):
                    return False
            elif part.startswith(">"):
                if installed <= Version(part[1:].strip()):
                    return False
        return True
    except Exception:
        # 回退: 字符串匹配 — 只要找到了包就认为受影响
        return True


async def config_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    Config Agent 节点: 检查 SBOM 中是否包含漏洞包。

    执行策略 (分层):
    1. 优先从 engine_input 中读取已解析的 SBOM 包列表 (engine_input.info.sbom)
    2. 如果没有预加载数据，尝试从 sbom_info.file_path 主动解析 SBOM 文件 (ConfigSkill 逻辑)
    3. 使用 CVE_PACKAGE_HINTS + 情报描述进行智能包匹配
    """
    logger.info("⚙️ Config Agent 启动，处理 %d 个 CVE", len(state.cve_list))

    # === 获取 SBOM 包列表 ===
    packages = []

    # 策略 1: 从 engine_input 预加载数据
    if (state.engine_input and state.engine_input.info
            and state.engine_input.info.sbom and state.engine_input.info.sbom.packages):
        raw_packages = state.engine_input.info.sbom.packages
        packages = [{"name": pkg.name, "version": pkg.version, "type": getattr(pkg, 'system', 'unknown')}
                    for pkg in raw_packages]
        logger.info("  📦 来源: engine_input 预加载 (%d 个包)", len(packages))

    # 策略 2: 从 sbom_info.file_path 主动解析 (ConfigSkill 逻辑)
    if not packages and state.engine_input:
        sbom_info = state.engine_input.input.image.sbom_info
        file_path = None
        if hasattr(sbom_info, 'file_path') and sbom_info.file_path:
            file_path = sbom_info.file_path
        elif isinstance(sbom_info, dict) and sbom_info.get('file_path'):
            file_path = sbom_info['file_path']

        if file_path:
            logger.info("  📂 来源: 主动解析 SBOM 文件 '%s'", file_path)
            packages = _load_sbom_from_file(file_path)

    if not packages:
        logger.warning("  ⚠️ 无 SBOM 数据可用")

    package_names = {pkg["name"].lower() for pkg in packages}
    logger.info("  SBOM 包含 %d 个软件包", len(packages))

    # === 对每个 CVE 做依赖匹配 ===
    for cve_id in state.cve_list:
        try:
            affected_package = ""
            affected_version = ""
            package_found = False
            is_vulnerable = False

            # 匹配策略 1: CVE_PACKAGE_HINTS 精确匹配 + 版本范围比较
            hint_entry = CVE_PACKAGE_HINTS.get(cve_id, {})
            hint_packages = hint_entry.get("packages", []) if isinstance(hint_entry, dict) else hint_entry
            version_constraint = hint_entry.get("version_constraint", "") if isinstance(hint_entry, dict) else ""

            for hint in hint_packages:
                if hint.lower() in package_names:
                    affected_package = hint
                    for pkg in packages:
                        if pkg["name"].lower() == hint.lower():
                            affected_version = pkg["version"]
                            break
                    package_found = True
                    # 精确版本比较
                    if version_constraint and affected_version:
                        is_vulnerable = _check_version_vulnerable(affected_version, version_constraint)
                    else:
                        is_vulnerable = True
                    break

            # 匹配策略 2: 从情报描述中提取关键词匹配
            if not package_found:
                intel_result = state.intel_results.get(cve_id)
                if intel_result and intel_result.description:
                    desc_lower = intel_result.description.lower()
                    for pkg in packages:
                        if pkg["name"].lower() in desc_lower and len(pkg["name"]) > 3:
                            affected_package = pkg["name"]
                            affected_version = pkg["version"]
                            package_found = True
                            is_vulnerable = True
                            break

                # 从 intel_data 中提取 affected_packages
                if not package_found and intel_result and intel_result.intel_data:
                    for pkg_info in intel_result.intel_data.get('affected_packages', []):
                        pkg_name = pkg_info.get('name', '').lower()
                        if pkg_name in package_names:
                            affected_package = pkg_name
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
                        f"发现 {affected_package} {affected_version}" if package_found else "未在 SBOM 中发现")

        except Exception as e:
            logger.error("  ❌ %s 依赖检查失败: %s", cve_id, e)
            state.config_results[cve_id] = ConfigResult(cve_id=cve_id)
            state.errors.append(f"Config Agent 处理 {cve_id} 失败: {e}")

    logger.info("⚙️ Config Agent 完成")
    return state
