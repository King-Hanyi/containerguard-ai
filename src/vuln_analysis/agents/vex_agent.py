# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
VEX Agent — 漏洞判定智能体。

职责: 综合 Intel / Code / Config 三个 Agent 的分析结果，
      生成最终的 VEX 判定 (affected / not_affected / unknown)。

Prompt 配置从 configs/prompts.yml 加载（支持 Few-shot 示例）。
"""

import logging
from pathlib import Path

import yaml

from vuln_analysis.agents.state import VEXJudgment, MultiAgentState

logger = logging.getLogger(__name__)

# 加载 Prompt 配置
_CONFIGS_DIR = Path(__file__).resolve().parent.parent / "configs"
_PROMPT_CONFIG = {}
try:
    _prompt_path = _CONFIGS_DIR / "prompts.yml"
    if _prompt_path.exists():
        with open(_prompt_path, "r", encoding="utf-8") as f:
            _PROMPT_CONFIG = yaml.safe_load(f) or {}
        logger.debug("已加载 Prompt 配置: %s", _prompt_path)
except Exception as e:
    logger.warning("加载 prompts.yml 失败: %s (使用默认 Prompt)", e)


def get_vex_prompt_config() -> dict:
    """获取 VEX Agent 的 Prompt 配置（含 Few-shot 示例）。"""
    return _PROMPT_CONFIG.get("vex_agent", {})


def _judge_vex_status(
    cve_id: str,
    has_intel: bool,
    severity: str,
    code_found: bool,
    package_found: bool,
    is_vulnerable: bool,
) -> tuple[str, str, float]:
    """
    基于多维证据进行 VEX 判定。
    
    使用标准 VEX justification 标签:
    - component_not_present: 容器中不包含漏洞组件
    - vulnerable_code_not_present: 漏洞代码不在容器中
    - vulnerable_code_not_in_execute_path: 漏洞代码存在但不在执行路径上
    
    Returns: (status, justification, confidence)
    """
    if not has_intel:
        return "unknown", "情报数据不足，无法判定", 0.2

    if not package_found:
        return "not_affected", "component_not_present: SBOM 中未发现受影响的软件包", 0.85

    if package_found and not code_found:
        return "not_affected", "vulnerable_code_not_in_execute_path: 漏洞包存在但未发现漏洞函数调用", 0.7

    if package_found and code_found and is_vulnerable:
        return "affected", f"漏洞包存在于 SBOM 中且代码中发现漏洞函数调用 (severity: {severity})", 0.9

    if package_found and code_found:
        return "affected", f"漏洞包和漏洞代码均存在 (severity: {severity})", 0.8

    return "unknown", "证据不足，需要人工审查", 0.3


async def vex_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    VEX Agent 节点: 综合判定每个 CVE 的影响状态。
    """
    logger.info("⚖️ VEX Agent 启动，综合判定 %d 个 CVE", len(state.cve_list))

    for cve_id in state.cve_list:
        try:
            # 收集各 Agent 的结果
            intel = state.intel_results.get(cve_id)
            code = state.code_results.get(cve_id)
            config = state.config_results.get(cve_id)
            
            has_intel = intel is not None and bool(intel.intel_data)
            severity = intel.severity if intel else "unknown"
            code_found = code.code_found if code else False
            package_found = config.package_found if config else False
            is_vulnerable = config.is_vulnerable_version if config else False

            status, justification, confidence = _judge_vex_status(
                cve_id, has_intel, severity, code_found, package_found, is_vulnerable
            )

            # 构建摘要
            summary_parts = []
            if intel:
                summary_parts.append(f"情报: severity={severity}")
            if code:
                summary_parts.append(f"代码: {'发现匹配' if code_found else '未发现'}")
            if config:
                summary_parts.append(f"依赖: {'存在' if package_found else '不存在'}")
            summary = f"{cve_id}: {status.upper()} | " + " | ".join(summary_parts)

            state.vex_judgments[cve_id] = VEXJudgment(
                cve_id=cve_id,
                status=status,
                justification=justification,
                confidence=confidence,
                summary=summary,
            )
            
            icon = {"affected": "🔴", "not_affected": "🟢", "unknown": "🟡"}
            logger.info("  %s %s → %s (confidence: %.0f%%)",
                        icon.get(status, "❓"), cve_id, status, confidence * 100)

        except Exception as e:
            logger.error("  ❌ %s 判定失败: %s", cve_id, e)
            state.vex_judgments[cve_id] = VEXJudgment(cve_id=cve_id)
            state.errors.append(f"VEX Agent 判定 {cve_id} 失败: {e}")

    logger.info("⚖️ VEX Agent 完成")
    return state
