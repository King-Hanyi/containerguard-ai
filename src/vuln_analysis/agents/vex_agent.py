# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
VEX Agent — 漏洞判定智能体。

职责: 综合 Intel / Code / Config 三个 Agent 的分析结果，
      生成最终的 VEX 判定 (affected / not_affected / unknown)。

架构:
    VEX Agent → NVIDIA NIM LLM (llama-3.1-70b-instruct) → VEX 判定
    若 LLM API 不可用 → 回退到规则引擎判定
    Prompt 配置从 configs/prompts.yml 加载（支持 Few-shot 示例）。
"""

import json
import logging
import os
import urllib.request
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
except Exception as e:
    logger.warning("加载 prompts.yml 失败: %s (使用默认 Prompt)", e)


# VEX 标准状态标签
VEX_STATUSES = ["affected", "not_affected", "under_investigation"]

# VEX 标准 justification 标签
VEX_JUSTIFICATIONS = {
    "component_not_present": "容器中不包含漏洞组件",
    "vulnerable_code_not_present": "漏洞代码不在容器中",
    "vulnerable_code_not_in_execute_path": "漏洞代码存在但不在执行路径上",
    "vulnerable_code_cannot_be_controlled_by_adversary": "漏洞代码无法被攻击者控制",
    "inline_mitigations_already_exist": "已有内联缓解措施",
}


def _build_llm_prompt(cve_id: str, evidence: dict) -> str:
    """
    构建 LLM 推理 Prompt，包含 Few-shot 示例和结构化证据。
    """
    # 加载 Few-shot 示例
    few_shot_examples = ""
    vex_config = _PROMPT_CONFIG.get("vex_agent", {})
    examples = vex_config.get("few_shot_examples", [])
    for ex in examples:
        few_shot_examples += f"""
案例: {ex.get('cve_id', 'N/A')}
  情报: severity={ex.get('severity', 'N/A')}
  代码: code_found={ex.get('code_found', 'N/A')}
  依赖: package_found={ex.get('package_found', 'N/A')}
  判定: {ex.get('judgment', 'N/A')}
  理由: {ex.get('justification', 'N/A')}
"""

    prompt = f"""你是一个专业的容器安全分析师，专门负责 VEX (Vulnerability Exploitability eXchange) 判定。

你需要基于以下多维证据，判断 CVE 是否影响目标容器镜像。

## 判定规则
- **affected**: 漏洞包存在于 SBOM 中，且版本在受影响范围内，且代码中存在漏洞函数调用
- **not_affected**: 以下任一条件成立:
  - component_not_present: SBOM 中不包含漏洞组件
  - vulnerable_code_not_present: 漏洞代码不在容器中
  - vulnerable_code_not_in_execute_path: 漏洞包存在但代码中未调用漏洞函数
- **under_investigation**: 证据不足，需要人工审查

## Few-shot 示例
{few_shot_examples if few_shot_examples else "(无示例)"}

## 当前待判定的 CVE
CVE ID: {cve_id}

### 证据汇总
- 情报: severity={evidence.get('severity', 'unknown')}, description={evidence.get('description', 'N/A')[:200]}
- 代码搜索: code_found={evidence.get('code_found', False)}, evidence={evidence.get('code_evidence', 'N/A')[:150]}
- 依赖检查: package_found={evidence.get('package_found', False)}, package={evidence.get('package_name', 'N/A')} {evidence.get('package_version', '')}, is_vulnerable={evidence.get('is_vulnerable', False)}

## 请输出你的判定
请严格按以下 JSON 格式回复:
```json
{{
  "status": "affected 或 not_affected 或 under_investigation",
  "justification": "选择一个标准理由标签或简要说明",
  "confidence": 0.0到1.0之间的置信度,
  "reasoning": "简要分析推理过程"
}}
```"""
    return prompt


def _call_nvidia_nim(prompt: str, api_key: str) -> dict | None:
    """
    调用 NVIDIA NIM API (llama-3.1-70b-instruct) 进行 VEX 推理。

    Returns:
        解析后的 JSON dict，失败返回 None
    """
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    payload = json.dumps({
        "model": "meta/llama-3.1-70b-instruct",
        "messages": [
            {"role": "system", "content": "你是一个专业的容器安全分析师，请用 JSON 格式回复。"},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 300,
        "temperature": 0.1,
    }).encode()

    req = urllib.request.Request(url, data=payload, headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    })

    try:
        resp = urllib.request.urlopen(req, timeout=30)
        data = json.loads(resp.read())
        content = data["choices"][0]["message"]["content"]
        tokens = data.get("usage", {})
        logger.info("  🤖 LLM 推理完成 (tokens: %s)", tokens)

        # 提取 JSON (可能包裹在 ```json ... ``` 中)
        if "```json" in content:
            json_str = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            json_str = content.split("```")[1].split("```")[0].strip()
        else:
            json_str = content.strip()

        return json.loads(json_str)

    except Exception as e:
        logger.warning("  ⚠️ LLM API 调用失败: %s", e)
        return None


def _rule_based_judgment(
    cve_id: str,
    has_intel: bool,
    severity: str,
    code_found: bool,
    package_found: bool,
    is_vulnerable: bool,
) -> tuple[str, str, float]:
    """
    规则引擎兜底判定 (当 LLM 不可用时使用)。

    使用标准 VEX justification 标签。
    Returns: (status, justification, confidence)
    """
    if not has_intel:
        return "under_investigation", "情报数据不足，需要进一步调查", 0.2

    if not package_found:
        return "not_affected", "component_not_present: SBOM 中未发现受影响的软件包", 0.85

    if package_found and not code_found:
        return "not_affected", "vulnerable_code_not_in_execute_path: 漏洞包存在但未发现漏洞函数调用", 0.7

    if package_found and code_found and is_vulnerable:
        return "affected", f"漏洞包存在于 SBOM 中且代码中发现漏洞函数调用 (severity: {severity})", 0.9

    if package_found and code_found:
        return "affected", f"漏洞包和漏洞代码均存在 (severity: {severity})", 0.8

    return "under_investigation", "证据不足，需要人工审查", 0.3


async def vex_agent_node(state: MultiAgentState) -> MultiAgentState:
    """
    VEX Agent 节点: 综合判定每个 CVE 的影响状态。

    执行策略 (分层):
    1. 有 NVIDIA API Key → 调用 LLM (llama-3.1-70b) 做推理判定
    2. 无 API Key 或 API 失败 → 回退到规则引擎判定
    """
    logger.info("⚖️ VEX Agent 启动，综合判定 %d 个 CVE", len(state.cve_list))

    # 检查 LLM 可用性
    api_key = os.environ.get("NVIDIA_API_KEY", "")
    use_llm = bool(api_key and not api_key.startswith("nvapi-xxx"))

    if use_llm:
        logger.info("  🤖 模式: NVIDIA NIM LLM 推理 (llama-3.1-70b-instruct)")
    else:
        logger.info("  📋 模式: 规则引擎判定 (无 NVIDIA API Key)")

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

            status = ""
            justification = ""
            confidence = 0.0
            reasoning = ""

            # 策略 1: LLM 推理
            if use_llm:
                evidence = {
                    "severity": severity,
                    "description": intel.description if intel else "",
                    "code_found": code_found,
                    "code_evidence": code.evidence if code else "",
                    "package_found": package_found,
                    "package_name": config.package_name if config else "",
                    "package_version": config.package_version if config else "",
                    "is_vulnerable": is_vulnerable,
                }
                prompt = _build_llm_prompt(cve_id, evidence)
                llm_result = _call_nvidia_nim(prompt, api_key)

                if llm_result:
                    status = llm_result.get("status", "under_investigation")
                    # 标准化状态
                    if status not in VEX_STATUSES:
                        if "not" in status.lower() or "unaffect" in status.lower():
                            status = "not_affected"
                        elif "affect" in status.lower():
                            status = "affected"
                        else:
                            status = "under_investigation"
                    justification = llm_result.get("justification", "")
                    confidence = min(max(float(llm_result.get("confidence", 0.5)), 0.0), 1.0)
                    reasoning = llm_result.get("reasoning", "")
                    logger.info("  🤖 %s LLM 判定: %s (confidence: %.0f%%)", cve_id, status, confidence * 100)

            # 策略 2: 规则引擎兜底
            if not status:
                status, justification, confidence = _rule_based_judgment(
                    cve_id, has_intel, severity, code_found, package_found, is_vulnerable
                )
                logger.info("  📋 %s 规则判定: %s (confidence: %.0f%%)", cve_id, status, confidence * 100)

            # 构建摘要
            summary_parts = []
            if intel:
                summary_parts.append(f"情报: severity={severity}")
            if code:
                summary_parts.append(f"代码: {'发现匹配' if code_found else '未发现'}")
            if config:
                summary_parts.append(f"依赖: {'存在' if package_found else '不存在'}")
            if reasoning:
                summary_parts.append(f"LLM: {reasoning[:80]}")
            summary = f"{cve_id}: {status.upper()} | " + " | ".join(summary_parts)

            state.vex_judgments[cve_id] = VEXJudgment(
                cve_id=cve_id,
                status=status,
                justification=justification,
                confidence=confidence,
                summary=summary,
            )

            icon = {"affected": "🔴", "not_affected": "🟢", "under_investigation": "🟡"}
            logger.info("  %s %s → %s (confidence: %.0f%%)",
                        icon.get(status, "❓"), cve_id, status, confidence * 100)

        except Exception as e:
            logger.error("  ❌ %s 判定失败: %s", cve_id, e)
            state.vex_judgments[cve_id] = VEXJudgment(cve_id=cve_id)
            state.errors.append(f"VEX Agent 判定 {cve_id} 失败: {e}")

    logger.info("⚖️ VEX Agent 完成")
    return state
