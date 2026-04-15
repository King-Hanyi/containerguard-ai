# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Supervisor Agent — 多智能体编排器。

核心创新: 将 Blueprint 的单 Agent 线性流水线改造为 Supervisor 调度多 Agent 并行架构。

工作流:
    init → gather (Intel + Code + Config 并行) → judge (VEX) → done

使用 LangGraph StateGraph 构建状态机。
"""

import asyncio
import logging
from typing import Any

from langgraph.graph import END, START, StateGraph

from vuln_analysis.agents.state import MultiAgentState
from vuln_analysis.agents.intel_agent import intel_agent_node
from vuln_analysis.agents.code_agent import code_agent_node
from vuln_analysis.agents.config_agent import config_agent_node
from vuln_analysis.agents.vex_agent import vex_agent_node
from vuln_analysis.policy import OPAEngine

logger = logging.getLogger(__name__)


# ============================================================
# 节点函数
# ============================================================

async def init_node(state: MultiAgentState) -> MultiAgentState:
    """
    初始化节点: 从引擎输入中提取 CVE 列表。
    """
    if state.engine_input is None:
        raise ValueError("engine_input 不能为空")
    
    # 从扫描结果中提取 CVE 列表
    cve_list = [vuln.vuln_id for vuln in state.engine_input.input.scan.vulns]
    state.cve_list = cve_list
    state.current_phase = "gather"
    
    logger.info("=" * 60)
    logger.info("🎯 Supervisor Agent 初始化完成")
    logger.info("   镜像: %s", state.engine_input.input.image.name)
    logger.info("   待分析 CVE: %d 个", len(cve_list))
    for cve in cve_list:
        logger.info("     - %s", cve)
    logger.info("=" * 60)
    
    return state


async def gather_node(state: MultiAgentState) -> MultiAgentState:
    """
    信息收集节点: 并行调度 Intel / Code / Config 三个 Agent。
    
    这是核心创新点 — 三个 Agent 同时执行，而非 Blueprint 的串行处理。
    """
    logger.info("📡 Supervisor: 启动并行信息收集阶段")
    
    # 并行执行三个 Agent
    # 注: 使用 asyncio.gather 实现真正的并发
    intel_state, code_state, config_state = await asyncio.gather(
        intel_agent_node(MultiAgentState(**state.model_dump())),
        code_agent_node(MultiAgentState(**state.model_dump())),
        config_agent_node(MultiAgentState(**state.model_dump())),
    )
    
    # 合并各 Agent 的结果到主状态
    state.intel_results = intel_state.intel_results
    state.code_results = code_state.code_results
    state.config_results = config_state.config_results
    state.errors.extend(intel_state.errors)
    state.errors.extend(code_state.errors)
    state.errors.extend(config_state.errors)
    state.current_phase = "judge"
    
    logger.info("📡 Supervisor: 信息收集完成")
    logger.info("   Intel 结果: %d 个", len(state.intel_results))
    logger.info("   Code 结果: %d 个", len(state.code_results))
    logger.info("   Config 结果: %d 个", len(state.config_results))
    
    return state


async def judge_node(state: MultiAgentState) -> MultiAgentState:
    """
    判定节点: 调用 VEX Agent 综合判定。
    """
    logger.info("⚖️ Supervisor: 启动综合判定阶段")
    state = await vex_agent_node(state)
    state.current_phase = "done"
    return state


async def summary_node(state: MultiAgentState) -> MultiAgentState:
    """
    汇总节点: 输出最终结果摘要。
    """
    logger.info("=" * 60)
    logger.info("📊 Supervisor: 分析完成，结果汇总")
    logger.info("=" * 60)
    
    affected = 0
    not_affected = 0
    unknown = 0
    
    for cve_id, judgment in state.vex_judgments.items():
        if judgment.status == "affected":
            affected += 1
            icon = "🔴"
        elif judgment.status == "not_affected":
            not_affected += 1
            icon = "🟢"
        else:
            unknown += 1
            icon = "🟡"
        logger.info("  %s %s: %s (confidence: %.0f%%)", icon, cve_id, judgment.status, judgment.confidence * 100)
    
    logger.info("-" * 60)
    logger.info("  🔴 Affected: %d | 🟢 Not Affected: %d | 🟡 Unknown: %d", affected, not_affected, unknown)
    
    if state.errors:
        logger.warning("  ⚠️ 处理过程中出现 %d 个错误", len(state.errors))
    
    logger.info("=" * 60)
    return state


async def policy_node(state: MultiAgentState) -> MultiAgentState:
    """
    策略评估节点: 调用 OPA 策略引擎对 VEX 判定结果做安全门禁决策。
    
    将每个 CVE 的 VEX 判定 + Intel 情报传入 OPAEngine,
    输出 block / warn / pass / manual_review 决策。
    """
    logger.info("🛡️ Supervisor: 启动 OPA 安全策略评估")
    
    engine = OPAEngine()
    decisions = engine.evaluate(state.vex_judgments, state.intel_results)
    summary = engine.summary(decisions)
    report = engine.print_report(decisions)
    
    # 将决策序列化存入 state
    state.policy_decisions = [
        {
            "cve_id": d.cve_id,
            "action": d.action,
            "matched_rule": d.matched_rule,
            "reason": d.reason,
            "severity": d.severity,
            "confidence": d.confidence,
        }
        for d in decisions
    ]
    state.policy_summary = summary
    state.current_phase = "done"
    
    return state


# ============================================================
# 构建 LangGraph 状态机
# ============================================================

def build_supervisor_graph() -> StateGraph:
    """
    构建 Supervisor 多 Agent 状态机。
    
    图结构:
        START → init → gather → judge → summary → policy → END
    
    其中 gather 节点内部并行调度 Intel/Code/Config 三个 Agent,
    policy 节点使用 OPA 策略引擎对判定结果做安全门禁评估。
    """
    graph_builder = StateGraph(MultiAgentState)
    
    # 添加节点
    graph_builder.add_node("init", init_node)
    graph_builder.add_node("gather", gather_node)
    graph_builder.add_node("judge", judge_node)
    graph_builder.add_node("summary", summary_node)
    graph_builder.add_node("policy", policy_node)
    
    # 定义边 (线性流程，并行在 gather 内部实现)
    graph_builder.add_edge(START, "init")
    graph_builder.add_edge("init", "gather")
    graph_builder.add_edge("gather", "judge")
    graph_builder.add_edge("judge", "summary")
    graph_builder.add_edge("summary", "policy")
    graph_builder.add_edge("policy", END)
    
    return graph_builder


async def run_supervisor(engine_input: Any) -> MultiAgentState:
    """
    运行 Supervisor 多 Agent 流水线。
    
    Args:
        engine_input: AgentMorpheusEngineInput 对象
    
    Returns:
        MultiAgentState: 包含所有分析结果的最终状态
    """
    graph = build_supervisor_graph().compile()
    
    initial_state = MultiAgentState(engine_input=engine_input)
    result = await graph.ainvoke(initial_state)
    
    return MultiAgentState(**result)
