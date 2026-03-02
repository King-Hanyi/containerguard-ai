# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
ContainerGuard AI 多智能体系统单元测试。

验证:
1. MultiAgentState 状态模型
2. 各子 Agent 独立功能
3. Supervisor 编排逻辑
4. VEX 判定逻辑
"""

import asyncio
import pytest
from unittest.mock import MagicMock

from vuln_analysis.agents.state import (
    MultiAgentState,
    AgentRole,
    TaskStatus,
    IntelResult,
    CodeSearchResult,
    ConfigResult,
    VEXJudgment,
)
from vuln_analysis.agents.intel_agent import intel_agent_node
from vuln_analysis.agents.code_agent import code_agent_node, _get_search_queries
from vuln_analysis.agents.config_agent import config_agent_node
from vuln_analysis.agents.vex_agent import vex_agent_node, _judge_vex_status
from vuln_analysis.agents.supervisor import build_supervisor_graph


# ============================================================
# 辅助函数
# ============================================================
def _make_state(cve_list: list[str] = None) -> MultiAgentState:
    """创建测试用的 MultiAgentState。"""
    return MultiAgentState(
        cve_list=cve_list or ["CVE-2023-36632"],
    )


# ============================================================
# TestMultiAgentState: 状态模型测试
# ============================================================
class TestMultiAgentState:
    
    def test_default_state(self):
        state = MultiAgentState()
        assert state.cve_list == []
        assert state.intel_results == {}
        assert state.code_results == {}
        assert state.config_results == {}
        assert state.vex_judgments == {}
        assert state.current_phase == "init"
    
    def test_state_with_cves(self):
        state = _make_state(["CVE-2023-36632", "CVE-2021-44228"])
        assert len(state.cve_list) == 2
    
    def test_intel_result_model(self):
        result = IntelResult(cve_id="CVE-2023-36632", severity="high", description="test")
        assert result.cve_id == "CVE-2023-36632"
        assert result.severity == "high"
    
    def test_code_search_result_model(self):
        result = CodeSearchResult(cve_id="CVE-2023-36632", code_found=True, matched_files=["foo.py"])
        assert result.code_found is True
        assert len(result.matched_files) == 1
    
    def test_config_result_model(self):
        result = ConfigResult(cve_id="CVE-2023-36632", package_found=True, package_name="cpython")
        assert result.package_found is True
    
    def test_vex_judgment_model(self):
        judgment = VEXJudgment(cve_id="CVE-2023-36632", status="affected", confidence=0.9)
        assert judgment.status == "affected"
        assert judgment.confidence == 0.9
    
    def test_agent_role_enum(self):
        assert AgentRole.INTEL == "intel_agent"
        assert AgentRole.CODE == "code_agent"
        assert AgentRole.CONFIG == "config_agent"
        assert AgentRole.VEX == "vex_agent"


# ============================================================
# TestCodeAgent: 搜索模式相关
# ============================================================
class TestCodeAgent:

    def test_known_cve_patterns(self):
        queries = _get_search_queries("CVE-2023-36632")
        assert "parseaddr" in queries or "email.utils.parseaddr" in queries

    def test_unknown_cve_fallback(self):
        queries = _get_search_queries("CVE-9999-99999")
        assert queries == ["CVE-9999-99999"]

    def test_description_extraction(self):
        queries = _get_search_queries("CVE-9999-99999", "Vulnerability in foo.bar.baz module")
        assert "foo.bar.baz" in queries

    @pytest.mark.asyncio
    async def test_code_agent_node(self):
        state = _make_state(["CVE-2023-36632"])
        state.intel_results["CVE-2023-36632"] = IntelResult(cve_id="CVE-2023-36632")
        result = await code_agent_node(state)
        assert "CVE-2023-36632" in result.code_results
        assert result.code_results["CVE-2023-36632"].code_found is True


# ============================================================
# TestVEXJudgment: 判定逻辑
# ============================================================
class TestVEXJudgment:

    def test_affected_judgment(self):
        status, _, conf = _judge_vex_status("CVE-1", True, "high", True, True, True)
        assert status == "affected"
        assert conf >= 0.8

    def test_not_affected_no_package(self):
        status, _, conf = _judge_vex_status("CVE-1", True, "high", False, False, False)
        assert status == "not_affected"
        assert conf >= 0.7

    def test_not_affected_no_code(self):
        status, _, conf = _judge_vex_status("CVE-1", True, "high", False, True, True)
        assert status == "not_affected"
        assert conf >= 0.6

    def test_unknown_no_intel(self):
        status, _, _ = _judge_vex_status("CVE-1", False, "unknown", False, False, False)
        assert status == "unknown"

    @pytest.mark.asyncio
    async def test_vex_agent_node(self):
        state = _make_state(["CVE-2023-36632"])
        state.intel_results["CVE-2023-36632"] = IntelResult(cve_id="CVE-2023-36632", severity="high", intel_data={"nvd": True})
        state.code_results["CVE-2023-36632"] = CodeSearchResult(cve_id="CVE-2023-36632", code_found=True)
        state.config_results["CVE-2023-36632"] = ConfigResult(cve_id="CVE-2023-36632", package_found=True, is_vulnerable_version=True)
        result = await vex_agent_node(state)
        assert "CVE-2023-36632" in result.vex_judgments
        assert result.vex_judgments["CVE-2023-36632"].status == "affected"


# ============================================================
# TestIntelAgent: Intel Agent
# ============================================================
class TestIntelAgent:

    @pytest.mark.asyncio
    async def test_intel_agent_empty_input(self):
        state = _make_state(["CVE-2023-36632"])
        result = await intel_agent_node(state)
        assert "CVE-2023-36632" in result.intel_results

    @pytest.mark.asyncio
    async def test_intel_agent_preserves_cve_list(self):
        state = _make_state(["CVE-1", "CVE-2"])
        result = await intel_agent_node(state)
        assert len(result.intel_results) == 2


# ============================================================
# TestSupervisor: Graph 构建
# ============================================================
class TestSupervisor:

    def test_build_graph(self):
        graph = build_supervisor_graph()
        assert graph is not None

    def test_graph_has_nodes(self):
        graph = build_supervisor_graph()
        # StateGraph 应该有 init, gather, judge, summary 节点
        assert "init" in graph.nodes
        assert "gather" in graph.nodes
        assert "judge" in graph.nodes
        assert "summary" in graph.nodes
