# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
ContainerGuard AI — 多智能体共享状态定义。

定义 Supervisor 和各子 Agent 之间传递的状态模型。
"""

import typing
from enum import Enum

from pydantic import BaseModel, Field

from vuln_analysis.data_models.input import AgentMorpheusEngineInput
from vuln_analysis.data_models.cve_intel import CveIntel


class AgentRole(str, Enum):
    """子 Agent 角色定义。"""
    INTEL = "intel_agent"
    CODE = "code_agent"
    CONFIG = "config_agent"
    VEX = "vex_agent"


class TaskStatus(str, Enum):
    """任务执行状态。"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class AgentTask(BaseModel):
    """分配给子 Agent 的单个任务。"""
    cve_id: str = Field(description="目标 CVE 编号")
    agent_role: AgentRole = Field(description="负责的 Agent 角色")
    status: TaskStatus = Field(default=TaskStatus.PENDING, description="任务状态")
    result: dict[str, typing.Any] = Field(default_factory=dict, description="Agent 返回的结果")
    error: str | None = Field(default=None, description="错误信息")


class IntelResult(BaseModel):
    """Intel Agent 的分析结果。"""
    cve_id: str
    intel_data: dict[str, typing.Any] = Field(default_factory=dict, description="从 NVD/GHSA 获取的情报")
    severity: str = Field(default="unknown", description="CVSS 严重程度")
    description: str = Field(default="", description="漏洞描述")


class CodeSearchResult(BaseModel):
    """Code Agent 的分析结果。"""
    cve_id: str
    code_found: bool = Field(default=False, description="是否在源码中找到漏洞函数")
    matched_files: list[str] = Field(default_factory=list, description="匹配的文件路径")
    search_query: str = Field(default="", description="搜索使用的关键词")
    evidence: str = Field(default="", description="代码证据描述")


class ConfigResult(BaseModel):
    """Config Agent 的分析结果。"""
    cve_id: str
    package_found: bool = Field(default=False, description="SBOM 中是否包含漏洞包")
    package_name: str = Field(default="", description="漏洞包名")
    package_version: str = Field(default="", description="漏洞包版本")
    is_vulnerable_version: bool = Field(default=False, description="是否为受影响版本")


class VEXJudgment(BaseModel):
    """VEX Agent 的最终判定。"""
    cve_id: str
    status: str = Field(default="unknown", description="判定状态: affected / not_affected / unknown")
    justification: str = Field(default="", description="判定理由")
    confidence: float = Field(default=0.0, description="置信度 0-1")
    summary: str = Field(default="", description="分析摘要")


class MultiAgentState(BaseModel):
    """
    多智能体系统的全局共享状态。
    
    Supervisor 创建并管理此状态，各子 Agent 读写自己负责的部分。
    """
    # 输入数据 (来自原始流水线)
    engine_input: AgentMorpheusEngineInput | None = Field(default=None, description="原始引擎输入")
    cve_list: list[str] = Field(default_factory=list, description="待分析的 CVE 列表")
    
    # 各 Agent 的结果
    intel_results: dict[str, IntelResult] = Field(default_factory=dict, description="Intel Agent 结果 (CVE ID → 结果)")
    code_results: dict[str, CodeSearchResult] = Field(default_factory=dict, description="Code Agent 结果")
    config_results: dict[str, ConfigResult] = Field(default_factory=dict, description="Config Agent 结果")
    vex_judgments: dict[str, VEXJudgment] = Field(default_factory=dict, description="VEX Agent 最终判定")
    
    # OPA 策略引擎结果
    policy_decisions: list[dict[str, typing.Any]] = Field(default_factory=list, description="OPA 策略决策列表")
    policy_summary: dict[str, typing.Any] = Field(default_factory=dict, description="OPA 策略评估摘要")

    # 任务追踪
    tasks: list[AgentTask] = Field(default_factory=list, description="任务列表")
    current_phase: str = Field(default="init", description="当前阶段: init → gather → judge → policy → done")
    errors: list[str] = Field(default_factory=list, description="全局错误记录")
