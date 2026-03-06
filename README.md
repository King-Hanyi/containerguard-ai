# ContainerGuard AI

**基于多智能体架构的高级容器漏洞分析系统**

> **注**: 本项目基于 [NVIDIA AI Blueprint for Vulnerability Analysis](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis) 二次开发，扩展了自定义的多智能体协同架构与 Skills 插件化系统。

[![CI](https://github.com/King-Hanyi/containerguard-ai/actions/workflows/containerguard.yml/badge.svg)](https://github.com/King-Hanyi/containerguard-ai/actions)

## 👥 核心团队

-   **组长**: 金韩溢
-   **组员**: 卢周全, 邓一凡

## 🚀 项目概述

**ContainerGuard AI** 通过引入模块化的 **多智能体 (Multi-Agent)** 架构，革新容器安全分析流程。

传统漏洞扫描工具只提供静态的漏洞列表，缺乏对上下文的深入理解。ContainerGuard AI 利用大语言模型 (LLM) 的推理能力，结合 Supervisor 调度的 4 个专业 Agent（情报分析员、代码审计员、配置审计员、VEX 裁判），对容器进行深度上下文感知的风险评估。

### 与 NVIDIA Blueprint 对比

| 维度 | NVIDIA Blueprint (原始) | ContainerGuard AI (我们) |
|:---|:---|:---|
| **架构** | 单 Agent 线性流水线 | Supervisor + 4 子 Agent 并行 |
| **代码分析** | 本地 Git Clone + FAISS VDB | GitHub API 远程搜索 (RemoteCodeSkill) |
| **VEX 判定** | 单 Agent + 单 LLM | 多维证据 → LLM 推理 (llama-3.1-70b) |
| **功能扩展** | 硬编码函数 | 插件化 Skill + 装饰器注册 |
| **执行方式** | 所有步骤串行 | 信息收集阶段三路并行 |
| **LLM 策略** | 统一用一个模型 | 异构 LLM (70B Supervisor + 8B Workers) |
| **Windows** | 路径长度崩溃 | 完全兼容 |

### Baseline 实验结果

| 指标 | Baseline (单 Agent) | Ours (多 Agent + LLM) |
|:---|:---|:---|
| **准确率** | 50% (2/4) | **100% (4/4)** |
| **Unknown 率** | 50% | **0%** |
| **平均置信度** | 40% | **88%** |
| **平均耗时** | 45.8s/CVE | **1.64s/CVE** |

## ✨ 核心特性

-   **LLM 驱动 VEX 判定**: VEX Agent 调用 NVIDIA NIM `llama-3.1-70b-instruct` 进行推理，基于多维证据生成标准 VEX 判定
-   **多智能体协同**: Supervisor Agent 调度 Intel / Code / Config / VEX 四个子 Agent 并行工作
-   **Agent ↔ Skill 分层架构**: 每个 Agent 集成对应 Skill，支持 API 实时调用 + 本地兜底双层策略
-   **Skills 插件化框架**: 基于 `BaseSkill` 抽象基类 + `SkillRegistry` 注册机制，实现分析能力的热插拔扩展
-   **远程代码检索**: Code Agent → RemoteCodeSkill → GitHub Code Search API，替代本地 Git Clone + VDB
-   **多源情报融合**: Intel Agent → IntelSkill（NVD / GHSA / RedHat）+ 内置情报库 (7 个高频 CVE)
-   **容器配置审计**: Config Agent → ConfigSkill，主动解析 SBOM 文件（支持 ANSI 码 + BOM 头处理）
-   **Prompt 工程优化**: Few-shot 示例 + 标准 VEX justification 标签 + YAML 配置外置
-   **CI/CD 集成**: GitHub Action 自动化测试与验证
-   **可视化 Dashboard**: Streamlit 4 页交互式答辩演示界面
-   **策略即代码** (规划中): 集成 OPA (Open Policy Agent)，实现自动化安全门禁

## 🏗️ 项目架构

```
src/vuln_analysis/
├── agents/                  # 多智能体系统 (阶段二)
│   ├── state.py             # 共享状态模型 (6 个 Pydantic 模型)
│   ├── supervisor.py        # Supervisor Agent (LangGraph 状态机)
│   ├── intel_agent.py       # Intel Agent — 情报分析
│   ├── code_agent.py        # Code Agent — 代码可达性 (14 CVE 模式)
│   ├── config_agent.py      # Config Agent — 依赖审计
│   └── vex_agent.py         # VEX Agent — 综合判定 (标准 VEX 标签)
├── skills/                  # Skills 插件化框架 (阶段一)
│   ├── base.py              # BaseSkill 抽象基类
│   ├── registry.py          # SkillRegistry 注册装饰器
│   ├── intel.py             # IntelSkill — 多源漏洞情报检索
│   ├── config.py            # ConfigSkill — SBOM 解析
│   └── remote_code.py       # RemoteCodeSkill — GitHub API 代码搜索
├── knowledge/               # BRON 知识图谱模块 (卢周全)
│   ├── bron_loader.py       # BRONLoader — 多格式 BRON 数据加载
│   └── knowledge_graph.py   # KnowledgeGraph — CVE↔CWE/CAPEC/ATT&CK 查询
├── configs/                 # 配置文件
│   └── prompts.yml          # Agent Prompt 配置 (Few-shot 示例)
├── data/                    # 测试数据
│   ├── input_messages/      # 测试输入 (Log4j / Spring4Shell / Heartbleed / Morpheus)
│   └── sboms/               # SBOM 文件
├── functions/               # NVIDIA Blueprint 原始函数
├── tools/                   # Agent 工具集
└── eval/                    # 评估管线

scripts/
├── demo_agents.py           # 多 Agent 系统演示脚本
├── run_baseline.py          # Baseline 对比实验
└── check_progress.py        # 项目进度自动检查

dashboard/
└── app.py                   # Streamlit 可视化 Dashboard (4 页)

tests/
├── test_skills.py           # Skills 框架测试 (13 项)
├── test_agents.py           # 多 Agent 系统测试 (20 项)
├── test_bron.py             # BRON 知识图谱测试 (卢周全)
└── test_java_script_extended.py

.github/workflows/
└── containerguard.yml       # CI/CD 自动化测试
```

## 🛠️ 技术栈

-   **核心语言**: Python 3.12
-   **Agent 框架**: NVIDIA NAT (NeMo Agent Toolkit), LangGraph, LangChain
-   **向量数据库**: FAISS
-   **大模型服务**: NVIDIA NIM
-   **包管理**: uv
-   **可视化**: Streamlit + Plotly
-   **CI/CD**: GitHub Actions

## 📅 开发进度

### 阶段一: 基础框架与技能构建 (2.9 - 2.22) ✅
-   [x] 本地开发环境搭建 (Windows / Mac / Python 3.12 / uv)
-   [x] Blueprint 工作流跑通与验证
-   [x] SBOM 解析 BOM 头修复 + Windows 路径适配
-   [x] Skills 插件化框架设计与实现 (BaseSkill + SkillRegistry)
-   [x] IntelSkill / ConfigSkill / RemoteCodeSkill 开发完成
-   [x] 单元测试 13/13 通过

### 阶段二: 多智能体系统开发 (2.23 - 3.8) ✅
-   [x] Supervisor Agent 状态机设计 (LangGraph StateGraph)
-   [x] Intel / Code / Config / VEX 四个专业 Agent 开发
-   [x] **Agent ↔ Skill 分层打通** (每个 Agent 集成对应 Skill + 兜底策略)
-   [x] **VEX Agent 接入 NVIDIA NIM LLM** (llama-3.1-70b-instruct 实时推理)
-   [x] 单元测试 33/33 通过 (20 Agent + 13 Skills)
-   [x] 测试输入数据 (Log4j / Spring4Shell / Heartbleed)
-   [x] Baseline 对比实验 — 准确率 100% vs Baseline 50%

### 阶段三: CI/CD 集成与优化 (3.9 - 3.22) 🟡 进行中
-   [x] GitHub Action 自动化测试 (`containerguard.yml`)
-   [x] Prompt 工程优化 (Few-shot + YAML 配置外置 `prompts.yml`)
-   [x] Code Agent (14 CVE 模式 + GitHub API 双层策略)
-   [x] VEX Agent (LLM 推理 + 规则引擎双层策略)
-   [x] Streamlit 可视化 Dashboard (4 页)
-   [ ] PR 触发漏洞扫描 + 自动评论

### 阶段四: OPA 策略门禁与交付 (3.23 - 4.5)
-   [ ] OPA Rego 安全策略引擎
-   [ ] 技术文档 + 演示材料

## 📦 快速开始

### 前置要求

-   Python 3.12+
-   [uv](https://github.com/astral-sh/uv) (包管理器)
-   NVIDIA API Key

### 安装与运行

1.  **克隆仓库**:
    ```bash
    git clone https://github.com/King-Hanyi/containerguard-ai.git
    cd containerguard-ai
    ```

2.  **安装依赖**:
    ```bash
    uv venv --python 3.12
    source .venv/bin/activate
    uv sync
    ```

3.  **配置环境**:
    ```bash
    cp .env.template .env
    # 编辑 .env 文件，填入您的 NVIDIA_API_KEY
    ```

4.  **运行多 Agent 演示**:
    ```bash
    uv run python scripts/demo_agents.py
    ```

5.  **运行 Baseline 对比实验**:
    ```bash
    uv run python scripts/run_baseline.py
    ```

6.  **运行测试**:
    ```bash
    uv run python -m pytest tests/ -v
    ```

7.  **启动 Dashboard** (需额外安装 `pip install streamlit plotly`):
    ```bash
    streamlit run dashboard/app.py
    ```

8.  **查看项目进度**:
    ```bash
    uv run python scripts/check_progress.py
    ```

## 📄 许可证

本项目采用 Apache 2.0 许可证。详见 [LICENSE](LICENSE) 文件。
