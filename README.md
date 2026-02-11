# ContainerGuard AI

**基于多智能体架构的高级容器漏洞分析系统**

> **注**: 本项目基于 [NVIDIA AI Blueprint for Vulnerability Analysis](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis) 二次开发，扩展了自定义的多智能体协同架构与插件化系统。

## 👥 核心团队

-   **组长**: 金韩溢
-   **组员**: 卢周全, 邓一凡

## 🚀 项目概述

**ContainerGuard AI** 旨在通过引入模块化的**多智能体 (Multi-Agent)** 架构，彻底革新容器安全分析的流程。

传统的漏洞扫描工具往往只提供静态的漏洞列表，缺乏对上下文的深入理解。ContainerGuard AI 利用大语言模型 (LLM) 的推理能力，结合专门设计的 Agent（如代码分析员、配置审核员、情报分析员），对容器环境及代码进行深度上下文感知的风险评估与验证。

## ✨ 核心特性 (规划路线图)

-   **Skills 插件化框架**: 解耦核心逻辑，通过插件形式轻松扩展分析能力（如：源码静态分析、配置合规检查、威胁情报关联等）。
-   **多智能体协同**: 专职 Agent 分工协作——Planner 负责规划路径，Executor 执行具体 Skill，Verifier 验证结果。
-   **知识图谱融合**: 构建软件供应链知识图谱，深度理解依赖关系与漏洞传播路径。
-   **策略即代码 (PaC)**: 集成 OPA (Open Policy Agent)，实现自动化的安全门禁。

## 🛠️ 技术栈

-   **核心语言**: Python 3.12
-   **Agent 框架**: NVIDIA NAT (NeMo Agent Toolkit), LangGraph, LangChain
-   **向量数据库**: FAISS
-   **大模型服务**: NVIDIA NIM

## 📅 开发进度

### Phase 1: 基础建设 (已完成)
-   [x] 本地开发环境搭建 (Windows/Python 3.12/uv)
-   [x] 基础工作流跑通与验证 (基于 NVIDIA Blueprint)
-   [x] 本地化配置与兼容性适配

### Phase 2: 核心组件 (进行中)
-   [ ] Skills 插件系统设计与实现
-   [ ] 多智能体运行时架构改造

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
    uv sync
    ```

3.  **配置环境**:
    ```bash
    cp .env.template .env
    # 编辑 .env 文件，填入您的 NVIDIA_API_KEY
    ```

4.  **运行 Demo 分析**:
    ```bash
    nat run --config_file=src/vuln_analysis/configs/config-local.yml --input_file=src/vuln_analysis/data/input_messages/morpheus_23.11-runtime.json
    ```

## 📄 许可证

本项目采用 Apache 2.0 许可证。详见 [LICENSE](LICENSE) 文件。
