# ContainerGuard AI

**基于多智能体架构的高级容器漏洞分析系统**

> **注**: 本项目基于 [NVIDIA AI Blueprint for Vulnerability Analysis](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis) 二次开发，扩展了自定义的多智能体协同架构与 Skills 插件化系统。

## 👥 核心团队

-   **组长**: 金韩溢
-   **组员**: 卢周全, 邓一凡

## 🚀 项目概述

**ContainerGuard AI** 旨在通过引入模块化的**多智能体 (Multi-Agent)** 架构，彻底革新容器安全分析的流程。

传统的漏洞扫描工具往往只提供静态的漏洞列表，缺乏对上下文的深入理解。ContainerGuard AI 利用大语言模型 (LLM) 的推理能力，结合专门设计的 Agent（如代码分析员、配置审核员、情报分析员），对容器环境及代码进行深度上下文感知的风险评估与验证。

## ✨ 核心特性

-   **Skills 插件化框架**: 基于 `BaseSkill` 抽象基类 + `SkillRegistry` 注册机制，实现分析能力的热插拔扩展。
-   **远程代码检索**: 通过 GitHub API 远程搜索代码（`RemoteCodeSkill`），替代传统的本地 Git Clone + VDB 方案。
-   **多源情报融合**: 集成 NVD / GHSA / RedHat / Ubuntu 等多个漏洞情报源（`IntelSkill`）。
-   **容器配置审计**: 支持 File / HTTP / Manual 三种模式解析 SBOM（`ConfigSkill`）。
-   **多智能体协同** (规划中): Supervisor 调度 + 专业 Agent 并行工作 + 异构 LLM 策略。
-   **策略即代码** (规划中): 集成 OPA (Open Policy Agent)，实现自动化安全门禁。

## 🏗️ 项目架构

```
src/vuln_analysis/
├── skills/                  # Skills 插件化框架 (自主创新)
│   ├── base.py              # BaseSkill 抽象基类
│   ├── registry.py          # SkillRegistry 注册装饰器
│   ├── intel.py             # IntelSkill — 多源漏洞情报检索
│   ├── config.py            # ConfigSkill — SBOM 解析
│   └── remote_code.py       # RemoteCodeSkill — GitHub API 代码搜索
├── functions/               # NVIDIA Blueprint 原始函数
├── tools/                   # Agent 工具集
├── eval/                    # 评估管线
└── configs/                 # 配置文件

tests/
└── test_skills.py           # Skills 框架单元测试 (13 项全通过)
```

## 🛠️ 技术栈

-   **核心语言**: Python 3.12
-   **Agent 框架**: NVIDIA NAT (NeMo Agent Toolkit), LangGraph, LangChain
-   **向量数据库**: FAISS
-   **大模型服务**: NVIDIA NIM
-   **包管理**: uv

## 📅 开发进度

### 阶段一: 基础框架与技能构建 (2.9 - 2.22)
-   [x] 本地开发环境搭建 (Windows / Python 3.12 / uv)
-   [x] Blueprint 工作流跑通与验证
-   [x] SBOM 解析 BOM 头修复 + Windows 路径适配
-   [x] Skills 插件化框架设计与实现 (BaseSkill + SkillRegistry)
-   [x] IntelSkill / ConfigSkill / RemoteCodeSkill 开发完成
-   [x] 单元测试 13/13 通过

### 阶段二: 多智能体系统开发 (2.23 - 3.8)
-   [ ] Supervisor Agent 状态机设计 (LangGraph)
-   [ ] 异构 LLM 调度策略 (70B Supervisor + 8B Workers)
-   [ ] Intel / Code / Config / VEX 专业 Agent 开发

### 阶段三: CI/CD 集成与测试 (3.9 - 3.22)
-   [ ] GitHub Action 自动化插件
-   [ ] 模型微调与优化

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

5.  **运行测试**:
    ```bash
    uv run python -m pytest tests/test_skills.py -v
    ```

## 📄 许可证

本项目采用 Apache 2.0 许可证。详见 [LICENSE](LICENSE) 文件。
