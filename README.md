# 🛡️ ContainerGuard AI

**基于多智能体架构的容器漏洞自动化分析平台**

> 本项目基于 [NVIDIA AI Blueprint for Vulnerability Analysis](https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis) 二次开发，重新设计了多智能体并行架构，并补齐了 Blueprint 的核心分析能力。

[![CI](https://github.com/King-Hanyi/containerguard-ai/actions/workflows/containerguard.yml/badge.svg)](https://github.com/King-Hanyi/containerguard-ai/actions)

## 👥 团队

- **组长**: 金韩溢
- **组员**: 卢周全, 邓一凡

---

## 🚀 项目概述

ContainerGuard AI 是一个**容器安全扫描平台**——输入 GitHub 仓库地址或 Docker 镜像名称，多智能体系统自动完成漏洞分析，输出带 OPA 策略门禁的专业报告。

**核心流程**：

```
输入 Docker 镜像 / GitHub URL
    ↓
Supervisor Agent（LangGraph 状态机调度）
    ↓ 并行分发
┌───────────┬───────────┬───────────┐
│ Intel Agent│ Code Agent│Config Agent│
│ NVD/GHSA   │ GitHub API│ SBOM 解析  │
│ BRON 知识图谱│ 代码搜索   │ 版本比较   │
└───────────┴───────────┴───────────┘
    ↓ 证据汇聚
VEX Agent（LLM 推理 — Checklist 分步判定）
    ↓
OPA 策略引擎（安全门禁: block / warn / pass）
    ↓
漏洞分析报告（Markdown / HTML / Word）
```

---

## 与 NVIDIA Blueprint 的关系

我们在 Blueprint 基础上做了**架构重构**和**功能补齐**。以下是基于源码分析的**定性比较**（非性能实测）：

| 维度 | Blueprint (原始) | ContainerGuard AI (我们) | 状态 |
|:---|:---|:---|:---|
| **架构** | 单 Agent + 9 串行函数 | Supervisor + 4 并行 Agent | 🆕 重构 |
| **LLM 调用** | 4-6 次 / CVE | 1 次 / CVE | 🆕 优化 |
| **版本比较** | `univers` 语义化 | `packaging.version` 精确范围 | ✅ 对等 |
| **推理方式** | Checklist + ReAct Agent | Checklist + Few-shot + 多证据 | ✅ 对等 |
| **情报来源** | NVD 单源 | NVD + GHSA + BRON 攻击链 | ✅ 超越 |
| **代码分析** | 本地 Git Clone + FAISS | GitHub Code Search API 远程 | 🆕 重构 |
| **策略引擎** | 无 | OPA 策略即代码 (4 规则) | 🆕 新增 |
| **可视化** | 无 | 产品级 Web 扫描平台 | 🆕 新增 |
| **报告输出** | JSON 文件 | Markdown / HTML / Word | 🆕 新增 |

> **说明**: 因缺少完整 NVIDIA NIM 集群环境，无法进行端到端性能实测。上述比较基于源码级架构分析，具体性能差异需实际 A/B 测试验证。

---

## ✨ 核心特性

### 多智能体并行架构
- **Supervisor Agent**: LangGraph 状态机调度，管理分析流程
- **Intel Agent**: NVD / GHSA / 内置情报库 + BRON 知识图谱 (CVE↔CWE↔CAPEC↔ATT&CK)
- **Code Agent**: GitHub Code Search API 远程代码搜索 + 14 CVE 本地模式匹配
- **Config Agent**: SBOM 解析 + `packaging.version` 精确版本范围比较
- **VEX Agent**: NVIDIA NIM `llama-3.1-70b-instruct` LLM 推理，Checklist 分步判定

### 安全门禁 (OPA)
- 基于 Open Policy Agent 的策略即代码引擎
- 4 条内置规则: `critical_affected → block`, `high_affected → warn` 等
- 自动部署决策: BLOCKED / PASSED

### 产品级前端
- 扫描入口: 手动输入 GitHub URL / Docker 镜像 或 选择本地 Docker 镜像
- 扫描进度: 实时 Agent 日志 + 进度条动画
- 漏洞报告: OPA 门禁横幅 + CVE 表格 (含 Checklist ✓✗ 列)
- 详情面板: 侧滑展示 Intel → Code → Config → Checklist → LLM 推理全链路
- 报告导出: Markdown / HTML (浏览器打印为 PDF) / Word

### Skills 插件化框架
- `BaseSkill` 抽象基类 + `SkillRegistry` 装饰器注册
- IntelSkill / ConfigSkill / RemoteCodeSkill 可热插拔

---

## 📊 Baseline 实验结果

在 10 个已知 CVE 上的分析结果：

| 指标 | 值 |
|:---|:---|
| CVE 总数 | 10 |
| Affected 判定 | 8 |
| Not Affected 判定 | 2 |
| 平均置信度 | 89% |
| 测试通过 | 61/61 |

> 判定基于 LLM 推理 + Checklist 验证，**非人工标注的 ground truth**。完整结果见 `docs/baseline_results.json`。

---

## 🏗️ 项目结构

```
src/vuln_analysis/
├── agents/                  # 多智能体系统
│   ├── state.py             # 共享状态 (Pydantic)
│   ├── supervisor.py        # Supervisor Agent (LangGraph)
│   ├── intel_agent.py       # Intel Agent + BRON 知识图谱
│   ├── code_agent.py        # Code Agent (GitHub API + 模式匹配)
│   ├── config_agent.py      # Config Agent (SBOM + 版本比较)
│   └── vex_agent.py         # VEX Agent (LLM + Checklist)
├── skills/                  # Skills 插件化框架
│   ├── base.py / registry.py
│   ├── intel.py / config.py / remote_code.py
├── knowledge/               # 知识增强检索
│   ├── bron_loader.py       # BRON 多格式加载器 (357行)
│   ├── knowledge_graph.py   # 攻击链查询 (232行)
│   ├── bm25_retriever.py    # BM25 稀疏检索
│   └── hybrid_retriever.py  # RRF 混合检索融合
├── policy/                  # OPA 策略引擎 (238行)
├── report_generator.py      # 报告生成 (MD/HTML/DOCX)
└── data/input_messages/     # 测试输入 (4 文件)

frontend/                    # 产品级 Web 前端
├── index.html / style.css / app.js

scripts/
├── api_server.py            # API 服务器 (含报告导出 + 真实扫描触发)
├── demo_agents.py           # 多 Agent 演示
├── run_baseline.py          # Baseline 对比实验
└── generate_report.py       # CI/CD 扫描报告生成

tests/                       # 61 项测试
├── test_agents.py / test_policy.py / test_bm25.py / test_bron.py / ...
```

---

## 📦 快速开始

### 前置要求

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (包管理器)
- NVIDIA API Key (用于 LLM 推理)

### 安装与运行

```bash
# 1. 克隆仓库
git clone https://github.com/King-Hanyi/containerguard-ai.git
cd containerguard-ai

# 2. 安装依赖
uv sync

# 3. 配置环境变量
cp .env.template .env
# 编辑 .env，填入 NVIDIA_API_KEY

# 4. 运行测试 (61/61 通过)
uv run python -m pytest tests/ -v

# 5. 启动产品级前端
uv run python scripts/api_server.py
# 浏览器打开 http://localhost:8090

# 6. 运行多 Agent 演示
uv run python scripts/demo_agents.py

# 7. 运行 Baseline 对比
uv run python scripts/run_baseline.py
```

---

## 🛠️ 技术栈

| 层级 | 技术 |
|:---|:---|
| 核心语言 | Python 3.12 |
| Agent 框架 | LangGraph + LangChain |
| LLM 服务 | NVIDIA NIM (llama-3.1-70b-instruct) |
| 知识图谱 | BRON (CVE↔CWE↔CAPEC↔ATT&CK) |
| 策略引擎 | OPA (Open Policy Agent) |
| 版本比较 | packaging.version |
| 前端 | Vanilla HTML/CSS/JS (深色主题) |
| 包管理 | uv |
| CI/CD | GitHub Actions |

---

## 📄 许可证

本项目采用 Apache 2.0 许可证。详见 [LICENSE](LICENSE) 文件。
