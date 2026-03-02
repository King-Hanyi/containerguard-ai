# ContainerGuard AI 项目执行方案 (v3 改进版)

> **变更说明**: 本方案基于 v2 计划修订，**不覆盖原计划**。仅针对以下三项进行改进：
> 1. 阶段三"模型微调" → **Prompt 工程优化 + Few-shot**
> 2. 新增阶段二末尾 **Baseline 对比实验**（量化答辩数据）
> 3. 新增阶段三 **Streamlit 可视化 Dashboard**（答辩演示）

---

## 📅 阶段一: 基础框架与技能构建 (2.9 - 2.22) — 无变更

与 v2 计划一致，已全部完成。详见原计划。

---

## 📅 阶段二: 多智能体系统开发 (2.23 - 3.8)

### 2.1 Supervisor 编排逻辑 (Week 3) — 无变更

### 2.2 专业 Agent 开发 (Week 4) — 无变更

### 🆕 2.3 Baseline 对比实验 (Week 4 末)

> **目的**: 产出**量化数据**，答辩时用数据说话。

**实验设计**:

| 对照组 | 配置 |
|:---|:---|
| **Baseline** | NVIDIA 原始单 Agent 流水线 (`cve_agent_workflow`) |
| **Ours** | 多 Agent + Skills 流水线 |

**测试集**: 使用 Blueprint 自带的 `morpheus:23.11-runtime` 输入（含 10+ CVE）

**对比指标**:
| 指标 | 含义 | 获取方式 |
|:---|:---|:---|
| **准确率 (Accuracy)** | VEX 判定正确率 | `nat eval` 评估管线 |
| **Unknown 率** | "Exploitability Unknown" 占比 | 统计 output.json |
| **平均耗时** | 单 CVE 分析时长 | 计时 output.json 中 started_at / completed_at |
| **Token 消耗** | 总 Token 数 | LLM 日志统计 |

**预期答辩话术**:
> "我们的多 Agent + Skills 架构将 Unknown 判定率从 X% 降至 Y%，准确率提升 Z 个百分点，单 CVE 分析时间从 A 秒缩短至 B 秒。"

---

## 📅 阶段三: CI/CD 集成与优化 (3.9 - 3.22) — 有变更

### 3.1 GitHub Action 插件 (Week 5) — 无变更

### ~~3.2 模型微调与优化 (Week 6)~~ → 改为 ↓

### 🆕 3.2 Prompt 工程优化 + Streamlit Dashboard (Week 6)

> **变更理由**: 模型微调需要标注数据集和大量 GPU 时间，风险高、收益不确定。改为**投入产出比更高**的两项工作。

#### A. Prompt 工程优化
- 基于阶段二的实验数据，分析 Agent 失败案例（哪些 CVE 判断错误或 Unknown）。
- 针对性优化各 Agent 的 System Prompt：
  - **Intel Agent**: 补充漏洞评分权重指引。
  - **Code Agent**: 优化代码搜索关键词生成策略。
  - **VEX Agent**: 加入 Few-shot 示例（提供 2-3 个标准判定案例）。
- 重新运行 Baseline 对比，验证 Prompt 优化效果。

#### B. Streamlit 可视化 Dashboard
- 开发一个轻量级 Web 界面用于**答辩现场演示**。

**Dashboard 功能规划**:
| 页面 | 内容 |
|:---|:---|
| **扫描总览** | 容器名称、CVE 数量、风险等级分布（饼图） |
| **多 Agent 流程** | 展示 Supervisor 调度过程（Mermaid 流程图） |
| **CVE 详情** | 单个 CVE 的 Checklist + Agent 分析 + 最终判定 |
| **对比面板** | Baseline vs Ours 的指标对比（柱状图） |

**技术选型**: Streamlit（Python 原生，无需前端，半天即可搭建）

**交付物**: Prompt 优化后的配置文件 + Streamlit Dashboard 源码

---

## 📅 阶段四: OPA 策略门禁与交付 (3.23 - 4.5) — 无变更

与 v2 计划一致。

---

## 📊 v2 → v3 变更对照

| 项目 | v2 (原计划) | v3 (改进版) | 改进理由 |
|:---|:---|:---|:---|
| Week 4 末 | 直接开始 CI/CD | **+** Baseline 对比实验 | 答辩需要量化数据 |
| Week 6 | 模型微调 (8B QLoRA) | Prompt 优化 + Few-shot | 微调风险高、数据不足 |
| Week 6 | 无 | **+** Streamlit Dashboard | 答辩演示效果 > 文字报告 |
