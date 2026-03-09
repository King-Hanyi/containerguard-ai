# ContainerGuard AI 项目执行方案 (v4 — 冲刺一等奖版)

> **更新日期**: 2026-03-09  
> **基于**: v3 计划 + 3.9 深度代码审查  
> **目标**: 识别差距，精准补强，冲击一等奖

---

## 一、当前代码深度分析

### 1.1 已有优势（答辩加分项）

| 优势 | 细节 | 答辩说服力 |
|:---|:---|:---|
| **真正的 LLM 推理** | VEX Agent 调用 NVIDIA NIM llama-3.1-70b，Few-shot Prompt | ⭐⭐⭐⭐⭐ |
| **多 Agent 并行** | LangGraph + asyncio.gather 三路并行 | ⭐⭐⭐⭐ |
| **Agent ↔ Skill 分层** | 每个 Agent 有对应 Skill + 多层兜底策略 | ⭐⭐⭐⭐ |
| **量化 Baseline 数据** | 100% vs 50%、1.64s vs 45.8s | ⭐⭐⭐⭐⭐ |
| **前端可视化** | 4 页深色安全风格 Dashboard | ⭐⭐⭐⭐ |
| **CI/CD + PR 扫描** | GitHub Action 自动测试 + PR 评论 | ⭐⭐⭐ |

### 1.2 诚实问题评估（评委可能的挑战）

| 问题 | 严重性 | 评委可能问的 | 影响 |
|:---|:---|:---|:---|
| **测试集太小** (4 CVE) | 🔴 高 | "只有 4 个样本，统计意义呢？" | 说服力不足 |
| **Baseline 非真实运行** | 🔴 高 | "Baseline 数据是模拟的还是真跑的？" | 数据可信度 |
| **知识图谱完全孤立** | 🟡 中 | "BRON 模块和 Agent 系统有什么关系？" | 架构完整性 |
| **Dashboard 硬编码** | 🟡 中 | "数据是实时的吗？" | 系统完整度 |
| **无安全策略引擎** | 🟡 中 | "怎么做自动化安全决策？" | 创新深度 |
| **缺少 Token 消耗分析** | 🟢 低 | "LLM 调用成本多少？" | 经济性 |

---

## 二、v3 → v4 改进对照

| 项目 | v3 现状 | v4 改进 | 改进理由 |
|:---|:---|:---|:---|
| 测试集 | 4 个 CVE | **扩至 10+ CVE** | 统计意义 |
| Baseline | 模拟参考值 | **真实运行 + 录屏** | 数据说服力 |
| KnowledgeGraph | 孤立模块 | **集成到 Intel Agent** | 架构完整性 |
| 前端 Dashboard | 硬编码数据 | **接 demo 实时输出** | 系统联动 |
| OPA 策略引擎 | 规划中 | **基础实现 + demo** | 创新深度 |
| Token 分析 | 无 | **加入 Baseline 报告** | 经济性论证 |

---

## 三、冲刺一等奖改进计划

### 3.1 测试集扩充 (最高优先级)

> 目标: 10+ CVE，覆盖 5 种语言生态

#### [NEW] `data/input_messages/` 新增 6+ 测试用例

| CVE | 名称 | 生态 | 期望结果 |
|:---|:---|:---|:---|
| CVE-2021-3449 | OpenSSL NULL pointer | C/OpenSSL | affected |
| CVE-2023-44487 | HTTP/2 Rapid Reset | Go/HTTP | affected |
| CVE-2021-41773 | Apache Path Traversal | Apache/httpd | affected |
| CVE-2017-5638 | Struts2 RCE | Java/Struts | affected |
| CVE-2023-32681 | Requests SSRF | Python/pip | not_affected |
| CVE-2022-42889 | Text4Shell | Java/Maven | affected |

---

### 3.2 知识图谱集成到 Agent 系统

#### [MODIFY] `intel_agent.py`
- 导入 `KnowledgeGraph`，在情报收集后调用 `query_attack_chain(cve_id)`
- 将 CWE/CAPEC/ATT&CK 信息追加到 `IntelResult.intel_data`
- VEX Agent 的 LLM Prompt 自动包含攻击链，提升推理深度

---

### 3.3 OPA 策略引擎 (基础版)

#### [NEW] `src/vuln_analysis/policy/opa_engine.py`
- 定义 Rego 安全策略（如: critical + affected → block deploy）
- 输入: VEX 判定结果 JSON
- 输出: pass/block 决策

#### [NEW] `policies/security_gate.rego`
```rego
package containerguard

default allow = true
deny[msg] {
    input.status == "affected"
    input.severity == "critical"
    msg := sprintf("BLOCKED: %v is critical and affected", [input.cve_id])
}
```

---

### 3.4 前端 Dashboard 接真实数据

#### [MODIFY] `frontend/app.js`
- 读取 `baseline_results.json` 而非硬编码
- 增加"一键运行"演示按钮 (调后端 API)

#### [NEW] `scripts/api_server.py`
- 轻量 FastAPI 服务器，暴露 `/api/scan` 和 `/api/results` 接口
- 前端通过 fetch 调用，实现真正的前后端联动

---

### 3.5 Token 消耗统计

#### [MODIFY] `vex_agent.py`
- 记录每个 CVE 的 prompt_tokens / completion_tokens
- 累加到 `MultiAgentState.metadata`

#### [MODIFY] `baseline_report.md`
- 增加 Token 消耗对比表（Ours vs Baseline）

---

## 四、一等奖评审视角自检

| 评审维度 | 当前水平 | v4 后水平 | 一等奖要求 |
|:---|:---|:---|:---|
| **技术创新** | LLM+多Agent | +知识图谱+OPA | ✅ 达到 |
| **工程完整度** | Agent+Skill | +策略引擎+前后端联动 | ✅ 达到 |
| **实验验证** | 4 CVE | 10+ CVE + Token 统计 | ✅ 达到 |
| **文档质量** | README + 报告 | +架构图+API文档 | ✅ 达到 |
| **团队分工** | 1 人主力 | 3 人有代码贡献 | ⚠️ 需确保 |
| **演示效果** | 前端静态 | 前后端联动实时demo | ✅ 达到 |

---

## 五、执行排期

| 日期 | 任务 | 负责人 |
|:---|:---|:---|
| **3.9 今天** | 测试集扩充 + 知识图谱集成 Intel Agent | 金韩溢 |
| **3.10-11** | OPA 策略引擎基础实现 | 金韩溢 |
| **3.12-13** | FastAPI 后端 + 前端接真实数据 | 金韩溢 |
| **3.14-15** | Token 统计 + Baseline 报告更新 | 金韩溢 |
| **3.16-18** | 整合测试 + 文档收尾 | 全体 |

---

## 六、v3 → v4 变更总结

| # | v3 | v4 | 核心价值 |
|:---|:---|:---|:---|
| 1 | 4 CVE 测试集 | 10+ CVE (5 种生态) | 统计说服力 |
| 2 | BRON 独立模块 | 集成到 Intel Agent | 架构完整 |
| 3 | 无策略引擎 | OPA Rego 基础版 | 创新深度 |
| 4 | 前端硬编码 | FastAPI + 实时数据 | 工程完整度 |
| 5 | 无 Token 分析 | 有完整成本数据 | 经济性论证 |
