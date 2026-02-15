# ContainerGuard AI — 项目创新点与修改记录

> **用途**: 竞赛答辩准备材料。记录本项目相较于 NVIDIA Blueprint 原始框架所做的全部创新与改造。
> **最后更新**: 2026.2.15

---

## 🏆 一、核心创新点

### 创新 1: Skills 插件化架构 (Week 2)

**问题**: NVIDIA Blueprint 的所有分析逻辑（情报获取、SBOM 解析、代码检索等）以硬编码函数形式存在于 `functions/` 目录，耦合度高，无法灵活扩展。

**方案**: 设计了 `BaseSkill` 抽象基类 + `SkillRegistry` 注册机制，将每个分析能力封装为独立的、可配置的 Skill。

**技术亮点**:
- **零侵入兼容**: 通过 `register_skill` 装饰器，一行代码即可将 Skill 注册为 NAT Framework 的标准函数，无需修改框架核心。
- **热插拔设计**: 新增 Skill 只需创建一个 Python 文件，继承 `BaseSkill`，实现 `run()` 方法。不需要修改任何现有代码。
- **类型安全**: 使用 Pydantic 泛型（`BaseSkill[InputT, OutputT, ConfigT]`）保证输入输出类型在编译期即可校验。

**文件**:
- `src/vuln_analysis/skills/base.py` — 抽象基类
- `src/vuln_analysis/skills/registry.py` — 注册机制
- `src/vuln_analysis/skills/__init__.py` — 统一导出

---

### 创新 2: 远程代码检索 Skill (RemoteCodeSkill)

**问题**: NVIDIA Blueprint 依赖本地 Git Clone + FAISS 向量数据库进行代码分析。在 Windows 环境下（路径限制）或 CI/CD 环境中（资源有限），本地 Clone 经常失败，导致 Agent 无法获取代码上下文。

**方案**: 开发 `RemoteCodeSkill`，通过 GitHub Code Search API 直接在远程仓库搜索代码，完全绕过本地 Clone 和 VDB 构建。

**技术亮点**:
- **轻量化**: 无需本地存储代码仓库和向量数据库（原方案需要 GB 级空间）。
- **实时性**: 搜索的是 GitHub 上的最新代码，而非本地 Clone 的快照。
- **跨平台**: 彻底解决 Windows 路径过长（260 字符限制）导致的构建失败问题。
- **可扩展**: 未来可轻松对接 GitLab、Gitee 等其他代码托管平台。

**文件**: `src/vuln_analysis/skills/remote_code.py`

---

### 创新 3: 多智能体协同架构 (规划中, Week 3-4)

**问题**: NVIDIA Blueprint 使用单一 Agent 执行所有分析任务（ReAct 循环），在面对复杂漏洞时容易达到迭代上限或分析不全面。

**方案**: 设计 **Supervisor + Worker Agents** 多智能体系统：
- **Supervisor Agent**: 高智商模型 (70B)，负责任务拆分与结果汇总。
- **Intel Agent**: 专精情报收集，调用 IntelSkill。
- **Code Agent**: 专精代码分析，调用 RemoteCodeSkill。
- **Config Agent**: 专精配置审计，调用 ConfigSkill。
- **VEX Agent**: 专精结论生成与 OpenVEX 输出。

**创新亮点**:
- **异构 LLM 策略**: Supervisor 用大模型保证决策质量，Worker 用小模型 (8B) 降低成本。
- **并行执行**: 多 Agent 可并行工作，大幅缩短分析耗时。

---

## 🔧 二、关键技术修改记录

### 修改 1: SBOM 文件 BOM 头修复

**原始问题**: `cve_process_sbom.py` 使用 `encoding="utf-8"` 读取 SBOM 文件，无法正确解析带 BOM (Byte Order Mark) 头的文件，导致所有依赖包名解析为空。

**修复方案**: 将编码改为 `utf-8-sig`，自动跳过 BOM 头。

```diff
- with open(sbom_info.file_path, "r", encoding="utf-8") as f:
+ with open(sbom_info.file_path, "r", encoding="utf-8-sig") as f:
```

**影响**: 修复后 SBOM 成功识别出 `python 3.10.12` 等关键依赖包，打通了整条数据分析链。

---

### 修改 2: Windows 环境适配

**原始问题**: Blueprint 设计为 Linux/Docker 环境运行，在 Windows 本地开发时存在多个兼容性障碍。

**修复内容**:
| 问题 | 修复方案 |
|:---|:---|
| Git Clone 路径过长 (260 字符限制) | 将 `base_git_dir` 配置为根目录短路径 |
| `.env` 环境变量加载 | 创建 `.env.template` 模板 + 标准化配置流程 |
| 符号链接/冒号文件名 | 使用 `.gitattributes` 过滤问题文件 |

---

### 修改 3: LLM 并发策略优化

**原始问题**: 默认 `llm_max_rate` 为 `None`（无限制），在非专线网络下并发请求导致连接中断。

**修复方案**: 将 `config-local.yml` 中的 `llm_max_rate` 设为 `1`，确保 API 调用稳定。

---

### 修改 4: 项目品牌重塑

**变更**: 将原 NVIDIA Blueprint 仓库完全独立化为 **ContainerGuard AI** 品牌。
- 重写 README.md (全中文)。
- 清除 Git 历史中的所有 NVIDIA 贡献者记录。
- 建立独立 GitHub 仓库: `King-Hanyi/containerguard-ai`。

---

## 📊 三、创新点对照表 (答辩速查)

| 维度 | NVIDIA Blueprint (原始) | ContainerGuard AI (我们) |
|:---|:---|:---|
| **架构** | 单 Agent + 硬编码函数 | 多 Agent + Skills 插件化 |
| **代码分析** | 本地 Git Clone + FAISS VDB | GitHub API 远程检索 (RemoteCodeSkill) |
| **扩展性** | 修改代码才能添加功能 | 继承 BaseSkill 即可扩展 |
| **LLM 策略** | 统一使用同一模型 | 异构 LLM (70B Supervisor + 8B Workers) |
| **知识图谱** | 无 | BRON (CVE→CWE→CAPEC→ATT&CK) |
| **部署** | 仅 Docker | Windows 本地 + Docker + CI/CD |
| **策略引擎** | 无 | OPA Rego 安全门禁 (规划中) |
