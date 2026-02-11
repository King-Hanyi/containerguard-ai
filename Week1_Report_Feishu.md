## 四、项目记录区

### Week 1 进度记录 (2025.2.9 - 2.15)

**当前阶段**: 阶段一：基础框架与技能构建 (2.9 - 2.22)
**记录人**: 金韩溢 (组长)
**整体状态**: 🟢 正常推进

#### 1. 阶段一目标完成度 (金韩溢部分)

| 任务项 | 计划目标 | 当前状态 | 备注 |
| :--- | :--- | :--- | :--- |
| **1** | **部署并跑通 Blueprint 原始流程** | ✅ **已完成** | 环境搭建完毕，Demo 运行成功，分析报告已生成 |
| **2** | **设计 Skills 插件化框架** | 🔄 **进行中** | 已完成前期调研，下周进入编码设计 |
| **3** | **开发 Intel/Config Skills** | 📅 **待开始** | 计划于 Week 2 后半段执行 |

#### 2. 本周详细产出 (Week 1)

**A. 基础设施 (Infrastructure)**
-   **环境**: Python 3.12 + uv + NVIDIA NAT 框架本地化部署完成。
-   **仓库**: 建立 [ContainerGuard AI](https://github.com/King-Hanyi/containerguard-ai) 独立仓库，完成代码迁移与历史清洗。
-   **配置**: 实现了适配 Windows 的 `config-local.yml` 及环境变量配置。

**B. 问题攻关 (Troubleshooting)**
-   [x] **SBOM 解析修复**: 修正了 `cve_process_sbom.py` 中对 BOM 头的处理，解决了依赖识别为空的 Critical Bug。
-   [x] **Windows 路径适配**: 解决了 Git Clone 路径过长导致 VDB 构建失败的问题。
-   [x] **网络稳定性**: 优化 LLM 并发策略，从默认 3 并发降为 1，确保 API 调用稳定。

#### 3. 下周计划 (Week 2: 2.16 - 2.22)

-   **核心目标**: 完成任务项 2 & 3 (Skills 框架与首批 Skill 实现)。
-   **具体行动**:
    1.  定义 `BaseSkill` 抽象基类与接口规范。
    2.  实现 `SkillRegistry` 注册机制。
    3.  重构 `cve_fetch_intel` 为独立 Skill。
    4.  重构 `cve_process_sbom` 为独立 Skill。

#### 4. 团队协同 (需同步)
-   **卢周全**: 需确认 BRON 数据集下载与 FAISS/BM25 检索模块进度。
-   **邓一凡**: 需确认 Log4j/Spring4Shell 测试镜像准备情况。
