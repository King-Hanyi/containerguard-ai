# ContainerGuard AI — 测试用例映射表

> 作者: 邓一凡 | 更新日期: 2026-03-10

## 一、漏洞判定测试

| # | CVE ID | 输入文件 | SBOM 关键包 | 期望判定 | 期望置信度 | 实际判定 | 实际置信度 | 通过 |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| 1 | CVE-2021-44228 | log4j_vulnerable.json | log4j-core 2.14.1 | affected | ≥ 80% | affected | 90% | ✅ |
| 2 | CVE-2022-22965 | spring4shell_vulnerable.json | spring-beans 5.3.17 | affected | ≥ 80% | affected | 90% | ✅ |
| 3 | CVE-2014-0160 | heartbleed_vulnerable.json | openssl 1.0.1 | affected | ≥ 80% | affected | 90% | ✅ |
| 4 | CVE-2023-36632 | morpheus_23.11-runtime.json | — | not_affected | ≥ 70% | not_affected | 70% | ✅ |
| 5 | CVE-2023-32681 | morpheus_23.11-runtime.json | — | not_affected | ≥ 70% | not_affected | 70% | ✅ |
| 6 | CVE-2021-44228 | morpheus_23.11-runtime.json | log4j-core 2.14.0 | affected | ≥ 80% | affected | 90% | ✅ |
| 7 | CVE-2022-42889 | morpheus_23.11-runtime.json | commons-text 1.9 | affected | ≥ 80% | affected | 90% | ✅ |
| 8 | CVE-2017-5638 | morpheus_23.11-runtime.json | struts2-core 2.3.31 | affected | ≥ 80% | affected | 90% | ✅ |

## 二、Agent 功能测试

| # | 测试项 | 输入 | 期望输出 | 实际结果 | 通过 |
|:---|:---|:---|:---|:---|:---|
| A1 | Intel Agent 情报收集 | CVE-2021-44228 | 返回 severity=critical, CVSS=10.0 | 成功获取严重等级 (critical) 与 CVSS 评分 | ✅ |
| A2 | Config Agent SBOM 解析 | log4j SBOM | 找到 log4j-core 2.14.1 | 成功解析并提取到目标依赖包 log4j-core | ✅ |
| A3 | Config Agent 版本比较 | log4j-core 2.14.1 vs < 2.17.0 | vulnerable=True | 版本比较通过，准确识别为脆弱版本 | ✅ |
| A4 | Code Agent 代码搜索 | "JndiLookup" 关键词 | 搜索命中 | 成功命中相关代码及调用链 (本地模式表匹配) | ✅ |
| A5 | VEX Agent LLM 推理 | 全部证据 → Checklist | affected, conf ≥ 0.8 | 成功综合推理，输出 affected, conf=0.9 | ✅ |

## 三、系统集成测试

| # | 测试项 | 命令 | 期望 | 实际 | 通过 |
|:---|:---|:---|:---|:---|:---|
| S1 | Baseline 扫描 | `uv run python scripts/run_baseline.py` | 10 CVE 全部有判定 | 成功扫描，准确率 100%，生成 baseline_results.json | ✅ |
| S2 | Demo 运行 | `uv run python scripts/demo_agents.py` | 完整输出，无报错 | Supervisor 调度正常，各 Agent 协同无报错 | ✅ |
| S3 | API 服务器 | `uv run python scripts/api_server.py` | 启动成功，4 个 API 正常 | Uvicorn 服务器正常启动，监听 8090 端口 | ✅ |
| S4 | 报告导出 | 浏览器访问报告页 | MD/HTML 文件下载成功 | 成功通过 API 下载 MD 格式多智能体分析报告 | ✅ |
| S5 | pytest 全部通过 | `uv run python -m pytest tests/ -v` | 43/43 passed | 43/43 tests passed，耗时 3.56s | ✅ |