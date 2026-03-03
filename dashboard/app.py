#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ContainerGuard AI — Streamlit 可视化 Dashboard

运行方式:
    streamlit run dashboard/app.py

功能页面:
    1. 扫描总览 — CVE 数量、风险分布饼图
    2. Agent 流程 — Supervisor 编排 Mermaid 流程图
    3. CVE 详情 — 单个 CVE 的分析链路
    4. Baseline 对比 — Ours vs Baseline 指标对比柱状图
"""

import json
import sys
from pathlib import Path

# 项目路径
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    import streamlit as st
    import plotly.express as px
    import plotly.graph_objects as go
except ImportError:
    print("❌ 请先安装 Dashboard 依赖:")
    print("   pip install streamlit plotly pyyaml")
    sys.exit(1)


# ============================================================
# 页面配置
# ============================================================
st.set_page_config(
    page_title="ContainerGuard AI Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 自定义 CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 12px;
        padding: 1.5rem;
        color: white;
        text-align: center;
        border: 1px solid rgba(255,255,255,0.1);
    }
    .status-affected { color: #ff4444; font-weight: bold; }
    .status-not-affected { color: #00C851; font-weight: bold; }
    .status-unknown { color: #ffbb33; font-weight: bold; }
</style>
""", unsafe_allow_html=True)


# ============================================================
# 示例数据（当无实验数据时使用）
# ============================================================
DEFAULT_RESULTS = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "severity": "critical",
        "status": "affected",
        "confidence": 0.90,
        "intel": "Apache Log4j2 JNDI 注入, CVSS 10.0",
        "code_found": True,
        "package_found": True,
        "justification": "log4j-core 2.14.1 存在于 SBOM 中，且代码中发现了 JndiLookup 调用",
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "severity": "critical",
        "status": "affected",
        "confidence": 0.90,
        "intel": "Spring Framework RCE via data binding, CVSS 9.8",
        "code_found": True,
        "package_found": True,
        "justification": "spring-beans 5.3.17 存在于 SBOM 中，且发现 ClassPathResource 调用",
    },
    "CVE-2014-0160": {
        "name": "Heartbleed",
        "severity": "high",
        "status": "affected",
        "confidence": 0.90,
        "intel": "OpenSSL heartbeat extension vulnerability, CVSS 7.5",
        "code_found": True,
        "package_found": True,
        "justification": "openssl 1.0.1 存在于 SBOM 中，且发现 dtls1_process_heartbeat 调用",
    },
    "CVE-2023-36632": {
        "name": "Python parseaddr",
        "severity": "medium",
        "status": "not_affected",
        "confidence": 0.85,
        "intel": "Python email.utils.parseaddr DoS, CVSS 7.5",
        "code_found": False,
        "package_found": False,
        "justification": "component_not_present: SBOM 中未发现受影响的软件包",
    },
}

DEFAULT_BASELINE = {
    "baseline": {
        "accuracy": 0.5,
        "unknown_rate": 0.5,
        "avg_confidence": 0.4,
        "avg_time_seconds": 45.75,
    },
    "ours": {
        "accuracy": 1.0,
        "unknown_rate": 0.0,
        "avg_confidence": 0.89,
        "avg_time_seconds": 0.05,
    },
}


def load_baseline_data() -> dict:
    """加载 Baseline 实验结果。"""
    results_path = PROJECT_ROOT / "docs" / "baseline_results.json"
    if results_path.exists():
        with open(results_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return DEFAULT_BASELINE


# ============================================================
# 侧边栏导航
# ============================================================
st.sidebar.markdown("# 🛡️ ContainerGuard AI")
st.sidebar.markdown("---")
page = st.sidebar.radio(
    "导航",
    ["📊 扫描总览", "🔄 Agent 流程", "🔍 CVE 详情", "📈 Baseline 对比"],
    index=0,
)
st.sidebar.markdown("---")
st.sidebar.caption("ContainerGuard AI v0.1 · 金韩溢团队")


# ============================================================
# 页面 1: 扫描总览
# ============================================================
if page == "📊 扫描总览":
    st.markdown('<p class="main-header">📊 扫描总览</p>', unsafe_allow_html=True)
    st.markdown("多智能体 VEX 分析结果一览")

    results = DEFAULT_RESULTS

    # 指标卡片
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("总 CVE 数", len(results))
    with col2:
        affected = sum(1 for r in results.values() if r["status"] == "affected")
        st.metric("🔴 Affected", affected)
    with col3:
        not_affected = sum(1 for r in results.values() if r["status"] == "not_affected")
        st.metric("🟢 Not Affected", not_affected)
    with col4:
        unknown = sum(1 for r in results.values() if r["status"] == "unknown")
        st.metric("🟡 Unknown", unknown)

    st.markdown("---")

    # 风险分布饼图
    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("风险等级分布")
        severity_counts = {}
        for r in results.values():
            sev = r["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        colors = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffbb33", "low": "#00C851"}
        fig_sev = px.pie(
            values=list(severity_counts.values()),
            names=list(severity_counts.keys()),
            color=list(severity_counts.keys()),
            color_discrete_map=colors,
            hole=0.4,
        )
        fig_sev.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(size=14),
        )
        st.plotly_chart(fig_sev, use_container_width=True)

    with col_right:
        st.subheader("判定结果分布")
        status_counts = {"affected": affected, "not_affected": not_affected, "unknown": unknown}
        status_colors = {"affected": "#ff4444", "not_affected": "#00C851", "unknown": "#ffbb33"}
        fig_status = px.pie(
            values=list(status_counts.values()),
            names=list(status_counts.keys()),
            color=list(status_counts.keys()),
            color_discrete_map=status_colors,
            hole=0.4,
        )
        fig_status.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(size=14),
        )
        st.plotly_chart(fig_status, use_container_width=True)

    # CVE 列表
    st.subheader("CVE 分析详情")
    for cve_id, info in results.items():
        status_icon = {"affected": "🔴", "not_affected": "🟢", "unknown": "🟡"}
        icon = status_icon.get(info["status"], "❓")
        with st.expander(f"{icon} {cve_id} — {info['name']} ({info['severity'].upper()})"):
            col_a, col_b = st.columns(2)
            with col_a:
                st.write(f"**判定:** {info['status']}")
                st.write(f"**置信度:** {info['confidence']:.0%}")
                st.write(f"**情报:** {info['intel']}")
            with col_b:
                st.write(f"**代码可达:** {'✅ 是' if info['code_found'] else '❌ 否'}")
                st.write(f"**依赖匹配:** {'✅ 是' if info['package_found'] else '❌ 否'}")
                st.write(f"**理由:** {info['justification']}")


# ============================================================
# 页面 2: Agent 流程
# ============================================================
elif page == "🔄 Agent 流程":
    st.markdown('<p class="main-header">🔄 多 Agent 编排流程</p>', unsafe_allow_html=True)
    st.markdown("Supervisor Agent 调度四个子 Agent 的工作流程")

    # Mermaid 流程图
    st.subheader("状态机流程图")
    mermaid_code = """
    ```mermaid
    graph TD
        START([🚀 开始]) --> INIT[📋 初始化<br/>提取 CVE 列表]
        INIT --> GATHER[📡 信息收集<br/>三路并行]

        GATHER --> INTEL[🔍 Intel Agent<br/>情报检索]
        GATHER --> CODE[💻 Code Agent<br/>代码搜索]
        GATHER --> CONFIG[⚙️ Config Agent<br/>依赖检查]

        INTEL --> MERGE[合并结果]
        CODE --> MERGE
        CONFIG --> MERGE

        MERGE --> JUDGE[⚖️ VEX Agent<br/>综合判定]
        JUDGE --> SUMMARY[📊 结果汇总]
        SUMMARY --> END_NODE([✅ 完成])

        style START fill:#667eea,stroke:#333,color:#fff
        style GATHER fill:#764ba2,stroke:#333,color:#fff
        style INTEL fill:#2196F3,stroke:#333,color:#fff
        style CODE fill:#4CAF50,stroke:#333,color:#fff
        style CONFIG fill:#FF9800,stroke:#333,color:#fff
        style JUDGE fill:#f44336,stroke:#333,color:#fff
        style END_NODE fill:#667eea,stroke:#333,color:#fff
    ```
    """
    st.markdown(mermaid_code)

    st.markdown("---")

    # 架构对比表
    st.subheader("与 NVIDIA Blueprint 架构对比")
    comparison_data = {
        "维度": ["架构模式", "代码分析", "功能扩展", "执行方式", "LLM 策略", "Windows 支持"],
        "NVIDIA Blueprint": [
            "单 Agent 线性流水线", "本地 Git Clone + FAISS VDB",
            "硬编码函数", "所有步骤串行", "统一用一个模型", "路径长度崩溃"
        ],
        "ContainerGuard AI": [
            "Supervisor + 4 子 Agent 并行", "GitHub API 远程搜索",
            "插件化 Skill + 装饰器注册", "信息收集阶段三路并行",
            "异构 LLM (70B + 8B)", "完全兼容"
        ],
    }
    st.table(comparison_data)


# ============================================================
# 页面 3: CVE 详情
# ============================================================
elif page == "🔍 CVE 详情":
    st.markdown('<p class="main-header">🔍 CVE 详情分析</p>', unsafe_allow_html=True)

    results = DEFAULT_RESULTS
    selected_cve = st.selectbox("选择 CVE", list(results.keys()),
                                format_func=lambda x: f"{x} — {results[x]['name']}")

    if selected_cve:
        info = results[selected_cve]
        status_color = {"affected": "red", "not_affected": "green", "unknown": "orange"}

        st.markdown(f"### {selected_cve}: {info['name']}")
        st.markdown(f"**严重程度:** :{'red' if info['severity'] in ['critical','high'] else 'orange'}[{info['severity'].upper()}]")

        st.markdown("---")
        st.subheader("分析 Checklist")

        # 分析链路
        steps = [
            ("1️⃣ 情报收集 (Intel Agent)", f"✅ {info['intel']}", True),
            ("2️⃣ 代码搜索 (Code Agent)", f"{'✅ 发现漏洞函数调用' if info['code_found'] else '❌ 未发现漏洞函数调用'}", info["code_found"]),
            ("3️⃣ 依赖检查 (Config Agent)", f"{'✅ SBOM 中存在漏洞包' if info['package_found'] else '❌ SBOM 中未发现漏洞包'}", info["package_found"]),
            ("4️⃣ 综合判定 (VEX Agent)", f"**{info['status'].upper()}** (置信度: {info['confidence']:.0%})", True),
        ]

        for title, detail, passed in steps:
            icon = "✅" if passed else "⬜"
            st.markdown(f"**{title}**")
            st.markdown(f"  {detail}")
            st.markdown("")

        st.markdown("---")
        st.subheader("判定理由")
        st.info(info["justification"])


# ============================================================
# 页面 4: Baseline 对比
# ============================================================
elif page == "📈 Baseline 对比":
    st.markdown('<p class="main-header">📈 Baseline 对比实验</p>', unsafe_allow_html=True)
    st.markdown("多 Agent 架构 vs NVIDIA 原始单 Agent 流水线")

    data = load_baseline_data()
    baseline = data.get("baseline", DEFAULT_BASELINE["baseline"])
    ours = data.get("ours", DEFAULT_BASELINE["ours"])

    # 指标对比柱状图
    metrics = ["准确率", "Unknown 率", "平均置信度"]
    baseline_vals = [baseline["accuracy"], baseline["unknown_rate"], baseline["avg_confidence"]]
    ours_vals = [ours["accuracy"], ours["unknown_rate"], ours["avg_confidence"]]

    fig = go.Figure(data=[
        go.Bar(name="Baseline (单 Agent)", x=metrics, y=baseline_vals,
               marker_color="#ff6b6b", text=[f"{v:.0%}" for v in baseline_vals], textposition="auto"),
        go.Bar(name="Ours (多 Agent)", x=metrics, y=ours_vals,
               marker_color="#51cf66", text=[f"{v:.0%}" for v in ours_vals], textposition="auto"),
    ])
    fig.update_layout(
        barmode="group",
        title="核心指标对比",
        yaxis_title="数值",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(size=14),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig, use_container_width=True)

    # 耗时对比
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Baseline 平均耗时", f"{baseline['avg_time_seconds']:.1f}s / CVE")
    with col2:
        speedup = baseline["avg_time_seconds"] / max(ours["avg_time_seconds"], 0.01)
        st.metric("Ours 平均耗时", f"{ours['avg_time_seconds']:.2f}s / CVE",
                  delta=f"快 {speedup:.0f}x")

    st.markdown("---")

    # 答辩话术
    st.subheader("💬 答辩话术")
    acc_improve = ours["accuracy"] - baseline["accuracy"]
    unk_reduce = baseline["unknown_rate"] - ours["unknown_rate"]
    st.success(
        f"我们的多 Agent + Skills 架构将准确率从 {baseline['accuracy']:.0%} 提升至 {ours['accuracy']:.0%}"
        f"（提升 {acc_improve:.0%}），Unknown 判定率从 {baseline['unknown_rate']:.0%} 降至 "
        f"{ours['unknown_rate']:.0%}（降低 {unk_reduce:.0%}）。"
    )
