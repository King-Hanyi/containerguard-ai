#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ContainerGuard AI — 项目进度自动检查助手

运行方式:
    uv run python scripts/check_progress.py

功能:
    1. 扫描代码模块完成度（Skills / Knowledge / Report / Tests）
    2. 运行单元测试
    3. 分析 Git 提交历史
    4. 对照项目计划生成进度报告
"""

import os
import sys
import subprocess
import json
from datetime import datetime, timedelta
from pathlib import Path

# ============================================================
# 配置：项目计划里程碑
# ============================================================
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src" / "vuln_analysis"

MILESTONES = {
    "阶段一: 基础框架与技能构建 (2.9 - 2.22)": {
        "金韩溢": [
            {"task": "环境搭建 + Blueprint 跑通", "check": lambda: _check_file_exists(SRC_DIR / "configs" / "config-local.yml")},
            {"task": "BaseSkill 抽象基类", "check": lambda: _check_file_has_class(SRC_DIR / "skills" / "base.py", "BaseSkill")},
            {"task": "SkillRegistry 注册机制", "check": lambda: _check_file_has_content(SRC_DIR / "skills" / "registry.py", "register_skill")},
            {"task": "IntelSkill 情报检索", "check": lambda: _check_file_has_class(SRC_DIR / "skills" / "intel.py", "IntelSkill")},
            {"task": "ConfigSkill SBOM 解析", "check": lambda: _check_file_has_class(SRC_DIR / "skills" / "config.py", "ConfigSkill")},
            {"task": "RemoteCodeSkill 远程代码", "check": lambda: _check_file_has_class(SRC_DIR / "skills" / "remote_code.py", "RemoteCodeSkill")},
            {"task": "单元测试", "check": lambda: _check_file_exists(PROJECT_ROOT / "tests" / "test_skills.py")},
        ],
        "卢周全": [
            {"task": "BRON 数据集下载", "check": lambda: _check_dir_exists(SRC_DIR / "knowledge")},
            {"task": "BRONLoader 实现", "check": lambda: _check_file_has_class(SRC_DIR / "knowledge" / "bron_loader.py", "BRONLoader")},
            {"task": "KnowledgeGraph 接口", "check": lambda: _check_file_has_class(SRC_DIR / "knowledge" / "knowledge_graph.py", "KnowledgeGraph")},
        ],
    },
    "阶段二: 多智能体系统开发 (2.23 - 3.8)": {
        "金韩溢": [
            {"task": "Supervisor Agent 状态机", "check": lambda: _check_file_has_content(SRC_DIR / "agents" / "supervisor.py", "build_supervisor_graph")},
            {"task": "Intel Agent", "check": lambda: _check_file_has_content(SRC_DIR / "agents" / "intel_agent.py", "intel_agent_node")},
            {"task": "Code Agent", "check": lambda: _check_file_has_content(SRC_DIR / "agents" / "code_agent.py", "code_agent_node")},
            {"task": "Config Agent", "check": lambda: _check_file_has_content(SRC_DIR / "agents" / "config_agent.py", "config_agent_node")},
            {"task": "VEX Agent", "check": lambda: _check_file_has_content(SRC_DIR / "agents" / "vex_agent.py", "vex_agent_node")},
        ],
        "卢周全": [
            {"task": "BM25 稀疏检索", "check": lambda: _check_file_has_class(SRC_DIR / "tools" / "bm25_search.py", "BM25Searcher")},
            {"task": "图检索模块", "check": lambda: _check_file_has_class(SRC_DIR / "tools" / "graph_search.py", "GraphSearcher")},
            {"task": "混合检索融合", "check": lambda: _check_file_has_class(SRC_DIR / "tools" / "hybrid_search.py", "HybridSearcher")},
            {"task": "报告生成模块", "check": lambda: _check_dir_exists(SRC_DIR / "report")},
        ],
        "邓一凡": [
            {"task": "Log4j 测试输入", "check": lambda: _check_file_exists(SRC_DIR / "data" / "input_messages" / "log4j_vulnerable.json")},
            {"task": "Spring4Shell 测试输入", "check": lambda: _check_file_exists(SRC_DIR / "data" / "input_messages" / "spring4shell_vulnerable.json")},
            {"task": "Heartbleed 测试输入", "check": lambda: _check_file_exists(SRC_DIR / "data" / "input_messages" / "heartbleed_vulnerable.json")},
            {"task": "测试用例表", "check": lambda: _check_file_exists(PROJECT_ROOT / "tests" / "test_cases.md")},
        ],
    },
    "阶段三: CI/CD 集成与测试 (3.9 - 3.22)": {
        "金韩溢": [
            {"task": "GitHub Action 插件", "check": lambda: _check_file_has_content(PROJECT_ROOT / ".github" / "workflows" / "containerguard.yml", "containerguard")},
            {"task": "Streamlit Dashboard", "check": lambda: _check_file_exists(PROJECT_ROOT / "dashboard" / "app.py")},
        ],
        "卢周全": [
            {"task": "PR 报告输出模块", "check": lambda: _check_file_has_content(SRC_DIR / "report" / "pr_comment.py", "PRComment")},
        ],
        "邓一凡": [
            {"task": "端到端测试执行记录", "check": lambda: _check_file_has_content(PROJECT_ROOT / "tests" / "test_cases.md", "实际结果")},
        ],
    },
    "阶段四: 策略门禁与最终交付 (3.23 - 4.5)": {
        "金韩溢": [
            {"task": "OPA 策略引擎", "check": lambda: _check_dir_exists(SRC_DIR / "policy")},
        ],
        "卢周全": [
            {"task": "技术文档 / API 文档", "check": lambda: _check_file_exists(PROJECT_ROOT / "docs" / "API文档.md")},
        ],
        "邓一凡": [
            {"task": "最终测试报告", "check": lambda: _check_file_exists(PROJECT_ROOT / "docs" / "测试报告.md")},
        ],
    },
}


# ============================================================
# 检查函数
# ============================================================
def _check_file_exists(path: Path) -> bool:
    return path.exists()

def _check_dir_exists(path: Path) -> bool:
    return path.is_dir() and any(path.iterdir()) if path.is_dir() else False

def _check_file_has_class(path: Path, class_name: str) -> bool:
    if not path.exists():
        return False
    content = path.read_text(encoding="utf-8", errors="ignore")
    return f"class {class_name}" in content

def _check_file_has_content(path: Path, keyword: str) -> bool:
    if not path.exists():
        return False
    content = path.read_text(encoding="utf-8", errors="ignore")
    return keyword in content


# ============================================================
# 核心逻辑
# ============================================================
def check_milestones():
    """扫描所有里程碑任务的完成状态。"""
    results = {}
    for phase, members in MILESTONES.items():
        results[phase] = {}
        for member, tasks in members.items():
            member_results = []
            for task in tasks:
                done = task["check"]()
                member_results.append({"task": task["task"], "done": done})
            results[phase][member] = member_results
    return results


def run_tests():
    """运行单元测试并返回结果。"""
    test_file = PROJECT_ROOT / "tests" / "test_skills.py"
    if not test_file.exists():
        return {"status": "未找到", "passed": 0, "failed": 0, "total": 0}

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_file), "-v", "--tb=no", "-q"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT), encoding="utf-8", errors="replace", timeout=60
        )
        output = result.stdout + result.stderr
        # 解析结果
        passed = output.count(" PASSED")
        failed = output.count(" FAILED")
        return {
            "status": "通过" if failed == 0 else "有失败",
            "passed": passed,
            "failed": failed,
            "total": passed + failed,
        }
    except Exception as e:
        return {"status": f"运行失败: {e}", "passed": 0, "failed": 0, "total": 0}


def get_git_stats():
    """读取 Git 统计信息。"""
    stats = {}
    try:
        # 最近提交
        result = subprocess.run(
            ["git", "log", "--oneline", "-5", "--format=%h %s (%ar)"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT), encoding="utf-8", errors="replace"
        )
        stats["recent_commits"] = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]

        # 总提交数
        result = subprocess.run(
            ["git", "rev-list", "--count", "HEAD"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT), encoding="utf-8", errors="replace"
        )
        stats["total_commits"] = int(result.stdout.strip())

        # 贡献者
        result = subprocess.run(
            ["git", "shortlog", "-sn", "--all"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT), encoding="utf-8", errors="replace"
        )
        stats["contributors"] = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]

        # 未提交的更改
        result = subprocess.run(
            ["git", "status", "--short"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT), encoding="utf-8", errors="replace"
        )
        uncommitted = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
        stats["uncommitted_files"] = len(uncommitted)

    except Exception as e:
        stats["error"] = str(e)

    return stats


def count_code_stats():
    """统计代码行数。"""
    stats = {"py_files": 0, "py_lines": 0, "test_files": 0, "test_lines": 0}
    
    for py_file in SRC_DIR.rglob("*.py"):
        stats["py_files"] += 1
        stats["py_lines"] += len(py_file.read_text(encoding="utf-8", errors="ignore").splitlines())
    
    tests_dir = PROJECT_ROOT / "tests"
    if tests_dir.exists():
        for py_file in tests_dir.rglob("*.py"):
            stats["test_files"] += 1
            stats["test_lines"] += len(py_file.read_text(encoding="utf-8", errors="ignore").splitlines())

    return stats


# ============================================================
# 报告生成
# ============================================================
def generate_report():
    """生成完整的进度检查报告。"""
    # Windows 终端默认 GBK，强制 UTF-8
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    
    print("=" * 60)
    print(f"  ContainerGuard AI — 项目进度自动检查报告")
    print(f"  生成时间: {now}")
    print("=" * 60)

    # 1. 里程碑检查
    print("\n📋 里程碑完成度")
    print("-" * 60)
    
    milestone_results = check_milestones()
    total_done = 0
    total_tasks = 0
    
    for phase, members in milestone_results.items():
        phase_done = sum(1 for m in members.values() for t in m if t["done"])
        phase_total = sum(len(m) for m in members.values())
        total_done += phase_done
        total_tasks += phase_total
        pct = int(phase_done / phase_total * 100) if phase_total else 0
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        
        print(f"\n  {phase}")
        print(f"  {bar} {pct}% ({phase_done}/{phase_total})")
        
        for member, tasks in members.items():
            member_done = sum(1 for t in tasks if t["done"])
            print(f"    {member}: {member_done}/{len(tasks)} 完成")
            for t in tasks:
                icon = "✅" if t["done"] else "❌"
                print(f"      {icon} {t['task']}")

    overall_pct = int(total_done / total_tasks * 100) if total_tasks else 0
    print(f"\n  📊 总体进度: {total_done}/{total_tasks} ({overall_pct}%)")

    # 2. 测试状态
    print("\n🧪 单元测试")
    print("-" * 60)
    test_results = run_tests()
    status_icon = "✅" if test_results["status"] == "通过" else "❌"
    print(f"  {status_icon} 状态: {test_results['status']}")
    print(f"     通过: {test_results['passed']}  失败: {test_results['failed']}  总计: {test_results['total']}")

    # 3. 代码统计
    print("\n📏 代码统计")
    print("-" * 60)
    code_stats = count_code_stats()
    print(f"  源码文件: {code_stats['py_files']} 个, {code_stats['py_lines']} 行")
    print(f"  测试文件: {code_stats['test_files']} 个, {code_stats['test_lines']} 行")

    # 4. Git 状态
    print("\n🔀 Git 状态")
    print("-" * 60)
    git_stats = get_git_stats()
    if "error" not in git_stats:
        print(f"  总提交: {git_stats['total_commits']} 次")
        print(f"  未提交文件: {git_stats['uncommitted_files']} 个")
        print(f"  贡献者:")
        for c in git_stats.get("contributors", []):
            print(f"    {c}")
        print(f"  最近提交:")
        for c in git_stats.get("recent_commits", []):
            print(f"    {c}")
    else:
        print(f"  ⚠️ Git 读取失败: {git_stats['error']}")

    # 5. 下一步建议
    print("\n💡 建议")
    print("-" * 60)
    
    suggestions = []
    for phase, members in milestone_results.items():
        for member, tasks in members.items():
            for t in tasks:
                if not t["done"]:
                    suggestions.append(f"{member} → {t['task']}")
    
    if suggestions:
        print("  待完成的最近任务:")
        for i, s in enumerate(suggestions[:5], 1):
            print(f"    {i}. {s}")
    else:
        print("  🎉 所有任务已完成！")

    print("\n" + "=" * 60)
    print("  检查完毕")
    print("=" * 60)


if __name__ == "__main__":
    generate_report()
