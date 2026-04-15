#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ContainerGuard AI — OPA 策略引擎单元测试。

验证:
1. OPAEngine 初始化和默认策略
2. block / warn / pass / manual_review 四种决策路径
3. summary 摘要输出
4. print_report 报告生成
"""

import pytest

from vuln_analysis.policy import OPAEngine, PolicyRule, PolicyDecision, DEFAULT_POLICIES
from vuln_analysis.agents.state import VEXJudgment, IntelResult


# ============================================================
# 辅助函数
# ============================================================
def _make_vex(cve_id: str, status: str = "affected", confidence: float = 0.9) -> VEXJudgment:
    return VEXJudgment(cve_id=cve_id, status=status, confidence=confidence)


def _make_intel(cve_id: str, severity: str = "high") -> IntelResult:
    return IntelResult(cve_id=cve_id, severity=severity)


# ============================================================
# TestOPAEngine: 策略引擎测试
# ============================================================
class TestOPAEngine:

    def test_init_default_policies(self):
        engine = OPAEngine()
        assert len(engine.policies) == len(DEFAULT_POLICIES)

    def test_init_custom_policies(self):
        custom = [PolicyRule(
            name="test", description="test", severity="any",
            status="any", min_confidence=0.0, action="pass",
        )]
        engine = OPAEngine(policies=custom)
        assert len(engine.policies) == 1

    def test_block_critical_affected(self):
        """critical + affected → block"""
        engine = OPAEngine()
        vex = {"CVE-1": _make_vex("CVE-1", "affected", 0.95)}
        intel = {"CVE-1": _make_intel("CVE-1", "critical")}
        decisions = engine.evaluate(vex, intel)
        assert len(decisions) == 1
        assert decisions[0].action == "block"
        assert decisions[0].matched_rule == "block_critical_affected"

    def test_warn_high_affected(self):
        """high + affected → warn"""
        engine = OPAEngine()
        vex = {"CVE-1": _make_vex("CVE-1", "affected", 0.85)}
        intel = {"CVE-1": _make_intel("CVE-1", "high")}
        decisions = engine.evaluate(vex, intel)
        assert len(decisions) == 1
        assert decisions[0].action == "warn"
        assert decisions[0].matched_rule == "warn_high_affected"

    def test_pass_not_affected(self):
        """not_affected → pass"""
        engine = OPAEngine()
        vex = {"CVE-1": _make_vex("CVE-1", "not_affected", 0.80)}
        intel = {"CVE-1": _make_intel("CVE-1", "critical")}
        decisions = engine.evaluate(vex, intel)
        assert len(decisions) == 1
        assert decisions[0].action == "pass"
        assert decisions[0].matched_rule == "pass_not_affected"

    def test_manual_review_low_confidence(self):
        """confidence < 0.5 → manual_review"""
        engine = OPAEngine()
        vex = {"CVE-1": _make_vex("CVE-1", "affected", 0.30)}
        intel = {"CVE-1": _make_intel("CVE-1", "critical")}
        decisions = engine.evaluate(vex, intel)
        assert len(decisions) == 1
        assert decisions[0].action == "manual_review"

    def test_medium_affected_passes(self):
        """medium + affected → pass (默认策略只有 critical/high 对应 block/warn)"""
        engine = OPAEngine()
        vex = {"CVE-1": _make_vex("CVE-1", "affected", 0.80)}
        intel = {"CVE-1": _make_intel("CVE-1", "medium")}
        decisions = engine.evaluate(vex, intel)
        assert len(decisions) == 1
        assert decisions[0].action == "pass"

    def test_multiple_cves(self):
        """多 CVE 混合场景"""
        engine = OPAEngine()
        vex = {
            "CVE-1": _make_vex("CVE-1", "affected", 0.95),
            "CVE-2": _make_vex("CVE-2", "not_affected", 0.85),
            "CVE-3": _make_vex("CVE-3", "affected", 0.30),
        }
        intel = {
            "CVE-1": _make_intel("CVE-1", "critical"),
            "CVE-2": _make_intel("CVE-2", "high"),
            "CVE-3": _make_intel("CVE-3", "high"),
        }
        decisions = engine.evaluate(vex, intel)
        assert len(decisions) == 3

        by_cve = {d.cve_id: d for d in decisions}
        assert by_cve["CVE-1"].action == "block"
        assert by_cve["CVE-2"].action == "pass"
        assert by_cve["CVE-3"].action == "manual_review"


class TestOPAHelpers:

    def test_get_blocked(self):
        engine = OPAEngine()
        decisions = [
            PolicyDecision(cve_id="CVE-1", action="block", matched_rule="r1", reason="test"),
            PolicyDecision(cve_id="CVE-2", action="pass", matched_rule="r2", reason="test"),
        ]
        blocked = engine.get_blocked(decisions)
        assert len(blocked) == 1
        assert blocked[0].cve_id == "CVE-1"

    def test_get_warnings(self):
        engine = OPAEngine()
        decisions = [
            PolicyDecision(cve_id="CVE-1", action="warn", matched_rule="r1", reason="test"),
            PolicyDecision(cve_id="CVE-2", action="pass", matched_rule="r2", reason="test"),
        ]
        assert len(engine.get_warnings(decisions)) == 1

    def test_get_review(self):
        engine = OPAEngine()
        decisions = [
            PolicyDecision(cve_id="CVE-1", action="manual_review", matched_rule="r1", reason="test"),
        ]
        assert len(engine.get_review(decisions)) == 1


class TestOPASummaryReport:

    def test_summary(self):
        engine = OPAEngine()
        decisions = [
            PolicyDecision(cve_id="CVE-1", action="block", matched_rule="r1", reason="test"),
            PolicyDecision(cve_id="CVE-2", action="warn", matched_rule="r2", reason="test"),
            PolicyDecision(cve_id="CVE-3", action="pass", matched_rule="r3", reason="test"),
        ]
        s = engine.summary(decisions)
        assert s["gate_result"] == "BLOCKED"
        assert s["total"] == 3
        assert s["blocked"] == 1
        assert s["warnings"] == 1
        assert s["passed"] == 1

    def test_summary_all_pass(self):
        engine = OPAEngine()
        decisions = [
            PolicyDecision(cve_id="CVE-1", action="pass", matched_rule="r1", reason="test"),
        ]
        s = engine.summary(decisions)
        assert s["gate_result"] == "PASSED"

    def test_print_report(self):
        engine = OPAEngine()
        decisions = [
            PolicyDecision(cve_id="CVE-1", action="block", matched_rule="r1", reason="critical", severity="critical", confidence=0.95),
        ]
        report = engine.print_report(decisions)
        assert "CVE-1" in report
        assert "BLOCK" in report
        assert "BLOCKED" in report
