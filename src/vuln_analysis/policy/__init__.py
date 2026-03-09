# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
OPA 策略引擎 — 基于 VEX 判定结果的自动化安全门禁。

职责: 根据预定义安全策略，对 VEX 判定结果做 pass/block 决策，
      实现"策略即代码 (Policy as Code)"的 DevSecOps 理念。

支持的策略:
    1. critical + affected → block
    2. high + affected → warn
    3. confidence < 阈值 → manual_review
    4. 自定义策略 (YAML/JSON)
"""

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ============================================================
# 安全策略定义
# ============================================================

@dataclass
class PolicyRule:
    """单条策略规则。"""
    name: str
    description: str
    severity: str           # "critical" / "high" / "any"
    status: str             # "affected" / "not_affected" / "any"
    min_confidence: float   # 置信度阈值
    action: str             # "block" / "warn" / "pass" / "manual_review"


@dataclass
class PolicyDecision:
    """策略引擎对单个 CVE 的决策。"""
    cve_id: str
    action: str             # "block" / "warn" / "pass" / "manual_review"
    matched_rule: str
    reason: str
    severity: str = ""
    confidence: float = 0.0


# 默认安全策略集
DEFAULT_POLICIES = [
    PolicyRule(
        name="block_critical_affected",
        description="Critical 且 Affected 的漏洞必须阻断部署",
        severity="critical",
        status="affected",
        min_confidence=0.5,
        action="block",
    ),
    PolicyRule(
        name="warn_high_affected",
        description="High 且 Affected 的漏洞发出警告",
        severity="high",
        status="affected",
        min_confidence=0.5,
        action="warn",
    ),
    PolicyRule(
        name="review_low_confidence",
        description="置信度低于 50% 需要人工审查",
        severity="any",
        status="any",
        min_confidence=0.0,  # 特殊: 仅当 confidence < 0.5 时触发
        action="manual_review",
    ),
    PolicyRule(
        name="pass_not_affected",
        description="Not Affected 的漏洞放行",
        severity="any",
        status="not_affected",
        min_confidence=0.0,
        action="pass",
    ),
]


class OPAEngine:
    """
    OPA (Open Policy Agent) 风格的策略引擎。

    将 VEX 判定结果与预定义安全策略进行匹配，
    输出 pass/block/warn/manual_review 决策。

    使用方式:
        engine = OPAEngine()
        decisions = engine.evaluate(vex_judgments, intel_results)
        blocked = engine.get_blocked(decisions)
    """

    def __init__(self, policies: list[PolicyRule] | None = None):
        self.policies = policies or DEFAULT_POLICIES
        logger.info("🛡️ OPA 策略引擎初始化: %d 条规则", len(self.policies))

    def evaluate(
        self,
        vex_judgments: dict[str, Any],
        intel_results: dict[str, Any] | None = None,
    ) -> list[PolicyDecision]:
        """
        对所有 CVE 的 VEX 判定结果进行策略评估。

        Args:
            vex_judgments: {cve_id: VEXJudgment} 字典
            intel_results: {cve_id: IntelResult} 字典 (用于获取 severity)

        Returns:
            list[PolicyDecision]: 每个 CVE 的策略决策
        """
        decisions = []
        intel_results = intel_results or {}

        for cve_id, judgment in vex_judgments.items():
            status = judgment.status if hasattr(judgment, 'status') else str(judgment)
            confidence = judgment.confidence if hasattr(judgment, 'confidence') else 0.0

            # 获取 severity
            severity = "unknown"
            if cve_id in intel_results:
                intel = intel_results[cve_id]
                severity = intel.severity if hasattr(intel, 'severity') else "unknown"

            decision = self._match_policy(cve_id, status, severity, confidence)
            decisions.append(decision)

        return decisions

    def _match_policy(
        self, cve_id: str, status: str, severity: str, confidence: float
    ) -> PolicyDecision:
        """按优先级匹配第一条符合的策略规则。"""
        # 特殊处理: 低置信度 → manual_review
        if confidence < 0.5:
            return PolicyDecision(
                cve_id=cve_id,
                action="manual_review",
                matched_rule="review_low_confidence",
                reason=f"置信度 {confidence:.0%} 低于阈值 50%，需人工审查",
                severity=severity,
                confidence=confidence,
            )

        for rule in self.policies:
            # 跳过 manual_review 规则 (已在上面处理)
            if rule.action == "manual_review":
                continue

            severity_match = rule.severity == "any" or rule.severity == severity
            status_match = rule.status == "any" or rule.status == status
            confidence_ok = confidence >= rule.min_confidence

            if severity_match and status_match and confidence_ok:
                return PolicyDecision(
                    cve_id=cve_id,
                    action=rule.action,
                    matched_rule=rule.name,
                    reason=rule.description,
                    severity=severity,
                    confidence=confidence,
                )

        # 默认放行
        return PolicyDecision(
            cve_id=cve_id,
            action="pass",
            matched_rule="default_pass",
            reason="未匹配任何阻断/警告规则",
            severity=severity,
            confidence=confidence,
        )

    def get_blocked(self, decisions: list[PolicyDecision]) -> list[PolicyDecision]:
        """返回被阻断的 CVE 列表。"""
        return [d for d in decisions if d.action == "block"]

    def get_warnings(self, decisions: list[PolicyDecision]) -> list[PolicyDecision]:
        """返回需要警告的 CVE 列表。"""
        return [d for d in decisions if d.action == "warn"]

    def get_review(self, decisions: list[PolicyDecision]) -> list[PolicyDecision]:
        """返回需要人工审查的 CVE 列表。"""
        return [d for d in decisions if d.action == "manual_review"]

    def summary(self, decisions: list[PolicyDecision]) -> dict[str, Any]:
        """生成策略评估摘要。"""
        blocked = self.get_blocked(decisions)
        warnings = self.get_warnings(decisions)
        reviews = self.get_review(decisions)
        passed = [d for d in decisions if d.action == "pass"]

        gate_result = "BLOCKED" if blocked else "PASSED"

        return {
            "gate_result": gate_result,
            "total": len(decisions),
            "blocked": len(blocked),
            "warnings": len(warnings),
            "manual_review": len(reviews),
            "passed": len(passed),
            "blocked_cves": [d.cve_id for d in blocked],
            "warning_cves": [d.cve_id for d in warnings],
        }

    def print_report(self, decisions: list[PolicyDecision]) -> str:
        """生成人类可读的策略报告。"""
        lines = []
        lines.append("=" * 60)
        lines.append("🛡️ OPA 安全策略评估报告")
        lines.append("=" * 60)

        icons = {"block": "🚫", "warn": "⚠️", "pass": "✅", "manual_review": "🔍"}

        for d in decisions:
            icon = icons.get(d.action, "❓")
            lines.append(f"  {icon} {d.cve_id}: {d.action.upper()}")
            lines.append(f"     规则: {d.matched_rule}")
            lines.append(f"     原因: {d.reason}")
            lines.append("")

        s = self.summary(decisions)
        lines.append("-" * 60)
        lines.append(f"  部署决策: {'🚫 BLOCKED' if s['gate_result'] == 'BLOCKED' else '✅ PASSED'}")
        lines.append(f"  🚫 阻断: {s['blocked']} | ⚠️ 警告: {s['warnings']} | ✅ 放行: {s['passed']} | 🔍 审查: {s['manual_review']}")
        lines.append("=" * 60)

        report = "\n".join(lines)
        logger.info("\n%s", report)
        return report
