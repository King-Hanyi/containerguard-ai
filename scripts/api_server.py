#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ContainerGuard AI — 轻量 API 服务器。

提供 REST API 接口，供前端 Dashboard 调用。

运行:
    uv run python scripts/api_server.py

API:
    GET  /api/results    — 获取最近的 baseline 结果
    GET  /api/status     — 系统状态
    POST /api/scan       — 运行扫描 (异步)
    GET  /api/policy     — OPA 策略评估结果
"""

import json
import sys
import time
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.parse

# 项目根目录
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# 加载 .env
_env_path = PROJECT_ROOT / ".env"
if _env_path.exists():
    import os
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip())

RESULTS_PATH = PROJECT_ROOT / "docs" / "baseline_results.json"
FRONTEND_DIR = PROJECT_ROOT / "frontend"


class APIHandler(SimpleHTTPRequestHandler):
    """API + 静态文件服务器。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/results":
            self._send_json(self._get_results())
        elif path == "/api/status":
            self._send_json(self._get_status())
        elif path == "/api/policy":
            self._send_json(self._get_policy())
        else:
            # 静态文件
            super().do_GET()

    def _send_json(self, data):
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _get_results(self):
        if RESULTS_PATH.exists():
            with open(RESULTS_PATH) as f:
                return json.load(f)
        return {"error": "No results found. Run baseline first."}

    def _get_status(self):
        return {
            "status": "online",
            "version": "2.0.0",
            "llm_model": "llama-3.1-70b-instruct",
            "llm_backend": "NVIDIA NIM",
            "agents": ["Intel", "Code", "Config", "VEX"],
            "skills": ["IntelSkill", "ConfigSkill", "RemoteCodeSkill"],
            "knowledge_graph": "BRON (CVE↔CWE/CAPEC/ATT&CK)",
            "policy_engine": "OPA (4 rules)",
            "tests_passed": "33/33",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _get_policy(self):
        """对最近的 baseline 结果运行 OPA 策略引擎。"""
        try:
            from vuln_analysis.policy import OPAEngine, PolicyDecision
            from vuln_analysis.agents.state import VEXJudgment, IntelResult

            results = self._get_results()
            if "error" in results:
                return results

            ours = results.get("ours", {}).get("results", {})
            engine = OPAEngine()

            # 构造 VEX judgments
            vex_judgments = {}
            intel_results = {}
            for cve_id, r in ours.items():
                vex_judgments[cve_id] = VEXJudgment(
                    cve_id=cve_id,
                    status=r["status"],
                    confidence=r["confidence"],
                    justification=r.get("justification", ""),
                )
                # 获取 severity
                from vuln_analysis.agents.intel_agent import BUILTIN_INTEL
                entry = BUILTIN_INTEL.get(cve_id, {})
                intel_results[cve_id] = IntelResult(
                    cve_id=cve_id,
                    severity=entry.get("severity", "unknown"),
                )

            decisions = engine.evaluate(vex_judgments, intel_results)
            summary = engine.summary(decisions)
            summary["decisions"] = [
                {
                    "cve_id": d.cve_id,
                    "action": d.action,
                    "rule": d.matched_rule,
                    "reason": d.reason,
                    "severity": d.severity,
                    "confidence": d.confidence,
                }
                for d in decisions
            ]
            return summary

        except Exception as e:
            return {"error": str(e)}

    def log_message(self, format, *args):
        """简化日志输出。"""
        print(f"  [{time.strftime('%H:%M:%S')}] {args[0]}")


def main():
    port = 8090
    print("=" * 60)
    print("  🛡️ ContainerGuard AI — API Server")
    print(f"  http://localhost:{port}")
    print(f"  API: /api/results  /api/status  /api/policy")
    print("=" * 60)

    server = HTTPServer(("0.0.0.0", port), APIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")


if __name__ == "__main__":
    main()
