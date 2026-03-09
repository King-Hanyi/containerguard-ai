#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ContainerGuard AI — 轻量 API 服务器。

提供 REST API 接口，供前端 Dashboard 调用。

运行:
    uv run python scripts/api_server.py

API:
    GET  /api/results         — 获取最近的 baseline 结果
    GET  /api/status          — 系统状态
    GET  /api/policy          — OPA 策略评估结果
    GET  /api/docker/images   — 列出本地 Docker 镜像
    GET  /api/report?format=  — 导出报告 (md / html / docx)
"""

import json
import os
import subprocess
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
    with open(_env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip())

RESULTS_PATH = PROJECT_ROOT / "docs" / "baseline_results.json"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)


class APIHandler(SimpleHTTPRequestHandler):
    """API + 静态文件服务器。"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(FRONTEND_DIR), **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))

        if path == "/api/results":
            self._send_json(self._get_results())
        elif path == "/api/status":
            self._send_json(self._get_status())
        elif path == "/api/policy":
            self._send_json(self._get_policy())
        elif path == "/api/docker/images":
            self._send_json(self._get_docker_images())
        elif path == "/api/report":
            self._handle_report_export(query)
        elif path.startswith("/reports/"):
            self._serve_report_file(path)
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

    def _send_file(self, filepath: Path, content_type: str, filename: str = ""):
        if not filepath.exists():
            self.send_error(404)
            return
        data = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

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
            "tests_passed": "43/43",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

    def _get_docker_images(self):
        """列出本地 Docker 镜像。"""
        try:
            result = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}"],
                capture_output=True, text=True, timeout=10
            )
            images = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                parts = line.split("\t")
                if len(parts) >= 4:
                    images.append({
                        "name": parts[0],
                        "id": parts[1][:12],
                        "size": parts[2],
                        "created": parts[3],
                    })
            return {"images": images, "count": len(images)}
        except FileNotFoundError:
            return {"images": [], "count": 0, "error": "Docker 未安装或未启动"}
        except subprocess.TimeoutExpired:
            return {"images": [], "count": 0, "error": "Docker 命令超时"}
        except Exception as e:
            return {"images": [], "count": 0, "error": str(e)}

    def _handle_report_export(self, query):
        """生成并返回报告文件。"""
        fmt = query.get("format", "md")
        target = query.get("target", "container scan")

        scan_data = self._get_results()
        if "error" in scan_data:
            self._send_json({"error": "No scan data available"})
            return

        from vuln_analysis.report_generator import (
            generate_markdown_report,
            generate_html_report,
            generate_docx_report,
        )

        ts = int(time.time())

        if fmt == "md":
            content = generate_markdown_report(scan_data, target)
            filepath = REPORTS_DIR / f"report_{ts}.md"
            filepath.write_text(content, encoding="utf-8")
            self._send_file(filepath, "text/markdown; charset=utf-8", f"ContainerGuard_Report_{ts}.md")

        elif fmt == "html":
            content = generate_html_report(scan_data, target)
            filepath = REPORTS_DIR / f"report_{ts}.html"
            filepath.write_text(content, encoding="utf-8")
            self._send_file(filepath, "text/html; charset=utf-8", f"ContainerGuard_Report_{ts}.html")

        elif fmt == "docx":
            filepath = REPORTS_DIR / f"report_{ts}.docx"
            result = generate_docx_report(scan_data, target, str(filepath))
            if result:
                self._send_file(filepath,
                                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                                f"ContainerGuard_Report_{ts}.docx")
            else:
                # python-docx 不可用 — 回退 HTML
                content = generate_html_report(scan_data, target)
                filepath = REPORTS_DIR / f"report_{ts}.html"
                filepath.write_text(content, encoding="utf-8")
                self._send_file(filepath, "text/html; charset=utf-8", f"ContainerGuard_Report_{ts}.html")
        else:
            self._send_json({"error": f"Unknown format: {fmt}. Use md/html/docx."})

    def _serve_report_file(self, path):
        """提供 reports/ 目录下的文件。"""
        filename = Path(path).name
        filepath = REPORTS_DIR / filename
        if filepath.exists():
            suffix = filepath.suffix.lower()
            ct_map = {".md": "text/markdown", ".html": "text/html", ".docx": "application/octet-stream"}
            self._send_file(filepath, ct_map.get(suffix, "application/octet-stream"))
        else:
            self.send_error(404)

    def _get_policy(self):
        """对最近的 baseline 结果运行 OPA 策略引擎。"""
        try:
            from vuln_analysis.policy import OPAEngine
            from vuln_analysis.agents.state import VEXJudgment, IntelResult

            results = self._get_results()
            if "error" in results:
                return results

            ours = results.get("ours", {}).get("results", {})
            engine = OPAEngine()

            vex_judgments = {}
            intel_results = {}
            for cve_id, r in ours.items():
                vex_judgments[cve_id] = VEXJudgment(
                    cve_id=cve_id,
                    status=r["status"],
                    confidence=r["confidence"],
                    justification=r.get("justification", ""),
                )
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
    print(f"       /api/docker/images  /api/report?format=md|html|docx")
    print("=" * 60)

    server = HTTPServer(("0.0.0.0", port), APIHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")


if __name__ == "__main__":
    main()
