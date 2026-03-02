#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ContainerGuard AI — 多智能体协同演示脚本

用途: 在会议上展示 Supervisor 如何并行调度多个子 Agent 进行漏洞判定
"""

import asyncio
import logging
import sys

from vuln_analysis.data_models.input import (
    AgentMorpheusEngineInput, 
    AgentMorpheusInput, 
    ScanInfoInput, 
    VulnInfo, 
    ImageInfoInput,
    SourceDocumentsInfo,
    ManualSBOMInfoInput,
)
from vuln_analysis.data_models.info import AgentMorpheusInfo, SBOMPackage
from vuln_analysis.data_models.cve_intel import CveIntel, CveIntelNvd
from vuln_analysis.agents.supervisor import run_supervisor

# 配置日志输出，使其更清晰适合演示
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

async def main():
    print("\n" + "="*60)
    print("🚀 ContainerGuard AI 多智能体分析演示开启")
    print("="*60 + "\n")

    # 1. 构造一个模拟输入，假设扫描到了两个漏洞
    mock_input = AgentMorpheusEngineInput(
        input=AgentMorpheusInput(
            scan=ScanInfoInput(
                vulns=[
                    VulnInfo(vuln_id="CVE-2021-44228"), # 著名的 Log4j 漏洞
                    VulnInfo(vuln_id="CVE-2023-36632"), # 一个普通的漏洞
                ]
            ),
            image=ImageInfoInput(
                name="my-demo-app:v1.0",
                source_info=[SourceDocumentsInfo(type="code", git_repo="NVIDIA/morpheus", ref="main")],
                sbom_info=ManualSBOMInfoInput(
                    packages=[SBOMPackage(name='log4j-core', version='2.14.0', system='maven')]
                )
            )
        ),
        info=AgentMorpheusInfo(
            # 模拟已经解析的 SBOM
            sbom=AgentMorpheusInfo.SBOMInfo(
                packages=[
                    SBOMPackage(name='log4j-core', version='2.14.0', system='maven')
                ]
            ),
            # 模拟已经获取的情报数据
            intel=[
                CveIntel(
                    vuln_id="CVE-2021-44228", 
                    nvd=CveIntelNvd(cve_id="CVE-2021-44228", cvss_severity="critical", cve_description="Apache Log4j2 JNDI features do not protect against attacker controlled LDAP. The log4j-core package is affected.", cvss_base_score=10.0)
                ),
                CveIntel(
                    vuln_id="CVE-2023-36632", 
                    nvd=CveIntelNvd(cve_id="CVE-2023-36632", cvss_severity="medium", cve_description="A vulnerability exists in parsing email addresses...", cvss_base_score=5.5)
                )
            ]
        )
    )

    # 2. 运行多 Agent 状态机调度
    await run_supervisor(mock_input)

    print("\n✅ 演示结束\n")

if __name__ == "__main__":
    # Windows 下终端编码保险设置
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    
    asyncio.run(main())
