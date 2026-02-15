# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import asyncio
import logging
import aiohttp
from pydantic import Field

from nat.builder.builder import Builder
from nat.data_models.function import FunctionBaseConfig

from vuln_analysis.data_models.input import AgentMorpheusEngineInput
from vuln_analysis.utils.intel_retriever import IntelRetriever
from .base import BaseSkill
from .registry import register_skill

logger = logging.getLogger(__name__)

class IntelSkillConfig(FunctionBaseConfig, name="intel_skill"):
    """
    Configuration for IntelSkill.
    """
    max_retries: int = Field(default=5, description="Maximum number of retries on client and server errors")
    retry_on_client_errors: bool = Field(default=True, description="Whether to retry on client errors")
    request_timeout: int = Field(default=30, description="Timeout for individual HTTP requests in seconds")
    intel_source_timeout: int | None = Field(
        default=None,
        description="Timeout for each intel source (across all retries) in seconds. None means no timeout.")


@register_skill
class IntelSkill(BaseSkill[AgentMorpheusEngineInput, AgentMorpheusEngineInput, IntelSkillConfig]):
    name = "intel_skill"
    description = "Fetches details about CVEs from NIST, GHSA, and other sources."
    input_schema = AgentMorpheusEngineInput
    output_schema = AgentMorpheusEngineInput
    config_schema = IntelSkillConfig

    async def run(self, message: AgentMorpheusEngineInput) -> AgentMorpheusEngineInput:
        """
        Executes the intel retrieval process.
        """
        async def _retrieve_all():
            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                intel_retriever = IntelRetriever(
                    session=session,
                    max_retries=self.config.max_retries,
                    retry_on_client_errors=self.config.retry_on_client_errors,
                    intel_source_timeout=self.config.intel_source_timeout,
                    request_timeout=self.config.request_timeout
                )
                
                # Retrieve intel for each CVE in the scan list
                tasks = [intel_retriever.retrieve(vuln_id=cve.vuln_id) for cve in message.input.scan.vulns]
                return await asyncio.gather(*tasks)

        self.logger.info(f"Starting Intel Retrieval for {len(message.input.scan.vulns)} CVEs...")
        intel_results = await _retrieve_all()
        
        # Populate the message info with retrieved intel
        message.info.intel = intel_results
        self.logger.info(f"Completed Intel Retrieval. Found data for {len(intel_results)} items.")
        
        return message
