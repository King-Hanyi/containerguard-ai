# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from pydantic import Field, NonNegativeInt

from nat.builder.builder import Builder
from nat.data_models.function import FunctionBaseConfig

from vuln_analysis.data_models.info import AgentMorpheusInfo
from vuln_analysis.data_models.input import (
    AgentMorpheusEngineInput,
    FileSBOMInfoInput,
    HTTPSBOMInfoInput,
    ManualSBOMInfoInput,
    SBOMPackage,
)
from vuln_analysis.utils import http_utils
from vuln_analysis.utils.http_utils import HTTPMethod
from .base import BaseSkill
from .registry import register_skill

logger = logging.getLogger(__name__)


class ConfigSkillConfig(FunctionBaseConfig, name="config_skill"):
    """
    解析容器 SBOM 与配置文件的 Skill 配置。
    支持三种输入模式：手动、本地文件、HTTP 远程获取。
    """
    max_retries: NonNegativeInt = Field(default=10, description="SBOM URL 最大重试次数")


@register_skill
class ConfigSkill(BaseSkill[AgentMorpheusEngineInput, AgentMorpheusEngineInput, ConfigSkillConfig]):
    """
    ConfigSkill: 容器配置与 SBOM 解析技能。
    
    核心职责:
    1. 解析容器的 SBOM (Software Bill of Materials)。
    2. 提取包名、版本号、类型等关键信息。
    3. 支持 File / HTTP / Manual 三种 SBOM 输入方式。
    
    创新点:
    - 使用 utf-8-sig 编码处理 BOM 头问题（修复自 NVIDIA 原始代码的 Bug）。
    - 作为可插拔 Skill，可被 Config Agent 直接调用。
    """
    name = "config_skill"
    description = "解析容器 SBOM 与配置文件，提取软件包和依赖信息。"
    input_schema = AgentMorpheusEngineInput
    output_schema = AgentMorpheusEngineInput
    config_schema = ConfigSkillConfig

    @staticmethod
    def _parse_sbom_packages(sbom_lines: list[str]) -> list[SBOMPackage]:
        """解析 SBOM 文本行并提取包列表。"""
        packages: list[SBOMPackage] = []

        if not sbom_lines or sbom_lines[0].split() != ["NAME", "VERSION", "TYPE"]:
            logger.error("无效的 SBOM 文件格式。期望包含列: 'NAME VERSION TYPE'。")
            return packages

        for line in sbom_lines[1:]:
            parts = line.split()
            if len(parts) < 3:
                continue
            packages.append(SBOMPackage(name=parts[0], version=parts[1], system=parts[2]))

        return packages

    async def run(self, message: AgentMorpheusEngineInput) -> AgentMorpheusEngineInput:
        """
        执行 SBOM 解析并填充到消息中。
        """
        sbom_info = message.input.image.sbom_info

        if sbom_info.type == ManualSBOMInfoInput.static_type():
            assert isinstance(sbom_info, ManualSBOMInfoInput)
            message.info.sbom = AgentMorpheusInfo.SBOMInfo(packages=sbom_info.packages)
            self.logger.info("使用手动 SBOM 输入，包含 %d 个包。", len(sbom_info.packages))

        elif sbom_info.type == FileSBOMInfoInput.static_type():
            assert isinstance(sbom_info, FileSBOMInfoInput)
            # 使用 utf-8-sig 编码处理 BOM 头（关键修复）
            with open(sbom_info.file_path, "r", encoding="utf-8-sig") as f:
                sbom_lines = f.readlines()
            packages = self._parse_sbom_packages(sbom_lines)
            message.info.sbom = AgentMorpheusInfo.SBOMInfo(packages=packages)
            self.logger.info("从文件 '%s' 解析到 %d 个包。", sbom_info.file_path, len(packages))

        elif sbom_info.type == HTTPSBOMInfoInput.static_type():
            assert isinstance(sbom_info, HTTPSBOMInfoInput)
            try:
                _, response = http_utils.request_with_retry(
                    request_kwargs={"url": sbom_info.url, "method": HTTPMethod.GET.value},
                    max_retries=self.config.max_retries
                )
                sbom_lines = response.text.splitlines()
                packages = self._parse_sbom_packages(sbom_lines)
                message.info.sbom = AgentMorpheusInfo.SBOMInfo(packages=packages)
                self.logger.info("从 URL '%s' 解析到 %d 个包。", sbom_info.url, len(packages))
            except Exception as e:
                self.logger.error("从 '%s' 获取 SBOM 失败: %s", sbom_info.url, e)
                message.info.sbom = AgentMorpheusInfo.SBOMInfo(packages=[])

        return message
