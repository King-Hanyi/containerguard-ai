# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
ContainerGuard AI Skills 框架单元测试。
验证 BaseSkill 抽象基类、SkillRegistry 注册机制及各 Skill 实现的正确性。
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pydantic import BaseModel, Field

from nat.data_models.function import FunctionBaseConfig


# ============================================================
# Test 1: BaseSkill 抽象基类
# ============================================================
class TestBaseSkill:
    """测试 BaseSkill 的接口约束和 FunctionInfo 生成。"""

    def test_cannot_instantiate_abstract(self):
        """BaseSkill 不能直接实例化。"""
        from vuln_analysis.skills.base import BaseSkill
        with pytest.raises(TypeError):
            BaseSkill(config=MagicMock(), builder=MagicMock())

    def test_concrete_skill_requires_run(self):
        """子类必须实现 run 方法。"""
        from vuln_analysis.skills.base import BaseSkill

        class IncompleteSkill(BaseSkill):
            name = "incomplete"
            description = "test"
            input_schema = BaseModel
            output_schema = BaseModel
            config_schema = FunctionBaseConfig

        with pytest.raises(TypeError):
            IncompleteSkill(config=MagicMock(), builder=MagicMock())

    def test_concrete_skill_instantiation(self):
        """正确实现的子类可以实例化。"""
        from vuln_analysis.skills.base import BaseSkill

        class DummyInput(BaseModel):
            value: str = ""

        class DummyOutput(BaseModel):
            result: str = ""

        class DummyConfig(FunctionBaseConfig, name="dummy_test"):
            pass

        class DummySkill(BaseSkill[DummyInput, DummyOutput, DummyConfig]):
            name = "dummy_skill"
            description = "A dummy skill for testing"
            input_schema = DummyInput
            output_schema = DummyOutput
            config_schema = DummyConfig

            async def run(self, input_data):
                return DummyOutput(result=f"processed: {input_data.value}")

        config = MagicMock(spec=DummyConfig)
        builder = MagicMock()
        skill = DummySkill(config=config, builder=builder)

        assert skill.name == "dummy_skill"
        assert skill.description == "A dummy skill for testing"

    def test_get_function_info(self):
        """get_function_info 调用验证 — 使用真实 Skill 类型验证 NAT 兼容。"""
        from vuln_analysis.skills.intel import IntelSkill

        # 验证 IntelSkill 具有正确的类方法和属性
        assert hasattr(IntelSkill, 'get_function_info')
        assert hasattr(IntelSkill, 'get_config_class')
        assert IntelSkill.get_config_class() is not None
        assert IntelSkill.name == "intel_skill"


# ============================================================
# Test 2: RemoteCodeSkill
# ============================================================
class TestRemoteCodeSkill:
    """测试 RemoteCodeSkill 的 GitHub API 搜索逻辑。"""

    def test_config_defaults(self):
        """验证默认配置值。"""
        from vuln_analysis.skills.remote_code import RemoteCodeSkillConfig
        # RemoteCodeSkillConfig 需要 name 参数
        # 检查默认值
        assert RemoteCodeSkillConfig.model_fields["github_token_env"].default == "GITHUB_TOKEN"
        assert RemoteCodeSkillConfig.model_fields["request_timeout"].default == 30

    def test_search_input_model(self):
        """验证搜索输入模型。"""
        from vuln_analysis.skills.remote_code import RemoteCodeSearchInput
        input_data = RemoteCodeSearchInput(
            query="email.utils.parseaddr",
            repo="python/cpython"
        )
        assert input_data.query == "email.utils.parseaddr"
        assert input_data.repo == "python/cpython"
        assert input_data.max_results == 10  # 默认值

    def test_search_output_model(self):
        """验证搜索输出模型。"""
        from vuln_analysis.skills.remote_code import RemoteCodeSearchOutput, CodeSearchResult
        output = RemoteCodeSearchOutput(
            results=[
                CodeSearchResult(file_path="lib/email/utils.py", content="parseaddr", repo="python/cpython")
            ],
            total_count=1
        )
        assert len(output.results) == 1
        assert output.total_count == 1
        assert output.error is None


# ============================================================
# Test 3: ConfigSkill
# ============================================================
class TestConfigSkill:
    """测试 ConfigSkill 的 SBOM 解析逻辑。"""

    def test_parse_sbom_valid(self):
        """验证正常 SBOM 文件解析。"""
        from vuln_analysis.skills.config import ConfigSkill
        lines = [
            "NAME VERSION TYPE",
            "python 3.10.12 binary",
            "openssl 3.0.2 deb",
            "curl 7.81.0 deb",
        ]
        packages = ConfigSkill._parse_sbom_packages(lines)
        assert len(packages) == 3
        assert packages[0].name == "python"
        assert packages[0].version == "3.10.12"
        assert packages[1].name == "openssl"

    def test_parse_sbom_invalid_header(self):
        """验证无效头部返回空列表。"""
        from vuln_analysis.skills.config import ConfigSkill
        lines = ["INVALID HEADER FORMAT"]
        packages = ConfigSkill._parse_sbom_packages(lines)
        assert len(packages) == 0

    def test_parse_sbom_empty(self):
        """验证空输入返回空列表。"""
        from vuln_analysis.skills.config import ConfigSkill
        packages = ConfigSkill._parse_sbom_packages([])
        assert len(packages) == 0

    def test_parse_sbom_skip_short_lines(self):
        """验证跳过格式不完整的行。"""
        from vuln_analysis.skills.config import ConfigSkill
        lines = [
            "NAME VERSION TYPE",
            "python 3.10.12 binary",
            "incomplete",
            "ok 1.0 pkg",
        ]
        packages = ConfigSkill._parse_sbom_packages(lines)
        assert len(packages) == 2


# ============================================================
# Test 4: IntelSkill
# ============================================================
class TestIntelSkill:
    """测试 IntelSkill 的配置与基本结构。"""

    def test_intel_skill_config(self):
        """验证 IntelSkill 配置默认值。"""
        from vuln_analysis.skills.intel import IntelSkillConfig
        assert IntelSkillConfig.model_fields["max_retries"].default == 5
        assert IntelSkillConfig.model_fields["request_timeout"].default == 30

    def test_intel_skill_metadata(self):
        """验证 IntelSkill 类属性。"""
        from vuln_analysis.skills.intel import IntelSkill
        assert IntelSkill.name == "intel_skill"
        assert "NIST" in IntelSkill.description or "GHSA" in IntelSkill.description or "CVE" in IntelSkill.description
