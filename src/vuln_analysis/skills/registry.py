# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Type
from nat.cli.register_workflow import register_function
from nat.builder.framework_enum import LLMFrameworkEnum
from nat.builder.builder import Builder
from nat.data_models.function import FunctionBaseConfig
from .base import BaseSkill

def register_skill(skill_cls: Type[BaseSkill]):
    """
    Decorator to register a BaseSkill implementation with NVIDIA Agent Toolkit (NAT).
    
    Usage:
    @register_skill
    class MySkill(BaseSkill[MyInput, MyOutput, MyConfig]):
        ...
    """
    config_cls = skill_cls.config_schema
    if not issubclass(config_cls, FunctionBaseConfig):
        raise TypeError(f"Skill config schema {config_cls} must inherit from FunctionBaseConfig")

    @register_function(config_type=config_cls, framework_wrappers=[LLMFrameworkEnum.LANGCHAIN])
    async def _skill_factory(config: FunctionBaseConfig, builder: Builder):
        skill_instance = skill_cls(config, builder)
        yield skill_instance.get_function_info()

    # 关键: 返回原始类而非工厂函数，保留类属性可访问性
    # 工厂函数已通过 @register_function 注册到 NAT
    return skill_cls
