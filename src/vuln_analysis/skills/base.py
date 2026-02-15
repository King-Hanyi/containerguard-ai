# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import abc
import logging
from typing import Any, Type, Generic, TypeVar

from pydantic import BaseModel, Field

from nat.builder.builder import Builder
from nat.builder.function_info import FunctionInfo
from nat.data_models.function import FunctionBaseConfig

logger = logging.getLogger(__name__)

InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)
ConfigT = TypeVar("ConfigT", bound=FunctionBaseConfig)

class BaseSkill(abc.ABC, Generic[InputT, OutputT, ConfigT]):
    """
    Abstract base class for all Skills in ContainerGuard AI.
    A Skill is a pluggable capability that wraps specific logic (e.g., fetching intel, parsing config).
    It is designed to be compatible with NVIDIA Agent Toolkit (NAT) registration mechanism.
    """

    name: str
    description: str
    input_schema: Type[InputT]
    output_schema: Type[OutputT]
    config_schema: Type[ConfigT]

    def __init__(self, config: ConfigT, builder: Builder):
        self.config = config
        self.builder = builder
        self.logger = logging.getLogger(f"skills.{self.name}")

    @abc.abstractmethod
    async def run(self, input_data: InputT) -> OutputT:
        """
        Execute the skill logic.
        """
        pass

    @classmethod
    def get_config_class(cls) -> Type[ConfigT]:
        """Return the configuration Pydantic model class."""
        return cls.config_schema

    def get_function_info(self) -> FunctionInfo:
        """
        Convert this skill instance into a NAT FunctionInfo object.
        This allows the skill to be yielded by a generator as expected by NAT.
        """
        
        async def _wrapper(input_data: InputT) -> OutputT:
            self.logger.debug(f"Skill {self.name} started with input: {input_data}")
            try:
                result = await self.run(input_data)
                self.logger.debug(f"Skill {self.name} finished with output: {result}")
                return result
            except Exception as e:
                self.logger.error(f"Skill {self.name} failed: {e}", exc_info=True)
                raise e

        # Set metadata clearly on the wrapper for observability
        _wrapper.__name__ = self.name
        _wrapper.__doc__ = self.description

        return FunctionInfo.from_fn(
            _wrapper,
            input_schema=self.input_schema,
            description=self.description
        )
