# SPDX-FileCopyrightText: Copyright (c) 2025, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from typing import Optional

import aiohttp
from pydantic import BaseModel, Field

from nat.builder.builder import Builder
from nat.data_models.function import FunctionBaseConfig

from .base import BaseSkill
from .registry import register_skill

logger = logging.getLogger(__name__)


class CodeSearchResult(BaseModel):
    """单个代码搜索结果。"""
    file_path: str = Field(description="文件路径")
    line_number: int = Field(default=0, description="匹配行号")
    content: str = Field(description="匹配的代码片段")
    repo: str = Field(description="仓库名")


class RemoteCodeSearchInput(BaseModel):
    """远程代码搜索请求。"""
    query: str = Field(description="搜索关键词 (例如: 'email.utils.parseaddr')")
    repo: str = Field(description="GitHub 仓库 (格式: owner/repo)")
    max_results: int = Field(default=10, description="最大结果数")


class RemoteCodeSearchOutput(BaseModel):
    """远程代码搜索响应。"""
    results: list[CodeSearchResult] = Field(default_factory=list, description="搜索结果列表")
    total_count: int = Field(default=0, description="匹配总数")
    error: Optional[str] = Field(default=None, description="错误信息")


class RemoteCodeSkillConfig(FunctionBaseConfig, name="remote_code_skill"):
    """
    远程代码检索 Skill 配置。
    通过 GitHub API 搜索代码，彻底替代本地 Git Clone + VDB 方案。
    """
    github_token_env: str = Field(
        default="GITHUB_TOKEN",
        description="包含 GitHub Token 的环境变量名称"
    )
    api_base_url: str = Field(
        default="https://api.github.com",
        description="GitHub API 基础 URL"
    )
    request_timeout: int = Field(default=30, description="HTTP 请求超时时间 (秒)")


@register_skill
class RemoteCodeSkill(BaseSkill[RemoteCodeSearchInput, RemoteCodeSearchOutput, RemoteCodeSkillConfig]):
    """
    RemoteCodeSkill: 远程代码搜索技能。

    核心创新:
    - 通过 GitHub Code Search API 直接在远程仓库中搜索代码。
    - 完全替代 NVIDIA Blueprint 的本地 Git Clone + FAISS VDB 方案。
    - 解决了 Windows 环境下路径过长、Git Clone 失败的致命问题。
    - 无需本地存储代码和向量数据库，极大降低资源消耗。

    使用场景:
    - Code Agent 调用此 Skill 搜索目标仓库中是否使用了某个漏洞函数。
    - 例如: 搜索 "email.utils.parseaddr" 以确认 CVE-2023-36632 的可利用性。
    """
    name = "remote_code_skill"
    description = "通过 GitHub API 远程搜索代码仓库，替代本地 Git Clone + VDB。"
    input_schema = RemoteCodeSearchInput
    output_schema = RemoteCodeSearchOutput
    config_schema = RemoteCodeSkillConfig

    def _get_github_token(self) -> Optional[str]:
        """从环境变量获取 GitHub Token。"""
        return os.environ.get(self.config.github_token_env)

    async def run(self, input_data: RemoteCodeSearchInput) -> RemoteCodeSearchOutput:
        """
        执行远程代码搜索。
        使用 GitHub Code Search API 在指定仓库中搜索关键词。
        """
        token = self._get_github_token()
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ContainerGuard-AI"
        }
        if token:
            headers["Authorization"] = f"token {token}"

        # 构造 GitHub Code Search 查询
        search_query = f"{input_data.query}+repo:{input_data.repo}"
        url = f"{self.config.api_base_url}/search/code?q={search_query}&per_page={input_data.max_results}"

        self.logger.info("正在搜索 '%s' (仓库: %s)...", input_data.query, input_data.repo)

        try:
            timeout = aiohttp.ClientTimeout(total=self.config.request_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        results = []
                        for item in data.get("items", []):
                            results.append(CodeSearchResult(
                                file_path=item.get("path", ""),
                                content=item.get("name", ""),
                                repo=item.get("repository", {}).get("full_name", input_data.repo)
                            ))
                        total = data.get("total_count", 0)
                        self.logger.info("搜索完成，找到 %d 个结果。", total)
                        return RemoteCodeSearchOutput(results=results, total_count=total)

                    elif response.status == 401:
                        msg = "GitHub API 认证失败。请检查 GITHUB_TOKEN 环境变量。"
                        self.logger.error(msg)
                        return RemoteCodeSearchOutput(error=msg)

                    elif response.status == 403:
                        msg = "GitHub API 访问被拒绝（可能触发了速率限制）。"
                        self.logger.warning(msg)
                        return RemoteCodeSearchOutput(error=msg)

                    elif response.status == 422:
                        msg = "GitHub API 无法处理该查询（仓库可能不存在或为私有仓库）。"
                        self.logger.warning(msg)
                        return RemoteCodeSearchOutput(error=msg)

                    else:
                        msg = f"GitHub API 返回非预期状态码: {response.status}"
                        self.logger.error(msg)
                        return RemoteCodeSearchOutput(error=msg)

        except aiohttp.ClientError as e:
            msg = f"网络错误: {e}"
            self.logger.error(msg)
            return RemoteCodeSearchOutput(error=msg)
        except Exception as e:
            msg = f"未知错误: {e}"
            self.logger.error(msg, exc_info=True)
            return RemoteCodeSearchOutput(error=msg)
