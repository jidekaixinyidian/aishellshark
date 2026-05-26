# -*- coding: utf-8 -*-
"""
AI 统一接口
支持 OpenAI GPT-4 / Claude / 通义千问 / 文心一言 / Ollama
支持代理和配置切换
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any
from loguru import logger

import httpx
from openai import OpenAI, AsyncOpenAI
import anthropic

from backend.models.schemas import AIAnalysisRequest, AIAnalysisResult, ThreatLevel


class AIClient:
    """AI 统一客户端"""

    def __init__(self, config: dict):
        self.config = config
        self.default_provider = config.get("default_provider", "openai")
        self.proxy = config.get("proxy", "")

        # 初始化各提供商配置
        self.openai_config = config.get("openai", {})
        self.deepseek_config = config.get("deepseek", {})
        self.claude_config = config.get("claude", {})
        self.qwen_config = config.get("qwen", {})
        self.ernie_config = config.get("ernie", {})
        self.ollama_config = config.get("ollama", {})

        # 客户端实例
        self.openai_client: Optional[AsyncOpenAI] = None
        self.deepseek_client: Optional[AsyncOpenAI] = None
        self.claude_client: Optional[anthropic.AsyncAnthropic] = None
        self.qwen_client: Optional[httpx.AsyncClient] = None
        self.ernie_client: Optional[httpx.AsyncClient] = None
        self.ollama_client: Optional[httpx.AsyncClient] = None

        # 初始化客户端
        self._init_clients()

        # 速率限制
        self.rate_limit = config.get("rate_limit", 60)  # 每分钟请求数
        self.batch_concurrency = config.get("batch_concurrency", 5)
        self.timeout = config.get("timeout", 60)

        # 请求队列
        self._semaphore = asyncio.Semaphore(self.batch_concurrency)
        self._last_request_time = 0
        self._request_count = 0
        self._window_start = time.time()

        logger.info(f"AI 客户端初始化完成，默认提供商: {self.default_provider}")

    def _init_clients(self):
        """初始化各提供商客户端"""
        # OpenAI
        if self.openai_config.get("api_key"):
            self.openai_client = AsyncOpenAI(
                api_key=self.openai_config["api_key"],
                base_url=self.openai_config.get("base_url", "https://api.openai.com/v1"),
                http_client=httpx.AsyncClient(proxy=self.proxy) if self.proxy else None
            )

        # DeepSeek（兼容 OpenAI 接口）
        if self.deepseek_config.get("api_key"):
            self.deepseek_client = AsyncOpenAI(
                api_key=self.deepseek_config["api_key"],
                base_url=self.deepseek_config.get("base_url", "https://api.deepseek.com"),
                http_client=httpx.AsyncClient(proxy=self.proxy) if self.proxy else None
            )

        # Claude
        if self.claude_config.get("api_key"):
            self.claude_client = anthropic.AsyncAnthropic(
                api_key=self.claude_config["api_key"],
                http_client=httpx.AsyncClient(proxy=self.proxy) if self.proxy else None
            )

        # 通义千问
        if self.qwen_config.get("api_key"):
            self.qwen_client = httpx.AsyncClient(
                base_url=self.qwen_config.get("base_url", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
                headers={
                    "Authorization": f"Bearer {self.qwen_config['api_key']}",
                    "Content-Type": "application/json"
                },
                proxy=self.proxy if self.proxy else None
            )

        # 文心一言
        if self.ernie_config.get("api_key") and self.ernie_config.get("secret_key"):
            self.ernie_client = httpx.AsyncClient(
                base_url="https://aip.baidubce.com",
                proxy=self.proxy if self.proxy else None
            )

        # Ollama
        if self.ollama_config.get("base_url"):
            self.ollama_client = httpx.AsyncClient(
                base_url=self.ollama_config["base_url"],
                proxy=self.proxy if self.proxy else None
            )

    async def _rate_limit_wait(self):
        """速率限制等待"""
        now = time.time()
        
        # 检查时间窗口
        if now - self._window_start > 60:  # 新的一分钟
            self._window_start = now
            self._request_count = 0
        
        # 检查请求计数
        if self._request_count >= self.rate_limit:
            wait_time = 60 - (now - self._window_start)
            if wait_time > 0:
                logger.debug(f"速率限制，等待 {wait_time:.1f} 秒")
                await asyncio.sleep(wait_time)
                self._window_start = time.time()
                self._request_count = 0
        
        # 更新计数
        self._request_count += 1
        
        # 最小请求间隔
        min_interval = 60.0 / self.rate_limit
        elapsed = now - self._last_request_time
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = time.time()

    async def analyze(self, request: AIAnalysisRequest) -> List[AIAnalysisResult]:
        """
        分析 HTTP 会话
        支持批量分析
        """
        if not request.session_ids:
            return []

        results = []
        tasks = []

        # 创建分析任务
        for session_id in request.session_ids:
            task = self._analyze_single(session_id, request)
            tasks.append(task)

        # 并发执行
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

        # 处理异常结果
        valid_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"AI 分析失败: {result}")
            elif result:
                valid_results.append(result)

        return valid_results

    async def _analyze_single(self, session_id: str, request: AIAnalysisRequest) -> Optional[AIAnalysisResult]:
        """分析单个会话"""
        async with self._semaphore:
            try:
                await self._rate_limit_wait()

                # 获取会话上下文（这里需要从数据库或缓存中获取）
                context = await self._get_session_context(session_id, request)
                if not context:
                    return None

                # 选择提供商
                provider = request.provider or self.default_provider
                model = request.model or self._get_default_model(provider)

                # 调用 AI 接口
                response = await self._call_ai_api(provider, model, context)

                # 解析响应
                result = self._parse_ai_response(response, session_id, provider, model)

                return result

            except Exception as e:
                logger.error(f"分析会话 {session_id} 失败: {e}")
                return None

    async def _get_session_context(self, session_id: str, request: AIAnalysisRequest) -> Optional[str]:
        """
        获取会话上下文
        这里需要实现从数据库或缓存中获取会话数据
        """
        # TODO: 实现从数据库获取会话数据
        # 这里返回示例上下文
        return f"会话ID: {session_id}\n这是一个示例上下文，需要替换为实际的会话数据。"

    def _get_default_model(self, provider: str) -> str:
        """获取默认模型"""
        model_map = {
            "openai": self.openai_config.get("model", "gpt-4o"),
            "deepseek": self.deepseek_config.get("model", "deepseek-chat"),
            "claude": self.claude_config.get("model", "claude-3-5-sonnet-20241022"),
            "qwen": self.qwen_config.get("model", "qwen-max"),
            "ernie": self.ernie_config.get("model", "ernie-4.0-8k"),
            "ollama": self.ollama_config.get("model", "llama3"),
        }
        return model_map.get(provider, "gpt-4o")

    async def _call_ai_api(self, provider: str, model: str, context: str) -> str:
        """调用 AI API"""
        try:
            if provider == "openai" and self.openai_client:
                return await self._call_openai(model, context)
            elif provider == "deepseek" and self.deepseek_client:
                return await self._call_deepseek(model, context)
            elif provider == "claude" and self.claude_client:
                return await self._call_claude(model, context)
            elif provider == "qwen" and self.qwen_client:
                return await self._call_qwen(model, context)
            elif provider == "ernie" and self.ernie_client:
                return await self._call_ernie(model, context)
            elif provider == "ollama" and self.ollama_client:
                return await self._call_ollama(model, context)
            else:
                raise ValueError(f"不支持的 AI 提供商: {provider}")
        except Exception as e:
            logger.error(f"调用 {provider} API 失败: {e}")
            raise

    async def _call_openai(self, model: str, context: str) -> str:
        """调用 OpenAI API"""
        if not self.openai_client:
            raise ValueError("OpenAI 客户端未初始化")

        response = await self.openai_client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "你是一个 WebShell 流量分析专家。请分析提供的 HTTP 流量数据，判断是否为 WebShell 通信。"
                },
                {
                    "role": "user",
                    "content": context
                }
            ],
            max_tokens=self.openai_config.get("max_tokens", 2000),
            temperature=self.openai_config.get("temperature", 0.1),
            timeout=self.timeout
        )

        return response.choices[0].message.content

    async def _call_deepseek(self, model: str, context: str) -> str:
        """调用 DeepSeek API（兼容 OpenAI 接口）"""
        if not self.deepseek_client:
            raise ValueError("DeepSeek 客户端未初始化")

        response = await self.deepseek_client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "你是一个 WebShell 流量分析专家。请分析提供的 HTTP 流量数据，判断是否为 WebShell 通信。"
                },
                {
                    "role": "user",
                    "content": context
                }
            ],
            max_tokens=self.deepseek_config.get("max_tokens", 2000),
            temperature=self.deepseek_config.get("temperature", 0.1),
            timeout=self.timeout
        )

        return response.choices[0].message.content

    async def _call_claude(self, model: str, context: str) -> str:
        """调用 Claude API"""
        if not self.claude_client:
            raise ValueError("Claude 客户端未初始化")

        response = await self.claude_client.messages.create(
            model=model,
            max_tokens=self.claude_config.get("max_tokens", 2000),
            messages=[
                {
                    "role": "user",
                    "content": f"请分析以下 HTTP 流量数据，判断是否为 WebShell 通信：\n\n{context}"
                }
            ]
        )

        return response.content[0].text

    async def _call_qwen(self, model: str, context: str) -> str:
        """调用通义千问 API"""
        if not self.qwen_client:
            raise ValueError("通义千问客户端未初始化")

        response = await self.qwen_client.post(
            "/chat/completions",
            json={
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "你是一个 WebShell 流量分析专家。请分析提供的 HTTP 流量数据，判断是否为 WebShell 通信。"
                    },
                    {
                        "role": "user",
                        "content": context
                    }
                ],
                "max_tokens": self.qwen_config.get("max_tokens", 2000)
            },
            timeout=self.timeout
        )

        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    async def _call_ernie(self, model: str, context: str) -> str:
        """调用文心一言 API"""
        if not self.ernie_client:
            raise ValueError("文心一言客户端未初始化")

        # 获取 access token
        token_response = await self.ernie_client.post(
            "/oauth/2.0/token",
            params={
                "grant_type": "client_credentials",
                "client_id": self.ernie_config["api_key"],
                "client_secret": self.ernie_config["secret_key"]
            }
        )

        token_response.raise_for_status()
        token_data = token_response.json()
        access_token = token_data["access_token"]

        # 调用聊天接口
        chat_response = await self.ernie_client.post(
            "/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions",
            params={"access_token": access_token},
            json={
                "messages": [
                    {
                        "role": "user",
                        "content": f"请分析以下 HTTP 流量数据，判断是否为 WebShell 通信：\n\n{context}"
                    }
                ],
                "temperature": 0.1
            },
            timeout=self.timeout
        )

        chat_response.raise_for_status()
        chat_data = chat_response.json()
        return chat_data["result"]

    async def _call_ollama(self, model: str, context: str) -> str:
        """调用 Ollama API"""
        if not self.ollama_client:
            raise ValueError("Ollama 客户端未初始化")

        response = await self.ollama_client.post(
            "/api/generate",
            json={
                "model": model,
                "prompt": f"请分析以下 HTTP 流量数据，判断是否为 WebShell 通信：\n\n{context}",
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": self.ollama_config.get("max_tokens", 2000)
                }
            },
            timeout=self.timeout
        )

        response.raise_for_status()
        data = response.json()
        return data["response"]

    def _parse_ai_response(self, response: str, session_id: str, provider: str, model: str) -> AIAnalysisResult:
        """解析 AI 响应"""
        try:
            # 尝试解析 JSON 格式的响应
            if response.strip().startswith("{"):
                data = json.loads(response)
                return self._parse_json_response(data, session_id, provider, model)
            else:
                # 解析文本响应
                return self._parse_text_response(response, session_id, provider, model)
        except Exception as e:
            logger.error(f"解析 AI 响应失败: {e}")
            # 返回默认结果
            return AIAnalysisResult(
                session_id=session_id,
                is_webshell=False,
                confidence=0.0,
                tool_type="未知",
                attack_intent="未知",
                payload="",
                commands=[],
                threat_level=ThreatLevel.LOW,
                recommendations=["无法解析 AI 响应"],
                provider=provider,
                model=model,
                raw_response=response[:1000]
            )

    def _parse_json_response(self, data: Dict[str, Any], session_id: str, provider: str, model: str) -> AIAnalysisResult:
        """解析 JSON 格式的响应"""
        return AIAnalysisResult(
            session_id=session_id,
            is_webshell=data.get("is_webshell", False),
            confidence=float(data.get("confidence", 0.0)),
            tool_type=data.get("tool_type", "未知"),
            attack_intent=data.get("attack_intent", "未知"),
            payload=data.get("payload", ""),
            commands=data.get("commands", []),
            threat_level=self._parse_threat_level(data.get("threat_level", "low")),
            recommendations=data.get("recommendations", []),
            provider=provider,
            model=model,
            raw_response=json.dumps(data, ensure_ascii=False)
        )

    def _parse_text_response(self, text: str, session_id: str, provider: str, model: str) -> AIAnalysisResult:
        """解析文本格式的响应"""
        # 这里实现简单的文本解析逻辑
        # 实际应用中可能需要更复杂的 NLP 解析
        
        is_webshell = False
        confidence = 0.0
        tool_type = "未知"
        attack_intent = "未知"
        threat_level = ThreatLevel.LOW
        recommendations = []

        # 简单关键词匹配
        text_lower = text.lower()
        
        if "webshell" in text_lower or "后门" in text_lower or "木马" in text_lower:
            is_webshell = True
            confidence = 0.7
        
        # 检测工具类型
        tool_keywords = {
            "菜刀": "中国菜刀",
            "蚁剑": "蚁剑",
            "冰蝎": "冰蝎",
            "哥斯拉": "哥斯拉",
            "weevely": "Weevely3",
        }
        
        for keyword, tool in tool_keywords.items():
            if keyword in text_lower:
                tool_type = tool
                break
        
        # 检测攻击意图
        intent_keywords = {
            "命令执行": ["命令执行", "执行命令", "system", "exec"],
            "文件上传": ["文件上传", "上传文件", "upload"],
            "数据库操作": ["数据库", "sql", "查询"],
            "权限维持": ["权限维持", "后门", "持久化"],
            "内网扫描": ["内网扫描", "端口扫描", "探测"],
        }
        
        for intent, keywords in intent_keywords.items():
            for keyword in keywords:
                if keyword in text_lower:
                    attack_intent = intent
                    break
        
        # 检测威胁等级
        if "高危" in text_lower or "严重" in text_lower:
            threat_level = ThreatLevel.HIGH
        elif "中危" in text_lower or "中等" in text_lower:
            threat_level = ThreatLevel.MEDIUM
        elif "低危" in text_lower or "低风险" in text_lower:
            threat_level = ThreatLevel.LOW
        
        # 提取建议
        lines = text.split("\n")
        for line in lines:
            if "建议" in line or "建议" in line or "应该" in line:
                recommendations.append(line.strip())

        return AIAnalysisResult(
            session_id=session_id,
            is_webshell=is_webshell,
            confidence=confidence,
            tool_type=tool_type,
            attack_intent=attack_intent,
            payload=text[:500],  # 截取部分作为载荷
            commands=[],  # 需要更复杂的解析来提取命令
            threat_level=threat_level,
            recommendations=recommendations[:3],  # 最多3条建议
            provider=provider,
            model=model,
            raw_response=text[:1000]
        )

    def _parse_threat_level(self, level_str: str) -> ThreatLevel:
        """解析威胁等级字符串"""
        level_str = level_str.lower()
        if level_str in ["high", "高危", "严重"]:
            return ThreatLevel.HIGH
        elif level_str in ["medium", "中危", "中等"]:
            return ThreatLevel.MEDIUM
        elif level_str in ["low", "低危", "低风险"]:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.LOW

    async def test_connection(self, provider: str = None) -> bool:
        """测试 AI 服务连接"""
        provider = provider or self.default_provider
        
        try:
            test_context = "这是一个连接测试。"
            
            if provider == "openai" and self.openai_client:
                await self.openai_client.chat.completions.create(
                    model=self._get_default_model("openai"),
                    messages=[{"role": "user", "content": test_context}],
                    max_tokens=10
                )
                return True

            elif provider == "deepseek" and self.deepseek_client:
                await self.deepseek_client.chat.completions.create(
                    model=self._get_default_model("deepseek"),
                    messages=[{"role": "user", "content": test_context}],
                    max_tokens=10
                )
                return True
                
            elif provider == "claude" and self.claude_client:
                await self.claude_client.messages.create(
                    model=self._get_default_model("claude"),
                    max_tokens=10,
                    messages=[{"role": "user", "content": test_context}]
                )
                return True
                
            elif provider == "ollama" and self.ollama_client:
                await self.ollama_client.post(
                    "/api/generate",
                    json={
                        "model": self._get_default_model("ollama"),
                        "prompt": test_context,
                        "stream": False
                    }
                )
                return True
                
            else:
                logger.warning(f"未配置 {provider} 客户端")
                return False
                
        except Exception as e:
            logger.error(f"测试 {provider} 连接失败: {e}")
            return False

    def get_providers_status(self) -> Dict[str, bool]:
        """获取各提供商状态"""
        status = {}
        
        for provider in ["openai", "deepseek", "claude", "qwen", "ernie", "ollama"]:
            client = getattr(self, f"{provider}_client", None)
            status[provider] = client is not None
        
        return status

    async def close(self):
        """关闭所有客户端"""
        clients = [
            self.openai_client,
            self.deepseek_client,
            self.claude_client,
            self.qwen_client,
            self.ernie_client,
            self.ollama_client,
        ]
        
        for client in clients:
            if client and hasattr(client, "close"):
                await client.close()