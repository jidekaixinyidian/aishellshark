# -*- coding: utf-8 -*-
"""
批量异步 AI 分析
支持并发控制和速率限制
"""

import asyncio
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from loguru import logger

from backend.models.schemas import (
    AIAnalysisRequest, AIAnalysisResult, ThreatLevel
)
from backend.ai.ai_client import AIClient
from backend.ai.context_builder import ContextBuilder
from backend.ai.prompt_templates import PromptTemplates


class BatchAnalyzer:
    """
    批量 AI 分析器
    支持异步并发分析，速率限制，结果聚合
    """

    def __init__(self, config: dict, sessions_store: dict = None, detections_store: dict = None, scores_store: dict = None):
        self.config = config
        self.sessions_store = sessions_store if sessions_store is not None else {}
        self.detections_store = detections_store if detections_store is not None else {}
        self.scores_store = scores_store if scores_store is not None else {}
        self.ai_client = AIClient(config.get("ai", {}))
        self.context_builder = ContextBuilder()
        self.prompt_templates = PromptTemplates(config.get("ai", {}))

        # 批量分析配置
        self.batch_concurrency = config.get("ai", {}).get("batch_concurrency", 5)
        self.rate_limit = config.get("ai", {}).get("rate_limit", 60)
        self.timeout = config.get("ai", {}).get("timeout", 60)
        self.max_batch_size = config.get("ai", {}).get("max_batch_size", 100)

        # 统计信息
        self._total_analyzed = 0
        self._total_threats = 0
        self._start_time = None

        logger.info(f"批量分析器初始化完成，并发数: {self.batch_concurrency}")

    async def analyze_batch(self, request: AIAnalysisRequest) -> List[AIAnalysisResult]:
        """
        批量分析 HTTP 会话
        支持并发控制和速率限制
        """
        if not request.session_ids:
            return []

        # 限制批量大小
        session_ids = request.session_ids[:self.max_batch_size]
        if len(session_ids) < len(request.session_ids):
            logger.warning(f"批量大小超过限制，只分析前 {self.max_batch_size} 个会话")

        self._start_time = time.time()
        self._total_analyzed = 0
        self._total_threats = 0

        logger.info(f"开始批量分析 {len(session_ids)} 个会话")

        # 创建分析任务
        tasks = []
        for session_id in session_ids:
            task = self._analyze_single_with_retry(
                session_id=session_id,
                provider=request.provider,
                model=request.model,
                include_context=request.include_context,
                max_context_packets=request.max_context_packets,
                max_retries=2
            )
            tasks.append(task)

        # 并发执行
        results = []
        if tasks:
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # 处理结果
            for result in batch_results:
                if isinstance(result, Exception):
                    logger.error(f"批量分析任务失败: {result}")
                elif result:
                    results.append(result)

        # 生成汇总报告
        if results:
            summary = self._generate_batch_summary(results)
            logger.info(summary)

        logger.info(f"批量分析完成，耗时: {time.time() - self._start_time:.2f} 秒")
        return results

    async def _analyze_single_with_retry(
        self,
        session_id: str,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        include_context: bool = True,
        max_context_packets: int = 5,
        max_retries: int = 2
    ) -> Optional[AIAnalysisResult]:
        """带重试的单个会话分析"""
        for attempt in range(max_retries + 1):
            try:
                return await self._analyze_single(
                    session_id=session_id,
                    provider=provider,
                    model=model,
                    include_context=include_context,
                    max_context_packets=max_context_packets
                )
            except Exception as e:
                if attempt < max_retries:
                    wait_time = 2 ** attempt  # 指数退避
                    logger.warning(f"分析会话 {session_id} 失败，第 {attempt + 1} 次重试，等待 {wait_time} 秒: {e}")
                    await asyncio.sleep(wait_time)
                else:
                    logger.error(f"分析会话 {session_id} 失败，已达到最大重试次数: {e}")
                    return None

        return None

    async def _analyze_single(
        self,
        session_id: str,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        include_context: bool = True,
        max_context_packets: int = 5
    ) -> Optional[AIAnalysisResult]:
        """分析单个会话"""
        try:
            # 获取会话数据（这里需要从数据库或缓存中获取）
            session_data = await self._get_session_data(session_id)
            if not session_data:
                logger.warning(f"未找到会话数据: {session_id}")
                return None

            # 获取相关会话（用于上下文）
            related_sessions = []
            if include_context:
                related_sessions = await self._get_related_sessions(
                    session_id, max_context_packets
                )

            # 构建上下文
            context = self.context_builder.build_context(session_data, related_sessions)

            # 获取 Prompt
            prompt = self.prompt_templates.get_template("webshell_analysis", {
                "context": context
            })

            # 调用 AI 分析
            response = await self._call_ai_with_timeout(
                prompt=prompt,
                provider=provider,
                model=model
            )

            # 解析响应
            result = self._parse_ai_response(
                response=response,
                session_id=session_id,
                session_data=session_data,
                provider=provider,
                model=model
            )

            # 更新统计
            self._total_analyzed += 1
            if result.is_webshell:
                self._total_threats += 1

            return result

        except asyncio.TimeoutError:
            logger.error(f"分析会话 {session_id} 超时")
            return self._create_timeout_result(session_id, provider, model)
        except Exception as e:
            logger.error(f"分析会话 {session_id} 失败: {e}")
            return self._create_error_result(session_id, str(e), provider, model)

    async def _get_session_data(self, session_id: str) -> Optional[Any]:
        """
        从 store 获取会话数据
        """
        session = self.sessions_store.get(session_id)
        if not session:
            logger.warning(f"未找到会话数据: {session_id}")
            return None
        # 返回 HttpSession 对象，context_builder.build_context 直接使用它
        return session

    async def _get_related_sessions(self, session_id: str, max_count: int) -> List[Any]:
        """
        从 store 获取相关会话（同源 IP 的最近会话）
        """
        session = self.sessions_store.get(session_id)
        if not session:
            return []
        src_ip = session.packet_info.five_tuple.src_ip
        related = []
        for sid, s in self.sessions_store.items():
            if sid == session_id:
                continue
            if s.packet_info and s.packet_info.five_tuple.src_ip == src_ip:
                related.append(s)
            if len(related) >= max_count:
                break
        return related

    async def _call_ai_with_timeout(
        self,
        prompt: str,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> str:
        """带超时的 AI 调用"""
        try:
            return await asyncio.wait_for(
                self._call_ai(prompt, provider, model),
                timeout=self.timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"AI 调用超时 ({self.timeout} 秒)")
            raise

    async def _call_ai(
        self,
        prompt: str,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> str:
        """调用 AI 服务（实际调用 AIClient）"""
        provider = provider or self.ai_client.default_provider
        model = model or self.ai_client._get_default_model(provider)
        return await self.ai_client._call_ai_api(provider, model, prompt)

    def _parse_ai_response(
        self,
        response: str,
        session_id: str,
        session_data: Any,
        provider: Optional[str],
        model: Optional[str]
    ) -> AIAnalysisResult:
        """解析 AI 响应"""
        try:
            import json
            # 尝试提取 JSON（处理 markdown ```json ... ``` 包装）
            text = response.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                start = 0
                for i, line in enumerate(lines):
                    if line.strip().startswith("```"):
                        start = i + 1
                        break
                end = len(lines)
                for i in range(len(lines) - 1, start - 1, -1):
                    if lines[i].strip().startswith("```"):
                        end = i
                        break
                text = "\n".join(lines[start:end]).strip()
            data = json.loads(text)

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
                analysis_time=datetime.now(),
                provider=provider or self.ai_client.default_provider,
                model=model or self.ai_client._get_default_model(provider or self.ai_client.default_provider),
                raw_response=response[:2000]
            )

        except json.JSONDecodeError:
            return self._parse_text_response(
                response, session_id, session_data, provider, model
            )
        except Exception as e:
            logger.error(f"解析 AI 响应失败: {e}")
            return self._create_error_result(session_id, f"解析失败: {str(e)}", provider, model)

    def _parse_threat_level(self, level_str: str) -> ThreatLevel:
        """解析威胁等级字符串"""
        level_str = level_str.lower()
        if level_str in ["high", "高危", "严重"]:
            return ThreatLevel.HIGH
        elif level_str in ["medium", "中危", "中等"]:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _create_timeout_result(
        self,
        session_id: str,
        provider: Optional[str],
        model: Optional[str]
    ) -> AIAnalysisResult:
        """创建超时结果"""
        return AIAnalysisResult(
            session_id=session_id,
            is_webshell=False,
            confidence=0.0,
            tool_type="未知",
            attack_intent="未知",
            payload="",
            commands=[],
            threat_level=ThreatLevel.LOW,
            recommendations=["AI 分析超时，建议人工检查"],
            analysis_time=datetime.now(),
            provider=provider or self.ai_client.default_provider,
            model=model or "unknown",
            raw_response="分析超时"
        )

    def _create_error_result(
        self,
        session_id: str,
        error: str,
        provider: Optional[str],
        model: Optional[str]
    ) -> AIAnalysisResult:
        """创建错误结果"""
        return AIAnalysisResult(
            session_id=session_id,
            is_webshell=False,
            confidence=0.0,
            tool_type="未知",
            attack_intent="未知",
            payload="",
            commands=[],
            threat_level=ThreatLevel.LOW,
            recommendations=[f"分析失败: {error}"],
            analysis_time=datetime.now(),
            provider=provider or self.ai_client.default_provider,
            model=model or "unknown",
            raw_response=f"分析错误: {error}"
        )

    def _generate_batch_summary(self, results: List[AIAnalysisResult]) -> str:
        """生成批量分析汇总报告"""
        total = len(results)
        webshell_count = sum(1 for r in results if r.is_webshell)
        high_threat = sum(1 for r in results if r.threat_level == ThreatLevel.HIGH)
        medium_threat = sum(1 for r in results if r.threat_level == ThreatLevel.MEDIUM)
        
        # 工具统计
        tool_stats = {}
        for result in results:
            if result.is_webshell:
                tool = result.tool_type
                tool_stats[tool] = tool_stats.get(tool, 0) + 1
        
        # 攻击意图统计
        intent_stats = {}
        for result in results:
            if result.is_webshell:
                intent = result.attack_intent
                intent_stats[intent] = intent_stats.get(intent, 0) + 1
        
        summary = [
            "=== 批量分析汇总报告 ===",
            f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"总耗时: {time.time() - self._start_time:.2f} 秒",
            f"分析会话数: {total}",
            f"WebShell 检测数: {webshell_count} ({webshell_count/total*100:.1f}%)",
            f"高危威胁: {high_threat}",
            f"中危威胁: {medium_threat}",
            "",
            "=== 工具分布 ===",
        ]
        
        for tool, count in sorted(tool_stats.items(), key=lambda x: x[1], reverse=True):
            summary.append(f"  {tool}: {count} ({count/webshell_count*100:.1f}%)")
        
        if intent_stats:
            summary.append("")
            summary.append("=== 攻击意图分布 ===")
            for intent, count in sorted(intent_stats.items(), key=lambda x: x[1], reverse=True):
                summary.append(f"  {intent}: {count}")
        
        # 置信度统计
        if results:
            avg_confidence = sum(r.confidence for r in results if r.is_webshell) / max(webshell_count, 1)
            summary.append("")
            summary.append(f"平均置信度: {avg_confidence:.3f}")
        
        return "\n".join(summary)

    async def analyze_with_progress(
        self,
        request: AIAnalysisRequest,
        progress_callback = None
    ) -> List[AIAnalysisResult]:
        """
        带进度回调的批量分析
        """
        if not request.session_ids:
            return []

        results = []
        total = len(request.session_ids)
        
        for i, session_id in enumerate(request.session_ids):
            try:
                result = await self._analyze_single_with_retry(
                    session_id=session_id,
                    provider=request.provider,
                    model=request.model,
                    include_context=request.include_context,
                    max_context_packets=request.max_context_packets
                )
                
                if result:
                    results.append(result)
                
                # 回调进度
                if progress_callback:
                    await progress_callback(i + 1, total, result)
                    
            except Exception as e:
                logger.error(f"分析会话 {session_id} 失败: {e}")
                if progress_callback:
                    await progress_callback(i + 1, total, None)
        
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_analyzed": self._total_analyzed,
            "total_threats": self._total_threats,
            "threat_ratio": self._total_threats / max(self._total_analyzed, 1),
            "batch_concurrency": self.batch_concurrency,
            "rate_limit": self.rate_limit,
            "timeout": self.timeout,
        }

    async def test_ai_connection(self) -> bool:
        """测试 AI 服务连接"""
        try:
            return await self.ai_client.test_connection()
        except Exception as e:
            logger.error(f"测试 AI 连接失败: {e}")
            return False

    async def close(self):
        """关闭资源"""
        await self.ai_client.close()