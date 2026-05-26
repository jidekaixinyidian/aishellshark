# -*- coding: utf-8 -*-
"""
上下文构建器
自动拼接请求/响应头、Body、五元组、时间戳、前后关联包
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from loguru import logger

from backend.models.schemas import HttpSession


class ContextBuilder:
    """
    上下文构建器
    为 AI 分析准备完整的会话上下文
    """

    def __init__(self, max_context_packets: int = 5):
        self.max_context_packets = max_context_packets

    def build_context(self, session: HttpSession, related_sessions: List[HttpSession] = None) -> str:
        """
        构建完整的分析上下文
        """
        context_parts = []

        # 1. 会话基本信息
        context_parts.append(self._build_session_info(session))

        # 2. 请求信息
        if session.request:
            context_parts.append(self._build_request_info(session.request))

        # 3. 响应信息
        if session.response:
            context_parts.append(self._build_response_info(session.response))

        # 4. 相关会话信息
        if related_sessions:
            context_parts.append(self._build_related_sessions_info(related_sessions))

        # 5. 分析提示
        context_parts.append(self._build_analysis_prompt())

        return "\n\n".join(context_parts)

    def _build_session_info(self, session: HttpSession) -> str:
        """构建会话基本信息"""
        info = [
            "=== 会话基本信息 ===",
            f"会话ID: {session.session_id}",
            f"时间戳: {session.packet_info.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')}",
            f"持续时间: {session.duration_ms:.1f} ms" if session.duration_ms else "持续时间: 未知",
            f"是否HTTPS: {'是' if session.is_https else '否'}",
            "",
            "=== 网络五元组 ===",
            f"源IP: {session.packet_info.five_tuple.src_ip}",
            f"源端口: {session.packet_info.five_tuple.src_port}",
            f"目的IP: {session.packet_info.five_tuple.dst_ip}",
            f"目的端口: {session.packet_info.five_tuple.dst_port}",
            f"协议: {session.packet_info.five_tuple.protocol}",
        ]

        return "\n".join(info)

    def _build_request_info(self, request) -> str:
        """构建请求信息"""
        info = [
            "=== HTTP 请求 ===",
            f"方法: {request.method}",
            f"URI: {request.uri}",
            f"版本: {request.version}",
            f"User-Agent: {request.user_agent or '无'}",
            f"Content-Type: {request.content_type or '无'}",
            f"Content-Length: {request.content_length or '0'}",
            f"Cookie: {request.cookie[:200] + '...' if request.cookie and len(request.cookie) > 200 else request.cookie or '无'}",
        ]

        # 请求头（重要部分）
        if request.headers:
            info.append("")
            info.append("=== 请求头（重要） ===")
            important_headers = [
                "host", "accept", "accept-encoding", "accept-language",
                "connection", "cache-control", "upgrade-insecure-requests",
                "x-forwarded-for", "x-real-ip", "referer", "origin"
            ]
            for header in important_headers:
                if header in request.headers:
                    info.append(f"{header}: {request.headers[header]}")

        # 请求体
        if request.body:
            info.append("")
            info.append("=== 请求体 ===")
            body_info = self._format_body(request.body, request.body_decoded, request.decoded_body)
            info.append(body_info)

        # 解码后的请求体
        if request.decoded_body and request.decoded_body != (request.body_decoded or ""):
            info.append("")
            info.append("=== 解码后的请求体 ===")
            info.append(request.decoded_body[:1000])

        return "\n".join(info)

    def _build_response_info(self, response) -> str:
        """构建响应信息"""
        info = [
            "=== HTTP 响应 ===",
            f"状态码: {response.status_code}",
            f"状态描述: {getattr(response, 'status_message', response.reason if hasattr(response, 'reason') else '')}",
            f"版本: {response.version}",
            f"Content-Type: {response.content_type or '无'}",
            f"Content-Length: {response.content_length or '0'}",
        ]

        # 响应头（重要部分）
        if response.headers:
            info.append("")
            info.append("=== 响应头（重要） ===")
            important_headers = [
                "server", "date", "content-type", "content-length",
                "connection", "cache-control", "set-cookie",
                "location", "x-powered-by", "x-frame-options"
            ]
            for header in important_headers:
                if header in response.headers:
                    info.append(f"{header}: {response.headers[header]}")

        # 响应体
        if response.body:
            info.append("")
            info.append("=== 响应体 ===")
            body_info = self._format_body(response.body, response.body_decoded, None)
            info.append(body_info)

        # 解码后的响应体
        if response.body_decoded and len(response.body_decoded) > 0:
            info.append("")
            info.append("=== 解码后的响应体 ===")
            info.append(response.body_decoded[:1000])

        return "\n".join(info)

    def _format_body(self, raw_body: bytes, decoded_body: str, extra_decoded: str = None) -> str:
        """格式化请求体/响应体"""
        if not raw_body:
            return "（空）"

        # 尝试多种格式显示
        lines = []

        # 原始字节信息
        lines.append(f"原始大小: {len(raw_body)} 字节")

        # 尝试显示为文本
        if decoded_body:
            lines.append("")
            lines.append("文本内容:")
            lines.append(decoded_body[:500])
            if len(decoded_body) > 500:
                lines.append(f"...（还有 {len(decoded_body) - 500} 个字符）")

        # 额外解码内容
        if extra_decoded and extra_decoded != decoded_body:
            lines.append("")
            lines.append("额外解码内容:")
            lines.append(extra_decoded[:500])
            if len(extra_decoded) > 500:
                lines.append(f"...（还有 {len(extra_decoded) - 500} 个字符）")

        # 十六进制视图（前100字节）
        if len(raw_body) > 0:
            lines.append("")
            lines.append("十六进制视图（前100字节）:")
            hex_str = raw_body[:100].hex()
            # 每32个字符（16字节）换行
            for i in range(0, min(len(hex_str), 200), 32):
                lines.append(hex_str[i:i+32])

        return "\n".join(lines)

    def _build_related_sessions_info(self, related_sessions: List[HttpSession]) -> str:
        """构建相关会话信息"""
        if not related_sessions:
            return ""

        info = [
            "=== 相关会话（前后关联） ===",
            f"共找到 {len(related_sessions)} 个相关会话",
            ""
        ]

        for i, related_session in enumerate(related_sessions[:self.max_context_packets], 1):
            info.append(f"--- 相关会话 #{i} ---")
            info.append(f"时间偏移: {(related_session.packet_info.timestamp - related_sessions[0].packet_info.timestamp).total_seconds():.3f} 秒")

            if related_session.request:
                info.append(f"请求: {related_session.request.method} {related_session.request.uri}")
                if related_session.request.body and len(related_session.request.body) > 0:
                    body_preview = related_session.request.body_decoded or related_session.request.body[:100].hex()
                    info.append(f"请求体预览: {body_preview[:100]}...")

            if related_session.response:
                info.append(f"响应: {related_session.response.status_code} {related_session.response.reason}")
                if related_session.response.body and len(related_session.response.body) > 0:
                    body_preview = related_session.response.body_decoded or related_session.response.body[:100].hex()
                    info.append(f"响应体预览: {body_preview[:100]}...")

            info.append("")

        return "\n".join(info)

    def _build_analysis_prompt(self) -> str:
        """构建分析提示"""
        prompt = [
            "=== 分析要求 ===",
            "请基于以上 HTTP 流量数据进行分析，回答以下问题：",
            "",
            "1. 判断是否为 WebShell 通信流量？置信度是多少（0-1）？",
            "2. 识别具体工具类型（菜刀/蚁剑/冰蝎/哥斯拉/Weevely3/自定义/未知）？",
            "3. 分析攻击意图（命令执行/文件上传/数据库操作/权限维持/内网扫描/其他）？",
            "4. 提取关键攻击载荷和执行的命令原文？",
            "5. 给出处置建议和威胁等级（高/中/低）？",
            "",
            "请以 JSON 格式回答，包含以下字段：",
            "- is_webshell: boolean",
            "- confidence: float (0-1)",
            "- tool_type: string",
            "- attack_intent: string",
            "- payload: string",
            "- commands: array of strings",
            "- threat_level: string (high/medium/low)",
            "- recommendations: array of strings",
            "",
            "如果无法确定某些信息，请使用合理的默认值。",
        ]

        return "\n".join(prompt)

    def build_batch_context(self, sessions: List[HttpSession]) -> List[str]:
        """为批量分析构建上下文"""
        contexts = []
        for session in sessions:
            context = self.build_context(session)
            contexts.append(context)
        return contexts

    def build_summary_context(self, sessions: List[HttpSession]) -> str:
        """为汇总分析构建上下文"""
        if not sessions:
            return "无会话数据"

        info = [
            "=== 批量分析汇总 ===",
            f"总会话数: {len(sessions)}",
            f"时间范围: {sessions[0].packet_info.timestamp.strftime('%Y-%m-%d %H:%M:%S')} - {sessions[-1].packet_info.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "=== 会话概览 ===",
        ]

        # 按源IP分组
        ip_groups = {}
        for session in sessions:
            src_ip = session.packet_info.five_tuple.src_ip
            if src_ip not in ip_groups:
                ip_groups[src_ip] = []
            ip_groups[src_ip].append(session)

        for src_ip, ip_sessions in ip_groups.items():
            info.append(f"")
            info.append(f"源IP: {src_ip}")
            info.append(f"  会话数: {len(ip_sessions)}")
            
            # 统计请求方法
            methods = {}
            for session in ip_sessions:
                if session.request:
                    method = session.request.method
                    methods[method] = methods.get(method, 0) + 1
            
            if methods:
                method_str = ", ".join([f"{k}: {v}" for k, v in methods.items()])
                info.append(f"  请求方法: {method_str}")

            # 统计目标端口
            ports = {}
            for session in ip_sessions:
                dst_port = session.packet_info.five_tuple.dst_port
                ports[dst_port] = ports.get(dst_port, 0) + 1
            
            if ports:
                port_str = ", ".join([f"{k}: {v}" for k, v in ports.items()])
                info.append(f"  目标端口: {port_str}")

        # 可疑特征统计
        info.append("")
        info.append("=== 可疑特征统计 ===")
        
        suspicious_features = {
            "POST请求": 0,
            "大请求体(>10KB)": 0,
            "非常见端口": 0,
            "异常User-Agent": 0,
            "加密/编码数据": 0,
        }

        for session in sessions:
            if session.request:
                if session.request.method == "POST":
                    suspicious_features["POST请求"] += 1
                
                if session.request.body and len(session.request.body) > 10240:
                    suspicious_features["大请求体(>10KB)"] += 1
                
                if session.request.user_agent:
                    ua = session.request.user_agent.lower()
                    if "python" in ua or "curl" in ua or "wget" in ua or not ua:
                        suspicious_features["异常User-Agent"] += 1
                
                # 检查端口
                dst_port = session.packet_info.five_tuple.dst_port
                if dst_port not in [80, 443, 8080, 8443]:
                    suspicious_features["非常见端口"] += 1
                
                # 检查编码数据
                if session.request.decoded_body and "base64" in session.request.decoded_body.lower():
                    suspicious_features["加密/编码数据"] += 1

        for feature, count in suspicious_features.items():
            if count > 0:
                info.append(f"  {feature}: {count}")

        # 分析提示
        info.append("")
        info.append("=== 分析要求 ===")
        info.append("请基于以上批量会话数据进行分析，回答以下问题：")
        info.append("")
        info.append("1. 整体威胁评估：这些会话中 WebShell 流量的比例？")
        info.append("2. 主要攻击工具：最可能使用的 WebShell 工具？")
        info.append("3. 攻击模式：主要的攻击意图和模式？")
        info.append("4. 关键发现：最重要的安全发现？")
        info.append("5. 处置建议：整体的安全建议？")
        info.append("")
        info.append("请提供详细的文本分析报告。")

        return "\n".join(info)

    def extract_key_indicators(self, session: HttpSession) -> Dict[str, Any]:
        """提取关键指标供 AI 分析参考"""
        indicators = {
            "suspicious_indicators": [],
            "encryption_indicators": [],
            "behavior_indicators": [],
            "tool_indicators": [],
        }

        if not session.request:
            return indicators

        # 可疑指标
        if session.request.method == "POST":
            indicators["suspicious_indicators"].append("POST请求")
        
        if session.request.body and len(session.request.body) > 10240:
            indicators["suspicious_indicators"].append("大请求体")
        
        if not session.request.user_agent or session.request.user_agent.strip() == "":
            indicators["suspicious_indicators"].append("空User-Agent")
        elif any(x in session.request.user_agent.lower() for x in ["python", "curl", "wget"]):
            indicators["suspicious_indicators"].append("自动化工具User-Agent")

        # 加密指标
        if session.request.decoded_body:
            decoded_lower = session.request.decoded_body.lower()
            if "base64" in decoded_lower:
                indicators["encryption_indicators"].append("Base64编码")
            if "eval(" in decoded_lower:
                indicators["encryption_indicators"].append("eval函数")
            if "exec(" in decoded_lower or "system(" in decoded_lower:
                indicators["encryption_indicators"].append("命令执行函数")

        # 工具指标
        ua = session.request.user_agent or ""
        ua_lower = ua.lower()
        if "antsword" in ua_lower:
            indicators["tool_indicators"].append("蚁剑")
        elif "msie 9.0" in ua_lower:
            indicators["tool_indicators"].append("冰蝎")
        elif "godzilla" in ua_lower:
            indicators["tool_indicators"].append("哥斯拉")

        # 行为指标
        if session.duration_ms and session.duration_ms < 100:
            indicators["behavior_indicators"].append("快速响应")
        
        if session.response and session.response.status_code == 200:
            if session.response.body and len(session.response.body) < 100:
                indicators["behavior_indicators"].append("短响应体")

        return indicators