# -*- coding: utf-8 -*-
"""
TCP 会话重组与管理
将 TCP 流重组为完整的 HTTP 请求/响应对
"""

import uuid
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, Optional, List, Tuple
from loguru import logger

from backend.models.schemas import (
    HttpSession, PacketInfo, FiveTuple, HttpRequest, HttpResponse
)
from backend.core.protocol_parser import ProtocolParser


class TcpStream:
    """TCP 流状态"""

    def __init__(self, stream_id: str, five_tuple: FiveTuple):
        self.stream_id = stream_id
        self.five_tuple = five_tuple
        self.created_at = time.time()
        self.last_seen = time.time()

        # 请求方向缓冲区（客户端 -> 服务器）
        self.request_buffer = b""
        # 响应方向缓冲区（服务器 -> 客户端）
        self.response_buffer = b""

        # 已完成的 HTTP 会话列表
        self.completed_sessions: List[HttpSession] = []

        # 当前请求包信息
        self.current_request_info: Optional[PacketInfo] = None

        # 是否已关闭
        self.is_closed = False

    def update(self):
        """更新最后活跃时间"""
        self.last_seen = time.time()

    def is_expired(self, timeout: float) -> bool:
        """检查是否超时"""
        return (time.time() - self.last_seen) > timeout


class SessionManager:
    """
    TCP 会话管理器
    负责 TCP 流重组和 HTTP 会话提取
    """

    def __init__(self, config: dict):
        self.config = config
        self.session_timeout = config.get("session_timeout", 3600)
        self.protocol_parser = ProtocolParser()

        # TCP 流字典 {stream_key: TcpStream}
        self._streams: Dict[str, TcpStream] = {}

        # 已完成的 HTTP 会话列表
        self._completed_sessions: List[HttpSession] = []

        # 清理计数器
        self._cleanup_counter = 0
        self._cleanup_interval = 100  # 每 100 个包清理一次

        logger.info("会话管理器初始化完成")

    async def process_packet(
        self,
        packet_info: PacketInfo,
        payload: bytes
    ) -> Optional[HttpSession]:
        """
        处理数据包，尝试重组 HTTP 会话
        返回完整的 HTTP 会话（如果重组完成）
        """
        if not payload:
            return None

        # 定期清理过期会话
        self._cleanup_counter += 1
        if self._cleanup_counter >= self._cleanup_interval:
            self._cleanup_expired_streams()
            self._cleanup_counter = 0

        five_tuple = packet_info.five_tuple
        stream_key = self._get_stream_key(five_tuple)
        reverse_key = self._get_reverse_stream_key(five_tuple)

        # 获取或创建 TCP 流
        stream = self._streams.get(stream_key)
        if stream is None:
            # 检查是否为反向流
            stream = self._streams.get(reverse_key)
            if stream is None:
                # 创建新流
                stream = TcpStream(
                    stream_id=str(uuid.uuid4()),
                    five_tuple=five_tuple
                )
                self._streams[stream_key] = stream

        stream.update()

        # 判断数据方向
        is_request = self._is_request_direction(five_tuple, stream)

        if is_request:
            # 客户端 -> 服务器（请求）
            stream.request_buffer += payload
            stream.current_request_info = packet_info

            # 尝试解析 HTTP 请求
            session = self._try_extract_session(stream, packet_info)
            if session:
                return session
        else:
            # 服务器 -> 客户端（响应）
            stream.response_buffer += payload

            # 尝试解析 HTTP 响应并配对
            session = self._try_extract_session(stream, packet_info)
            if session:
                return session

        return None

    def _try_extract_session(
        self,
        stream: TcpStream,
        packet_info: PacketInfo
    ) -> Optional[HttpSession]:
        """尝试从缓冲区提取完整的 HTTP 会话"""
        # 尝试解析请求
        if stream.request_buffer:
            request = self.protocol_parser.parse_http_request(stream.request_buffer)
            if request:
                # 尝试解析响应
                response = None
                if stream.response_buffer:
                    response = self.protocol_parser.parse_http_response(stream.response_buffer)

                # 构建会话
                session = self._build_session(stream, request, response, packet_info)

                # 清空缓冲区（简单处理，实际应处理 HTTP 管道化）
                stream.request_buffer = b""
                stream.response_buffer = b""

                return session

        return None

    def _build_session(
        self,
        stream: TcpStream,
        request: HttpRequest,
        response: Optional[HttpResponse],
        packet_info: PacketInfo
    ) -> HttpSession:
        """构建 HTTP 会话对象"""
        session_id = str(uuid.uuid4())

        # 计算会话持续时间
        duration_ms = None
        if stream.current_request_info:
            req_time = stream.current_request_info.timestamp.timestamp()
            resp_time = packet_info.timestamp.timestamp()
            duration_ms = (resp_time - req_time) * 1000

        # 判断是否为 HTTPS
        dst_port = stream.five_tuple.dst_port
        is_https = dst_port in (443, 8443)

        session = HttpSession(
            session_id=session_id,
            packet_info=packet_info,
            request=request,
            response=response,
            duration_ms=duration_ms,
            is_https=is_https
        )

        return session

    def _is_request_direction(self, five_tuple: FiveTuple, stream: TcpStream) -> bool:
        """
        判断数据包方向
        通常目标端口为 HTTP 端口（80/443/8080 等）时为请求方向
        """
        http_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
        return five_tuple.dst_port in http_ports

    def _get_stream_key(self, five_tuple: FiveTuple) -> str:
        """生成 TCP 流键"""
        return f"{five_tuple.src_ip}:{five_tuple.src_port}-{five_tuple.dst_ip}:{five_tuple.dst_port}"

    def _get_reverse_stream_key(self, five_tuple: FiveTuple) -> str:
        """生成反向 TCP 流键"""
        return f"{five_tuple.dst_ip}:{five_tuple.dst_port}-{five_tuple.src_ip}:{five_tuple.src_port}"

    def _cleanup_expired_streams(self):
        """清理过期的 TCP 流"""
        expired_keys = [
            key for key, stream in self._streams.items()
            if stream.is_expired(self.session_timeout)
        ]

        for key in expired_keys:
            del self._streams[key]

        if expired_keys:
            logger.debug(f"清理了 {len(expired_keys)} 个过期 TCP 流")

    def get_active_streams(self) -> int:
        """获取活跃 TCP 流数量"""
        return len(self._streams)

    def get_statistics(self) -> dict:
        """获取会话管理统计信息"""
        return {
            "active_streams": len(self._streams),
            "completed_sessions": len(self._completed_sessions),
        }

    def reset(self):
        """重置会话管理器"""
        self._streams.clear()
        self._completed_sessions.clear()
        logger.info("会话管理器已重置")
