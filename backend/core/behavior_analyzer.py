# -*- coding: utf-8 -*-
"""
行为分析模块
检测非工作时段高频连接、固定心跳间隔、POST 大小异常、静态文件接收 POST 等
"""

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from loguru import logger

from backend.models.schemas import (
    HttpSession, BehaviorAlert, ThreatLevel, FiveTuple
)


class ConnectionTracker:
    """连接频率追踪器"""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # {ip: deque of timestamps}
        self._timestamps: Dict[str, deque] = defaultdict(lambda: deque())

    def record(self, ip: str) -> int:
        """记录连接并返回当前窗口内的连接数"""
        now = time.time()
        timestamps = self._timestamps[ip]

        # 清理过期记录
        cutoff = now - self.window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        timestamps.append(now)
        return len(timestamps)

    def get_count(self, ip: str) -> int:
        """获取当前窗口内的连接数"""
        now = time.time()
        timestamps = self._timestamps[ip]
        cutoff = now - self.window_seconds
        return sum(1 for t in timestamps if t >= cutoff)


class HeartbeatDetector:
    """心跳间隔检测器"""

    def __init__(self, window_size: int = 10, tolerance: float = 5.0):
        self.window_size = window_size
        self.tolerance = tolerance
        # {session_key: deque of timestamps}
        self._intervals: Dict[str, deque] = defaultdict(lambda: deque(maxlen=window_size))

    def record(self, session_key: str, timestamp: float) -> Optional[float]:
        """
        记录时间戳，返回检测到的心跳间隔（如果存在）
        """
        intervals = self._intervals[session_key]

        if intervals:
            last_time = intervals[-1]
            interval = timestamp - last_time
            intervals.append(timestamp)

            # 检查是否存在固定间隔
            if len(intervals) >= 3:
                return self._check_fixed_interval(session_key)
        else:
            intervals.append(timestamp)

        return None

    def _check_fixed_interval(self, session_key: str) -> Optional[float]:
        """检查是否存在固定心跳间隔"""
        timestamps = list(self._intervals[session_key])
        if len(timestamps) < 3:
            return None

        # 计算相邻时间戳的间隔
        diffs = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        if not diffs:
            return None

        avg_diff = sum(diffs) / len(diffs)

        # 检查间隔是否稳定（标准差小于容差）
        variance = sum((d - avg_diff) ** 2 for d in diffs) / len(diffs)
        std_dev = variance ** 0.5

        if std_dev < self.tolerance and avg_diff > 0:
            return avg_diff

        return None


class BehaviorAnalyzer:
    """
    行为分析器
    基于统计和规则检测异常行为模式
    """

    # 静态文件扩展名（不应接收 POST 请求）
    STATIC_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".pdf", ".zip", ".rar", ".tar", ".gz",
        ".mp3", ".mp4", ".avi", ".mov",
    }

    # 可疑 URI 路径
    SUSPICIOUS_PATHS = [
        "/shell", "/cmd", "/exec", "/upload", "/webshell",
        "/backdoor", "/hack", "/exploit", "/payload",
        "/c.php", "/s.php", "/x.php", "/1.php", "/test.php",
        "/info.php", "/phpinfo.php", "/config.php",
    ]

    def __init__(self, config: dict):
        self.config = config
        self.off_hours_start = config.get("off_hours_start", 22)
        self.off_hours_end = config.get("off_hours_end", 6)
        self.high_freq_threshold = config.get("high_freq_threshold", 30)
        self.heartbeat_window = config.get("heartbeat_window", 300)
        self.heartbeat_tolerance = config.get("heartbeat_tolerance", 5)
        self.large_post_threshold = config.get("large_post_threshold", 102400)

        # 追踪器
        self.connection_tracker = ConnectionTracker(window_seconds=60)
        self.heartbeat_detector = HeartbeatDetector(
            tolerance=self.heartbeat_tolerance
        )

        # 会话历史 {src_ip: list of session info}
        self._session_history: Dict[str, List[dict]] = defaultdict(list)

        logger.info("行为分析器初始化完成")

    def analyze(self, session: HttpSession) -> List[BehaviorAlert]:
        """
        分析 HTTP 会话的行为特征
        返回告警列表
        """
        alerts = []

        if not session.request:
            return alerts

        src_ip = session.packet_info.five_tuple.src_ip
        timestamp = session.packet_info.timestamp

        # 记录会话历史
        self._record_session(src_ip, session)

        # 1. 检测非工作时段访问
        alert = self._check_off_hours(timestamp, src_ip)
        if alert:
            alerts.append(alert)

        # 2. 检测高频连接
        alert = self._check_high_frequency(src_ip)
        if alert:
            alerts.append(alert)

        # 3. 检测心跳间隔
        alert = self._check_heartbeat(src_ip, timestamp.timestamp())
        if alert:
            alerts.append(alert)

        # 4. 检测 POST 大小异常
        alert = self._check_large_post(session)
        if alert:
            alerts.append(alert)

        # 5. 检测静态文件接收 POST
        alert = self._check_static_post(session)
        if alert:
            alerts.append(alert)

        # 6. 检测可疑 URI
        alert = self._check_suspicious_uri(session)
        if alert:
            alerts.append(alert)

        # 7. 检测响应异常
        alert = self._check_response_anomaly(session)
        if alert:
            alerts.append(alert)

        # 8. 检测 Cookie 异常
        alert = self._check_cookie_anomaly(session)
        if alert:
            alerts.append(alert)

        return alerts

    def _record_session(self, src_ip: str, session: HttpSession):
        """记录会话到历史"""
        history = self._session_history[src_ip]
        history.append({
            "timestamp": session.packet_info.timestamp.timestamp(),
            "uri": session.request.uri if session.request else "",
            "method": session.request.method if session.request else "",
            "body_size": len(session.request.body) if session.request and session.request.body else 0,
        })

        # 只保留最近 1000 条记录
        if len(history) > 1000:
            self._session_history[src_ip] = history[-1000:]

        # 记录连接频率
        self.connection_tracker.record(src_ip)

    def _check_off_hours(self, timestamp: datetime, src_ip: str) -> Optional[BehaviorAlert]:
        """检测非工作时段访问"""
        hour = timestamp.hour

        is_off_hours = False
        if self.off_hours_start > self.off_hours_end:
            # 跨午夜（如 22:00 - 06:00）
            is_off_hours = hour >= self.off_hours_start or hour < self.off_hours_end
        else:
            is_off_hours = self.off_hours_start <= hour < self.off_hours_end

        if is_off_hours:
            return BehaviorAlert(
                alert_type="off_hours_access",
                description=f"非工作时段访问（{hour:02d}:xx），可能为自动化攻击",
                severity=ThreatLevel.LOW,
                details={
                    "hour": hour,
                    "src_ip": src_ip,
                    "off_hours_range": f"{self.off_hours_start:02d}:00 - {self.off_hours_end:02d}:00"
                }
            )
        return None

    def _check_high_frequency(self, src_ip: str) -> Optional[BehaviorAlert]:
        """检测高频连接"""
        count = self.connection_tracker.get_count(src_ip)

        if count >= self.high_freq_threshold:
            severity = ThreatLevel.HIGH if count >= self.high_freq_threshold * 2 else ThreatLevel.MEDIUM
            return BehaviorAlert(
                alert_type="high_frequency_connection",
                description=f"高频连接检测：{src_ip} 在 60 秒内发起 {count} 次请求",
                severity=severity,
                details={
                    "src_ip": src_ip,
                    "count": count,
                    "threshold": self.high_freq_threshold,
                    "window_seconds": 60
                }
            )
        return None

    def _check_heartbeat(self, src_ip: str, timestamp: float) -> Optional[BehaviorAlert]:
        """检测固定心跳间隔"""
        interval = self.heartbeat_detector.record(src_ip, timestamp)

        if interval is not None and 5 <= interval <= 300:  # 5秒到5分钟的心跳
            return BehaviorAlert(
                alert_type="fixed_heartbeat",
                description=f"检测到固定心跳间隔：{src_ip} 每 {interval:.1f} 秒发送一次请求",
                severity=ThreatLevel.MEDIUM,
                details={
                    "src_ip": src_ip,
                    "interval_seconds": round(interval, 2),
                    "tolerance": self.heartbeat_tolerance
                }
            )
        return None

    def _check_large_post(self, session: HttpSession) -> Optional[BehaviorAlert]:
        """检测 POST 请求体过大"""
        if not session.request:
            return None

        if session.request.method != "POST":
            return None

        body_size = len(session.request.body) if session.request.body else 0

        if body_size > self.large_post_threshold:
            severity = ThreatLevel.HIGH if body_size > self.large_post_threshold * 10 else ThreatLevel.MEDIUM
            return BehaviorAlert(
                alert_type="large_post_body",
                description=f"POST 请求体异常大：{body_size / 1024:.1f} KB",
                severity=severity,
                details={
                    "body_size": body_size,
                    "threshold": self.large_post_threshold,
                    "uri": session.request.uri
                }
            )
        return None

    def _check_static_post(self, session: HttpSession) -> Optional[BehaviorAlert]:
        """检测静态文件接收 POST 请求"""
        if not session.request:
            return None

        if session.request.method != "POST":
            return None

        uri = session.request.uri.lower()
        # 去除查询参数
        path = uri.split("?")[0]

        # 检查文件扩展名
        for ext in self.STATIC_EXTENSIONS:
            if path.endswith(ext):
                return BehaviorAlert(
                    alert_type="static_file_post",
                    description=f"静态文件接收 POST 请求：{session.request.uri}",
                    severity=ThreatLevel.HIGH,
                    details={
                        "uri": session.request.uri,
                        "extension": ext,
                        "method": "POST"
                    }
                )
        return None

    def _check_suspicious_uri(self, session: HttpSession) -> Optional[BehaviorAlert]:
        """检测可疑 URI"""
        if not session.request:
            return None

        uri = session.request.uri.lower()

        for suspicious_path in self.SUSPICIOUS_PATHS:
            if suspicious_path in uri:
                return BehaviorAlert(
                    alert_type="suspicious_uri",
                    description=f"访问可疑路径：{session.request.uri}",
                    severity=ThreatLevel.MEDIUM,
                    details={
                        "uri": session.request.uri,
                        "matched_pattern": suspicious_path
                    }
                )

        # 检测单字母 PHP 文件（如 a.php, x.php）
        import re
        if re.search(r'/[a-z]\.(php|asp|aspx|jsp)(\?|$)', uri):
            return BehaviorAlert(
                alert_type="suspicious_uri",
                description=f"访问单字母脚本文件：{session.request.uri}",
                severity=ThreatLevel.MEDIUM,
                details={
                    "uri": session.request.uri,
                    "pattern": "single_letter_script"
                }
            )

        return None

    def _check_response_anomaly(self, session: HttpSession) -> Optional[BehaviorAlert]:
        """检测响应异常"""
        if not session.response:
            return None

        # 检测响应体中的 MD5 哈希（WebShell 心跳响应特征）
        if session.response.body:
            body_str = session.response.body.decode("utf-8", errors="replace")
            import re
            # 检测 32 位 MD5 哈希
            md5_pattern = re.compile(r'^[a-f0-9]{32}$', re.MULTILINE)
            if md5_pattern.search(body_str.strip()):
                return BehaviorAlert(
                    alert_type="md5_response",
                    description="响应体为 MD5 哈希值，疑似 WebShell 心跳响应",
                    severity=ThreatLevel.HIGH,
                    details={
                        "response_body": body_str[:100],
                        "status_code": session.response.status_code
                    }
                )

        # 检测 200 响应但内容极短（可能为 WebShell 执行结果）
        if (session.response.status_code == 200 and
                session.response.body and
                len(session.response.body) < 50 and
                session.request and
                session.request.method == "POST"):
            return BehaviorAlert(
                alert_type="short_post_response",
                description=f"POST 请求收到极短响应（{len(session.response.body)} 字节），疑似命令执行",
                severity=ThreatLevel.MEDIUM,
                details={
                    "response_size": len(session.response.body),
                    "status_code": session.response.status_code
                }
            )

        return None

    def _check_cookie_anomaly(self, session: HttpSession) -> Optional[BehaviorAlert]:
        """检测 Cookie 异常"""
        if not session.request or not session.request.cookie:
            return None

        cookie = session.request.cookie

        # 检测 Cookie 中的 Base64 编码数据（冰蝎特征）
        import re, base64
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{32,}={0,2}')
        matches = b64_pattern.findall(cookie)

        for match in matches:
            try:
                decoded = base64.b64decode(match + "==")
                # 检查是否为二进制数据（可能为加密载荷）
                non_printable = sum(1 for b in decoded if b < 32 or b > 126)
                if non_printable / len(decoded) > 0.3:
                    return BehaviorAlert(
                        alert_type="suspicious_cookie",
                        description="Cookie 中包含疑似加密数据，可能为冰蝎会话密钥",
                        severity=ThreatLevel.HIGH,
                        details={
                            "cookie_snippet": cookie[:200],
                            "base64_match": match[:50]
                        }
                    )
            except Exception:
                pass

        return None

    def get_statistics(self) -> dict:
        """获取行为分析统计信息"""
        return {
            "tracked_ips": len(self._session_history),
            "total_sessions": sum(len(v) for v in self._session_history.values()),
        }
