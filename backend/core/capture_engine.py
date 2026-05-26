# -*- coding: utf-8 -*-
"""
抓包引擎
支持实时网络抓包和离线 PCAP 文件分析
支持 BPF 过滤器、大文件分块处理
"""

import asyncio
import os
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable, AsyncGenerator, List
from loguru import logger

from backend.models.schemas import (
    CaptureStatus, FiveTuple, PacketInfo, HttpSession, HttpRequest,
    CaptureStartRequest, CaptureStatusResponse
)
from backend.core.protocol_parser import ProtocolParser
from backend.core.detection_engine import DetectionEngine
from backend.core.session_manager import SessionManager


class CaptureEngine:
    """
    抓包引擎核心类
    支持实时抓包（scapy/pyshark）和离线 PCAP 分析
    """

    def __init__(self, config: dict):
        self.config = config
        self.status = CaptureStatus.IDLE
        self.interface: Optional[str] = None
        self.bpf_filter: str = ""
        self.packets_captured: int = 0
        self.sessions_detected: int = 0
        self.threats_found: int = 0
        self.started_at: Optional[datetime] = None
        self._stop_event = asyncio.Event()
        self._capture_task: Optional[asyncio.Task] = None

        # 子模块
        self.protocol_parser = ProtocolParser()
        self.detection_engine = DetectionEngine(config.get("detection", {}))
        self.session_manager = SessionManager(config.get("behavior", {}))

        # 回调函数
        self._on_packet_callback: Optional[Callable] = None
        self._on_threat_callback: Optional[Callable] = None

        # PCAP 保存目录
        pcap_dir = config.get("capture", {}).get("pcap_dir", "data/pcap")
        Path(pcap_dir).mkdir(parents=True, exist_ok=True)
        self.pcap_dir = pcap_dir

        # 启动时缓存接口列表
        self._cached_interfaces: List[dict] = []

    # ───────────────────────── 公共方法 ─────────────────────────

    def set_callbacks(self, on_packet: Callable = None, on_threat: Callable = None):
        self._on_packet_callback = on_packet
        self._on_threat_callback = on_threat

    def get_status(self) -> CaptureStatusResponse:
        elapsed = None
        if self.started_at:
            elapsed = (datetime.now() - self.started_at).total_seconds()
        return CaptureStatusResponse(
            status=self.status,
            interface=self.interface,
            filter=self.bpf_filter,
            packets_captured=self.packets_captured,
            sessions_detected=self.sessions_detected,
            threats_found=self.threats_found,
            started_at=self.started_at,
            elapsed_seconds=elapsed
        )

    async def start_live_capture(self, request: CaptureStartRequest) -> str:
        if self.status == CaptureStatus.RUNNING:
            raise RuntimeError("抓包已在运行中")
        self.interface = request.interface or self._auto_select_interface()
        self.bpf_filter = request.bpf_filter or self.config.get("capture", {}).get("default_filter", "")
        self.packets_captured = 0
        self.sessions_detected = 0
        self.threats_found = 0
        self.started_at = datetime.now()
        self._stop_event.clear()
        task_id = str(uuid.uuid4())
        self.status = CaptureStatus.RUNNING
        self._capture_task = asyncio.create_task(self._live_capture_loop(request))
        logger.info(f"实时抓包已启动: interface={self.interface}, filter={self.bpf_filter}")
        return task_id

    async def stop_capture(self):
        if self.status != CaptureStatus.RUNNING:
            return
        self._stop_event.set()
        if self._capture_task:
            self._capture_task.cancel()
            try:
                await self._capture_task
            except asyncio.CancelledError:
                pass
        self.status = CaptureStatus.STOPPED
        logger.info(f"抓包已停止，共捕获 {self.packets_captured} 个包，发现 {self.threats_found} 个威胁")

    # ───────────────────────── 接口探测 ─────────────────────────

    @staticmethod
    def get_interfaces() -> List[dict]:
        """
        获取本机所有网卡接口（多策略探测）
        返回列表，每项含：name / description / ipv4 / mac / is_loopback / is_virtual / status
        """
        interfaces = []
        # 策略1: 优先使用 psutil（最可靠，跨平台）
        try:
            interfaces = CaptureEngine._probe_via_psutil()
            if interfaces:
                return interfaces
        except Exception:
            pass

        # 策略2: Windows WMI
        if sys.platform == "win32":
            try:
                interfaces = CaptureEngine._probe_via_wmi()
                if interfaces:
                    return interfaces
            except Exception:
                pass

        # 策略3: scapy
        try:
            interfaces = CaptureEngine._probe_via_scapy()
            if interfaces:
                return interfaces
        except Exception:
            pass

        # 策略4: socket 兜底
        try:
            interfaces = CaptureEngine._probe_via_socket()
        except Exception:
            pass

        return interfaces

    @staticmethod
    def _probe_via_psutil() -> List[dict]:
        import psutil
        import socket as sock
        result = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, snic in stats.items():
            ipv4 = ""
            mac = ""
            for addr in addrs.get(name, []):
                if addr.family == sock.AF_INET:
                    ipv4 = addr.address
                elif addr.family == -1:  # AF_LINK
                    mac = addr.address
            lower = name.lower()
            is_loopback = lower in ("lo", "loopback") or ipv4 == "127.0.0.1"
            is_virtual = any(k in lower for k in ("vmware", "virtual", "vbox", "hyper-v", "docker", "veth", "br-", "tailscale"))
            result.append({
                "name": name,
                "description": snic.isup and f"{name} ({ipv4 or '无IP'})" or f"{name} (已断开)",
                "ipv4": ipv4,
                "mac": mac,
                "is_loopback": is_loopback,
                "is_virtual": is_virtual,
                "status": "up" if snic.isup else "down",
                "speed": snic.speed,
            })
        return result

    @staticmethod
    def _probe_via_wmi() -> List[dict]:
        import subprocess, json
        script = """
$adapters = Get-NetAdapter | Where-Object { $_.Status -ne 'Disconnected' }
$ips = Get-NetIPAddress -AddressFamily IPv4 | Group-Object InterfaceAlias -AsHashTable
$result = @()
foreach ($a in $adapters) {
    $ip = $ips[$a.Name]
    $result += @{
        name = $a.Name
        description = $a.InterfaceDescription
        ipv4 = if ($ip) { $ip[0].IPAddress } else { '' }
        mac = $a.MacAddress
        is_loopback = $a.Name -eq 'Loopback'
        status = $a.Status
        speed = $a.LinkSpeed
    }
}
return $result | ConvertTo-Json -Compress
"""
        raw = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        if not raw:
            return []
        adapters = json.loads(raw)
        result = []
        for a in adapters:
            lower = (a.get("name") or "").lower()
            desc = (a.get("description") or "").lower()
            is_virtual = any(k in lower + desc for k in ("vmware", "virtual", "vbox", "hyper-v", "docker", "veth", "tailscale"))
            is_loopback = a.get("is_loopback", False) or (a.get("ipv4") or "") == "127.0.0.1"
            result.append({
                "name": a.get("name", ""),
                "description": a.get("description", ""),
                "ipv4": a.get("ipv4", ""),
                "mac": a.get("mac", ""),
                "is_loopback": is_loopback,
                "is_virtual": is_virtual,
                "status": (a.get("status") or "down").lower(),
                "speed": a.get("speed", 0),
            })
        return result

    @staticmethod
    def _probe_via_scapy() -> List[dict]:
        from scapy.all import get_if_list, get_if_addr, conf
        interfaces = []
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
            except Exception:
                addr = ""
            lower = iface.lower()
            is_loopback = lower in ("lo", "loopback") or addr == "127.0.0.1"
            is_virtual = any(k in lower for k in ("vmware", "virtual", "vbox", "hyper-v", "docker", "veth", "br-"))
            interfaces.append({
                "name": iface,
                "description": iface,
                "ipv4": addr,
                "mac": "",
                "is_loopback": is_loopback,
                "is_virtual": is_virtual,
                "status": "up",
                "speed": 0,
            })
        return interfaces

    @staticmethod
    def _probe_via_socket() -> List[dict]:
        import socket
        hostname = socket.gethostname()
        try:
            addr = socket.gethostbyname(hostname)
        except Exception:
            addr = "127.0.0.1"
        return [{
            "name": hostname,
            "description": f"主机 {hostname}",
            "ipv4": addr,
            "mac": "",
            "is_loopback": addr == "127.0.0.1",
            "is_virtual": False,
            "status": "up",
            "speed": 0,
        }]

    def _auto_select_interface(self) -> str:
        """
        自动选择最优网卡：
        1) 非回环 + 有 IPv4 + 非虚拟
        2) 非回环 + 有 IPv4
        3) 第一个有IPv4的
        4) scapy 默认接口
        5) 枚举第一个
        """
        ifaces = self.get_interfaces()
        if not ifaces:
            try:
                from scapy.all import conf
                return conf.iface
            except Exception:
                return "eth0"

        for pref in [
            lambda i: not i["is_loopback"] and bool(i["ipv4"]) and not i["is_virtual"] and i["status"] == "up",
            lambda i: not i["is_loopback"] and bool(i["ipv4"]),
            lambda i: bool(i["ipv4"]),
        ]:
            for iface in ifaces:
                if pref(iface):
                    return iface["name"]

        return ifaces[0]["name"]

    # ───────────────────────── 实时抓包 ─────────────────────────

    async def _live_capture_loop(self, request: CaptureStartRequest):
        try:
            await self._scapy_capture(request)
        except ImportError:
            logger.warning("scapy 不可用，尝试 pyshark")
            try:
                await self._pyshark_capture(request)
            except ImportError:
                logger.error("scapy 和 pyshark 均不可用")
                self.status = CaptureStatus.ERROR
        except Exception as e:
            logger.error(f"抓包错误: {e}")
            self.status = CaptureStatus.ERROR

    async def _scapy_capture(self, request: CaptureStartRequest):
        from scapy.all import AsyncSniffer, IP, TCP
        loop = asyncio.get_event_loop()
        packet_queue = asyncio.Queue()

        def packet_handler(pkt):
            try:
                loop.call_soon_threadsafe(packet_queue.put_nowait, pkt)
            except Exception:
                pass

        sniffer = AsyncSniffer(iface=self.interface, filter=self.bpf_filter, prn=packet_handler, store=False)
        sniffer.start()
        try:
            max_pkts = request.max_packets or 0
            timeout = request.timeout or 0
            start_time = time.time()
            while not self._stop_event.is_set():
                if timeout > 0 and (time.time() - start_time) > timeout:
                    logger.info("抓包超时")
                    break
                if max_pkts > 0 and self.packets_captured >= max_pkts:
                    logger.info(f"已达最大包数 {max_pkts}")
                    break
                try:
                    pkt = await asyncio.wait_for(packet_queue.get(), timeout=1.0)
                    await self._process_scapy_packet(pkt)
                except asyncio.TimeoutError:
                    continue
        finally:
            sniffer.stop()

    async def _process_scapy_packet(self, pkt):
        from scapy.all import IP, TCP, Raw
        try:
            if not (IP in pkt and TCP in pkt):
                return
            self.packets_captured += 1
            five_tuple = FiveTuple(
                src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                src_port=pkt[TCP].sport, dst_port=pkt[TCP].dport, protocol="TCP"
            )
            payload = bytes(pkt[TCP].payload) if Raw in pkt else b""
            if not payload:
                return
            packet_info = PacketInfo(
                packet_id=str(uuid.uuid4()),
                timestamp=datetime.fromtimestamp(float(pkt.time)),
                five_tuple=five_tuple, raw_size=len(pkt)
            )
            session = await self.session_manager.process_packet(packet_info, payload)
            if session:
                await self._analyze_session(session)
            else:
                await self._analyze_raw_payload(packet_info, payload)
        except Exception as e:
            logger.debug(f"处理包出错: {e}")

    async def _pyshark_capture(self, request: CaptureStartRequest):
        import pyshark
        capture = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter)
        try:
            async for pkt in capture.packets_from_tshark():
                if self._stop_event.is_set():
                    break
                await self._process_pyshark_packet(pkt)
        finally:
            capture.close()

    async def _process_pyshark_packet(self, pkt):
        try:
            self.packets_captured += 1
            if not hasattr(pkt, 'ip') or not hasattr(pkt, 'tcp'):
                return
            five_tuple = FiveTuple(
                src_ip=str(pkt.ip.src), dst_ip=str(pkt.ip.dst),
                src_port=int(pkt.tcp.srcport), dst_port=int(pkt.tcp.dstport), protocol="TCP"
            )
            packet_info = PacketInfo(
                packet_id=str(uuid.uuid4()), timestamp=datetime.now(),
                five_tuple=five_tuple, raw_size=int(pkt.length)
            )
            payload = str(pkt).encode('utf-8', errors='replace')
            if not payload:
                return
            session = await self.session_manager.process_packet(packet_info, payload)
            if session:
                await self._analyze_session(session)
            else:
                await self._analyze_raw_payload(packet_info, payload)
        except Exception as e:
            logger.debug(f"处理 pyshark 包出错: {e}")

    # ───────────────────────── 离线 PCAP ─────────────────────────

    async def analyze_pcap_file(
        self, file_path: str, bpf_filter: str = "",
        progress_callback: Optional[Callable] = None
    ) -> AsyncGenerator[dict, None]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP 文件不存在: {file_path}")
        file_size = os.path.getsize(file_path)
        logger.info(f"开始分析 PCAP: {file_path} ({file_size / 1024 / 1024:.2f} MB)")
        self.status = CaptureStatus.RUNNING
        self.packets_captured = 0
        self.sessions_detected = 0
        self.threats_found = 0
        self.started_at = datetime.now()
        try:
            from scapy.all import PcapReader, IP, TCP, Raw
            chunk_size = self.config.get("capture", {}).get("chunk_size", 1000)
            chunk = []
            with PcapReader(file_path) as reader:
                for pkt in reader:
                    if self._stop_event.is_set():
                        break
                    chunk.append(pkt)
                    self.packets_captured += 1
                    if len(chunk) >= chunk_size:
                        async for r in self._process_packet_chunk(chunk):
                            yield r
                        chunk = []
                        if progress_callback:
                            await progress_callback(self.packets_captured)
                if chunk:
                    async for r in self._process_packet_chunk(chunk):
                        yield r
            self.status = CaptureStatus.STOPPED
            logger.info(f"PCAP 分析完成: {self.packets_captured} 包, {self.threats_found} 威胁")
        except ImportError:
            async for r in self._analyze_pcap_pyshark(file_path, bpf_filter, progress_callback):
                yield r
        except Exception as e:
            self.status = CaptureStatus.ERROR
            logger.error(f"PCAP 分析失败: {e}")
            raise

    async def _process_packet_chunk(self, chunk: list) -> AsyncGenerator[dict, None]:
        from scapy.all import IP, TCP, Raw
        for pkt in chunk:
            try:
                if not (IP in pkt and TCP in pkt):
                    continue
                payload = bytes(pkt[TCP].payload) if Raw in pkt else b""
                if not payload:
                    continue
                five_tuple = FiveTuple(
                    src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
                    src_port=pkt[TCP].sport, dst_port=pkt[TCP].dport, protocol="TCP"
                )
                packet_info = PacketInfo(
                    packet_id=str(uuid.uuid4()),
                    timestamp=datetime.fromtimestamp(float(pkt.time)),
                    five_tuple=five_tuple, raw_size=len(pkt)
                )
                session = await self.session_manager.process_packet(packet_info, payload)
                if session:
                    r = await self._analyze_session(session)
                    if r:
                        yield r
                else:
                    r = await self._analyze_raw_payload(packet_info, payload)
                    if r:
                        yield r
            except Exception as e:
                logger.debug(f"处理包块出错: {e}")
                continue

    async def _analyze_raw_payload(self, packet_info: PacketInfo, payload: bytes) -> Optional[dict]:
        try:
            session = HttpSession(
                session_id=str(uuid.uuid4()),
                packet_info=packet_info,
                request=HttpRequest(
                    method="RAW",
                    uri=f"tcp://{packet_info.five_tuple.src_ip}:{packet_info.five_tuple.src_port}",
                    host=packet_info.five_tuple.dst_ip,
                    body=payload,
                    content_type="application/octet-stream",
                    content_length=len(payload),
                ),
                duration_ms=None,
            )
            self.sessions_detected += 1
            detection_result = await self.detection_engine.analyze(session)
            result = {"session": session, "detection": detection_result}
            if self._on_packet_callback:
                await self._on_packet_callback(result)
            if detection_result.threat_score > 0:
                self.threats_found += 1
                if self._on_threat_callback:
                    await self._on_threat_callback(result)
            return result
        except Exception as e:
            logger.debug(f"分析原始载荷出错: {e}")
            return None

    async def _analyze_pcap_pyshark(self, file_path, bpf_filter, progress_callback):
        import pyshark
        cap = pyshark.FileCapture(file_path, display_filter=bpf_filter or None)
        try:
            for pkt in cap:
                if self._stop_event.is_set():
                    break
                self.packets_captured += 1
                await self._process_pyshark_packet(pkt)
                if progress_callback and self.packets_captured % 100 == 0:
                    await progress_callback(self.packets_captured)
                await asyncio.sleep(0)
        finally:
            cap.close()
        yield {}

    # ───────────────────────── 会话分析 ─────────────────────────

    async def _analyze_session(self, session: HttpSession) -> Optional[dict]:
        try:
            self.sessions_detected += 1
            detection_result = await self.detection_engine.analyze(session)
            result = {"session": session, "detection": detection_result}
            if self._on_packet_callback:
                await self._on_packet_callback(result)
            if detection_result.threat_score > 0:
                self.threats_found += 1
                if self._on_threat_callback:
                    await self._on_threat_callback(result)
            return result
        except Exception as e:
            logger.debug(f"分析会话出错: {e}")
            return None
