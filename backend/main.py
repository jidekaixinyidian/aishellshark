import os
import re
import uuid
import random
import base64
from datetime import datetime, timedelta
from typing import List, Optional
from contextlib import asynccontextmanager

import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from loguru import logger

from backend.models.schemas import (
    APIResponse, CaptureStartRequest, CaptureStatusResponse, NetworkInterface,
    HttpSession, HttpRequest, HttpResponse, PacketInfo, FiveTuple,
    DetectionResult, ThreatScore, ReportRequest, ReportInfo,
    AIAnalysisRequest, AIAnalysisResult, DecryptionResult, BehaviorAlert,
    ThreatLevel, WebShellType, SignatureMatch, EntropyResult,
)
from backend.core.capture_engine import CaptureEngine
from backend.core.threat_scorer import ThreatScorer
from backend.decryption.plugin_manager import PluginManager
from backend.ai import AIClient, BatchAnalyzer, ContextBuilder, PromptTemplates
from backend.reporting.report_generator import ReportGenerator

config: dict = {}
capture_engine: Optional[CaptureEngine] = None
threat_scorer: Optional[ThreatScorer] = None
plugin_manager: Optional[PluginManager] = None
batch_analyzer: Optional[BatchAnalyzer] = None
report_generator: Optional[ReportGenerator] = None

sessions_store: dict = {}
detections_store: dict = {}
scores_store: dict = {}
behavior_store: dict = {}
decryption_store: dict = {}
packets_store: list = []

ws_connections: List[WebSocket] = []


def load_config() -> dict:
    cfg_path = os.environ.get("SHELLSHARK_CONFIG", "config.yaml")
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global config, capture_engine, threat_scorer, plugin_manager, batch_analyzer, report_generator
    global sessions_store, detections_store, scores_store, behavior_store, decryption_store, packets_store
    config = load_config()
    capture_engine = CaptureEngine(config)
    threat_scorer = ThreatScorer(config)
    plugin_manager = PluginManager(config)
    batch_analyzer = BatchAnalyzer(config, sessions_store, detections_store, scores_store)
    report_generator = ReportGenerator(config)

    async def on_packet(result: dict):
        try:
            session = result.get("session")
            detection = result.get("detection")
            if session and detection:
                sid = session.session_id
                sessions_store[sid] = session
                detections_store[sid] = detection
                alerts = detection.behavior_alerts if hasattr(detection, "behavior_alerts") else []
                score = threat_scorer.score(sid, detection=detection, behavior_alerts=alerts, entropy=detection.entropy_result)
                scores_store[sid] = score
                pi = session.packet_info
                ft = pi.five_tuple if pi else None
                packets_store.append({
                    "packet_id": pi.packet_id if pi else sid,
                    "timestamp": pi.timestamp.isoformat() if pi and pi.timestamp else "",
                    "src_ip": ft.src_ip if ft else "",
                    "dst_ip": ft.dst_ip if ft else "",
                    "src_port": ft.src_port if ft else 0,
                    "dst_port": ft.dst_port if ft else 0,
                    "protocol": "TCP",
                    "size": pi.raw_size if pi else 0,
                    "method": session.request.method if session and session.request else "RAW",
                    "uri": session.request.uri if session and session.request else "",
                    "webshell_type": detection.webshell_type.value if detection else "unknown",
                    "threat_score": score.total_score if score else 0,
                    "threat_level": score.threat_level.value if score else "low",
                    "session_id": sid,
                })
            msg = {"type": "packet", "data": str(session.session_id if session else "")}
            await broadcast(msg)
        except Exception as e:
            logger.warning(f"on_packet 回调处理出错: {e}")

    async def on_threat(result: dict):
        det = result.get("detection")
        summary = det.summary if hasattr(det, "summary") else str(det) if det else ""
        msg = {"type": "threat", "data": str(summary)}
        await broadcast(msg)

    capture_engine.set_callbacks(on_packet=on_packet, on_threat=on_threat)
    logger.info("ShellShark 服务启动完成")
    yield
    await batch_analyzer.close()
    logger.info("ShellShark 服务已关闭")


app = FastAPI(title="ShellShark", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
if os.path.isdir(frontend_dir):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dir, "assets")), name="assets")


async def broadcast(msg: dict):
    dead = []
    for ws in ws_connections:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_connections.remove(ws)


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    ws_connections.append(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        if ws in ws_connections:
            ws_connections.remove(ws)


@app.get("/api/status")
async def get_status() -> APIResponse:
    status = capture_engine.get_status() if capture_engine else CaptureStatusResponse()
    return APIResponse(data=status.dict())


@app.post("/api/capture/start")
async def start_capture(req: CaptureStartRequest) -> APIResponse:
    try:
        task_id = await capture_engine.start_live_capture(req)
        return APIResponse(message="抓包已启动", data={"task_id": task_id})
    except RuntimeError as e:
        raise HTTPException(400, str(e))


@app.post("/api/capture/stop")
async def stop_capture() -> APIResponse:
    await capture_engine.stop_capture()
    return APIResponse(message="抓包已停止")


@app.get("/api/interfaces")
async def get_interfaces() -> APIResponse:
    ifaces = CaptureEngine.get_interfaces()
    return APIResponse(data=ifaces)


@app.post("/api/capture/upload")
async def upload_pcap(file: UploadFile = File(...)) -> APIResponse:
    ext = os.path.splitext(file.filename or "upload.pcap")[1].lower()
    if ext not in (".pcap", ".pcapng"):
        raise HTTPException(400, "仅支持 PCAP/PCAPNG 文件")
    tmp = f"data/pcap/{uuid.uuid4()}{ext}"
    os.makedirs("data/pcap", exist_ok=True)
    content = await file.read()
    with open(tmp, "wb") as f:
        f.write(content)
    logger.info(f"PCAP 文件已上传: {file.filename} ({len(content)} bytes)")
    return APIResponse(message="文件上传成功", data={"path": tmp, "size": len(content)})


@app.post("/api/analyze/pcap")
async def analyze_pcap(filepath: str) -> APIResponse:
    if not os.path.exists(filepath):
        raise HTTPException(404, f"文件不存在: {filepath}")
    total_packets = capture_engine.packets_captured
    results = []
    try:
        async for result in capture_engine.analyze_pcap_file(filepath):
            session = result.get("session")
            detection = result.get("detection")
            if session and detection:
                sid = session.session_id
                sessions_store[sid] = session
                detections_store[sid] = detection
                alerts = detection.behavior_alerts if hasattr(detection, "behavior_alerts") else []
                score = threat_scorer.score(sid, detection=detection, behavior_alerts=alerts, entropy=detection.entropy_result)
                scores_store[sid] = score
                results.append({
                    "session_id": sid,
                    "threat_score": score.total_score,
                    "threat_level": score.threat_level.value,
                    "summary": detection.summary,
                })
    except Exception as e:
        logger.error(f"PCAP 分析失败: {e}")
        raise HTTPException(500, f"PCAP 分析失败: {str(e)}")
    total_packets = capture_engine.packets_captured - total_packets
    logger.info(f"PCAP 分析完成: 处理 {total_packets} 个包, 发现 {len(results)} 个会话 (威胁 {len([r for r in results if r['threat_score'] > 0])})")
    return APIResponse(data={"total": len(results), "total_packets": total_packets, "results": results})


@app.post("/api/demo/seed")
async def seed_demo_data() -> APIResponse:
    """生成演示用的模拟会话数据"""
    demo_sessions = [
        {
            "src_ip": "192.168.1.100", "dst_ip": "10.0.0.5", "src_port": 54321, "dst_port": 80,
            "method": "POST", "uri": "/upload.php", "host": "www.target.com",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "body": b"z0=@eval($_POST['cmd']);&cmd=whoami",
            "webshell_type": WebShellType.CHOPPER,
            "threat_score": 65.0, "threat_level": ThreatLevel.MEDIUM,
            "summary": "疑似中国菜刀 WebShell 流量；命中 3 条特征规则",
            "signature_matches": [
                SignatureMatch(rule_id="CHOPPER-001", rule_name="菜刀 PHP 一句话特征", category="webshell",
                    description="检测中国菜刀 PHP WebShell 特征", matched_content="z0=@eval(", confidence=0.9, webshell_type=WebShellType.CHOPPER),
                SignatureMatch(rule_id="CHOPPER-002", rule_name="菜刀流量特征", category="traffic",
                    description="检测菜刀 HTTP 流量特征", matched_content="@ini_set(\"display_errors\"", confidence=0.85, webshell_type=WebShellType.CHOPPER),
            ],
        },
        {
            "src_ip": "10.0.0.5", "dst_ip": "192.168.1.100", "src_port": 80, "dst_port": 54321,
            "method": "POST", "uri": "/admin/index.php", "host": "www.target.com",
            "ua": "antSword/v2.1",
            "body": b"@ini_set(\"display_errors\",\"0\");@set_time_limit(0);function asenc($s){return base64_encode(str_rot13($s));}echo md5(123);",
            "webshell_type": WebShellType.ANTSWORD,
            "threat_score": 82.0, "threat_level": ThreatLevel.HIGH,
            "summary": "疑似蚁剑 WebShell 流量；命中 4 条特征规则；检测到高熵加密流量",
            "signature_matches": [
                SignatureMatch(rule_id="ANTSWORD-001", rule_name="蚁剑 User-Agent 特征", category="ua",
                    description="检测蚁剑默认 User-Agent", matched_content="antSword", confidence=0.95, webshell_type=WebShellType.ANTSWORD),
                SignatureMatch(rule_id="ANTSWORD-002", rule_name="蚁剑 PHP 载荷特征", category="payload",
                    description="检测蚁剑 PHP 载荷特征", matched_content="@ini_set(\"display_errors\"", confidence=0.88, webshell_type=WebShellType.ANTSWORD),
            ],
        },
        {
            "src_ip": "192.168.1.50", "dst_ip": "10.0.0.5", "src_port": 49152, "dst_port": 443,
            "method": "POST", "uri": "/api/shell.php", "host": "www.target.com",
            "ua": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
            "body": b"e45e329feb5d925b" + b"A" * 100,
            "webshell_type": WebShellType.BEHINDER,
            "threat_score": 95.0, "threat_level": ThreatLevel.CRITICAL,
            "summary": "疑似冰蝎 WebShell 流量；命中 3 条特征规则；检测到高熵加密流量；疑似 AES 加密数据",
            "signature_matches": [
                SignatureMatch(rule_id="BEHINDER-001", rule_name="冰蝎 v2 流量特征", category="traffic",
                    description="检测冰蝎 v2 AES 加密流量特征", matched_content="e45e329feb5d925b", confidence=0.95, webshell_type=WebShellType.BEHINDER),
                SignatureMatch(rule_id="BEHINDER-004", rule_name="冰蝎默认 User-Agent", category="ua",
                    description="检测冰蝎默认 User-Agent", matched_content="Mozilla/5.0 (compatible; MSIE 9.0", confidence=0.7, webshell_type=WebShellType.BEHINDER),
            ],
        },
        {
            "src_ip": "172.16.0.10", "dst_ip": "10.0.0.5", "src_port": 33456, "dst_port": 8080,
            "method": "POST", "uri": "/shell.jsp", "host": "www.target.com:8080",
            "ua": "Go-http-client/1.1",
            "body": b"pass=godzilla&cmd=whoami&mode=exec",
            "webshell_type": WebShellType.GODZILLA,
            "threat_score": 78.0, "threat_level": ThreatLevel.HIGH,
            "summary": "疑似哥斯拉 WebShell 流量；命中 2 条特征规则",
            "signature_matches": [
                SignatureMatch(rule_id="GODZILLA-003", rule_name="哥斯拉流量特征", category="traffic",
                    description="检测哥斯拉 HTTP 流量特征", matched_content="pass=godzilla&cmd=whoami", confidence=0.75, webshell_type=WebShellType.GODZILLA),
            ],
        },
        {
            "src_ip": "192.168.1.200", "dst_ip": "10.0.0.5", "src_port": 44321, "dst_port": 80,
            "method": "POST", "uri": "/wp-content/plugins/shell.php", "host": "blog.target.com",
            "ua": "python-requests/2.28.0",
            "body": b"$k=\"a1b2c3d4\";$r=@file_get_contents(\"php://input\");$s=array_map(\"ord\",str_split($r));echo implode(array_map(\"chr\",$s));",
            "webshell_type": WebShellType.WEEVELY,
            "threat_score": 72.0, "threat_level": ThreatLevel.MEDIUM,
            "summary": "疑似 Weevely3 WebShell 流量；命中 2 条特征规则；检测到高熵加密流量",
            "signature_matches": [
                SignatureMatch(rule_id="WEEVELY-001", rule_name="Weevely3 PHP 特征", category="webshell",
                    description="检测 Weevely3 PHP WebShell 特征", matched_content="$k=\"a1b2c3d4\"", confidence=0.88, webshell_type=WebShellType.WEEVELY),
            ],
        },
        {
            "src_ip": "192.168.1.150", "dst_ip": "10.0.0.5", "src_port": 44123, "dst_port": 80,
            "method": "GET", "uri": "/index.html", "host": "www.target.com",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
            "body": b"",
            "webshell_type": WebShellType.UNKNOWN,
            "threat_score": 5.0, "threat_level": ThreatLevel.LOW,
            "summary": "未检测到威胁",
            "signature_matches": [],
        },
        {
            "src_ip": "192.168.1.150", "dst_ip": "10.0.0.5", "src_port": 44124, "dst_port": 80,
            "method": "GET", "uri": "/css/style.css", "host": "www.target.com",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
            "body": b"",
            "webshell_type": WebShellType.UNKNOWN,
            "threat_score": 0.0, "threat_level": ThreatLevel.LOW,
            "summary": "未检测到威胁",
            "signature_matches": [],
        },
        {
            "src_ip": "10.0.0.20", "dst_ip": "10.0.0.5", "src_port": 50001, "dst_port": 8443,
            "method": "POST", "uri": "/api/v1/upload", "host": "internal.admin.com",
            "ua": "Java/17.0.1",
            "body": b"U2FsdGVkX1" + b"B" * 200,
            "webshell_type": WebShellType.SHARPYSHELL,
            "threat_score": 88.0, "threat_level": ThreatLevel.HIGH,
            "summary": "疑似 SharPyShell WebShell 流量；命中 2 条特征规则",
            "signature_matches": [
                SignatureMatch(rule_id="SHARPYSHELL-001", rule_name="SharPyShell 特征", category="webshell",
                    description="检测 SharPyShell WebShell 特征", matched_content="U2FsdGVkX1", confidence=0.9, webshell_type=WebShellType.SHARPYSHELL),
            ],
        },
    ]

    now = datetime.now()
    created = 0
    for i, demo in enumerate(demo_sessions):
        ts = now - timedelta(hours=len(demo_sessions) - i, minutes=random.randint(0, 59))
        req_ft = FiveTuple(src_ip=demo["src_ip"], src_port=demo["src_port"],
                            dst_ip=demo["dst_ip"], dst_port=demo["dst_port"], protocol="TCP")
        resp_ft = FiveTuple(src_ip=demo["dst_ip"], src_port=demo["dst_port"],
                            dst_ip=demo["src_ip"], dst_port=demo["src_port"], protocol="TCP")

        req_pkt = PacketInfo(packet_id=str(uuid.uuid4()), timestamp=ts, five_tuple=req_ft, raw_size=len(demo["body"]) + 300)
        resp_pkt = PacketInfo(packet_id=str(uuid.uuid4()), timestamp=ts + timedelta(milliseconds=random.randint(10, 500)),
                              five_tuple=resp_ft, raw_size=len(demo["body"]) + 500)

        http_req = HttpRequest(
            method=demo["method"], uri=demo["uri"], host=demo["host"],
            user_agent=demo["ua"], body=demo["body"] if demo["body"] else None,
            headers={"host": demo["host"], "user-agent": demo["ua"], "accept": "*/*",
                     "content-type": "application/x-www-form-urlencoded"},
        )
        http_resp = HttpResponse(
            status_code=200, status_message="OK",
            headers={"server": "nginx/1.24", "content-type": "text/html", "content-length": "1024"},
            body=b"<html><body>OK</body></html>",
        )

        entropy_result = EntropyResult(
            request_body_entropy=6.5 if demo["body"] else None,
            response_body_entropy=4.2,
            is_high_entropy=demo["threat_score"] > 60,
            is_aes_aligned=demo["webshell_type"] == WebShellType.BEHINDER,
            block_size=16 if demo["webshell_type"] == WebShellType.BEHINDER else None,
        )

        session = HttpSession(
            session_id=str(uuid.uuid4()),
            packet_info=req_pkt,
            request=http_req,
            response=http_resp,
            duration_ms=random.uniform(10.0, 500.0),
        )

        detection = DetectionResult(
            session_id=session.session_id,
            signature_matches=demo["signature_matches"],
            entropy_result=entropy_result,
            threat_score=demo["threat_score"],
            threat_level=demo["threat_level"],
            webshell_type=demo["webshell_type"],
            confidence=demo["threat_score"] / 100.0,
            summary=demo["summary"],
        )

        score = threat_scorer.score(
            session.session_id,
            detection=detection,
            behavior_alerts=[],
            entropy=entropy_result,
        )

        sessions_store[session.session_id] = session
        detections_store[session.session_id] = detection
        scores_store[session.session_id] = score
        created += 1

    logger.info(f"生成了 {created} 条演示数据")
    return APIResponse(message=f"已生成 {created} 条演示会话数据", data={"count": created})


def _sessions_to_packet(session) -> dict:
    """Convert an HttpSession to a packet dict for filtering."""
    det = detections_store.get(session.session_id)
    sc = scores_store.get(session.session_id)
    pi = session.packet_info
    ft = pi.five_tuple if pi else None
    return {
        "src_ip": ft.src_ip if ft else "",
        "dst_ip": ft.dst_ip if ft else "",
        "src_port": ft.src_port if ft else 0,
        "dst_port": ft.dst_port if ft else 0,
        "method": session.request.method if session and session.request else "RAW",
        "uri": session.request.uri if session and session.request else "",
        "webshell_type": det.webshell_type.value if det else "unknown",
        "threat_score": sc.total_score if sc else 0,
        "threat_level": sc.threat_level.value if sc else "low",
        "protocol": "TCP",
    }


@app.get("/api/sessions")
async def list_sessions(page: int = 1, page_size: int = 20, level: str = "", q: str = "") -> APIResponse:
    items = list(sessions_store.values())
    if level:
        items = [s for s in items if s.session_id in scores_store and scores_store[s.session_id].threat_level.value == level]
    if q:
        pkt_items = [_sessions_to_packet(s) for s in items]
        filtered_pkts = _apply_packet_filter(pkt_items, q)
        filtered_ids = {p["src_ip"] + p["dst_ip"] + p["method"] + p["uri"] for p in filtered_pkts}
        items = [s for s in items if (_sessions_to_packet(s)["src_ip"] +
                                       _sessions_to_packet(s)["dst_ip"] +
                                       _sessions_to_packet(s)["method"] +
                                       _sessions_to_packet(s)["uri"]) in filtered_ids]
    items.sort(key=lambda s: s.packet_info.timestamp if s.packet_info else datetime.min, reverse=True)
    start = (page - 1) * page_size
    end = start + page_size
    page_items = items[start:end]
    result = []
    for s in page_items:
        det = detections_store.get(s.session_id)
        sc = scores_store.get(s.session_id)
        result.append({
            "session_id": s.session_id,
            "timestamp": s.packet_info.timestamp.isoformat() if s.packet_info else "",
            "src_ip": s.packet_info.five_tuple.src_ip if s.packet_info else "",
            "dst_ip": s.packet_info.five_tuple.dst_ip if s.packet_info else "",
            "method": s.request.method if s and s.request else "",
            "uri": s.request.uri if s and s.request else "",
            "threat_score": round(sc.total_score, 1) if sc else 0,
            "threat_level": sc.threat_level.value if sc else "low",
            "webshell_type": det.webshell_type.value if det else "unknown",
            "summary": det.summary if det else "",
        })
    return APIResponse(data={"items": result, "total": len(items), "page": page, "page_size": page_size})


def _safe_serialize(obj):
    """递归将对象中的 bytes 转为 base64 字符串，安全序列化"""
    if obj is None:
        return None
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, dict):
        return {k: _safe_serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_serialize(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(_safe_serialize(v) for v in obj)
    return obj


def _model_to_safe_dict(model):
    """将 Pydantic 模型转为 JSON 安全的字典"""
    if model is None:
        return None
    raw = model.model_dump() if hasattr(model, "model_dump") else model.dict()
    return _safe_serialize(raw)


@app.get("/api/sessions/{session_id}")
async def get_session_detail(session_id: str) -> APIResponse:
    session = sessions_store.get(session_id)
    if not session:
        raise HTTPException(404, "会话不存在")
    det = detections_store.get(session_id)
    sc = scores_store.get(session_id)
    dec = decryption_store.get(session_id)
    return APIResponse(data={
        "session": _model_to_safe_dict(session),
        "detection": _model_to_safe_dict(det),
        "threat_score": _model_to_safe_dict(sc),
        "decryption": _model_to_safe_dict([d.dict() for d in dec]) if dec else [],
    })


@app.post("/api/analyze/ai")
async def analyze_ai(req: AIAnalysisRequest) -> APIResponse:
    results = await batch_analyzer.analyze_batch(req)
    for r in results:
        if r.session_id in scores_store:
            sc = scores_store[r.session_id]
            sc.ai_score = r.confidence * 30
            sc.total_score = min(sc.feature_score + sc.behavior_score + sc.entropy_score + sc.ai_score, 100.0)
    return APIResponse(data=[r.dict() for r in results])


@app.post("/api/decrypt/{session_id}")
async def decrypt_session(session_id: str) -> APIResponse:
    session = sessions_store.get(session_id)
    if not session:
        raise HTTPException(404, "会话不存在")
    results = plugin_manager.decrypt_session(session)
    decryption_store[session_id] = results
    return APIResponse(data=[r.dict() for r in results])


@app.post("/api/report/generate")
async def generate_report(req: ReportRequest) -> APIResponse:
    sessions = [sessions_store[sid] for sid in req.session_ids if sid in sessions_store]
    if not sessions:
        raise HTTPException(400, "没有有效的会话")
    fmt = req.format
    content = ""
    if fmt == "jsonl":
        content = report_generator.generate_jsonl(sessions, detections_store, scores_store)
    elif fmt == "csv":
        content = report_generator.generate_csv(sessions, detections_store, scores_store)
    else:
        content = report_generator.generate_html(sessions, detections_store, scores_store)
        fmt = "html"
    path = report_generator.save_report(content, fmt)
    return APIResponse(data={"path": str(path), "format": fmt, "size": os.path.getsize(path)})


@app.get("/api/report/download/{filename}")
async def download_report(filename: str):
    report_dir = report_generator.output_dir if report_generator else Path("data/reports")
    filepath = report_dir / filename
    if not filepath.exists():
        raise HTTPException(404, "报告文件不存在")
    return FileResponse(str(filepath), filename=filename)


@app.get("/api/reports")
async def list_reports() -> APIResponse:
    report_dir = report_generator.output_dir if report_generator else Path("data/reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    files = []
    for f in sorted(report_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if f.is_file():
            files.append({
                "filename": f.name,
                "size": f.stat().st_size,
                "created_at": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
            })
    return APIResponse(data=files)


@app.get("/api/stats")
async def get_statistics() -> APIResponse:
    total = len(sessions_store)
    if total == 0:
        return APIResponse(data={"total_sessions": 0})
    levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    tools = {}
    for sid, sc in scores_store.items():
        lv = sc.threat_level.value
        if lv in levels:
            levels[lv] += 1
    for sid, det in detections_store.items():
        t = det.webshell_type.value
        tools[t] = tools.get(t, 0) + 1
    return APIResponse(data={
        "total_sessions": total,
        "threat_distribution": levels,
        "tool_distribution": tools,
    })


def _apply_packet_filter(items: list, q: str) -> list:
    """Wireshark-style filter expression parser."""
    if not q:
        return items

    filters = []
    # Handle 'or' - split on ' or ' (case-insensitive)
    or_groups = [g.strip() for g in re.split(r'\s+or\s+', q, flags=re.IGNORECASE)]

    for group in or_groups:
        and_parts = re.split(r'\s+and\s+', group, flags=re.IGNORECASE)
        if len(and_parts) == 1:
            and_parts = _split_filter_conditions(group)

        conditions = []
        for part in and_parts:
            if not part:
                continue
            cond = _parse_filter_condition(part)
            if cond:
                conditions.append(cond)

        if conditions:
            filters.append(conditions)

    def matches(item):
        if not filters:
            return True
        # OR groups: any group must match
        for group in filters:
            if all(cond(item) for cond in group):
                return True
        return False

    return [item for item in items if matches(item)]


def _split_filter_conditions(expr: str) -> list:
    """Split filter expression into individual conditions, preserving multi-word operators like 'contains'."""
    parts = []
    i = 0
    tokens = expr.split()
    while i < len(tokens):
        if i + 2 < len(tokens) and tokens[i+1].lower() == "contains":
            parts.append(f"{tokens[i]} contains {tokens[i+2]}")
            i += 3
        else:
            parts.append(tokens[i])
            i += 1
    return parts


def _parse_filter_condition(expr: str):
    """Parse a single filter expression like 'ip==1.2.3.4' or 'uri contains /admin'."""
    expr = expr.strip()

    # contains operator
    contains_match = re.match(r'^(\w+(?:\.\w+)*)\s+contains\s+(.+)$', expr, re.IGNORECASE)
    if contains_match:
        field = contains_match.group(1).lower()
        value = contains_match.group(2).strip().strip('"').strip("'")
        return _make_contains_filter(field, value)

    # != operator
    ne_match = re.match(r'^(\w+(?:\.\w+)*)\s*!=\s*(.+)$', expr)
    if ne_match:
        field = ne_match.group(1).lower()
        value = ne_match.group(2).strip().strip('"').strip("'")
        return _make_comparison_filter(field, value, ne=True)

    # > >= < <= operators
    cmp_match = re.match(r'^(\w+(?:\.\w+)*)\s*([><]=?)\s*(.+)$', expr)
    if cmp_match:
        field = cmp_match.group(1).lower()
        op = cmp_match.group(2)
        value = cmp_match.group(3).strip().strip('"').strip("'")
        return _make_numeric_filter(field, value, op)

    # == operator
    eq_match = re.match(r'^(\w+(?:\.\w+)*)\s*==\s*(.+)$', expr)
    if eq_match:
        field = eq_match.group(1).lower()
        value = eq_match.group(2).strip().strip('"').strip("'")
        return _make_comparison_filter(field, value)

    # Bare word - search across multiple fields
    bare = expr.strip('"').strip("'")
    if bare:
        return _make_bareword_filter(bare)

    return None


def _make_contains_filter(field: str, value: str):
    field_map = {
        "uri": "uri", "url": "uri",
        "ip": "src_ip", "ip.src": "src_ip", "ip.dst": "dst_ip",
        "method": "method",
        "type": "webshell_type", "webshell": "webshell_type",
    }
    pkt_key = field_map.get(field)
    if pkt_key:
        return lambda p: value.lower() in str(p.get(pkt_key, "")).lower()
    return None


def _make_comparison_filter(field: str, value: str, ne=False):
    field_map = {
        "ip": "src_ip", "ip.addr": "src_ip", "ip.src": "src_ip", "ip.dst": "dst_ip",
        "method": "method", "uri": "uri",
        "level": "threat_level", "threat.level": "threat_level",
        "type": "webshell_type", "webshell": "webshell_type",
        "protocol": "protocol",
    }
    pkt_key = field_map.get(field)
    if pkt_key:
        if field in ("ip", "ip.addr"):
            return lambda p: (value.lower() == str(p.get("src_ip", "")).lower() or
                              value.lower() == str(p.get("dst_ip", "")).lower())
        if field in ("ip.src",):
            return lambda p: value.lower() == str(p.get("src_ip", "")).lower()
        if field in ("ip.dst",):
            return lambda p: value.lower() == str(p.get("dst_ip", "")).lower()
        if ne:
            return lambda p: value.lower() != str(p.get(pkt_key, "")).lower()
        return lambda p: value.lower() == str(p.get(pkt_key, "")).lower()

    # port handling
    if field in ("port", "tcp.port", "tcp.srcport", "tcp.dstport"):
        port_val = int(value) if value.isdigit() else None
        if port_val is None:
            return None
        if field in ("tcp.srcport",):
            return lambda p: p.get("src_port") == port_val
        if field in ("tcp.dstport",):
            return lambda p: p.get("dst_port") == port_val
        # port / tcp.port: match either
        return lambda p: p.get("src_port") == port_val or p.get("dst_port") == port_val

    return None


def _make_numeric_filter(field: str, value: str, op: str):
    field_map = {
        "threat": "threat_score", "score": "threat_score",
        "threat.score": "threat_score",
        "size": "size",
    }
    pkt_key = field_map.get(field)
    if not pkt_key:
        return None
    try:
        val = float(value)
    except ValueError:
        return None
    if op == ">":
        return lambda p: (p.get(pkt_key) or 0) > val
    if op == ">=":
        return lambda p: (p.get(pkt_key) or 0) >= val
    if op == "<":
        return lambda p: (p.get(pkt_key) or 0) < val
    if op == "<=":
        return lambda p: (p.get(pkt_key) or 0) <= val
    return None


def _make_bareword_filter(text: str):
    fields = ["src_ip", "dst_ip", "method", "uri", "webshell_type", "protocol"]
    return lambda p: any(text.lower() in str(p.get(f, "")).lower() for f in fields)


@app.get("/api/packets")
async def list_packets(page: int = 1, page_size: int = 50, level: str = "", q: str = "") -> APIResponse:
    items = list(packets_store)
    if level:
        items = [p for p in items if p["threat_level"] == level]
    if q:
        items = _apply_packet_filter(items, q)
    items.sort(key=lambda p: p.get("timestamp", ""), reverse=True)
    start = (page - 1) * page_size
    end = start + page_size
    return APIResponse(data={
        "items": items[start:end],
        "total": len(items),
        "page": page,
        "page_size": page_size,
    })


@app.get("/api/packets/{packet_id}")
async def get_packet_detail(packet_id: str) -> APIResponse:
    for p in packets_store:
        if p["packet_id"] == packet_id:
            sid = p.get("session_id", "")
            session = sessions_store.get(sid)
            det = detections_store.get(sid)
            sc = scores_store.get(sid)
            return APIResponse(data={
                "packet": p,
                "session": session.dict() if session else None,
                "detection": det.dict() if det else None,
                "threat_score": sc.dict() if sc else None,
            })
    raise HTTPException(404, "数据包不存在")


@app.get("/{full_path:path}")
async def serve_frontend(full_path: str):
    index = os.path.join(frontend_dir, "index.html")
    if os.path.isfile(index):
        return FileResponse(index)
    return HTMLResponse("<h1>ShellShark API</h1><p>前端未构建，请运行前端项目</p>")
