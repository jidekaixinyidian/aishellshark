from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WebShellType(str, Enum):
    CHOPPER = "chopper"
    ANTSWORD = "antsword"
    BEHINDER = "behinder"
    GODZILLA = "godzilla"
    WEEVELY = "weevely"
    SHARPYSHELL = "sharpyshell"
    UNKNOWN = "unknown"


class CaptureStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


class FiveTuple(BaseModel):
    src_ip: str = Field(..., description="源IP")
    src_port: int = Field(..., description="源端口")
    dst_ip: str = Field(..., description="目的IP")
    dst_port: int = Field(..., description="目的端口")
    protocol: str = Field("TCP", description="协议")


class PacketInfo(BaseModel):
    packet_id: str = Field(..., description="数据包ID")
    timestamp: datetime = Field(..., description="时间戳")
    five_tuple: FiveTuple = Field(..., description="五元组")
    raw_size: int = Field(0, description="原始大小")


class HttpRequest(BaseModel):
    method: str = Field(..., description="请求方法")
    uri: str = Field(..., description="请求URI")
    version: str = Field("HTTP/1.1", description="HTTP版本")
    headers: Dict[str, str] = Field(default_factory=dict, description="请求头")
    body: Optional[bytes] = Field(None, description="请求体")
    body_decoded: Optional[str] = Field(None, description="解码后的请求体")
    decoded_body: Optional[str] = Field(None, description="多种解码尝试结果")
    params: Dict[str, Any] = Field(default_factory=dict, description="请求参数")
    content_type: Optional[str] = Field(None, description="Content-Type")
    content_length: Optional[int] = Field(None, description="Content-Length")
    user_agent: Optional[str] = Field(None, description="User-Agent")
    cookie: Optional[str] = Field(None, description="Cookie")
    host: Optional[str] = Field(None, description="Host")


class HttpResponse(BaseModel):
    status_code: int = Field(..., description="状态码")
    status_message: str = Field("", description="状态描述")
    version: str = Field("HTTP/1.1", description="HTTP版本")
    headers: Dict[str, str] = Field(default_factory=dict, description="响应头")
    body: Optional[bytes] = Field(None, description="响应体")
    body_decoded: Optional[str] = Field(None, description="解码后的响应体")
    decoded_body: Optional[str] = Field(None, description="多种解码尝试结果")
    content_type: Optional[str] = Field(None, description="Content-Type")
    content_length: Optional[int] = Field(None, description="Content-Length")


class HttpSession(BaseModel):
    session_id: str = Field(..., description="会话ID")
    packet_info: PacketInfo = Field(..., description="数据包信息")
    request: Optional[HttpRequest] = Field(None, description="HTTP请求")
    response: Optional[HttpResponse] = Field(None, description="HTTP响应")
    duration_ms: Optional[float] = Field(None, description="请求响应耗时(毫秒)")
    is_https: bool = Field(False, description="是否HTTPS")


class SignatureMatch(BaseModel):
    rule_id: str = Field(..., description="规则ID")
    rule_name: str = Field(..., description="规则名称")
    category: str = Field(..., description="规则类别")
    description: str = Field(..., description="规则描述")
    matched_content: str = Field(..., description="匹配内容")
    confidence: float = Field(..., description="置信度")
    webshell_type: WebShellType = Field(WebShellType.UNKNOWN, description="WebShell类型")


class BehaviorAlert(BaseModel):
    alert_type: str = Field(..., description="告警类型")
    description: str = Field(..., description="告警描述")
    severity: ThreatLevel = Field(..., description="严重程度")
    details: Dict[str, Any] = Field(default_factory=dict, description="详细信息")
    timestamp: datetime = Field(default_factory=datetime.now, description="告警时间")


class EntropyResult(BaseModel):
    request_body_entropy: Optional[float] = Field(None, description="请求体熵值")
    response_body_entropy: Optional[float] = Field(None, description="响应体熵值")
    is_high_entropy: bool = Field(False, description="是否高熵")
    is_aes_aligned: bool = Field(False, description="是否AES对齐")
    block_size: Optional[int] = Field(None, description="块大小")


class DetectionResult(BaseModel):
    session_id: str = Field(..., description="会话ID")
    signature_matches: List[SignatureMatch] = Field(default_factory=list, description="特征匹配")
    entropy_result: Optional[EntropyResult] = Field(None, description="熵值结果")
    threat_score: float = Field(0.0, description="威胁评分(0-100)")
    threat_level: ThreatLevel = Field(ThreatLevel.LOW, description="威胁等级")
    webshell_type: WebShellType = Field(WebShellType.UNKNOWN, description="WebShell类型")
    confidence: float = Field(0.0, description="综合置信度")
    summary: str = Field("", description="检测摘要")


class DecryptionResult(BaseModel):
    success: bool = Field(..., description="是否成功")
    tool_name: str = Field(..., description="工具名称")
    original_data: str = Field(..., description="原始数据")
    decrypted_data: str = Field(..., description="解密后数据")
    algorithm: str = Field(..., description="解密算法")
    key: Optional[str] = Field(None, description="密钥")
    error: Optional[str] = Field(None, description="错误信息")


class AIAnalysisRequest(BaseModel):
    session_ids: List[str] = Field(..., description="会话ID列表")
    provider: Optional[str] = Field(None, description="AI提供商")
    model: Optional[str] = Field(None, description="模型")
    include_context: bool = Field(True, description="包含上下文")
    max_context_packets: int = Field(3, description="关联包数量")


class AIAnalysisResult(BaseModel):
    session_id: str = Field(..., description="会话ID")
    is_webshell: bool = Field(False, description="是否WebShell")
    confidence: float = Field(0.0, description="置信度")
    tool_type: str = Field("未知", description="工具类型")
    attack_intent: str = Field("未知", description="攻击意图")
    payload: str = Field("", description="攻击载荷")
    commands: List[str] = Field(default_factory=list, description="执行命令")
    threat_level: ThreatLevel = Field(ThreatLevel.LOW, description="威胁等级")
    recommendations: List[str] = Field(default_factory=list, description="处置建议")
    analysis_time: datetime = Field(default_factory=datetime.now, description="分析时间")
    provider: str = Field("", description="AI提供商")
    model: str = Field("", description="模型名称")
    raw_response: Optional[str] = Field(None, description="原始响应")


class ThreatScore(BaseModel):
    session_id: str = Field(..., description="会话ID")
    total_score: float = Field(0.0, description="总分")
    feature_score: float = Field(0.0, description="特征匹配得分")
    behavior_score: float = Field(0.0, description="行为分析得分")
    entropy_score: float = Field(0.0, description="熵值得分")
    ai_score: float = Field(0.0, description="AI得分")
    threat_level: ThreatLevel = Field(ThreatLevel.LOW, description="威胁等级")


class CaptureStartRequest(BaseModel):
    interface: Optional[str] = Field(None, description="网络接口")
    bpf_filter: Optional[str] = Field(None, description="BPF过滤器")
    max_packets: int = Field(0, description="最大包数(0=无限)")
    timeout: int = Field(0, description="超时秒数(0=无限)")


class CaptureStatusResponse(BaseModel):
    status: CaptureStatus = Field(CaptureStatus.IDLE, description="抓包状态")
    interface: Optional[str] = Field(None, description="网络接口")
    filter: Optional[str] = Field(None, description="当前过滤器")
    packets_captured: int = Field(0, description="已捕获包数")
    sessions_detected: int = Field(0, description="已检测会话数")
    threats_found: int = Field(0, description="发现威胁数")
    started_at: Optional[datetime] = Field(None, description="开始时间")
    elapsed_seconds: Optional[float] = Field(None, description="已运行秒数")


class ReportRequest(BaseModel):
    session_ids: List[str] = Field(..., description="会话ID列表")
    format: str = Field("html", description="报告格式(jsonl/csv/excel/html)")
    include_raw: bool = Field(False, description="包含原始数据")


class ReportInfo(BaseModel):
    report_id: str = Field(..., description="报告ID")
    filename: str = Field(..., description="文件名")
    format: str = Field(..., description="格式")
    size: int = Field(0, description="文件大小")
    created_at: datetime = Field(default_factory=datetime.now, description="创建时间")
    session_count: int = Field(0, description="会话数")


class NetworkInterface(BaseModel):
    name: str = Field(..., description="接口名称(用于抓包绑定)")
    description: str = Field("", description="接口描述")
    ipv4: str = Field("", description="IPv4地址")
    mac: str = Field("", description="MAC地址")
    is_loopback: bool = Field(False, description="是否回环")
    is_virtual: bool = Field(False, description="是否虚拟网卡")
    status: str = Field("unknown", description="状态(up/down)")
    speed: int = Field(0, description="速度(Mbps)")


class APIResponse(BaseModel):
    success: bool = Field(True, description="是否成功")
    message: str = Field("ok", description="消息")
    data: Optional[Any] = Field(None, description="数据")
    error: Optional[str] = Field(None, description="错误信息")
