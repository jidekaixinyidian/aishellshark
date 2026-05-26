# -*- coding: utf-8 -*-
"""
特征匹配检测引擎
内置菜刀、蚁剑、冰蝎、哥斯拉、Weevely3、SharPyShell 指纹库
检测 UA 异常、危险函数等
"""

import re
import hashlib
from typing import List, Dict, Optional, Tuple
from loguru import logger

from backend.models.schemas import (
    HttpSession, DetectionResult, SignatureMatch, ThreatLevel,
    WebShellType, EntropyResult
)
from backend.core.entropy_analyzer import EntropyAnalyzer


class DetectionRule:
    """检测规则"""
    def __init__(
        self,
        rule_id: str,
        name: str,
        category: str,
        description: str,
        patterns: List[str],
        webshell_type: WebShellType,
        confidence: float,
        score: float,
        flags: int = re.IGNORECASE
    ):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.description = description
        self.webshell_type = webshell_type
        self.confidence = confidence
        self.score = score
        # 编译正则表达式
        self.compiled_patterns = []
        for pattern in patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern, flags))
            except re.error as e:
                logger.warning(f"规则 {rule_id} 正则编译失败: {e}")


class DetectionEngine:
    """
    特征匹配检测引擎
    支持多种 WebShell 工具的指纹识别
    """

    def __init__(self, config: dict):
        self.config = config
        self.threat_threshold = config.get("threat_threshold", 60)
        self.high_threat_threshold = config.get("high_threat_threshold", 80)
        self.entropy_analyzer = EntropyAnalyzer(config)

        # 加载检测规则
        self.rules: List[DetectionRule] = []
        self._load_builtin_rules()

        logger.info(f"检测引擎初始化完成，加载了 {len(self.rules)} 条规则")

    def _load_builtin_rules(self):
        """加载内置检测规则"""

        # ==================== 中国菜刀 ====================
        self.rules.extend([
            DetectionRule(
                rule_id="CHOPPER-001",
                name="菜刀 PHP 一句话特征",
                category="webshell",
                description="检测中国菜刀 PHP WebShell 特征",
                patterns=[
                    r'@eval\(base64_decode\(',
                    r'@eval\(\$_POST\[',
                    r'@eval\(\$_GET\[',
                    r'@eval\(\$_REQUEST\[',
                    r'eval\(gzinflate\(base64_decode\(',
                    r'eval\(str_rot13\(',
                ],
                webshell_type=WebShellType.CHOPPER,
                confidence=0.9,
                score=80.0
            ),
            DetectionRule(
                rule_id="CHOPPER-002",
                name="菜刀流量特征",
                category="traffic",
                description="检测菜刀 HTTP 流量特征",
                patterns=[
                    r'z0=@eval\(',
                    r'z1=\$_POST\[',
                    r'@ini_set\("display_errors",\s*"0"\)',
                    r'@set_time_limit\(0\)',
                    r'echo\s+md5\(',
                ],
                webshell_type=WebShellType.CHOPPER,
                confidence=0.85,
                score=75.0
            ),
        ])

        # ==================== 蚁剑 AntSword ====================
        self.rules.extend([
            DetectionRule(
                rule_id="ANTSWORD-001",
                name="蚁剑 User-Agent 特征",
                category="ua",
                description="检测蚁剑默认 User-Agent",
                patterns=[
                    r'antSword',
                    r'antsword',
                ],
                webshell_type=WebShellType.ANTSWORD,
                confidence=0.95,
                score=85.0
            ),
            DetectionRule(
                rule_id="ANTSWORD-002",
                name="蚁剑 PHP 载荷特征",
                category="payload",
                description="检测蚁剑 PHP 载荷特征",
                patterns=[
                    r'@ini_set\("display_errors",\s*"0"\);\s*@set_time_limit\(0\)',
                    r'function\s+asenc\(',
                    r'function\s+asdecode\(',
                    r'\$as_err\s*=\s*@',
                    r'echo\s+\$as_err',
                ],
                webshell_type=WebShellType.ANTSWORD,
                confidence=0.88,
                score=78.0
            ),
            DetectionRule(
                rule_id="ANTSWORD-003",
                name="蚁剑编码器特征",
                category="encoding",
                description="检测蚁剑 Base64/ROT13 编码特征",
                patterns=[
                    r'base64_decode\(str_rot13\(',
                    r'str_rot13\(base64_decode\(',
                    r'gzinflate\(base64_decode\(str_rot13\(',
                ],
                webshell_type=WebShellType.ANTSWORD,
                confidence=0.82,
                score=72.0
            ),
        ])

        # ==================== 冰蝎 Behinder ====================
        self.rules.extend([
            DetectionRule(
                rule_id="BEHINDER-001",
                name="冰蝎 v2 流量特征",
                category="traffic",
                description="检测冰蝎 v2 AES 加密流量特征",
                patterns=[
                    r'e45e329feb5d925b',  # 默认密钥
                ],
                webshell_type=WebShellType.BEHINDER,
                confidence=0.95,
                score=90.0
            ),
            DetectionRule(
                rule_id="BEHINDER-002",
                name="冰蝎 v3 流量特征",
                category="traffic",
                description="检测冰蝎 v3 流量特征",
                patterns=[
                    r'Accept:\s*application/json',
                    r'Content-Type:\s*application/octet-stream',
                ],
                webshell_type=WebShellType.BEHINDER,
                confidence=0.6,
                score=50.0
            ),
            DetectionRule(
                rule_id="BEHINDER-003",
                name="冰蝎 PHP WebShell 特征",
                category="webshell",
                description="检测冰蝎 PHP WebShell 代码特征",
                patterns=[
                    r'\$_SESSION\[\'k\'\]',
                    r'openssl_decrypt\(',
                    r'mcrypt_decrypt\(MCRYPT_RIJNDAEL_128',
                    r'session_start\(\).*\$_SESSION\[',
                ],
                webshell_type=WebShellType.BEHINDER,
                confidence=0.88,
                score=80.0
            ),
            DetectionRule(
                rule_id="BEHINDER-004",
                name="冰蝎默认 User-Agent",
                category="ua",
                description="检测冰蝎默认 User-Agent",
                patterns=[
                    r'Mozilla/5\.0 \(compatible; MSIE 9\.0; Windows NT 6\.1; Trident/5\.0\)',
                    r'Mozilla/5\.0 \(Windows NT 6\.1\)',
                ],
                webshell_type=WebShellType.BEHINDER,
                confidence=0.7,
                score=55.0
            ),
        ])

        # ==================== 哥斯拉 Godzilla ====================
        self.rules.extend([
            DetectionRule(
                rule_id="GODZILLA-001",
                name="哥斯拉 PHP 特征",
                category="webshell",
                description="检测哥斯拉 PHP WebShell 特征",
                patterns=[
                    r'md5\(md5\(\$pass\)',
                    r'\$payloadName\s*=\s*\$parameters\[',
                    r'Encrypt\(\$payloadName',
                    r'base64_decode\(str_rot13\(base64_decode\(',
                ],
                webshell_type=WebShellType.GODZILLA,
                confidence=0.9,
                score=85.0
            ),
            DetectionRule(
                rule_id="GODZILLA-002",
                name="哥斯拉 Java 特征",
                category="webshell",
                description="检测哥斯拉 Java WebShell 特征",
                patterns=[
                    r'U2FsdGVkX1',  # Godzilla Java 加密前缀
                    r'pageContext\.getSession\(\)',
                    r'getClass\(\)\.getClassLoader\(\)',
                ],
                webshell_type=WebShellType.GODZILLA,
                confidence=0.85,
                score=80.0
            ),
            DetectionRule(
                rule_id="GODZILLA-003",
                name="哥斯拉流量特征",
                category="traffic",
                description="检测哥斯拉 HTTP 流量特征",
                patterns=[
                    r'pass=\w+&cmd=\w+',
                    r'caidao',  # 默认密钥
                ],
                webshell_type=WebShellType.GODZILLA,
                confidence=0.75,
                score=65.0
            ),
        ])

        # ==================== Weevely3 ====================
        self.rules.extend([
            DetectionRule(
                rule_id="WEEVELY-001",
                name="Weevely3 PHP 特征",
                category="webshell",
                description="检测 Weevely3 PHP WebShell 特征",
                patterns=[
                    r'\$k\s*=\s*"[a-f0-9]{8}"',
                    r'str_split\(\$r,3\)',
                    r'array_map\("ord"',
                    r'implode\(array_map\("chr"',
                ],
                webshell_type=WebShellType.WEEVELY,
                confidence=0.88,
                score=80.0
            ),
            DetectionRule(
                rule_id="WEEVELY-002",
                name="Weevely3 流量特征",
                category="traffic",
                description="检测 Weevely3 HTTP 流量特征",
                patterns=[
                    r'[A-Za-z0-9]{8}=[A-Za-z0-9+/]{10,}',  # 参数混淆
                ],
                webshell_type=WebShellType.WEEVELY,
                confidence=0.65,
                score=55.0
            ),
        ])

        # ==================== SharPyShell ====================
        self.rules.extend([
            DetectionRule(
                rule_id="SHARPYSHELL-001",
                name="SharPyShell 特征",
                category="webshell",
                description="检测 SharPyShell WebShell 特征",
                patterns=[
                    r'SharPyShell',
                    r'Assembly\.Load\(',
                    r'Activator\.CreateInstance\(',
                    r'System\.Reflection\.Assembly',
                ],
                webshell_type=WebShellType.SHARPYSHELL,
                confidence=0.9,
                score=85.0
            ),
        ])

        # ==================== 通用危险函数 ====================
        self.rules.extend([
            DetectionRule(
                rule_id="GENERIC-001",
                name="PHP 危险函数",
                category="dangerous_function",
                description="检测 PHP 危险函数调用",
                patterns=[
                    r'system\s*\(',
                    r'shell_exec\s*\(',
                    r'passthru\s*\(',
                    r'popen\s*\(',
                    r'proc_open\s*\(',
                    r'exec\s*\(',
                ],
                webshell_type=WebShellType.UNKNOWN,
                confidence=0.7,
                score=60.0
            ),
            DetectionRule(
                rule_id="GENERIC-002",
                name="命令执行特征",
                category="command_execution",
                description="检测命令执行相关特征",
                patterns=[
                    r'cmd\.exe',
                    r'/bin/sh',
                    r'/bin/bash',
                    r'whoami',
                    r'net\s+user',
                    r'ipconfig',
                    r'ifconfig',
                    r'cat\s+/etc/passwd',
                    r'ls\s+-la',
                ],
                webshell_type=WebShellType.UNKNOWN,
                confidence=0.75,
                score=65.0
            ),
            DetectionRule(
                rule_id="GENERIC-003",
                name="文件操作特征",
                category="file_operation",
                description="检测文件读写操作特征",
                patterns=[
                    r'file_get_contents\s*\(',
                    r'file_put_contents\s*\(',
                    r'fwrite\s*\(',
                    r'move_uploaded_file\s*\(',
                    r'copy\s*\(',
                    r'unlink\s*\(',
                ],
                webshell_type=WebShellType.UNKNOWN,
                confidence=0.5,
                score=40.0
            ),
            DetectionRule(
                rule_id="GENERIC-004",
                name="Base64 编码执行",
                category="obfuscation",
                description="检测 Base64 编码执行特征",
                patterns=[
                    r'eval\s*\(\s*base64_decode\s*\(',
                    r'assert\s*\(\s*base64_decode\s*\(',
                    r'preg_replace\s*\(\s*[\'"]/.*/e[\'"]',
                    r'create_function\s*\(',
                ],
                webshell_type=WebShellType.UNKNOWN,
                confidence=0.85,
                score=75.0
            ),
        ])

        # ==================== 异常 User-Agent ====================
        self.rules.extend([
            DetectionRule(
                rule_id="UA-001",
                name="空 User-Agent",
                category="ua_anomaly",
                description="检测空 User-Agent（可能为自动化工具）",
                patterns=[
                    r'^$',
                ],
                webshell_type=WebShellType.UNKNOWN,
                confidence=0.4,
                score=30.0
            ),
            DetectionRule(
                rule_id="UA-002",
                name="Python/curl/wget User-Agent",
                category="ua_anomaly",
                description="检测自动化工具 User-Agent",
                patterns=[
                    r'python-requests',
                    r'python-urllib',
                    r'^curl/',
                    r'^wget/',
                    r'Go-http-client',
                    r'Java/',
                ],
                webshell_type=WebShellType.UNKNOWN,
                confidence=0.5,
                score=35.0
            ),
        ])

    async def analyze(self, session: HttpSession) -> DetectionResult:
        """
        对 HTTP 会话进行综合检测分析
        返回 DetectionResult
        """
        result = DetectionResult(session_id=session.session_id)
        total_score = 0.0
        signature_matches = []

        # 构建检测目标文本
        target_texts = self._build_target_texts(session)

        # 1. 特征匹配检测
        for rule in self.rules:
            match = self._apply_rule(rule, target_texts, session)
            if match:
                signature_matches.append(match)
                total_score += rule.score

        result.signature_matches = signature_matches

        # 2. 熵值分析
        entropy_result = self._analyze_entropy(session)
        result.entropy_result = entropy_result
        if entropy_result.is_high_entropy:
            total_score += 20.0
        if entropy_result.is_aes_aligned:
            total_score += 15.0

        # 3. 确定威胁等级和工具类型
        result.threat_score = min(total_score, 100.0)
        result.threat_level = self._score_to_level(result.threat_score)
        result.webshell_type = self._determine_webshell_type(signature_matches)
        result.confidence = self._calculate_confidence(signature_matches, entropy_result)

        # 4. 生成摘要
        result.summary = self._generate_summary(result)

        return result

    def _build_target_texts(self, session: HttpSession) -> Dict[str, str]:
        """构建检测目标文本字典"""
        texts = {}

        if session.request:
            req = session.request
            # 请求 URI
            texts["uri"] = req.uri or ""
            # User-Agent
            texts["ua"] = req.user_agent or ""
            # 请求体
            if req.body:
                texts["request_body"] = req.body.decode("utf-8", errors="replace")
            if req.body_decoded:
                texts["request_body_decoded"] = req.body_decoded
            if req.decoded_body:
                texts["request_decoded"] = req.decoded_body
            # Cookie
            texts["cookie"] = req.cookie or ""
            # 所有请求头
            texts["request_headers"] = str(req.headers)

        if session.response:
            resp = session.response
            if resp.body:
                texts["response_body"] = resp.body.decode("utf-8", errors="replace")
            if resp.body_decoded:
                texts["response_body_decoded"] = resp.body_decoded

        return texts

    def _apply_rule(
        self,
        rule: DetectionRule,
        target_texts: Dict[str, str],
        session: HttpSession
    ) -> Optional[SignatureMatch]:
        """应用单条规则进行检测"""
        # 根据规则类别选择检测目标
        if rule.category == "ua" or rule.category == "ua_anomaly":
            targets = [target_texts.get("ua", "")]
        elif rule.category == "traffic":
            targets = list(target_texts.values())
        elif rule.category in ("webshell", "payload", "encoding", "obfuscation"):
            targets = [
                target_texts.get("request_body", ""),
                target_texts.get("request_body_decoded", ""),
                target_texts.get("request_decoded", ""),
                target_texts.get("response_body", ""),
            ]
        elif rule.category in ("dangerous_function", "command_execution", "file_operation"):
            targets = [
                target_texts.get("request_body", ""),
                target_texts.get("request_decoded", ""),
                target_texts.get("response_body", ""),
            ]
        else:
            targets = list(target_texts.values())

        for pattern in rule.compiled_patterns:
            for target in targets:
                if not target:
                    continue
                match = pattern.search(target)
                if match:
                    matched_content = match.group(0)[:200]  # 截取匹配内容
                    return SignatureMatch(
                        rule_id=rule.rule_id,
                        rule_name=rule.name,
                        category=rule.category,
                        description=rule.description,
                        matched_content=matched_content,
                        confidence=rule.confidence,
                        webshell_type=rule.webshell_type
                    )

        return None

    def _analyze_entropy(self, session: HttpSession) -> EntropyResult:
        """分析会话的熵值"""
        req_entropy = None
        resp_entropy = None

        if session.request and session.request.body:
            req_entropy = self.entropy_analyzer.calculate_entropy(session.request.body)

        if session.response and session.response.body:
            resp_entropy = self.entropy_analyzer.calculate_entropy(session.response.body)

        entropy_threshold = self.config.get("entropy_threshold", 7.0)
        is_high = (
            (req_entropy is not None and req_entropy > entropy_threshold) or
            (resp_entropy is not None and resp_entropy > entropy_threshold)
        )

        # 检测 AES 块对齐
        is_aes = False
        if session.request and session.request.body:
            is_aes = self.entropy_analyzer.check_aes_alignment(session.request.body)

        return EntropyResult(
            request_body_entropy=req_entropy,
            response_body_entropy=resp_entropy,
            is_high_entropy=is_high,
            is_aes_aligned=is_aes,
            block_size=16 if is_aes else None
        )

    def _score_to_level(self, score: float) -> ThreatLevel:
        """将威胁分数转换为威胁等级"""
        if score >= 90:
            return ThreatLevel.CRITICAL
        elif score >= self.high_threat_threshold:
            return ThreatLevel.HIGH
        elif score >= self.threat_threshold:
            return ThreatLevel.MEDIUM
        elif score >= 30:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.CLEAN

    def _determine_webshell_type(self, matches: List[SignatureMatch]) -> WebShellType:
        """根据匹配结果确定 WebShell 类型"""
        if not matches:
            return WebShellType.UNKNOWN

        # 统计各类型的置信度
        type_scores: Dict[WebShellType, float] = {}
        for match in matches:
            if match.webshell_type != WebShellType.UNKNOWN:
                current = type_scores.get(match.webshell_type, 0.0)
                type_scores[match.webshell_type] = current + match.confidence

        if not type_scores:
            return WebShellType.UNKNOWN

        # 返回置信度最高的类型
        return max(type_scores, key=type_scores.get)

    def _calculate_confidence(
        self,
        matches: List[SignatureMatch],
        entropy_result: EntropyResult
    ) -> float:
        """计算综合置信度"""
        if not matches and not entropy_result.is_high_entropy:
            return 0.0

        confidences = [m.confidence for m in matches]
        if entropy_result.is_high_entropy:
            confidences.append(0.6)
        if entropy_result.is_aes_aligned:
            confidences.append(0.7)

        if not confidences:
            return 0.0

        # 使用最大置信度加权平均
        max_conf = max(confidences)
        avg_conf = sum(confidences) / len(confidences)
        return (max_conf * 0.7 + avg_conf * 0.3)

    def _generate_summary(self, result: DetectionResult) -> str:
        """生成检测摘要"""
        if result.threat_level == ThreatLevel.CLEAN:
            return "未检测到威胁"

        parts = []
        if result.webshell_type != WebShellType.UNKNOWN:
            type_names = {
                WebShellType.CHOPPER: "中国菜刀",
                WebShellType.ANTSWORD: "蚁剑",
                WebShellType.BEHINDER: "冰蝎",
                WebShellType.GODZILLA: "哥斯拉",
                WebShellType.WEEVELY: "Weevely3",
                WebShellType.SHARPYSHELL: "SharPyShell",
            }
            tool_name = type_names.get(result.webshell_type, "未知工具")
            parts.append(f"疑似 {tool_name} WebShell 流量")

        if result.signature_matches:
            parts.append(f"命中 {len(result.signature_matches)} 条特征规则")

        if result.entropy_result and result.entropy_result.is_high_entropy:
            parts.append("检测到高熵加密流量")

        if result.entropy_result and result.entropy_result.is_aes_aligned:
            parts.append("疑似 AES 加密数据")

        level_names = {
            ThreatLevel.LOW: "低危",
            ThreatLevel.MEDIUM: "中危",
            ThreatLevel.HIGH: "高危",
            ThreatLevel.CRITICAL: "严重",
        }
        level_name = level_names.get(result.threat_level, "未知")
        parts.append(f"威胁等级: {level_name}（{result.threat_score:.1f}分）")

        return "；".join(parts)

    def add_custom_rule(self, rule: DetectionRule):
        """添加自定义检测规则"""
        self.rules.append(rule)
        logger.info(f"已添加自定义规则: {rule.rule_id}")

    def get_rules_summary(self) -> List[Dict]:
        """获取规则摘要"""
        return [
            {
                "rule_id": r.rule_id,
                "name": r.name,
                "category": r.category,
                "webshell_type": r.webshell_type.value,
                "confidence": r.confidence,
                "score": r.score
            }
            for r in self.rules
        ]
