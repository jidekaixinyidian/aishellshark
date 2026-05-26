# -*- coding: utf-8 -*-
"""
解密基类
定义解密接口和插件机制
"""

import abc
import base64
import hashlib
from typing import Optional, Dict, Any
from loguru import logger

from backend.models.schemas import DecryptionResult


class DecryptionPlugin(abc.ABC):
    """解密插件基类"""

    @abc.abstractmethod
    def get_name(self) -> str:
        """获取插件名称"""
        pass

    @abc.abstractmethod
    def get_description(self) -> str:
        """获取插件描述"""
        pass

    @abc.abstractmethod
    def get_supported_tools(self) -> list:
        """获取支持的 WebShell 工具列表"""
        pass

    @abc.abstractmethod
    def can_decrypt(self, data: bytes, metadata: Dict[str, Any]) -> bool:
        """判断是否能解密该数据"""
        pass

    @abc.abstractmethod
    def decrypt(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """执行解密"""
        pass


class BaseDecryptor:
    """基础解密器"""

    def __init__(self, config: dict):
        self.config = config

    def try_base64_decode(self, data: str) -> Optional[bytes]:
        """尝试 Base64 解码"""
        try:
            # 补全 padding
            data = data.strip()
            padding = 4 - len(data) % 4
            if padding != 4:
                data += "=" * padding
            return base64.b64decode(data)
        except Exception as e:
            logger.debug(f"Base64 解码失败: {e}")
            return None

    def try_url_decode(self, data: str) -> Optional[str]:
        """尝试 URL 解码"""
        try:
            import urllib.parse
            return urllib.parse.unquote(data)
        except Exception as e:
            logger.debug(f"URL 解码失败: {e}")
            return None

    def try_hex_decode(self, data: str) -> Optional[bytes]:
        """尝试 Hex 解码"""
        try:
            # 清理可能的 \x 前缀
            clean_data = data.replace("\\x", "").replace("0x", "")
            return bytes.fromhex(clean_data)
        except Exception as e:
            logger.debug(f"Hex 解码失败: {e}")
            return None

    def try_rot13_decode(self, data: str) -> str:
        """尝试 ROT13 解码"""
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    def try_gzip_decompress(self, data: bytes) -> Optional[bytes]:
        """尝试 Gzip 解压缩"""
        try:
            import gzip
            return gzip.decompress(data)
        except Exception as e:
            logger.debug(f"Gzip 解压失败: {e}")
            return None

    def try_zlib_decompress(self, data: bytes) -> Optional[bytes]:
        """尝试 Zlib 解压缩"""
        try:
            import zlib
            return zlib.decompress(data)
        except Exception as e:
            logger.debug(f"Zlib 解压失败: {e}")
            return None

    def extract_key_from_cookie(self, cookie: str) -> Optional[str]:
        """从 Cookie 中提取密钥"""
        if not cookie:
            return None

        # 冰蝎 Cookie 特征
        if "PHPSESSID" in cookie:
            # 尝试从 Cookie 值中提取可能的密钥
            import re
            b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
            matches = b64_pattern.findall(cookie)
            for match in matches:
                try:
                    decoded = base64.b64decode(match + "==")
                    if len(decoded) == 16:  # AES-128 密钥长度
                        return decoded.hex()
                except Exception:
                    continue

        return None

    def extract_key_from_params(self, params: Dict[str, Any]) -> Optional[str]:
        """从请求参数中提取密钥"""
        # 检查常见的密钥参数名
        key_param_names = ["key", "pass", "password", "k", "pwd", "secret"]
        for param_name in key_param_names:
            if param_name in params:
                value = params[param_name]
                if isinstance(value, str) and len(value) >= 8:
                    return value

        return None

    def detect_encryption_type(self, data: bytes) -> str:
        """检测加密类型"""
        if len(data) < 16:
            return "unknown"

        # 检查是否为 Base64 编码
        try:
            text = data.decode("ascii", errors="strict")
            import re
            if re.match(r'^[A-Za-z0-9+/=\n]+$', text):
                return "base64"
        except UnicodeDecodeError:
            pass

        # 检查是否为 Hex 编码
        try:
            text = data.decode("ascii", errors="strict")
            if re.match(r'^[0-9a-fA-F]+$', text):
                return "hex"
        except UnicodeDecodeError:
            pass

        # 检查是否为 AES 加密（16 字节对齐）
        if len(data) % 16 == 0:
            # 计算熵值
            from backend.core.entropy_analyzer import EntropyAnalyzer
            analyzer = EntropyAnalyzer({"entropy_threshold": 7.0})
            entropy = analyzer.calculate_entropy(data)
            if entropy > 6.5:
                return "aes"

        return "unknown"

    def create_result(
        self,
        success: bool,
        tool_name: str,
        original_data: str,
        decrypted_data: str = "",
        algorithm: str = "",
        key: str = "",
        error: str = ""
    ) -> DecryptionResult:
        """创建解密结果对象"""
        return DecryptionResult(
            success=success,
            tool_name=tool_name,
            original_data=original_data[:1000],  # 限制长度
            decrypted_data=decrypted_data[:5000] if decrypted_data else "",
            algorithm=algorithm,
            key=key,
            error=error
        )