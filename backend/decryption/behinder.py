# -*- coding: utf-8 -*-
"""
冰蝎（Behinder）解密器
支持 AES-128-ECB/XOR 解密
"""

import base64
import hashlib
from typing import Dict, Any, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from loguru import logger

from backend.decryption.base import BaseDecryptor, DecryptionResult


class BehinderDecryptor(BaseDecryptor):
    """冰蝎解密器"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.default_key = config.get("behinder_default_key", "e45e329feb5d925b")
        self.supported_versions = ["v2", "v3", "v4"]

    def get_name(self) -> str:
        return "冰蝎（Behinder）解密器"

    def get_description(self) -> str:
        return "支持冰蝎 v2/v3/v4 版本的 AES-128-ECB 和 XOR 解密"

    def get_supported_tools(self) -> list:
        return ["冰蝎", "Behinder"]

    def can_decrypt(self, data: bytes, metadata: Dict[str, Any]) -> bool:
        """判断是否能解密冰蝎数据"""
        if not data:
            return False

        # 检查是否为冰蝎特征
        request = metadata.get("request")
        if request:
            # 检查 User-Agent
            ua = request.get("user_agent", "")
            if "MSIE 9.0" in ua or "Windows NT 6.1" in ua:
                return True

            # 检查 Cookie
            cookie = request.get("cookie", "")
            if "PHPSESSID" in cookie:
                return True

            # 检查 Content-Type
            content_type = request.get("content_type", "")
            if "application/octet-stream" in content_type:
                return True

        # 检查数据特征
        try:
            data_str = data.decode("utf-8", errors="replace")
            # 冰蝎 v2 默认密钥特征
            if self.default_key in data_str:
                return True

            # 检查是否为 Base64 编码的加密数据
            if len(data) % 4 == 0:
                try:
                    decoded = base64.b64decode(data)
                    if len(decoded) % 16 == 0:  # AES 块对齐
                        return True
                except Exception:
                    pass
        except Exception:
            pass

        return False

    def decrypt(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """解密冰蝎数据"""
        try:
            # 尝试多种解密方式
            result = self._try_decrypt_v2(data, metadata)
            if result.success:
                return result

            result = self._try_decrypt_v3(data, metadata)
            if result.success:
                return result

            result = self._try_decrypt_v4(data, metadata)
            if result.success:
                return result

            # 尝试 XOR 解密
            result = self._try_xor_decrypt(data, metadata)
            if result.success:
                return result

            return self.create_result(
                success=False,
                tool_name="冰蝎",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error="无法解密：未找到有效的解密方法"
            )

        except Exception as e:
            logger.error(f"冰蝎解密失败: {e}")
            return self.create_result(
                success=False,
                tool_name="冰蝎",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"解密异常: {str(e)}"
            )

    def _try_decrypt_v2(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试冰蝎 v2 解密（AES-128-ECB）"""
        try:
            # 获取密钥
            key = self._extract_key(metadata)
            if not key:
                key = self.default_key

            # 确保密钥为 16 字节
            if len(key) < 16:
                key = key.ljust(16, "0")
            elif len(key) > 16:
                key = key[:16]

            key_bytes = key.encode("utf-8")

            # 尝试 Base64 解码
            try:
                encrypted_data = base64.b64decode(data)
            except Exception:
                # 如果不是 Base64，直接使用原始数据
                encrypted_data = data

            # 检查数据长度是否为 16 的倍数
            if len(encrypted_data) % 16 != 0:
                return self.create_result(
                    success=False,
                    tool_name="冰蝎 v2",
                    original_data=data.decode("utf-8", errors="replace")[:500],
                    error="数据长度不是 16 的倍数"
                )

            # AES-128-ECB 解密
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted_data)

            # 去除 PKCS7 padding
            decrypted = unpad(decrypted, AES.block_size)

            # 解码为字符串
            decrypted_str = decrypted.decode("utf-8", errors="replace")

            return self.create_result(
                success=True,
                tool_name="冰蝎 v2",
                original_data=data.decode("utf-8", errors="replace")[:500],
                decrypted_data=decrypted_str,
                algorithm="AES-128-ECB",
                key=key
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="冰蝎 v2",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"v2 解密失败: {str(e)}"
            )

    def _try_decrypt_v3(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试冰蝎 v3 解密"""
        try:
            # v3 使用动态密钥，通常从 Cookie 中提取
            cookie = metadata.get("request", {}).get("cookie", "")
            key = self.extract_key_from_cookie(cookie)

            if not key:
                # 尝试从参数中提取
                params = metadata.get("request", {}).get("params", {})
                key = self.extract_key_from_params(params)

            if not key:
                return self.create_result(
                    success=False,
                    tool_name="冰蝎 v3",
                    original_data=data.decode("utf-8", errors="replace")[:500],
                    error="未找到密钥"
                )

            # v3 使用 XOR 加密
            key_bytes = key.encode("utf-8")
            data_bytes = data

            # 尝试 Base64 解码
            try:
                data_bytes = base64.b64decode(data)
            except Exception:
                pass

            # XOR 解密
            decrypted = bytearray()
            for i in range(len(data_bytes)):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted.append(data_bytes[i] ^ key_byte)

            decrypted_str = bytes(decrypted).decode("utf-8", errors="replace")

            return self.create_result(
                success=True,
                tool_name="冰蝎 v3",
                original_data=data.decode("utf-8", errors="replace")[:500],
                decrypted_data=decrypted_str,
                algorithm="XOR",
                key=key
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="冰蝎 v3",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"v3 解密失败: {str(e)}"
            )

    def _try_decrypt_v4(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试冰蝎 v4 解密"""
        try:
            # v4 使用更复杂的加密，这里简化处理
            # 通常为 AES-128-CBC 或 AES-128-GCM

            # 尝试从 Cookie 获取 IV
            cookie = metadata.get("request", {}).get("cookie", "")
            iv = None
            if "iv=" in cookie:
                import re
                iv_match = re.search(r'iv=([A-Za-z0-9+/=]+)', cookie)
                if iv_match:
                    iv = base64.b64decode(iv_match.group(1))

            # 获取密钥
            key = self._extract_key(metadata)
            if not key:
                key = self.default_key

            key_bytes = key.encode("utf-8")

            # 尝试 Base64 解码
            try:
                encrypted_data = base64.b64decode(data)
            except Exception:
                encrypted_data = data

            if iv:
                # AES-128-CBC 解密
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(encrypted_data)
                decrypted = unpad(decrypted, AES.block_size)
                algorithm = "AES-128-CBC"
            else:
                # 尝试 AES-128-ECB
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                decrypted = cipher.decrypt(encrypted_data)
                decrypted = unpad(decrypted, AES.block_size)
                algorithm = "AES-128-ECB"

            decrypted_str = decrypted.decode("utf-8", errors="replace")

            return self.create_result(
                success=True,
                tool_name="冰蝎 v4",
                original_data=data.decode("utf-8", errors="replace")[:500],
                decrypted_data=decrypted_str,
                algorithm=algorithm,
                key=key
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="冰蝎 v4",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"v4 解密失败: {str(e)}"
            )

    def _try_xor_decrypt(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试 XOR 解密"""
        try:
            # 尝试常见的 XOR 密钥
            common_keys = [
                "e45e329feb5d925b",  # 冰蝎默认
                "caidao",  # 哥斯拉默认
                "ant",  # 蚁剑默认
                "123456",
                "admin",
                "password",
                "webshell",
            ]

            # 添加从元数据中提取的密钥
            key = self._extract_key(metadata)
            if key:
                common_keys.insert(0, key)

            for key in common_keys:
                result = self._xor_decrypt_with_key(data, key)
                if result and self._is_valid_decrypted(result):
                    return self.create_result(
                        success=True,
                        tool_name="冰蝎（XOR）",
                        original_data=data.decode("utf-8", errors="replace")[:500],
                        decrypted_data=result,
                        algorithm="XOR",
                        key=key
                    )

            return self.create_result(
                success=False,
                tool_name="冰蝎（XOR）",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error="XOR 解密失败：未找到有效密钥"
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="冰蝎（XOR）",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"XOR 解密异常: {str(e)}"
            )

    def _xor_decrypt_with_key(self, data: bytes, key: str) -> Optional[str]:
        """使用指定密钥进行 XOR 解密"""
        try:
            key_bytes = key.encode("utf-8")
            decrypted = bytearray()

            for i in range(len(data)):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted.append(data[i] ^ key_byte)

            return bytes(decrypted).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _is_valid_decrypted(self, text: str) -> bool:
        """检查解密结果是否有效"""
        if not text:
            return False

        # 检查是否包含可读内容
        import re
        # 检查是否包含常见命令
        common_commands = [
            "system", "exec", "shell_exec", "passthru",
            "whoami", "ipconfig", "ifconfig", "ls", "dir",
            "cat", "type", "echo", "print", "var_dump",
        ]

        for cmd in common_commands:
            if cmd in text.lower():
                return True

        # 检查是否包含 PHP 代码特征
        php_patterns = [
            r'<\?php',
            r'<\?=',
            r'echo\s+',
            r'print\s+',
            r'\$[a-zA-Z_]',
        ]

        for pattern in php_patterns:
            if re.search(pattern, text):
                return True

        # 检查可打印字符比例
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        ratio = printable / len(text) if text else 0
        return ratio > 0.7

    def _extract_key(self, metadata: Dict[str, Any]) -> Optional[str]:
        """从元数据中提取密钥"""
        # 从请求参数中提取
        params = metadata.get("request", {}).get("params", {})
        key = self.extract_key_from_params(params)
        if key:
            return key

        # 从 Cookie 中提取
        cookie = metadata.get("request", {}).get("cookie", "")
        key = self.extract_key_from_cookie(cookie)
        if key:
            return key

        # 从请求体中提取
        body = metadata.get("request", {}).get("body", "")
        if body:
            import re
            # 查找可能的密钥
            key_patterns = [
                r'key=([^&]+)',
                r'pass=([^&]+)',
                r'password=([^&]+)',
                r'k=([^&]+)',
            ]
            for pattern in key_patterns:
                match = re.search(pattern, body)
                if match:
                    return match.group(1)

        return None