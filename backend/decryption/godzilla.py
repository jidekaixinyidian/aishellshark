# -*- coding: utf-8 -*-
"""
哥斯拉（Godzilla）解密器
支持 Java/PHP 版本的自定义加密算法
"""

import base64
import hashlib
import re
from typing import Dict, Any, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from loguru import logger

from backend.decryption.base import BaseDecryptor, DecryptionResult


class GodzillaDecryptor(BaseDecryptor):
    """哥斯拉解密器"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.default_key = config.get("godzilla_default_key", "caidao")
        self.supported_versions = ["java", "php"]

    def get_name(self) -> str:
        return "哥斯拉（Godzilla）解密器"

    def get_description(self) -> str:
        return "支持哥斯拉 Java/PHP 版本的自定义加密算法"

    def get_supported_tools(self) -> list:
        return ["哥斯拉", "Godzilla"]

    def can_decrypt(self, data: bytes, metadata: Dict[str, Any]) -> bool:
        """判断是否能解密哥斯拉数据"""
        if not data:
            return False

        # 检查哥斯拉特征
        request = metadata.get("request")
        if request:
            # 检查参数特征
            params = request.get("params", {})
            if "pass" in params or "cmd" in params:
                return True

            # 检查请求体特征
            body = request.get("body", "")
            if isinstance(body, str):
                if "pass=" in body and "cmd=" in body:
                    return True
                # 哥斯拉 Java 版特征
                if "U2FsdGVkX1" in body:
                    return True

        # 检查数据特征
        try:
            data_str = data.decode("utf-8", errors="replace")
            # 哥斯拉默认密钥特征
            if self.default_key in data_str:
                return True

            # 哥斯拉 Java 版加密前缀
            if data_str.startswith("U2FsdGVkX1"):
                return True

            # 检查是否为 Base64 编码的加密数据
            if len(data) % 4 == 0:
                try:
                    decoded = base64.b64decode(data)
                    # 哥斯拉 PHP 版通常使用 XOR 加密
                    return True
                except Exception:
                    pass
        except Exception:
            pass

        return False

    def decrypt(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """解密哥斯拉数据"""
        try:
            # 先尝试 Java 版解密
            result = self._try_decrypt_java(data, metadata)
            if result.success:
                return result

            # 再尝试 PHP 版解密
            result = self._try_decrypt_php(data, metadata)
            if result.success:
                return result

            # 尝试通用解密
            result = self._try_general_decrypt(data, metadata)
            if result.success:
                return result

            return self.create_result(
                success=False,
                tool_name="哥斯拉",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error="无法解密：未找到有效的解密方法"
            )

        except Exception as e:
            logger.error(f"哥斯拉解密失败: {e}")
            return self.create_result(
                success=False,
                tool_name="哥斯拉",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"解密异常: {str(e)}"
            )

    def _try_decrypt_java(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试哥斯拉 Java 版解密"""
        try:
            data_str = data.decode("utf-8", errors="replace")

            # 检查是否为 Java 版特征
            if not data_str.startswith("U2FsdGVkX1"):
                return self.create_result(
                    success=False,
                    tool_name="哥斯拉 Java",
                    original_data=data_str[:500],
                    error="不是哥斯拉 Java 版加密数据"
                )

            # 获取密钥
            key = self._extract_key(metadata)
            if not key:
                key = self.default_key

            # Java 版使用 AES-128-CBC 加密，密钥为 MD5(pass)
            key_md5 = hashlib.md5(key.encode("utf-8")).hexdigest()[:16]
            key_bytes = key_md5.encode("utf-8")

            # Base64 解码
            encrypted_data = base64.b64decode(data_str)

            # 提取 IV（前 16 字节）
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            # AES-128-CBC 解密
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted, AES.block_size)

            decrypted_str = decrypted.decode("utf-8", errors="replace")

            return self.create_result(
                success=True,
                tool_name="哥斯拉 Java",
                original_data=data_str[:500],
                decrypted_data=decrypted_str,
                algorithm="AES-128-CBC (Java)",
                key=key
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="哥斯拉 Java",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"Java 版解密失败: {str(e)}"
            )

    def _try_decrypt_php(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试哥斯拉 PHP 版解密"""
        try:
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

            # PHP 版使用 XOR 加密
            decrypted = bytearray()
            for i in range(len(encrypted_data)):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted.append(encrypted_data[i] ^ key_byte)

            decrypted_str = bytes(decrypted).decode("utf-8", errors="replace")

            # 检查解密结果是否有效
            if not self._is_valid_php_decrypted(decrypted_str):
                return self.create_result(
                    success=False,
                    tool_name="哥斯拉 PHP",
                    original_data=data.decode("utf-8", errors="replace")[:500],
                    error="解密结果无效"
                )

            return self.create_result(
                success=True,
                tool_name="哥斯拉 PHP",
                original_data=data.decode("utf-8", errors="replace")[:500],
                decrypted_data=decrypted_str,
                algorithm="XOR (PHP)",
                key=key
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="哥斯拉 PHP",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"PHP 版解密失败: {str(e)}"
            )

    def _try_general_decrypt(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试通用解密方法"""
        try:
            # 获取密钥
            key = self._extract_key(metadata)
            if not key:
                key = self.default_key

            # 尝试多种加密方式
            decryption_methods = [
                self._try_aes_ecb_decrypt,
                self._try_aes_cbc_decrypt,
                self._try_xor_decrypt,
                self._try_base64_xor_decrypt,
            ]

            for method in decryption_methods:
                result = method(data, key)
                if result and self._is_valid_decrypted(result):
                    return self.create_result(
                        success=True,
                        tool_name="哥斯拉（通用）",
                        original_data=data.decode("utf-8", errors="replace")[:500],
                        decrypted_data=result,
                        algorithm="通用解密",
                        key=key
                    )

            return self.create_result(
                success=False,
                tool_name="哥斯拉（通用）",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error="通用解密失败"
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="哥斯拉（通用）",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"通用解密异常: {str(e)}"
            )

    def _try_aes_ecb_decrypt(self, data: bytes, key: str) -> Optional[str]:
        """尝试 AES-ECB 解密"""
        try:
            # 准备密钥
            if len(key) < 16:
                key = key.ljust(16, "0")
            elif len(key) > 16:
                key = key[:16]

            key_bytes = key.encode("utf-8")

            # 尝试 Base64 解码
            try:
                encrypted_data = base64.b64decode(data)
            except Exception:
                encrypted_data = data

            # 检查数据长度
            if len(encrypted_data) % 16 != 0:
                return None

            # AES-ECB 解密
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted = cipher.decrypt(encrypted_data)
            decrypted = unpad(decrypted, AES.block_size)

            return decrypted.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _try_aes_cbc_decrypt(self, data: bytes, key: str) -> Optional[str]:
        """尝试 AES-CBC 解密"""
        try:
            # 准备密钥
            key_md5 = hashlib.md5(key.encode("utf-8")).hexdigest()[:16]
            key_bytes = key_md5.encode("utf-8")

            # 尝试 Base64 解码
            try:
                encrypted_data = base64.b64decode(data)
            except Exception:
                encrypted_data = data

            # 检查数据长度
            if len(encrypted_data) < 32:  # 至少需要 IV + 一个块
                return None

            # 使用前 16 字节作为 IV
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            if len(ciphertext) % 16 != 0:
                return None

            # AES-CBC 解密
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted, AES.block_size)

            return decrypted.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _try_xor_decrypt(self, data: bytes, key: str) -> Optional[str]:
        """尝试 XOR 解密"""
        try:
            key_bytes = key.encode("utf-8")
            decrypted = bytearray()

            for i in range(len(data)):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted.append(data[i] ^ key_byte)

            return bytes(decrypted).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _try_base64_xor_decrypt(self, data: bytes, key: str) -> Optional[str]:
        """尝试 Base64 解码后再 XOR 解密"""
        try:
            # 先尝试 Base64 解码
            decoded = base64.b64decode(data)
            # 再尝试 XOR 解密
            return self._try_xor_decrypt(decoded, key)
        except Exception:
            return None

    def _is_valid_php_decrypted(self, text: str) -> bool:
        """检查 PHP 版解密结果是否有效"""
        if not text:
            return False

        # 检查是否包含 PHP 代码特征
        php_patterns = [
            r'<\?php',
            r'<\?=',
            r'echo\s+',
            r'print\s+',
            r'\$[a-zA-Z_]',
            r'@eval\(',
            r'@assert\(',
        ]

        for pattern in php_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        # 检查是否包含哥斯拉特定特征
        godzilla_patterns = [
            r'md5\(md5\(\$pass\)',
            r'\$payloadName\s*=',
            r'Encrypt\(',
        ]

        for pattern in godzilla_patterns:
            if re.search(pattern, text):
                return True

        return self._is_valid_decrypted(text)

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
            "md5", "base64_decode", "str_rot13",
        ]

        for cmd in common_commands:
            if cmd in text.lower():
                return True

        # 检查可打印字符比例
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        ratio = printable / len(text) if text else 0
        return ratio > 0.7

    def _extract_key(self, metadata: Dict[str, Any]) -> Optional[str]:
        """从元数据中提取密钥"""
        # 从请求参数中提取
        params = metadata.get("request", {}).get("params", {})
        if "pass" in params:
            return str(params["pass"])

        # 从请求体中提取
        body = metadata.get("request", {}).get("body", "")
        if body and isinstance(body, str):
            # 查找 pass 参数
            match = re.search(r'pass=([^&]+)', body)
            if match:
                return match.group(1)

            # 查找其他可能的密钥参数
            key_patterns = [
                r'key=([^&]+)',
                r'password=([^&]+)',
                r'pwd=([^&]+)',
                r'k=([^&]+)',
            ]
            for pattern in key_patterns:
                match = re.search(pattern, body)
                if match:
                    return match.group(1)

        return None