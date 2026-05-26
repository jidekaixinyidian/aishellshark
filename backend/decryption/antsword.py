# -*- coding: utf-8 -*-
"""
蚁剑（AntSword）解密器
支持 Base64/ROT13/编码后的命令还原
"""

import base64
import re
from typing import Dict, Any, Optional
from loguru import logger

from backend.decryption.base import BaseDecryptor, DecryptionResult


class AntSwordDecryptor(BaseDecryptor):
    """蚁剑解密器"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.default_pass = config.get("antsword_default_pass", "ant")
        self.supported_encodings = ["base64", "rot13", "hex", "url"]

    def get_name(self) -> str:
        return "蚁剑（AntSword）解密器"

    def get_description(self) -> str:
        return "支持蚁剑的 Base64/ROT13/Hex/URL 编码解密"

    def get_supported_tools(self) -> list:
        return ["蚁剑", "AntSword"]

    def can_decrypt(self, data: bytes, metadata: Dict[str, Any]) -> bool:
        """判断是否能解密蚁剑数据"""
        if not data:
            return False

        # 检查蚁剑特征
        request = metadata.get("request")
        if request:
            # 检查 User-Agent
            ua = request.get("user_agent", "")
            if "antSword" in ua or "antsword" in ua:
                return True

            # 检查请求体特征
            body = request.get("body", "")
            if isinstance(body, str):
                # 蚁剑编码特征
                if "base64_decode" in body or "str_rot13" in body:
                    return True

                # 蚁剑特定函数
                if "asenc(" in body or "asdecode(" in body:
                    return True

        # 检查数据特征
        try:
            data_str = data.decode("utf-8", errors="replace")
            # 检查是否为编码数据
            if self._is_encoded_data(data_str):
                return True

            # 检查是否包含蚁剑特定模式
            ant_patterns = [
                r'@ini_set\("display_errors",\s*"0"\)',
                r'@set_time_limit\(0\)',
                r'function\s+asenc\(',
                r'function\s+asdecode\(',
            ]

            for pattern in ant_patterns:
                if re.search(pattern, data_str):
                    return True

        except Exception:
            pass

        return False

    def decrypt(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """解密蚁剑数据"""
        try:
            data_str = data.decode("utf-8", errors="replace")

            # 尝试多种解密方式
            result = self._try_decode_antsword(data_str, metadata)
            if result.success:
                return result

            result = self._try_decode_nested(data_str)
            if result.success:
                return result

            result = self._try_decode_simple(data_str)
            if result.success:
                return result

            return self.create_result(
                success=False,
                tool_name="蚁剑",
                original_data=data_str[:500],
                error="无法解密：未找到有效的解密方法"
            )

        except Exception as e:
            logger.error(f"蚁剑解密失败: {e}")
            return self.create_result(
                success=False,
                tool_name="蚁剑",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"解密异常: {str(e)}"
            )

    def _try_decode_antsword(self, data: str, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试蚁剑特定解码"""
        try:
            # 提取可能的密码
            password = self._extract_password(metadata)

            # 蚁剑常见编码模式
            patterns = [
                # base64_decode(str_rot13(...))
                (r'base64_decode\(str_rot13\(["\']([^"\']+)["\']\)\)', self._decode_base64_rot13),
                # str_rot13(base64_decode(...))
                (r'str_rot13\(base64_decode\(["\']([^"\']+)["\']\)\)', self._decode_rot13_base64),
                # gzinflate(base64_decode(str_rot13(...)))
                (r'gzinflate\(base64_decode\(str_rot13\(["\']([^"\']+)["\']\)\)\)', self._decode_gzip_base64_rot13),
                # 直接 Base64 编码
                (r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']', self._decode_base64),
            ]

            for pattern, decoder in patterns:
                matches = re.findall(pattern, data)
                for match in matches:
                    if isinstance(match, tuple):
                        encoded = match[0]
                    else:
                        encoded = match

                    decoded = decoder(encoded)
                    if decoded and self._is_valid_decrypted(decoded):
                        return self.create_result(
                            success=True,
                            tool_name="蚁剑",
                            original_data=data[:500],
                            decrypted_data=decoded,
                            algorithm=decoder.__name__.replace("_decode_", ""),
                            key=password or "default"
                        )

            return self.create_result(
                success=False,
                tool_name="蚁剑",
                original_data=data[:500],
                error="未找到蚁剑特定编码模式"
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="蚁剑",
                original_data=data[:500],
                error=f"蚁剑特定解码失败: {str(e)}"
            )

    def _try_decode_nested(self, data: str) -> DecryptionResult:
        """尝试嵌套解码"""
        try:
            # 尝试多层解码
            decoded = data
            algorithms = []

            # 最多尝试 5 层解码
            for i in range(5):
                prev_decoded = decoded

                # 尝试各种解码
                if self._looks_like_base64(decoded):
                    temp = self._decode_base64_simple(decoded)
                    if temp and temp != decoded:
                        decoded = temp
                        algorithms.append("base64")
                        continue

                if self._looks_like_rot13(decoded):
                    temp = self.try_rot13_decode(decoded)
                    if temp and temp != decoded:
                        decoded = temp
                        algorithms.append("rot13")
                        continue

                if self._looks_like_url_encoded(decoded):
                    temp = self.try_url_decode(decoded)
                    if temp and temp != decoded:
                        decoded = temp
                        algorithms.append("url")
                        continue

                if self._looks_like_hex(decoded):
                    temp = self._decode_hex_simple(decoded)
                    if temp and temp != decoded:
                        decoded = temp
                        algorithms.append("hex")
                        continue

                # 如果没有变化，停止
                if decoded == prev_decoded:
                    break

            # 检查最终结果是否有效
            if decoded != data and self._is_valid_decrypted(decoded):
                algorithm = "->".join(algorithms) if algorithms else "nested"
                return self.create_result(
                    success=True,
                    tool_name="蚁剑（嵌套）",
                    original_data=data[:500],
                    decrypted_data=decoded,
                    algorithm=algorithm,
                    key=""
                )

            return self.create_result(
                success=False,
                tool_name="蚁剑（嵌套）",
                original_data=data[:500],
                error="嵌套解码未产生有效结果"
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="蚁剑（嵌套）",
                original_data=data[:500],
                error=f"嵌套解码失败: {str(e)}"
            )

    def _try_decode_simple(self, data: str) -> DecryptionResult:
        """尝试简单解码"""
        try:
            # 尝试直接 Base64 解码
            decoded = self._decode_base64_simple(data)
            if decoded and self._is_valid_decrypted(decoded):
                return self.create_result(
                    success=True,
                    tool_name="蚁剑（Base64）",
                    original_data=data[:500],
                    decrypted_data=decoded,
                    algorithm="base64",
                    key=""
                )

            # 尝试 ROT13 解码
            decoded = self.try_rot13_decode(data)
            if decoded and decoded != data and self._is_valid_decrypted(decoded):
                return self.create_result(
                    success=True,
                    tool_name="蚁剑（ROT13）",
                    original_data=data[:500],
                    decrypted_data=decoded,
                    algorithm="rot13",
                    key=""
                )

            # 尝试 URL 解码
            decoded = self.try_url_decode(data)
            if decoded and decoded != data and self._is_valid_decrypted(decoded):
                return self.create_result(
                    success=True,
                    tool_name="蚁剑（URL）",
                    original_data=data[:500],
                    decrypted_data=decoded,
                    algorithm="url",
                    key=""
                )

            # 尝试 Hex 解码
            decoded = self._decode_hex_simple(data)
            if decoded and self._is_valid_decrypted(decoded):
                return self.create_result(
                    success=True,
                    tool_name="蚁剑（Hex）",
                    original_data=data[:500],
                    decrypted_data=decoded,
                    algorithm="hex",
                    key=""
                )

            return self.create_result(
                success=False,
                tool_name="蚁剑（简单）",
                original_data=data[:500],
                error="简单解码未产生有效结果"
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="蚁剑（简单）",
                original_data=data[:500],
                error=f"简单解码失败: {str(e)}"
            )

    def _decode_base64_rot13(self, encoded: str) -> Optional[str]:
        """Base64 解码后 ROT13 解码"""
        try:
            # 先 Base64 解码
            decoded_bytes = base64.b64decode(encoded)
            decoded_str = decoded_bytes.decode("utf-8", errors="replace")
            # 再 ROT13 解码
            return self.try_rot13_decode(decoded_str)
        except Exception:
            return None

    def _decode_rot13_base64(self, encoded: str) -> Optional[str]:
        """ROT13 解码后 Base64 解码"""
        try:
            # 先 ROT13 解码
            rot13_decoded = self.try_rot13_decode(encoded)
            # 再 Base64 解码
            decoded_bytes = base64.b64decode(rot13_decoded)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _decode_gzip_base64_rot13(self, encoded: str) -> Optional[str]:
        """Gzip 解压 + Base64 解码 + ROT13 解码"""
        try:
            # 先 ROT13 解码
            rot13_decoded = self.try_rot13_decode(encoded)
            # 再 Base64 解码
            decoded_bytes = base64.b64decode(rot13_decoded)
            # 最后 Gzip 解压
            import gzip
            decompressed = gzip.decompress(decoded_bytes)
            return decompressed.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _decode_base64(self, encoded: str) -> Optional[str]:
        """简单 Base64 解码"""
        try:
            decoded_bytes = base64.b64decode(encoded)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _decode_base64_simple(self, data: str) -> Optional[str]:
        """尝试 Base64 解码（带 padding 处理）"""
        try:
            # 清理数据
            clean_data = data.strip()
            # 补全 padding
            padding = 4 - len(clean_data) % 4
            if padding != 4:
                clean_data += "=" * padding

            decoded_bytes = base64.b64decode(clean_data)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _decode_hex_simple(self, data: str) -> Optional[str]:
        """尝试 Hex 解码"""
        try:
            # 清理数据
            clean_data = data.strip().replace("\\x", "").replace("0x", "")
            # 确保长度为偶数
            if len(clean_data) % 2 != 0:
                clean_data = clean_data[:-1]

            decoded_bytes = bytes.fromhex(clean_data)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _looks_like_base64(self, data: str) -> bool:
        """判断是否像 Base64 编码"""
        if not data:
            return False
        pattern = r'^[A-Za-z0-9+/=\n]{20,}$'
        return bool(re.match(pattern, data.strip()))

    def _looks_like_rot13(self, data: str) -> bool:
        """判断是否像 ROT13 编码"""
        if not data:
            return False
        # ROT13 编码通常只包含字母
        letters = sum(1 for c in data if 'a' <= c <= 'z' or 'A' <= c <= 'Z')
        return letters / len(data) > 0.7 if data else False

    def _looks_like_url_encoded(self, data: str) -> bool:
        """判断是否像 URL 编码"""
        if not data:
            return False
        return '%' in data

    def _looks_like_hex(self, data: str) -> bool:
        """判断是否像 Hex 编码"""
        if not data:
            return False
        pattern = r'^[0-9a-fA-F]{20,}$'
        return bool(re.match(pattern, data.strip()))

    def _is_encoded_data(self, data: str) -> bool:
        """判断是否为编码数据"""
        return (
            self._looks_like_base64(data) or
            self._looks_like_hex(data) or
            self._looks_like_url_encoded(data)
        )

    def _is_valid_decrypted(self, text: str) -> bool:
        """检查解密结果是否有效"""
        if not text:
            return False

        # 检查是否包含蚁剑特定特征
        ant_patterns = [
            r'@ini_set\("display_errors",\s*"0"\)',
            r'@set_time_limit\(0\)',
            r'function\s+asenc\(',
            r'function\s+asdecode\(',
            r'\$as_err\s*=',
            r'echo\s+\$as_err',
        ]

        for pattern in ant_patterns:
            if re.search(pattern, text):
                return True

        # 检查是否包含 PHP 代码
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

        # 检查是否包含常见命令
        common_commands = [
            "system", "exec", "shell_exec", "passthru",
            "whoami", "ipconfig", "ifconfig", "ls", "dir",
            "cat", "type", "echo", "print",
        ]

        for cmd in common_commands:
            if cmd in text.lower():
                return True

        # 检查可打印字符比例
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        ratio = printable / len(text) if text else 0
        return ratio > 0.7

    def _extract_password(self, metadata: Dict[str, Any]) -> Optional[str]:
        """从元数据中提取密码"""
        # 从请求参数中提取
        params = metadata.get("request", {}).get("params", {})
        if "ant" in params:
            return str(params["ant"])

        # 从请求体中提取
        body = metadata.get("request", {}).get("body", "")
        if body and isinstance(body, str):
            # 查找 ant 参数
            match = re.search(r'ant=([^&]+)', body)
            if match:
                return match.group(1)

            # 查找其他可能的密码参数
            key_patterns = [
                r'pass=([^&]+)',
                r'password=([^&]+)',
                r'pwd=([^&]+)',
                r'key=([^&]+)',
            ]
            for pattern in key_patterns:
                match = re.search(pattern, body)
                if match:
                    return match.group(1)

        return None