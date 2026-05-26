# -*- coding: utf-8 -*-
"""
Weevely3 解密器
支持参数混淆还原
"""

import re
import base64
from typing import Dict, Any, Optional
from loguru import logger

from backend.decryption.base import BaseDecryptor, DecryptionResult


class WeevelyDecryptor(BaseDecryptor):
    """Weevely3 解密器"""

    def __init__(self, config: dict):
        super().__init__(config)
        self.supported_versions = ["v3"]

    def get_name(self) -> str:
        return "Weevely3 解密器"

    def get_description(self) -> str:
        return "支持 Weevely3 参数混淆还原"

    def get_supported_tools(self) -> list:
        return ["Weevely3", "Weevely"]

    def can_decrypt(self, data: bytes, metadata: Dict[str, Any]) -> bool:
        """判断是否能解密 Weevely3 数据"""
        if not data:
            return False

        # 检查 Weevely3 特征
        request = metadata.get("request")
        if request:
            # 检查参数特征
            params = request.get("params", {})
            for key in params:
                # Weevely3 参数通常为 8 位随机字符串
                if len(key) == 8 and re.match(r'^[A-Za-z0-9]{8}$', key):
                    return True

            # 检查请求体特征
            body = request.get("body", "")
            if isinstance(body, str):
                # Weevely3 参数模式
                if re.search(r'[A-Za-z0-9]{8}=[A-Za-z0-9+/]{10,}', body):
                    return True

        # 检查数据特征
        try:
            data_str = data.decode("utf-8", errors="replace")
            # Weevely3 特定模式
            if re.search(r'\$k\s*=\s*"[a-f0-9]{8}"', data_str):
                return True

            if re.search(r'str_split\(\$r,3\)', data_str):
                return True

            if re.search(r'array_map\("ord"', data_str):
                return True

        except Exception:
            pass

        return False

    def decrypt(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """解密 Weevely3 数据"""
        try:
            data_str = data.decode("utf-8", errors="replace")

            # 尝试多种解密方式
            result = self._try_decode_weevely(data_str, metadata)
            if result.success:
                return result

            result = self._try_decode_params(data_str, metadata)
            if result.success:
                return result

            result = self._try_decode_php_code(data_str)
            if result.success:
                return result

            return self.create_result(
                success=False,
                tool_name="Weevely3",
                original_data=data_str[:500],
                error="无法解密：未找到有效的解密方法"
            )

        except Exception as e:
            logger.error(f"Weevely3 解密失败: {e}")
            return self.create_result(
                success=False,
                tool_name="Weevely3",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"解密异常: {str(e)}"
            )

    def _try_decode_weevely(self, data: str, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试 Weevely3 特定解码"""
        try:
            # 查找 Weevely3 密钥
            key_match = re.search(r'\$k\s*=\s*"([a-f0-9]{8})"', data)
            if not key_match:
                return self.create_result(
                    success=False,
                    tool_name="Weevely3",
                    original_data=data[:500],
                    error="未找到 Weevely3 密钥"
                )

            key = key_match.group(1)

            # 查找加密数据
            # Weevely3 通常将数据放在特定参数中
            param_pattern = r'([A-Za-z0-9]{8})=([A-Za-z0-9+/=]+)'
            matches = re.findall(param_pattern, data)

            for param_name, param_value in matches:
                # 尝试解密参数值
                decrypted = self._decrypt_weevely_param(param_value, key)
                if decrypted and self._is_valid_decrypted(decrypted):
                    return self.create_result(
                        success=True,
                        tool_name="Weevely3",
                        original_data=data[:500],
                        decrypted_data=decrypted,
                        algorithm="Weevely3 XOR",
                        key=key,
                    )

            return self.create_result(
                success=False,
                tool_name="Weevely3",
                original_data=data[:500],
                error="未找到可解密的参数"
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="Weevely3",
                original_data=data[:500],
                error=f"Weevely3 特定解码失败: {str(e)}"
            )

    def _try_decode_params(self, data: str, metadata: Dict[str, Any]) -> DecryptionResult:
        """尝试从参数中解码"""
        try:
            # 从元数据中获取参数
            params = metadata.get("request", {}).get("params", {})
            if not params:
                # 尝试从请求体中解析参数
                body = metadata.get("request", {}).get("body", "")
                if body:
                    import urllib.parse
                    params = urllib.parse.parse_qs(body)
                    # 将列表转换为单个值
                    params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}

            # 查找可能的 Weevely3 参数
            for param_name, param_value in params.items():
                if not isinstance(param_value, str):
                    continue

                # Weevely3 参数名通常为 8 位随机字符串
                if len(param_name) == 8 and re.match(r'^[A-Za-z0-9]{8}$', param_name):
                    # 尝试多种解密方式
                    decrypted = self._try_decode_param_value(param_value)
                    if decrypted and self._is_valid_decrypted(decrypted):
                        return self.create_result(
                        success=True,
                        tool_name="Weevely3（参数）",
                        original_data=data[:500],
                        decrypted_data=decrypted,
                        algorithm="参数解码",
                        key=param_name,
                    )

            return self.create_result(
                success=False,
                tool_name="Weevely3（参数）",
                original_data=data[:500],
                error="未找到可解密的参数"
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="Weevely3（参数）",
                original_data=data[:500],
                error=f"参数解码失败: {str(e)}"
            )

    def _try_decode_php_code(self, data: str) -> DecryptionResult:
        """尝试从 PHP 代码中解码"""
        try:
            # 查找 Weevely3 PHP 代码模式
            patterns = [
                # str_split($r,3) 模式
                (r'str_split\(\$r,3\)', self._decode_str_split),
                # array_map("ord", ...) 模式
                (r'array_map\("ord"', self._decode_array_map),
                # implode(array_map("chr", ...)) 模式
                (r'implode\(array_map\("chr"', self._decode_implode_chr),
            ]

            for pattern, decoder in patterns:
                if re.search(pattern, data):
                    decoded = decoder(data)
                    if decoded and self._is_valid_decrypted(decoded):
                        return self.create_result(
                            success=True,
                            tool_name="Weevely3（PHP）",
                            original_data=data[:500],
                            decrypted_data=decoded,
                            algorithm="PHP 代码解析",
                            key=""
                        )

            return self.create_result(
                success=False,
                tool_name="Weevely3（PHP）",
                original_data=data[:500],
                error="未找到可解析的 PHP 代码"
            )

        except Exception as e:
            return self.create_result(
                success=False,
                tool_name="Weevely3（PHP）",
                original_data=data[:500],
                error=f"PHP 代码解析失败: {str(e)}"
            )

    def _decrypt_weevely_param(self, encrypted: str, key: str) -> Optional[str]:
        """解密 Weevely3 参数"""
        try:
            # Weevely3 使用 XOR 加密，密钥为 8 位十六进制字符串
            key_bytes = bytes.fromhex(key)

            # 参数值通常是 Base64 编码的
            try:
                encrypted_bytes = base64.b64decode(encrypted)
            except Exception:
                # 如果不是 Base64，直接使用原始数据
                encrypted_bytes = encrypted.encode("utf-8")

            # XOR 解密
            decrypted = bytearray()
            for i in range(len(encrypted_bytes)):
                key_byte = key_bytes[i % len(key_bytes)]
                decrypted.append(encrypted_bytes[i] ^ key_byte)

            return bytes(decrypted).decode("utf-8", errors="replace")

        except Exception:
            return None

    def _try_decode_param_value(self, value: str) -> Optional[str]:
        """尝试解密参数值"""
        # 尝试多种解密方式
        methods = [
            self._try_base64_decode,
            self._try_base64_xor_decode,
            self._try_url_decode,
            self._try_hex_decode,
        ]

        for method in methods:
            decoded = method(value)
            if decoded and self._is_valid_decrypted(decoded):
                return decoded

        return None

    def _try_base64_decode(self, value: str) -> Optional[str]:
        """尝试 Base64 解码"""
        try:
            decoded_bytes = base64.b64decode(value)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _try_base64_xor_decode(self, value: str) -> Optional[str]:
        """尝试 Base64 解码后 XOR 解密"""
        try:
            # 先 Base64 解码
            decoded_bytes = base64.b64decode(value)
            # 尝试常见 XOR 密钥
            common_keys = [
                b"weevely",
                b"password",
                b"12345678",
                b"admin123",
            ]

            for key in common_keys:
                result = bytearray()
                for i in range(len(decoded_bytes)):
                    result.append(decoded_bytes[i] ^ key[i % len(key)])
                decoded_str = bytes(result).decode("utf-8", errors="replace")
                if self._is_valid_decrypted(decoded_str):
                    return decoded_str

        except Exception:
            pass

        return None

    def _try_url_decode(self, value: str) -> Optional[str]:
        """尝试 URL 解码"""
        try:
            import urllib.parse
            return urllib.parse.unquote(value)
        except Exception:
            return None

    def _try_hex_decode(self, value: str) -> Optional[str]:
        """尝试 Hex 解码"""
        try:
            clean_value = value.replace("\\x", "").replace("0x", "")
            decoded_bytes = bytes.fromhex(clean_value)
            return decoded_bytes.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _decode_str_split(self, code: str) -> Optional[str]:
        """解析 str_split($r,3) 模式"""
        try:
            # 查找 $r 变量的值
            r_match = re.search(r'\$r\s*=\s*["\']([^"\']+)["\']', code)
            if not r_match:
                return None

            r_value = r_match.group(1)

            # str_split($r,3) 表示每 3 个字符一组
            groups = [r_value[i:i+3] for i in range(0, len(r_value), 3)]

            # 每组转换为十进制，然后转换为字符
            result = []
            for group in groups:
                try:
                    # 每组是十六进制字符串
                    decimal = int(group, 16)
                    result.append(chr(decimal))
                except ValueError:
                    # 如果不是十六进制，直接使用
                    result.append(group)

            return ''.join(result)

        except Exception:
            return None

    def _decode_array_map(self, code: str) -> Optional[str]:
        """解析 array_map("ord", ...) 模式"""
        try:
            # 查找数组变量
            array_match = re.search(r'array_map\("ord",\s*([^)]+)\)', code)
            if not array_match:
                return None

            array_expr = array_match.group(1)

            # 尝试解析数组表达式
            if array_expr.startswith('$'):
                # 查找变量值
                var_match = re.search(r'\$' + array_expr[1:] + r'\s*=\s*["\']([^"\']+)["\']', code)
                if not var_match:
                    return None
                array_str = var_match.group(1)
            else:
                # 可能是直接字符串
                array_str = array_expr.strip('"\'')

            # array_map("ord", ...) 返回字符的 ASCII 值
            # 这里简化处理，直接返回字符串
            return array_str

        except Exception:
            return None

    def _decode_implode_chr(self, code: str) -> Optional[str]:
        """解析 implode(array_map("chr", ...)) 模式"""
        try:
            # 查找 implode(array_map("chr", ...))
            pattern = r'implode\(array_map\("chr",\s*([^)]+)\)\)'
            match = re.search(pattern, code)
            if not match:
                return None

            array_expr = match.group(1)

            # 尝试解析数组
            if 'explode' in array_expr:
                # 可能是 explode(",", $data) 形式
                explode_match = re.search(r'explode\(["\'],["\'],\s*([^)]+)\)', array_expr)
                if explode_match:
                    data_expr = explode_match.group(1)
                    # 查找数据变量
                    data_match = re.search(r'\$' + data_expr[1:] + r'\s*=\s*["\']([^"\']+)["\']', code)
                    if data_match:
                        data_str = data_match.group(1)
                        # 按逗号分割，转换为字符
                        parts = data_str.split(',')
                        result = []
                        for part in parts:
                            try:
                                result.append(chr(int(part.strip())))
                            except ValueError:
                                result.append(part.strip())
                        return ''.join(result)

            return None

        except Exception:
            return None

    def _is_valid_decrypted(self, text: str) -> bool:
        """检查解密结果是否有效"""
        if not text:
            return False

        # 检���是否包含 Weevely3 特征
        weevely_patterns = [
            r'str_split\(\$r,3\)',
            r'array_map\("ord"',
            r'implode\(array_map\("chr"',
            r'\$k\s*=\s*"[a-f0-9]{8}"',
        ]

        for pattern in weevely_patterns:
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