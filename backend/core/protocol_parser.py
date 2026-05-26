# -*- coding: utf-8 -*-
"""
HTTP/HTTPS 协议解析器
提取请求方法、URI、POST Body、Cookie、响应状态码等
自动解码 Base64/URL/Hex 编码
"""

import re
import base64
import urllib.parse
import binascii
import json
from typing import Optional, Dict, Any, Tuple
from loguru import logger

from backend.models.schemas import HttpRequest, HttpResponse, HttpSession


class ProtocolParser:
    """
    HTTP 协议解析器
    从原始 TCP 载荷中解析 HTTP 请求和响应
    """

    # HTTP 方法列表
    HTTP_METHODS = {b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS", b"TRACE"}

    # 常见 WebShell 相关的 Content-Type
    SUSPICIOUS_CONTENT_TYPES = [
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "application/octet-stream",
        "text/plain",
    ]

    def parse_http_request(self, raw_data: bytes) -> Optional[HttpRequest]:
        """
        解析 HTTP 请求
        返回 HttpRequest 对象，解析失败返回 None
        """
        try:
            # 分离请求头和请求体
            if b"\r\n\r\n" in raw_data:
                header_part, body = raw_data.split(b"\r\n\r\n", 1)
            elif b"\n\n" in raw_data:
                header_part, body = raw_data.split(b"\n\n", 1)
            else:
                header_part = raw_data
                body = b""

            # 解析请求行和头部
            lines = header_part.split(b"\r\n") if b"\r\n" in header_part else header_part.split(b"\n")
            if not lines:
                return None

            # 解析请求行
            request_line = lines[0].decode("utf-8", errors="replace").strip()
            parts = request_line.split(" ")
            if len(parts) < 2:
                return None

            method = parts[0].upper()
            if method.encode() not in self.HTTP_METHODS:
                return None

            uri = parts[1] if len(parts) > 1 else "/"
            version = parts[2] if len(parts) > 2 else "HTTP/1.1"

            # 解析请求头
            headers = {}
            for line in lines[1:]:
                line_str = line.decode("utf-8", errors="replace").strip()
                if ":" in line_str:
                    key, _, value = line_str.partition(":")
                    headers[key.strip().lower()] = value.strip()

            # 构建请求对象
            request = HttpRequest(
                method=method,
                uri=uri,
                version=version,
                headers=headers,
                body=body,
                content_type=headers.get("content-type", ""),
                content_length=int(headers.get("content-length", 0)) if headers.get("content-length", "").isdigit() else None,
                user_agent=headers.get("user-agent", ""),
                cookie=headers.get("cookie", ""),
                host=headers.get("host", "")
            )

            # 解码请求体
            if body:
                request.body_decoded = self._decode_body(body, headers.get("content-type", ""))
                request.decoded_body = self._try_decode_payload(body)
                request.params = self._parse_params(uri, body, headers.get("content-type", ""))

            return request

        except Exception as e:
            logger.debug(f"解析 HTTP 请求失败: {e}")
            return None

    def parse_http_response(self, raw_data: bytes) -> Optional[HttpResponse]:
        """
        解析 HTTP 响应
        返回 HttpResponse 对象，解析失败返回 None
        """
        try:
            # 分离响应头和响应体
            if b"\r\n\r\n" in raw_data:
                header_part, body = raw_data.split(b"\r\n\r\n", 1)
            elif b"\n\n" in raw_data:
                header_part, body = raw_data.split(b"\n\n", 1)
            else:
                header_part = raw_data
                body = b""

            lines = header_part.split(b"\r\n") if b"\r\n" in header_part else header_part.split(b"\n")
            if not lines:
                return None

            # 解析状态行
            status_line = lines[0].decode("utf-8", errors="replace").strip()
            parts = status_line.split(" ", 2)
            if len(parts) < 2:
                return None

            version = parts[0]
            try:
                status_code = int(parts[1])
            except ValueError:
                return None
            status_message = parts[2] if len(parts) > 2 else ""

            # 解析响应头
            headers = {}
            for line in lines[1:]:
                line_str = line.decode("utf-8", errors="replace").strip()
                if ":" in line_str:
                    key, _, value = line_str.partition(":")
                    headers[key.strip().lower()] = value.strip()

            response = HttpResponse(
                status_code=status_code,
                status_message=status_message,
                version=version,
                headers=headers,
                body=body,
                content_type=headers.get("content-type", ""),
                content_length=int(headers.get("content-length", 0)) if headers.get("content-length", "").isdigit() else None
            )

            # 解码响应体
            if body:
                response.body_decoded = self._decode_body(body, headers.get("content-type", ""))
                response.decoded_body = self._try_decode_payload(body)

            return response

        except Exception as e:
            logger.debug(f"解析 HTTP 响应失败: {e}")
            return None

    def _decode_body(self, body: bytes, content_type: str) -> str:
        """根据 Content-Type 解码请求体"""
        try:
            # 处理 gzip 压缩
            if "gzip" in content_type:
                import gzip
                body = gzip.decompress(body)

            # 处理 deflate 压缩
            elif "deflate" in content_type:
                import zlib
                body = zlib.decompress(body)

            # 尝试 UTF-8 解码
            return body.decode("utf-8", errors="replace")
        except Exception:
            return body.decode("latin-1", errors="replace")

    def _try_decode_payload(self, data: bytes) -> Optional[str]:
        """
        尝试多种解码方式还原载荷
        顺序：Base64 -> URL -> Hex -> 原始
        """
        if not data:
            return None

        # 先尝试 UTF-8 解码
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")

        decoded_results = []

        # 1. 尝试 Base64 解码
        b64_result = self._try_base64_decode(text)
        if b64_result:
            decoded_results.append(f"[Base64] {b64_result}")

        # 2. 尝试 URL 解码
        url_result = self._try_url_decode(text)
        if url_result and url_result != text:
            decoded_results.append(f"[URL] {url_result}")

        # 3. 尝试 Hex 解码
        hex_result = self._try_hex_decode(text)
        if hex_result:
            decoded_results.append(f"[Hex] {hex_result}")

        # 4. 尝试 JSON 解析
        json_result = self._try_json_parse(text)
        if json_result:
            decoded_results.append(f"[JSON] {json_result}")

        if decoded_results:
            return "\n".join(decoded_results)

        return text[:2000] if len(text) > 2000 else text

    def _try_base64_decode(self, text: str) -> Optional[str]:
        """尝试 Base64 解码"""
        # 提取可能的 Base64 字符串（长度 >= 20）
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        matches = b64_pattern.findall(text)

        results = []
        for match in matches[:5]:  # 最多处理 5 个
            try:
                # 补全 padding
                padded = match + "=" * (4 - len(match) % 4) if len(match) % 4 else match
                decoded = base64.b64decode(padded)
                # 检查是否为可打印字符
                decoded_str = decoded.decode("utf-8", errors="replace")
                if self._is_printable_ratio(decoded_str) > 0.7:
                    results.append(decoded_str[:500])
            except Exception:
                continue

        return "\n".join(results) if results else None

    def _try_url_decode(self, text: str) -> Optional[str]:
        """尝试 URL 解码"""
        try:
            decoded = urllib.parse.unquote(text)
            # 多次解码（处理双重编码）
            decoded2 = urllib.parse.unquote(decoded)
            return decoded2 if decoded2 != text else decoded
        except Exception:
            return None

    def _try_hex_decode(self, text: str) -> Optional[str]:
        """尝试 Hex 解码"""
        # 匹配纯十六进制字符串
        hex_pattern = re.compile(r'^[0-9a-fA-F]{20,}$')
        clean_text = text.strip()

        if hex_pattern.match(clean_text):
            try:
                decoded = bytes.fromhex(clean_text).decode("utf-8", errors="replace")
                if self._is_printable_ratio(decoded) > 0.7:
                    return decoded[:500]
            except Exception:
                pass

        # 匹配 \x 格式
        if "\\x" in text:
            try:
                decoded = bytes.fromhex(text.replace("\\x", "")).decode("utf-8", errors="replace")
                return decoded[:500]
            except Exception:
                pass

        return None

    def _try_json_parse(self, text: str) -> Optional[str]:
        """尝试 JSON 解析"""
        text = text.strip()
        if text.startswith(("{", "[")):
            try:
                parsed = json.loads(text)
                return json.dumps(parsed, ensure_ascii=False, indent=2)[:1000]
            except Exception:
                pass
        return None

    def _is_printable_ratio(self, text: str) -> float:
        """计算可打印字符比例"""
        if not text:
            return 0.0
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        return printable / len(text)

    def _parse_params(self, uri: str, body: bytes, content_type: str) -> Dict[str, Any]:
        """解析请求参数（URL 参数 + POST 参数）"""
        params = {}

        # 解析 URL 参数
        if "?" in uri:
            query_string = uri.split("?", 1)[1]
            try:
                url_params = urllib.parse.parse_qs(query_string)
                for k, v in url_params.items():
                    params[k] = v[0] if len(v) == 1 else v
            except Exception:
                pass

        # 解析 POST 参数
        if body and content_type:
            if "application/x-www-form-urlencoded" in content_type:
                try:
                    body_str = body.decode("utf-8", errors="replace")
                    post_params = urllib.parse.parse_qs(body_str)
                    for k, v in post_params.items():
                        params[k] = v[0] if len(v) == 1 else v
                except Exception:
                    pass

            elif "application/json" in content_type:
                try:
                    body_str = body.decode("utf-8", errors="replace")
                    json_params = json.loads(body_str)
                    if isinstance(json_params, dict):
                        params.update(json_params)
                except Exception:
                    pass

            elif "multipart/form-data" in content_type:
                # 解析 multipart 表单
                boundary_match = re.search(r'boundary=([^\s;]+)', content_type)
                if boundary_match:
                    boundary = boundary_match.group(1).encode()
                    parts = body.split(b"--" + boundary)
                    for part in parts[1:-1]:
                        if b"\r\n\r\n" in part:
                            part_header, part_body = part.split(b"\r\n\r\n", 1)
                            name_match = re.search(rb'name="([^"]+)"', part_header)
                            if name_match:
                                name = name_match.group(1).decode("utf-8", errors="replace")
                                params[name] = part_body.rstrip(b"\r\n").decode("utf-8", errors="replace")

        return params

    def extract_webshell_indicators(self, request: HttpRequest) -> Dict[str, Any]:
        """
        提取 WebShell 相关指标
        返回可疑特征字典
        """
        indicators = {
            "suspicious_params": [],
            "encoded_content": [],
            "dangerous_functions": [],
            "suspicious_ua": False,
            "large_post": False
        }

        # 检查 User-Agent 异常
        ua = request.user_agent or ""
        suspicious_uas = [
            "antSword", "Behinder", "Godzilla", "chopper",
            "Mozilla/5.0 (compatible; MSIE 9.0",  # 冰蝎默认 UA
            "Mozilla/5.0 (Windows NT 6.1)",  # 常见 WebShell UA
        ]
        for sus_ua in suspicious_uas:
            if sus_ua.lower() in ua.lower():
                indicators["suspicious_ua"] = True
                break

        # 检查 POST 大小
        if request.body and len(request.body) > 10240:  # 10KB
            indicators["large_post"] = True

        # 检查危险函数
        dangerous_funcs = [
            "eval", "exec", "system", "shell_exec", "passthru",
            "popen", "proc_open", "assert", "preg_replace",
            "create_function", "call_user_func", "base64_decode",
            "gzinflate", "str_rot13", "gzuncompress"
        ]

        body_str = ""
        if request.body:
            body_str = request.body.decode("utf-8", errors="replace").lower()
        if request.decoded_body:
            body_str += request.decoded_body.lower()

        for func in dangerous_funcs:
            if func in body_str:
                indicators["dangerous_functions"].append(func)

        # 检查编码内容
        if request.body:
            body_text = request.body.decode("utf-8", errors="replace")
            # 检查 Base64 编码
            if re.search(r'[A-Za-z0-9+/]{50,}={0,2}', body_text):
                indicators["encoded_content"].append("base64")
            # 检查 Hex 编码
            if re.search(r'[0-9a-fA-F]{50,}', body_text):
                indicators["encoded_content"].append("hex")

        return indicators
