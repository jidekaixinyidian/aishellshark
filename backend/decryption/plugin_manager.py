# -*- coding: utf-8 -*-
"""
解密插件管理器
支持注册自定义解密函数，插件化适配新变种
"""

import importlib
import inspect
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Type, Any
from loguru import logger

from backend.decryption.base import DecryptionPlugin, DecryptionResult
from backend.models.schemas import HttpSession


class PluginManager:
    """解密插件管理器"""

    def __init__(self, config: dict):
        self.config = config
        self.plugins: Dict[str, DecryptionPlugin] = {}
        self.plugin_dir = Path("plugins/decryption")
        self.plugin_dir.mkdir(parents=True, exist_ok=True)

        # 加载内置插件
        self._load_builtin_plugins()

        # 加载自定义插件
        self._load_custom_plugins()

        logger.info(f"插件管理器初始化完成，加载了 {len(self.plugins)} 个插件")

    def _load_builtin_plugins(self):
        """加载内置解密插件"""
        try:
            # 导入内置插件
            from backend.decryption.behinder import BehinderDecryptor
            from backend.decryption.godzilla import GodzillaDecryptor
            from backend.decryption.antsword import AntSwordDecryptor
            from backend.decryption.weevely import WeevelyDecryptor

            # 注册内置插件
            builtin_plugins = [
                ("behinder", BehinderDecryptor(self.config.get("decryption", {}))),
                ("godzilla", GodzillaDecryptor(self.config.get("decryption", {}))),
                ("antsword", AntSwordDecryptor(self.config.get("decryption", {}))),
                ("weevely", WeevelyDecryptor(self.config.get("decryption", {}))),
            ]

            for name, plugin in builtin_plugins:
                self.plugins[name] = plugin
                logger.debug(f"已加载内置插件: {plugin.get_name()}")

        except ImportError as e:
            logger.error(f"加载内置插件失败: {e}")

    def _load_custom_plugins(self):
        """加载自定义插件"""
        try:
            # 扫描插件目录
            for plugin_file in self.plugin_dir.glob("*.py"):
                if plugin_file.name.startswith("_"):
                    continue

                try:
                    plugin = self._load_plugin_from_file(plugin_file)
                    if plugin:
                        plugin_name = plugin_file.stem
                        self.plugins[plugin_name] = plugin
                        logger.info(f"已加载自定义插件: {plugin.get_name()}")
                except Exception as e:
                    logger.error(f"加载插件 {plugin_file} 失败: {e}")

        except Exception as e:
            logger.error(f"扫描插件目录失败: {e}")

    def _load_plugin_from_file(self, plugin_file: Path) -> Optional[DecryptionPlugin]:
        """从文件加载插件"""
        try:
            # 动态导入模块
            module_name = f"plugins.decryption.{plugin_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if not spec or not spec.loader:
                return None

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # 查找插件类
            plugin_class = None
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and
                    issubclass(obj, DecryptionPlugin) and
                    obj != DecryptionPlugin):
                    plugin_class = obj
                    break

            if not plugin_class:
                logger.warning(f"插件文件 {plugin_file} 中未找到 DecryptionPlugin 子类")
                return None

            # 实例化插件
            return plugin_class(self.config.get("decryption", {}))

        except Exception as e:
            logger.error(f"加载插件文件 {plugin_file} 失败: {e}")
            return None

    def register_plugin(self, name: str, plugin: DecryptionPlugin):
        """注册插件"""
        if name in self.plugins:
            logger.warning(f"插件 {name} 已存在，将被覆盖")
        self.plugins[name] = plugin
        logger.info(f"已注册插件: {plugin.get_name()}")

    def unregister_plugin(self, name: str):
        """注销插件"""
        if name in self.plugins:
            plugin = self.plugins.pop(name)
            logger.info(f"已注销插件: {plugin.get_name()}")

    def get_plugin(self, name: str) -> Optional[DecryptionPlugin]:
        """获取指定插件"""
        return self.plugins.get(name)

    def list_plugins(self) -> List[Dict[str, Any]]:
        """列出所有插件"""
        return [
            {
                "name": name,
                "plugin_name": plugin.get_name(),
                "description": plugin.get_description(),
                "supported_tools": plugin.get_supported_tools(),
            }
            for name, plugin in self.plugins.items()
        ]

    def decrypt_session(self, session: HttpSession) -> List[DecryptionResult]:
        """
        对会话进行解密
        返回所有成功解密的結果
        """
        results = []

        if not session.request or not session.request.body:
            return results

        # 准备元数据
        metadata = self._build_metadata(session)

        # 尝试所有插件
        for plugin_name, plugin in self.plugins.items():
            try:
                if plugin.can_decrypt(session.request.body, metadata):
                    result = plugin.decrypt(session.request.body, metadata)
                    if result.success:
                        results.append(result)
                        logger.debug(f"插件 {plugin_name} 解密成功")
            except Exception as e:
                logger.error(f"插件 {plugin_name} 解密失败: {e}")

        return results

    def decrypt_data(self, data: bytes, metadata: Dict[str, Any]) -> List[DecryptionResult]:
        """
        对原始数据进行解密
        返回所有成功解密的結果
        """
        results = []

        if not data:
            return results

        # 尝试所有插件
        for plugin_name, plugin in self.plugins.items():
            try:
                if plugin.can_decrypt(data, metadata):
                    result = plugin.decrypt(data, metadata)
                    if result.success:
                        results.append(result)
                        logger.debug(f"插件 {plugin_name} 解密成功")
            except Exception as e:
                logger.error(f"插件 {plugin_name} 解密失败: {e}")

        return results

    def _build_metadata(self, session: HttpSession) -> Dict[str, Any]:
        """构建解密元数据"""
        metadata = {
            "session_id": session.session_id,
            "timestamp": session.packet_info.timestamp,
            "five_tuple": session.packet_info.five_tuple.dict(),
        }

        if session.request:
            metadata["request"] = {
                "method": session.request.method,
                "uri": session.request.uri,
                "headers": session.request.headers,
                "user_agent": session.request.user_agent,
                "content_type": session.request.content_type,
                "cookie": session.request.cookie,
                "body": session.request.body_decoded,
                "params": self._extract_params(session.request),
            }

        if session.response:
            metadata["response"] = {
                "status_code": session.response.status_code,
                "headers": session.response.headers,
                "content_type": session.response.content_type,
                "body": session.response.body_decoded,
            }

        return metadata

    def _extract_params(self, request) -> Dict[str, Any]:
        """从请求中提取参数"""
        params = {}

        # 从 URL 中提取参数
        if "?" in request.uri:
            import urllib.parse
            query_string = request.uri.split("?", 1)[1]
            try:
                url_params = urllib.parse.parse_qs(query_string)
                for k, v in url_params.items():
                    params[k] = v[0] if len(v) == 1 else v
            except Exception:
                pass

        # 从请求体中提取参数
        if request.body and request.content_type:
            body_str = request.body_decoded or ""

            if "application/x-www-form-urlencoded" in request.content_type:
                try:
                    post_params = urllib.parse.parse_qs(body_str)
                    for k, v in post_params.items():
                        params[k] = v[0] if len(v) == 1 else v
                except Exception:
                    pass

            elif "application/json" in request.content_type:
                try:
                    json_params = json.loads(body_str)
                    if isinstance(json_params, dict):
                        params.update(json_params)
                except Exception:
                    pass

        return params

    def create_custom_plugin_template(self, plugin_name: str, tool_name: str) -> str:
        """
        创建自定义插件模板
        返回模板文件内容
        """
        template = f'''# -*- coding: utf-8 -*-
"""
{tool_name} 自定义解密插件
用户自定义的解密插件
"""

import base64
from typing import Dict, Any
from loguru import logger

from backend.decryption.base import BaseDecryptor, DecryptionResult


class {plugin_name.capitalize()}Decryptor(BaseDecryptor):
    """{tool_name} 解密器"""

    def __init__(self, config: dict):
        super().__init__(config)
        # 在这里配置默认参数
        self.default_key = config.get("{plugin_name}_default_key", "")

    def get_name(self) -> str:
        return "{tool_name} 解密器"

    def get_description(self) -> str:
        return "支持 {tool_name} 的自定义解密算法"

    def get_supported_tools(self) -> list:
        return ["{tool_name}"]

    def can_decrypt(self, data: bytes, metadata: Dict[str, Any]) -> bool:
        """判断是否能解密该数据"""
        if not data:
            return False

        # TODO: 添加你的检测逻辑
        # 检查数据特征、请求头、参数等
        
        try:
            data_str = data.decode("utf-8", errors="replace")
            # 示例：检查特定特征
            if "your_pattern" in data_str:
                return True
        except Exception:
            pass

        return False

    def decrypt(self, data: bytes, metadata: Dict[str, Any]) -> DecryptionResult:
        """执行解密"""
        try:
            data_str = data.decode("utf-8", errors="replace")
            
            # TODO: 实现你的解密逻辑
            # 示例：简单的 Base64 解码
            try:
                decoded_bytes = base64.b64decode(data_str)
                decrypted_str = decoded_bytes.decode("utf-8", errors="replace")
                
                if self._is_valid_decrypted(decrypted_str):
                    return self.create_result(
                        success=True,
                        tool_name="{tool_name}",
                        original_data=data_str[:500],
                        decrypted_data=decrypted_str,
                        algorithm="base64",
                        key=self.default_key or "default"
                    )
            except Exception:
                pass

            return self.create_result(
                success=False,
                tool_name="{tool_name}",
                original_data=data_str[:500],
                error="无法解密：未实现解密方法"
            )

        except Exception as e:
            logger.error(f"{tool_name} 解密失败: {{e}}")
            return self.create_result(
                success=False,
                tool_name="{tool_name}",
                original_data=data.decode("utf-8", errors="replace")[:500],
                error=f"解密异常: {{str(e)}}"
            )

    def _is_valid_decrypted(self, text: str) -> bool:
        """检查解密结果是否有效"""
        if not text:
            return False

        # TODO: 添加你的有效性检查逻辑
        # 检查是否包含特定特征、命令等
        
        # 示例：检查可打印字符比例
        printable = sum(1 for c in text if c.isprintable() or c in "\\n\\r\\t")
        ratio = printable / len(text) if text else 0
        return ratio > 0.7
'''

        return template

    def save_plugin_template(self, plugin_name: str, tool_name: str) -> Path:
        """保存插件模板到文件"""
        template = self.create_custom_plugin_template(plugin_name, tool_name)
        plugin_file = self.plugin_dir / f"{plugin_name}.py"

        with open(plugin_file, "w", encoding="utf-8") as f:
            f.write(template)

        logger.info(f"已创建插件模板: {plugin_file}")
        return plugin_file

    def reload_plugins(self):
        """重新加载所有插件"""
        old_count = len(self.plugins)
        self.plugins.clear()
        self._load_builtin_plugins()
        self._load_custom_plugins()
        new_count = len(self.plugins)

        logger.info(f"插件重新加载完成: {old_count} -> {new_count} 个插件")

    def get_statistics(self) -> Dict[str, Any]:
        """获取插件管理器统计信息"""
        return {
            "total_plugins": len(self.plugins),
            "builtin_plugins": sum(1 for p in self.plugins.values() 
                                 if p.__class__.__module__.startswith("backend.decryption")),
            "custom_plugins": sum(1 for p in self.plugins.values() 
                                if not p.__class__.__module__.startswith("backend.decryption")),
            "plugin_dir": str(self.plugin_dir.absolute()),
        }