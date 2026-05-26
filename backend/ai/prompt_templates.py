# -*- coding: utf-8 -*-
"""
Prompt 模板
包含威胁判定、工具识别、攻击意图、载荷提取、处置建议
"""

from typing import Dict, Any, List


class PromptTemplates:
    """
    AI 分析 Prompt 模板管理器
    支持自定义模板和不同场景的提示词
    """

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.templates = self._load_default_templates()

    def _load_default_templates(self) -> Dict[str, str]:
        """加载默认模板"""
        return {
            "webshell_analysis": self._get_webshell_analysis_template(),
            "batch_analysis": self._get_batch_analysis_template(),
            "threat_assessment": self._get_threat_assessment_template(),
            "tool_identification": self._get_tool_identification_template(),
            "command_extraction": self._get_command_extraction_template(),
            "custom_analysis": self._get_custom_analysis_template(),
        }

    def get_template(self, template_name: str, variables: Dict[str, Any] = None) -> str:
        """获取模板并填充变量"""
        template = self.templates.get(template_name)
        if not template:
            raise ValueError(f"模板不存在: {template_name}")

        if variables:
            return template.format(**variables)
        return template

    def add_template(self, name: str, template: str):
        """添加自定义模板"""
        self.templates[name] = template

    def remove_template(self, name: str):
        """移除模板"""
        if name in self.templates:
            del self.templates[name]

    def list_templates(self) -> List[Dict[str, str]]:
        """列出所有模板"""
        return [
            {"name": name, "description": self._get_template_description(name)}
            for name in self.templates.keys()
        ]

    def _get_template_description(self, template_name: str) -> str:
        """获取模板描述"""
        descriptions = {
            "webshell_analysis": "WebShell 流量分析模板",
            "batch_analysis": "批量会话分析模板",
            "threat_assessment": "威胁评估模板",
            "tool_identification": "工具识别模板",
            "command_extraction": "命令提取模板",
            "custom_analysis": "自定义分析模板",
        }
        return descriptions.get(template_name, "自定义模板")

    def _get_webshell_analysis_template(self) -> str:
        """WebShell 流量分析模板"""
        return """你是一个专业的 WebShell 流量分析专家，具有多年的网络安全经验。请分析以下 HTTP 流量数据。

## 分析数据
{context}

## 分析要求
请基于以上数据，回答以下问题：

### 1. 威胁判定
- 是否为 WebShell 通信流量？请给出是/否的判断。
- 置信度是多少（0-1，1表示完全确定）？

### 2. 工具识别
- 识别具体工具类型（选择最可能的一个）：
  - 中国菜刀 (China Chopper)
  - 蚁剑 (AntSword)
  - 冰蝎 (Behinder)
  - 哥斯拉 (Godzilla)
  - Weevely3
  - SharPyShell
  - 自定义/未知工具
- 说明识别依据。

### 3. 攻击意图分析
- 主要攻击意图（选择最可能的一个或多个）：
  - 命令执行 (Command Execution)
  - 文件上传 (File Upload)
  - 文件下载/读取 (File Download/Read)
  - 数据库操作 (Database Operation)
  - 权限维持 (Persistence)
  - 内网扫描/探测 (Internal Network Scanning)
  - 信息收集 (Information Gathering)
  - 其他 (Other)
- 详细说明攻击意图的证据。

### 4. 载荷提取
- 提取关键攻击载荷（如果有）：
  - 执行的系统命令
  - 上传的文件名和内容
  - 数据库查询语句
  - 其他攻击载荷
- 如果载荷被编码/加密，请尝试还原。

### 5. 威胁等级评估
- 威胁等级（选择一项）：
  - 高 (High): 确认的 WebShell，正在执行危险操作
  - 中 (Medium): 高度可疑，可能为 WebShell
  - 低 (Low): 可疑但不确定，需要进一步监控
- 说明评估依据。

### 6. 处置建议
- 提供具体的处置建议（至少3条）：
  - 立即处置措施
  - 调查建议
  - 防护建议
  - 监控建议

## 输出格式
请以 JSON 格式回答，包含以下字段：

```json
{{
  "is_webshell": boolean,
  "confidence": float (0-1),
  "tool_type": string,
  "tool_confidence": float (0-1),
  "attack_intent": string,
  "intent_details": string,
  "payload": string,
  "commands": [string],
  "threat_level": "high" | "medium" | "low",
  "threat_reason": string,
  "recommendations": [string],
  "analysis_summary": string
}}
```

## 注意事项
1. 如果某些信息无法确定，请使用合理的默认值
2. 保持客观，基于数据事实进行分析
3. 不要猜测或假设不存在的信息
4. 重点关注异常特征和可疑模式"""

    def _get_batch_analysis_template(self) -> str:
        """批量会话分析模板"""
        return """你是一个专业的网络安全分析师，负责分析批量 HTTP 会话数据，识别潜在的 WebShell 攻击。

## 分析数据
{context}

## 分析要求
请基于以上批量会话数据，回答以下问题：

### 1. 整体威胁评估
- 这些会话中 WebShell 流量的比例估计是多少？
- 整体威胁程度如何？

### 2. 攻击模式分析
- 主要攻击工具有哪些？按可能性排序。
- 主要的攻击意图和模式是什么？
- 是否有明显的攻击链或攻击阶段？

### 3. 关键发现
- 最重要的安全发现是什么？
- 是否有新的攻击手法或变种？
- 攻击者的技术水平如何评估？

### 4. 受影响资产
- 哪些服务器/服务可能被入侵？
- 攻击者的入口点是什么？
- 可能的横向移动迹象？

### 5. 时间线分析
- 攻击活动的时间分布如何？
- 是否有明显的高峰时段？
- 攻击持续时间？

### 6. 综合建议
- 立即处置措施
- 长期防护建议
- 监控和检测建议
- 应急响应建议

## 输出格式
请提供详细的文本分析报告，包含以下部分：

1. 执行摘要（200字以内）
2. 详细分析
   - 威胁评估
   - 攻击模式
   - 关键发现
   - 受影响资产
   - 时间线分析
3. 建议措施
4. 附录：可疑会话列表

## 注意事项
1. 关注整体模式和趋势，而不是单个会话
2. 识别攻击者的战术、技术和程序（TTP）
3. 提供可操作的防御建议
4. 保持专业和客观"""

    def _get_threat_assessment_template(self) -> str:
        """威胁评估模板"""
        return """你是一个威胁情报分析师，请评估以下 HTTP 流量的威胁等级。

## 分析数据
{context}

## 评估标准
请基于以下标准进行评估：

### 1. 特征匹配（权重：40%）
- 已知 WebShell 工具特征
- 危险函数调用
- 编码/加密特征
- 异常请求模式

### 2. 行为异常（权重：30%）
- 非工作时段访问
- 高频连接
- 固定心跳间隔
- 异常请求大小

### 3. 加密强度（权重：20%）
- 数据熵值
- 加密算法特征
- 密钥复杂度

### 4. 上下文关联（权重：10%）
- 前后关联会话
- 攻击链完整性
- 横向移动迹象

## 输出要求
请提供详细的威胁评估报告，包含：

1. 威胁评分（0-100分）
2. 威胁等级（高/中/低）
3. 评分依据（按标准详细说明）
4. 置信度说明
5. 风险描述
6. 影响评估

## 输出格式
```json
{{
  "threat_score": integer (0-100),
  "threat_level": "high" | "medium" | "low",
  "confidence": float (0-1),
  "scoring_details": {{
    "feature_matching": {{
      "score": integer,
      "details": string
    }},
    "behavior_anomaly": {{
      "score": integer,
      "details": string
    }},
    "encryption_strength": {{
      "score": integer,
      "details": string
    }},
    "context_correlation": {{
      "score": integer,
      "details": string
    }}
  }},
  "risk_description": string,
  "impact_assessment": string,
  "immediate_actions": [string]
}}
```"""

    def _get_tool_identification_template(self) -> str:
        """工具识别模板"""
        return """你是一个 WebShell 工具识别专家，请识别以下流量使用的具体工具。

## 分析数据
{context}

## 已知工具特征

### 1. 中国菜刀 (China Chopper)
- 特征：@eval(base64_decode(...)), z0=@eval(...)
- UA：通常为空或简单
- 加密：简单 Base64，有时双重编码

### 2. 蚁剑 (AntSword)
- 特征：antSword UA, @ini_set("display_errors","0"), function asenc()
- 加密：Base64 + ROT13 组合
- 模式：有错误处理函数

### 3. 冰蝎 (Behinder)
- 特征：MSIE 9.0 UA, AES-128-ECB 加密，默认密钥 e45e329feb5d925b
- Cookie：PHPSESSID 包含加密数据
- 模式：Java/PHP 版本差异

### 4. 哥斯拉 (Godzilla)
- 特征：动态密钥，Java版有 U2FsdGVkX1 前缀
- 加密：AES-128-CBC (Java), XOR (PHP)
- 参数：pass=xxx&cmd=xxx

### 5. Weevely3
- 特征：8位随机参数名，str_split($r,3), array_map("ord")
- 加密：XOR 加密，密钥在代码中
- 模式：参数混淆

### 6. SharPyShell
- 特征：.NET 相关，Assembly.Load, Activator.CreateInstance
- 模式：Windows 特定

## 识别要求
1. 识别最可能的工具（按可能性排序）
2. 说明识别依据和匹配的特征
3. 评估识别置信度
4. 提供工具版本信息（如果可能）
5. 说明工具的已知变种

## 输出格式
```json
{{
  "primary_tool": {{
    "name": string,
    "confidence": float (0-1),
    "version": string,
    "evidence": [string]
  }},
  "alternative_tools": [
    {{
      "name": string,
      "confidence": float (0-1),
      "evidence": [string]
    }}
  ],
  "tool_characteristics": {{
    "encryption_method": string,
    "communication_pattern": string,
    "obfuscation_techniques": string,
    "known_variants": [string]
  }},
  "identification_summary": string
}}
```"""

    def _get_command_extraction_template(self) -> str:
        """命令提取模板"""
        return """你是一个命令分析专家，请从以下流量中提取执行的系统命令。

## 分析数据
{context}

## 命令类型

### 1. 系统信息收集
- whoami, id, hostname, uname -a
- ipconfig, ifconfig, netstat
- systeminfo, ps, tasklist

### 2. 文件操作
- ls, dir, find, locate
- cat, type, more, less
- cp, mv, rm, del
- wget, curl, certutil

### 3. 权限提升
- sudo, su, runas
- chmod, chown, attrib

### 4. 网络探测
- ping, traceroute, nslookup
- nmap, nc, telnet

### 5. 数据窃取
- tar, zip, gzip
- base64, xxd, hexdump

### 6. 持久化
- crontab, schtasks, at
- registry, service, daemon

## 提取要求
1. 提取所有系统命令（包括参数）
2. 还原被编码/加密的命令
3. 识别命令意图和危险等级
4. 按执行顺序排列命令
5. 标记可疑或危险的命令

## 输出格式
```json
{{
  "commands": [
    {{
      "command": string,
      "decoded_command": string,
      "intent": string,
      "danger_level": "high" | "medium" | "low",
      "evidence": string,
      "timestamp": string
    }}
  ],
  "command_chain": {{
    "execution_order": [string],
    "attack_progression": string,
    "objectives": [string]
  }},
  "analysis": {{
    "total_commands": integer,
    "dangerous_commands": integer,
    "primary_intent": string,
    "attacker_skill_level": "beginner" | "intermediate" | "advanced"
  }}
}}
```"""

    def _get_custom_analysis_template(self) -> str:
        """自定义分析模板"""
        return """{custom_prompt}

## 分析数据
{context}

## 输出要求
{output_format}

## 注意事项
1. 基于数据事实进行分析
2. 保持客观和专业
3. 如果信息不足，请说明
4. 提供可验证的结论"""

    def create_custom_template(self, name: str, system_prompt: str, user_prompt: str, output_format: str) -> str:
        """创建自定义模板"""
        template = f"""{system_prompt}

## 分析数据
{{context}}

## 分析要求
{user_prompt}

## 输出格式
{output_format}

## 注意事项
1. 基于数据事实进行分析
2. 保持客观和专业
3. 如果信息不足，请说明
4. 提供可验证的结论"""
        
        self.add_template(name, template)
        return template

    def get_analysis_guidelines(self) -> Dict[str, Any]:
        """获取分析指导原则"""
        return {
            "webshell_indicators": [
                "异常 User-Agent（空、自动化工具、固定模式）",
                "POST 请求到静态文件（.jpg/.css 等）",
                "请求体包含危险函数（eval、system、exec 等）",
                "Base64/Hex/URL 编码的请求参数",
                "固定心跳间隔的请求",
                "非工作时段的高频访问",
                "响应体为 MD5 哈希或其他固定格式",
                "Cookie 中包含加密数据",
            ],
            "tool_specific_indicators": {
                "中国菜刀": ["@eval(base64_decode(", "z0=@eval("],
                "蚁剑": ["antSword UA", "@ini_set(", "function asenc("],
                "冰蝎": ["MSIE 9.0 UA", "e45e329feb5d925b", "PHPSESSID"],
                "哥斯拉": ["U2FsdGVkX1", "pass=", "cmd="],
                "Weevely3": ["str_split($r,3)", "array_map(", "8位参数名"],
            },
            "threat_level_criteria": {
                "high": [
                    "确认的 WebShell 工具特征",
                    "正在执行系统命令",
                    "文件上传/下载操作",
                    "数据库查询操作",
                    "明显的横向移动",
                ],
                "medium": [
                    "高度可疑的特征",
                    "编码/加密的请求体",
                    "异常行为模式",
                    "可疑的 UA 或参数",
                ],
                "low": [
                    "轻微异常",
                    "需要进一步验证",
                    "可能的���报",
                ],
            },
        }