import json
import csv
import io
import os
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
from loguru import logger
from jinja2 import Template

from backend.models.schemas import HttpSession, DetectionResult, ThreatScore


REPORT_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>ShellShark 威胁分析报告</title>
<style>
body { font-family: -apple-system, sans-serif; margin: 20px; color: #333; }
h1 { color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 8px; }
h2 { color: #1976d2; margin-top: 24px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0; }
th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
th { background: #f5f5f5; }
tr:nth-child(even) { background: #fafafa; }
.summary-card { background: #fff3e0; border-left: 4px solid #ff9800; padding: 12px 16px; margin: 12px 0; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
.badge-critical { background: #d32f2f; color: #fff; }
.badge-high { background: #f44336; color: #fff; }
.badge-medium { background: #ff9800; color: #fff; }
.badge-low { background: #ffc107; color: #333; }
.footer { margin-top: 32px; font-size: 12px; color: #999; text-align: center; }
</style>
</head>
<body>
<h1>ShellShark 威胁分析报告</h1>
<p>生成时间: {{ generated_at }}</p>
<div class="summary-card">
<h3>报告摘要</h3>
<p>总会话数: {{ total_sessions }} | 高危: {{ high_count }} | 中危: {{ medium_count }} | 低危: {{ low_count }}</p>
</div>
<h2>检测详情</h2>
<table>
<thead><tr><th>会话ID</th><th>时间</th><th>源IP</th><th>目的IP</th><th>URL</th><th>威胁等级</th><th>评分</th><th>WebShell类型</th></tr></thead>
<tbody>
{% for item in items %}
<tr>
<td>{{ item.session_id[:8] }}...</td>
<td>{{ item.timestamp }}</td>
<td>{{ item.src_ip }}</td>
<td>{{ item.dst_ip }}</td>
<td>{{ item.uri[:50] }}</td>
<td><span class="badge badge-{{ item.level }}">{{ item.level }}</span></td>
<td>{{ item.score }}</td>
<td>{{ item.tool_type }}</td>
</tr>
{% endfor %}
</tbody>
</table>
{% if items %}
<h2>威胁分布</h2>
<table>
<thead><tr><th>威胁等级</th><th>数量</th></tr></thead>
<tbody>
{% for level, count in distribution.items() %}
<tr><td>{{ level }}</td><td>{{ count }}</td></tr>
{% endfor %}
</tbody>
</table>
{% endif %}
<div class="footer">
<p>ShellShark WebShell 流量检测分析工具 | {{ generated_at }}</p>
</div>
</body>
</html>"""


class ReportGenerator:
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.output_dir = Path(config.get("report", {}).get("output_dir", "data/reports")) if config else Path("data/reports")

    def _build_rows(self, sessions: List[HttpSession], detections: Dict[str, DetectionResult], scores: Dict[str, ThreatScore]) -> List[dict]:
        rows = []
        for s in sessions:
            det = detections.get(s.session_id)
            sc = scores.get(s.session_id)
            level_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
            level = level_map.get(sc.threat_level.value if sc else "low", "low")
            tool = det.webshell_type.value if det and det.webshell_type else "unknown"
            rows.append({
                "session_id": s.session_id,
                "timestamp": s.packet_info.timestamp.strftime("%Y-%m-%d %H:%M:%S") if s.packet_info else "",
                "src_ip": s.packet_info.five_tuple.src_ip if s.packet_info else "",
                "dst_ip": s.packet_info.five_tuple.dst_ip if s.packet_info else "",
                "uri": s.request.uri if s and s.request else "",
                "level": level,
                "score": round(sc.total_score, 1) if sc else 0,
                "tool_type": tool,
                "method": s.request.method if s and s.request else "",
                "src_port": s.packet_info.five_tuple.src_port if s.packet_info else 0,
                "dst_port": s.packet_info.five_tuple.dst_port if s.packet_info else 0,
            })
        return rows

    def generate_jsonl(self, sessions: List[HttpSession], detections: Dict[str, DetectionResult], scores: Dict[str, ThreatScore]) -> str:
        lines = []
        for s in sessions:
            det = detections.get(s.session_id)
            sc = scores.get(s.session_id)
            record = {
                "session_id": s.session_id,
                "timestamp": s.packet_info.timestamp.isoformat() if s.packet_info else None,
                "five_tuple": s.packet_info.five_tuple.dict() if s.packet_info else None,
                "uri": s.request.uri if s and s.request else None,
                "method": s.request.method if s and s.request else None,
                "threat_score": round(sc.total_score, 1) if sc else 0,
                "threat_level": sc.threat_level.value if sc else "low",
                "webshell_type": det.webshell_type.value if det else "unknown",
                "confidence": round(det.confidence, 3) if det else 0,
                "summary": det.summary if det else "",
            }
            lines.append(json.dumps(record, ensure_ascii=False))
        return "\n".join(lines)

    def generate_csv(self, sessions: List[HttpSession], detections: Dict[str, DetectionResult], scores: Dict[str, ThreatScore]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["会话ID", "时间", "源IP", "源端口", "目的IP", "目的端口", "方法", "URL", "威胁等级", "评分", "WebShell类型", "置信度"])
        for s in sessions:
            det = detections.get(s.session_id)
            sc = scores.get(s.session_id)
            writer.writerow([
                s.session_id[:8],
                s.packet_info.timestamp.strftime("%Y-%m-%d %H:%M:%S") if s.packet_info else "",
                s.packet_info.five_tuple.src_ip if s.packet_info else "",
                s.packet_info.five_tuple.src_port if s.packet_info else "",
                s.packet_info.five_tuple.dst_ip if s.packet_info else "",
                s.packet_info.five_tuple.dst_port if s.packet_info else "",
                s.request.method if s and s.request else "",
                s.request.uri if s and s.request else "",
                sc.threat_level.value if sc else "low",
                round(sc.total_score, 1) if sc else 0,
                det.webshell_type.value if det else "unknown",
                round(det.confidence, 3) if det else 0,
            ])
        return output.getvalue()

    def generate_html(self, sessions: List[HttpSession], detections: Dict[str, DetectionResult], scores: Dict[str, ThreatScore]) -> str:
        rows = self._build_rows(sessions, detections, scores)
        dist = {}
        for r in rows:
            dist[r["level"]] = dist.get(r["level"], 0) + 1
        template = Template(REPORT_HTML_TEMPLATE)
        return template.render(
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_sessions=len(sessions),
            high_count=dist.get("high", 0) + dist.get("critical", 0),
            medium_count=dist.get("medium", 0),
            low_count=dist.get("low", 0),
            items=rows,
            distribution=dist,
        )

    def save_report(self, content: str, fmt: str) -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        ext = {"jsonl": ".jsonl", "csv": ".csv", "html": ".html", "excel": ".xlsx"}
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext.get(fmt, '.txt')}"
        path = self.output_dir / filename
        path.write_text(content, encoding="utf-8")
        logger.info(f"报告已保存: {path}")
        return path
