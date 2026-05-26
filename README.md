# ShellShark — WebShell 流量检测分析工具

融合特征检测、行为分析、解密还原与 AI 智能研判的 WebShell 检测系统，支持实时抓包与离线 PCAP 分析双模式。

## 架构概览

```
shellshark/
├── backend/                # FastAPI 后端
│   ├── main.py             # 入口，API 路由，WebSocket
│   ├── core/               # 核心引擎
│   │   ├── capture_engine.py      # 抓包引擎 (Scapy/PyShark)
│   │   ├── detection_engine.py    # 特征检测引擎
│   │   ├── behavior_analyzer.py   # 行为分析
│   │   ├── entropy_analyzer.py    # 熵值/加密检测
│   │   ├── protocol_parser.py     # 协议解析
│   │   ├── session_manager.py     # 会话管理
│   │   └── threat_scorer.py       # 综合威胁评分
│   ├── ai/                 # AI 分析模块
│   │   ├── ai_client.py           # AI 统一接口 (OpenAI/DeepSeek/Claude/Qwen/Ollama)
│   │   ├── batch_analyzer.py      # 批量异步分析
│   │   ├── context_builder.py     # 上下文自动构建
│   │   └── prompt_templates.py    # Prompt 模板管理
│   ├── decryption/         # 解密插件
│   │   └── plugin_manager.py      # 插件管理器
│   ├── models/             # Pydantic 数据模型
│   │   └── schemas.py
│   └── reporting/          # 报告生成
│       └── report_generator.py
├── frontend/               # Vue3 前端
│   ├── src/
│   │   ├── views/
│   │   │   ├── Dashboard.vue        # 仪表盘
│   │   │   ├── TrafficList.vue      # 流量列表 (Wireshark 风格过滤)
│   │   │   ├── PacketsView.vue      # 数据包列表
│   │   │   ├── CaptureControl.vue   # 抓包控制
│   │   │   ├── AIAnalysis.vue       # AI 智能分析
│   │   │   └── Reports.vue          # 报告管理
│   │   ├── api/index.js
│   │   └── main.js
│   └── dist/               # 构建产物
├── config.yaml             # 全局配置文件
└── requirements.txt        # Python 依赖
```

## 快速开始

### 依赖

- Python 3.10+
- Node.js 18+ (仅前端开发时需要)
- Npcap / WinPcap (Windows 实时抓包)

### 安装

```bash
# 后端
pip install -r requirements.txt

# 前端 (构建)
cd frontend
npm install
npm run build
```

### 配置

编辑 `config.yaml`，至少配置 AI API 密钥：

```yaml
ai:
  default_provider: "deepseek"   # 默认为 DeepSeek
  deepseek:
    api_key: "sk-your-key-here"
    base_url: "https://api.deepseek.com"
    model: "deepseek-chat"
```

支持多厂商：`openai` / `deepseek` / `claude` / `qwen` / `ernie` / `ollama`

### 启动

```bash
# 启动后端 (http://localhost:8080)
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8080

# 开发前端 (http://localhost:5173，需配置代理)
cd frontend && npm run dev
```

打开浏览器访问 `http://localhost:8080` 即可使用。

### 生成演示数据

点击界面上的"生成演示数据"按钮，或调用 API：

```bash
curl -X POST http://localhost:8080/api/demo/seed
```

## 核心功能

### 流量采集

| 模式 | 说明 |
|------|------|
| 实时抓包 | Scapy/PyShark 监听网卡，支持 BPF 过滤 |
| 离线分析 | 上传 PCAP/PCAPNG 文件，分块处理 |
| 接口探测 | 自动检测可用网卡 (WMI/psutil/scapy/socket 多方式) |

### 检测引擎

- **特征匹配** — 内置 6 种 WebShell 指纹库（菜刀/蚁剑/冰蝎/哥斯拉/Weevely3/SharPyShell），检测 UA 异常、危险函数、编码载荷等
- **行为分析** — 非工作时段高频连接、固定心跳间隔、POST 大小异常、静态文件接收参数
- **熵值检测** — Shannon 熵计算，标记高熵加密流量（AES 块对齐检测）
- **综合评分** — 特征命中(0-30) + 行为异常(0-25) + 熵值得分(0-15) + AI 得分(0-30)，满分 100

### AI 智能分析

1. 在流量列表或数据包视图中勾选目标会话
2. 点击"AI 分析"按钮
3. 系统自动构建上下文（五元组 + 请求/响应头 + Body + 关联包）
4. 发送至 AI 模型进行分析
5. 返回结果：威胁判定、工具类型、攻击意图、提取命令、处置建议

支持**批量异步分析**（可配置并发数与速率限制），结果自动更新威胁评分。

### Wireshark 风格过滤

支持 `GET /api/packets?q=...` 查询语法：

| 示例 | 说明 |
|------|------|
| `ip==192.168.1.1` | IP 匹配 |
| `port==80` | 端口匹配 |
| `method==POST` | HTTP 方法 |
| `uri contains /upload` | URI 包含 |
| `threat>50` | 威胁评分大于 |
| `type==chopper` | WebShell 类型 |
| `ip==1.1.1.1 and port==443` | 与条件 |
| `method==GET or method==POST` | 或条件 |

### 解密还原

内置解密插件：冰蝎 AES-128-ECB、哥斯拉、蚁剑 Base64/ROT13、Weevely3。支持通过插件接口扩展自定义解密算法。

### 报告导出

支持 JSONL / CSV / HTML 三种格式，包含五元组、时间、威胁评分、检测摘要、AI 分析结论。

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/status` | 服务状态 |
| POST | `/api/capture/start` | 开始抓包 |
| POST | `/api/capture/stop` | 停止抓包 |
| GET | `/api/interfaces` | 网卡列表 |
| POST | `/api/capture/upload` | 上传 PCAP |
| POST | `/api/analyze/pcap` | 分析 PCAP |
| GET | `/api/sessions` | 会话列表 (支持 `level`/`q` 过滤) |
| GET | `/api/sessions/{id}` | 会话详情 |
| GET | `/api/packets` | 数据包列表 (支持 `level`/`q` 过滤) |
| GET | `/api/packets/{id}` | 数据包详情 |
| POST | `/api/analyze/ai` | AI 智能分析 |
| POST | `/api/decrypt/{id}` | 解密会话 |
| POST | `/api/demo/seed` | 生成演示数据 |
| POST | `/api/report/generate` | 生成报告 |
| GET | `/api/reports` | 报告列表 |
| GET | `/api/stats` | 统计信息 |
| WS | `/ws` | WebSocket 实时推送 |

## 威胁等级

| 等级 | 评分范围 | 说明 |
|------|----------|------|
| critical | ≥ 90 | 确认的 WebShell，正在执行危险操作 |
| high | 70-89 | 高度可疑，多种特征命中 |
| medium | 40-69 | 可疑，需进一步验证 |
| low | 10-39 | 轻微异常 |
| clean | < 10 | 正常流量 |

## 配置说明

完整配置项见 `config.yaml`，主要包括：

- **server** – 服务监听地址与端口
- **capture** – 网卡选择策略、BPF 过滤、分块大小
- **detection** – 特征/行为/熵值检测开关与阈值
- **behavior** – 非工作时段、心跳间隔、高频阈值
- **decryption** – 解密密钥与插件配置
- **ai** – 多厂商 API 密钥、模型、并发限制
- **report** – 输出格式与路径
- **database** – 持久化配置（可选）

## 开发

```bash
# 后端热重载
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8080 --reload

# 前端开发服务器
cd frontend && npm run dev
```

## 技术栈

**后端**: Python 3.10+, FastAPI, Scapy, PyShark, httpx, OpenAI SDK, PyCryptodome

**前端**: Vue 3, Vue Router, Axios, Vite
"# aishellshark" 
