# Coding Agent Explorer (Rust)

实时拦截、可视化、分析 AI Coding Agent（Claude Code）API 流量的本地代理工具。

基于 [tndata/CodingAgentExplorer](https://github.com/tndata/CodingAgentExplorer) 用 Rust 重写，单二进制 ~15MB，无需运行时，冷启动 <10ms。

## 功能

- **HTTP Inspector** — 表格视图展示所有 API 请求/响应，含完整 headers、body、token 用量、耗时
- **Conversation 视图** — 将 API 流量渲染为可读的对话时间线（messages → tool calls → responses）
- **SSE 实时解析** — 流式响应逐事件解析，实时推送 Time-To-First-Token
- **MCP Observer** — 透明代理 MCP JSON-RPC 调用，支持 Pretty / Raw 双视图
- **Hook 事件采集** — 通过 `hook-agent` CLI 将 Claude Code 的 15 种 hook 事件上报到仪表盘
- **会话录制与导出** — 录制请求序列，支持导出 JSON / HAR / Markdown 三种格式
- **Tee Writer 旁路抓包** — 所有流量可实时写入磁盘文件（类 tcpdump 格式）

## 架构

```
浏览器 ──► :5000  仪表盘 SPA（WebSocket 实时推送）
Claude Code ──► :8888  透明代理 → api.anthropic.com
Claude Code ──► :9999  透明代理 → MCP Server（用户配置）
HookAgent ──► :5000/api/hook-event
```

## 快速开始

### 构建

```bash
# 需要 Rust 1.80+
git clone https://github.com/tndata/CodingAgentExplorer.git
cd CodingAgentExplorer

# 构建 release
cargo build -p proxy-server --release
cargo build -p proxy-hook-agent --release

# 二进制文件
ls target/release/proxy-server       # 主服务
ls target/release/hook-agent         # Hook CLI
```

### 运行

```bash
# 启动代理服务（使用默认配置）
./target/release/proxy-server

# 或指定配置文件
./target/release/proxy-server config.toml
```

启动后：

| 端口 | 用途 | 访问方式 |
|------|------|---------|
| **5000** | 仪表盘 UI | 浏览器打开 http://localhost:5000 |
| **8888** | Anthropic API 代理 | Claude Code 配置环境变量 |
| **9999** | MCP 代理 | `claude mcp add` 命令注册 |

### 配置 Claude Code

**拦截 Anthropic API：**

```bash
export ANTHROPIC_BASE_URL=http://localhost:8888
# 或 source 项目中的 EnableProxy.sh
```

**拦截 MCP 调用：**

```bash
# 1. 在仪表盘 → MCP Observer 页面设置目标 URL
#    例如：https://gitmcp.io/user/repo
# 2. 注册代理
claude mcp add --transport http mcp_proxy http://localhost:9999
```

### 配置 Hook 事件上报

将 `hook-agent` 配置到 Claude Code 的 hooks 中（参考 `.claude/settings.json`）：

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "command": "/path/to/hook-agent"
      }
    ]
  }
}
```

## 仪表盘功能

仪表盘包含 5 个视图标签页：

### Inspector
- 所有 API 请求/响应的表格视图
- 点击行展开详情面板（Request / Response / SSE Events）
- 按 Model 筛选
- Clear / Clear MCP 清空数据

### Conversation
- 对话时间线视图，按时间顺序展示所有交互
- 支持 API 请求、Hook 事件、MCP 调用三种类型

### MCP Observer
- 设置/查看 MCP 目标地址
- MCP JSON-RPC 请求/响应表格

### Hooks
- Hook 事件列表（事件名、Session、CWD、Exit Code）

### Sessions
- 开始/停止录制会话（label 可选）
- 录制期间自动关联 API 请求
- 导出：JSON（可重新导入）/ HAR（Chrome DevTools 兼容）/ Markdown（可读对话）

## 实时抓包（Tee Writer）

在仪表盘点击 **Start Capture** 按钮，所有流量将旁路写入 `captures/` 目录：

```
captures/
└── capture_20260517_143025.txt
```

Raw 格式示例：

```
============================================================
2026-05-17T14:30:25.123Z POST /v1/messages
content-type: application/json
x-api-key: [REDACTED]

{"model":"claude-sonnet-4-6","max_tokens":4096,"stream":true,...}
============================================================
2026-05-17T14:30:27.345Z 200 OK — 2222ms
event: message_start
data: {"type":"message_start","message":{"id":"msg_xxx",...}}
...
Tokens: 500 in / 300 out | TTFT: 234ms
============================================================
```

## 配置

```toml
# config.toml
[proxy]
api_target = "https://api.anthropic.com"   # 上游 API 地址
request_store_capacity = 1000              # 请求缓冲区容量
mcp_store_capacity = 500                   # MCP 缓冲区容量
hook_store_capacity = 1000                 # Hook 缓冲区容量

[server]
http_port = 5000                           # 仪表盘端口
proxy_port = 8888                          # Anthropic 代理端口
mcp_proxy_port = 9999                      # MCP 代理端口
listen_address = "127.0.0.1"               # 仅监听本地

[logging]
level = "info"                             # trace | debug | info | warn | error
```

## API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/health` | 健康检查 |
| GET | `/api/requests` | 请求列表 |
| GET | `/api/request/{id}` | 请求详情 |
| POST | `/api/hook-event` | 接收 Hook 事件 |
| POST | `/api/clear` | 清空所有数据 |
| POST | `/api/clear-mcp` | 清空 MCP 数据 |
| PUT | `/api/mcp-destination` | 设置 MCP 目标 |
| GET | `/api/mcp-destination` | 获取 MCP 目标 |
| POST | `/api/session/start` | 开始录制会话 |
| POST | `/api/session/{id}/stop` | 停止录制 |
| GET | `/api/session/{id}/export?format=json` | 导出会话 |
| POST | `/api/capture` | 开关 Tee Writer |
| GET | `/api/capture/status` | 抓包状态 |
| WebSocket | `/ws` | 实时推送 |

## 安全

- 所有端口仅监听 `127.0.0.1`，不暴露到网络
- `x-api-key` 和 `Authorization` header 自动脱敏为 `[REDACTED]`
- 纯内存存储，环形缓冲区上限 1000 条，不持久化敏感数据
- 导出功能由用户主动触发，文件落用户本地磁盘

## 与 .NET 原版对比

| | .NET 10 版本 | Rust 版本 |
|---|---|---|
| 运行时 | .NET Runtime (~200MB) | 无 |
| 二进制 | ~15MB / ~80MB self-contained | ~15MB stripped |
| 冷启动 | ~2-3s (JIT) | <10ms |
| 内存 | ~80-120MB | ~15-30MB |

## License

MIT
