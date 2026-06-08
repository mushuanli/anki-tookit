# 架构总览

## 项目概述

Claude Code API 透明代理 — 拦截、可视化、分析 AI Coding Agent 的 API 流量。

- **语言**: Rust (2021 edition, Cargo workspace)
- **前端**: Vanilla JS/HTML/CSS，通过 `rust-embed` 内嵌到二进制
- **数据库**: SQLite（`data.db`，WAL 模式）
- **持久化**: 运行时配置变更写入 `config.toml`

## 3 个端口

```
浏览器      ──► :5000  仪表盘 SPA + REST API + WebSocket 实时推送
Claude Code ──► :8888  Anthropic API 透明代理（Tier 路由 → 上游 Provider）
Claude Code ──► :9999  MCP JSON-RPC 透明代理
```

## Crate 结构

| Crate | 职责 | 关键依赖 |
|-------|------|---------|
| `proxy-core` | 纯逻辑库：models、config、db、sse、export、store（RingBuffer） | serde, rusqlite, chrono, uuid, tokio |
| `proxy-server` | 组装层：axum 路由、proxy/mcp/ws/tee handler、main 入口 + AppState | axum, reqwest, tower-http, rust-embed, tracing, futures, bytes |
| `proxy-hook-agent` | 独立 CLI：读取 stdin hook JSON → POST 到仪表盘 | clap, reqwest |

## 文件结构

```
config.toml                          # 运行时配置（[proxy] [server] [logging] 三段）
data.db                              # SQLite 数据库
captures/YYYY-MM-DD/session_*.txt    # 录制输出（Record 开关）

crates/proxy-core/src/
  config.rs       # AppConfig, ProxyConfig, ServerConfig, LoggingConfig, Provider, ModelInfo, TierRule, UpstreamConfig, Retention
  models.rs       # ProxiedRequest, SseEvent, HookEvent, McpRequest, Session, SessionStatus, ProviderInfo, UpstreamInfo, TierRuleInfo, WsMessage, HasId, ModelCost, SessionCost, CostData
  db.rs           # Database — SQLite CRUD + 清理（sessions, requests, sse_events, hooks, mcp）
  sse.rs          # SseParser — SSE 字节流解析（\n\n / \r\n\r\n 分隔），Anthropic 事件字段提取
  export.rs       # export_json / export_har / export_markdown / export_yaml — 会话导出（JSON/HAR/MD/YAML 四种格式）
  store.rs        # RingBuffer<T> — 内存环形缓冲区（已不用于持久化，SQLite 替代）
  lib.rs          # 公共 re-export

crates/proxy-server/src/
  main.rs         # 入口 + AppState（db, providers, upstreams, active_upstream, active_effort, retention, mcp_destination, tee_writer, broadcaster, client）
  api.rs          # REST API 路由表 + 所有 handler（Providers/Upstreams CRUD、Session、Hook、MCP、Capture、Retention、Cleanup、Effort、Cost）
  proxy.rs        # Anthropic 代理 — 三种模式：CONNECT tunnel / Forward proxy / Reverse proxy；Tier 路由、effort 注入、重试、SSE 解析、token 累计
  mcp.rs          # MCP 代理 — JSON-RPC 透传
  ws.rs           # WebSocket handler — 10s ping / 300s dead timeout，broadcast 转发 + 连接时推送首态（不含请求历史，由 REST 加载）
  tee.rs          # TeeWriter — 录制开关开启后实时写入文件，按日期+session 组织，合并 SSE 内容块（含 Thinking/Response/Tool Use 分类）

crates/proxy-hook-agent/src/
  main.rs         # CLI — stdin hook JSON → POST /api/hook-event（失败时静默退出，不阻塞 Claude Code）；--dashboard-url 参数（默认 http://localhost:5000）

wwwroot/
  index.html      # SPA 骨架（6 个视图 tab + 全屏 overlay）
  css/style.css   # 深色主题 CSS（变量、BEM 命名）
  js/app.js       # 前端全部逻辑（~1756 行）：WebSocket、session 折叠表格、filters、分页、多选删除、Providers/Upstreams CRUD、Effort 控制、Cost 视图、Retention 设置、Inspector Cost 统计、录制按钮
```

## AppState

```rust
pub struct AppState {
    pub config: AppConfig,
    pub config_path: String,
    pub db: Database,
    pub mcp_destination: RwLock<Option<String>>,
    pub providers: RwLock<Vec<Provider>>,
    pub upstreams: RwLock<Vec<UpstreamConfig>>,
    pub active_upstream: RwLock<String>,
    pub active_effort: RwLock<String>,
    pub retention: RwLock<Retention>,
    pub tee_writer: TeeWriter,
    pub broadcaster: broadcast::Sender<WsMessage>,
    pub client: reqwest::Client,
}
```
