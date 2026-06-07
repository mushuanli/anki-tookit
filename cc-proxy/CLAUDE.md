# CC Proxy — AI 助手配置

## 语言
- 始终使用**中文**交流
- 代码注释用英文，Git commit 用 Conventional Commits (`type(scope): description`)

## 开发原则
SOLID / DRY / KISS / YAGNI / CoC / LoD — 函数≤30行，圈复杂度≤10

---

## 项目概述

Claude Code API 透明代理 — 拦截、可视化、分析 AI Coding Agent 的 API 流量。
- **语言**: Rust (2021 edition, Cargo workspace)
- **前端**: Vanilla JS/HTML/CSS，通过 `rust-embed` 内嵌到二进制
- **数据库**: SQLite（`data.db`，WAL 模式）
- **持久化**: 运行时配置变更写入 `config.toml`

[img](./cc-proxy.png)
## 架构总览（3 个端口）

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

## 文件结构（按职责）

```
config.toml                          # 运行时配置（[proxy] [server] [logging] 三段）
data.db                              # SQLite 数据库
captures/YYYY-MM-DD/session_*.txt    # Tee Writer 旁路抓包输出

crates/proxy-core/src/
  config.rs       # AppConfig, ProxyConfig, ServerConfig, LoggingConfig, Provider, ModelInfo, TierRule, UpstreamConfig, Retention
  models.rs       # ProxiedRequest, SseEvent, HookEvent, McpRequest, Session, SessionStatus, ProviderInfo, UpstreamInfo, TierRuleInfo, WsMessage, HasId
  db.rs           # Database — SQLite CRUD + 清理（sessions, requests, sse_events, hooks, mcp）
  sse.rs          # SseParser — SSE 字节流解析（\n\n / \r\n\r\n 分隔），Anthropic 事件字段提取
  export.rs       # export_json / export_har / export_markdown — 会话导出（JSON/HAR/MD 三种格式）
  store.rs        # RingBuffer<T> — 内存环形缓冲区（已不用于持久化，SQLite 替代）
  lib.rs          # 公共 re-export

crates/proxy-server/src/
  main.rs         # 入口 + AppState（db, providers, upstreams, active_upstream, retention, mcp_destination, tee_writer, broadcaster, client）
  api.rs          # REST API 路由表 + 所有 handler（Providers/Upstreams CRUD、Session、Hook、MCP、Capture、Retention、Cleanup）
  proxy.rs        # Anthropic 代理 — 三种模式：CONNECT tunnel / Forward proxy / Reverse proxy；Tier 路由、重试、SSE 解析、token 累计
  mcp.rs          # MCP 代理 — JSON-RPC 透传
  ws.rs           # WebSocket handler — 10s ping / 300s dead timeout，broadcast 转发 + 连接时推送首态
  tee.rs          # TeeWriter — 旁路实时写入 capture 文件，按日期+session 组织，合并 SSE 内容块

crates/proxy-hook-agent/src/
  main.rs         # CLI — stdin hook JSON → POST /api/hook-event（失败时静默退出，不阻塞 Claude Code）

wwwroot/
  index.html      # SPA 骨架（5 个视图 tab + 全屏 overlay）
  css/style.css   # 深色主题 CSS（变量、BEM 命名）
  js/app.js       # 前端全部逻辑（~1466 行）：WebSocket、session 折叠表格、filters、分页、多选删除、Providers/Upstreams CRUD、Retention 设置
```

---

## 核心概念速查

### 配置结构（`config.rs`）

```
AppConfig { proxy: ProxyConfig, server: ServerConfig, logging: LoggingConfig }

ProxyConfig {
    active_upstream: String,
    providers: Vec<Provider>,      // Provider { name, url, token?, models: Vec<ModelInfo> }
    upstreams: Vec<UpstreamConfig>,
    retry_count: u32,              // 默认 3
    request_store_capacity: usize, // 默认 1000（RingBuffer，已不再使用）
    mcp_store_capacity: usize,     // 默认 500
    hook_store_capacity: usize,    // 默认 1000
    request_retention_hours: u32,  // 默认 72，0=不清理
    session_max_count: u32,        // 默认 20，0=不限制
}

ModelInfo {
    id: String,                              // 模型 ID
    price_per_million_input: Option<f64>,     // ¥/百万 token，默认 5
    price_per_million_output: Option<f64>,    // ¥/百万 token，默认 25
}
```

`Config.migrate()` — 启动时确保 `active_upstream` 指向存在的 upstream，否则回退到第一个。

### Tier 路由（`UpstreamConfig.resolve()`）

```
请求 model → lower → high.keywords 匹配? → mid.keywords? → low.keywords? → default
匹配时：用 match 的 provider + model（model 为空则透传原 model）
```

- `TierRule` 需 provider 非空且至少一个非空 keyword 才视为 active
- 匹配是 case-insensitive 子串匹配

### Proxy 三种模式（`proxy.rs`）

| 模式 | 触发条件 | 行为 |
|------|---------|------|
| **CONNECT tunnel** | `method == CONNECT` | 建立 TCP 双向隧道（`tokio::io::copy_bidirectional`） |
| **Forward proxy** | URI 含 scheme（如 `https://`） | 客户端已确定目标 URL，只注入 provider token + 翻译 model |
| **Reverse proxy** | URI 不含 scheme（相对路径） | 从 upstream config 解析 provider base URL + 拼接路径（`ANTHROPIC_BASE_URL` 模式） |

- 重试：`execute_with_retry()` — 指数退避 200ms×2^n，只对 connect/timeout 错误重试
- Session ID：从请求 body 的 `metadata.user_id.session_id` 提取（嵌套 JSON 解析）
- Headers：`x-api-key`/`authorization` 脱敏为 `[REDACTED]`，`transfer-encoding`/`content-encoding`/`content-length` 丢弃

### 模型价格（`ModelInfo` 级别）

- 每个 Provider 的 models 列表中，每个 `ModelInfo` 有独立的 `price_per_million_input` / `price_per_million_output`（`Option<f64>`, ¥/百万 token）
- 前端 `lookupProviderPrice(model)` 在所有 providers 的 models 列表中查找匹配，默认 input=5 / output=25
- `fill_session_totals()` 在 `proxy.rs` 中每个请求完成时调用，通过 `db.sum_session_tokens()` 计算 session 累计值
- 存储到 `requests.total_input_tokens` / `total_output_tokens` 列（migration 中用 ALTER TABLE 追加，idempotent）

### 数据库表

| 表 | 关键字段 |
|----|---------|
| `sessions` | id, label, started_at, ended_at, status |
| `requests` | id, session_id, model, input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens, total_input_tokens, total_output_tokens, duration_ms, ttft_ms, … |
| `sse_events` | request_id, event_type, data, seq（FK CASCADE 到 requests） |
| `hook_events` | id, timestamp, hook_event_name, session_id, cwd, permission_mode, transcript_path, hook_input, environment_variables, exit_code, stdout, stderr |
| `mcp_requests` | id, timestamp, method, model, status_code, request_body, response_body |

### 数据清理机制

- **后台任务**（`cleanup_loop`）：启动时执行一次，之后每 30 分钟运行
- **保留策略**：`request_retention_hours` 小时后删除旧请求，但保留最新 session 的请求
- **Session 限制**：超过 `session_max_count` 时删除最旧的 sessions
- **手动触发**：`POST /api/cleanup`

### WebSocket 消息类型（`WsMessage` enum，tagged union）

`NewRequest` | `RequestUpdated` | `SseEvent` | `NewHook` | `NewMcp` | `Cleared` | `McpCleared` | `McpConfigChanged` | `UpstreamChanged` | `History` | `HookHistory` | `McpHistory` | `SessionStarted` | `SessionStopped` | `SessionUpdated` | `TeeStatusChanged`

### API 端点（见 `api.rs` → `build_router()`）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/ws` | WebSocket 升级 |
| GET | `/api/health` | 健康检查（请求数/hook数/mcp数） |
| GET | `/api/requests?limit=&session_id=&q=&from=&to=` | 请求列表 |
| DELETE | `/api/requests` | 批量删除 `{ids: []}` |
| GET/DELETE | `/api/request/:id` | 单条请求 |
| GET/POST | `/api/providers` | 列表/新增 |
| PUT/DELETE | `/api/providers/:name` | 更新/删除 Provider |
| GET/POST | `/api/upstreams` | 列表/新增（含 active_upstream + providers） |
| PUT/DELETE | `/api/upstreams/:name` | 更新/删除 Upstream（最后一条不可删） |
| POST | `/api/upstreams/:name/activate` | 切换 active upstream |
| GET | `/api/sessions?q=` | 会话列表 |
| GET/PUT/DELETE | `/api/session/:id` | 查看/重命名/删除（rename 时 broadcast SessionUpdated） |
| GET | `/api/session/:id/export?format=json\|har\|markdown` | 导出（带 content-disposition） |
| POST | `/api/hook-event` | 接收 Hook 事件（由 proxy-hook-agent 调用） |
| PUT | `/api/hook-event/:id` | 更新 Hook 响应（exit_code/stdout/stderr） |
| GET/PUT | `/api/mcp-destination` | MCP 目标地址 |
| POST | `/api/capture` | 开关 Tee Writer `{enabled: bool}` |
| GET | `/api/capture/status` | Capture 状态 `{enabled: bool}` |
| GET/PUT | `/api/retention` | 数据保留设置 |
| POST | `/api/cleanup` | 手动触发清理 |
| POST | `/api/clear`, `/api/clear-mcp`, `/api/clear-hooks` | 清空数据 |

---

## 前端视图（5 个 tab）

| Tab | 功能 |
|-----|------|
| **Inspector** | 请求表格 — **Session 分组折叠**（expand/collapse per-session），多选删除、行内详情，表头: ✓/Time/Method/Path/Status/Model/Session/In·Out/Total In·Out/Cost/Duration/TTFT |
| **Conversation** | 实时时间轴（API+Hook+MCP 混合，按 session 过滤，最多 100 条） |
| **MCP Observer** | MCP JSON-RPC 请求列表 + 目标地址配置 |
| **Hooks** | Hook 事件表格（Event/Session/CWD/ExitCode，最多 200 条） |
| **Settings** | Providers CRUD（含 model 级价格编辑） + Upstreams CRUD（High/Mid/Low/Default 四层 Tier） + Data Retention 面板 |

### Settings — Data Retention 面板

- `request_retention_hours`：保留所有请求的小时数（0=不清理）
- `session_max_count`：最大 session 数（0=不限制）
- "Clean Up Now" 按钮手动触发清理
- 显示上次清理时间

### 前端关键变量（`app.js`）

- `requestRows: Map` — 全部请求数据（id → ProxiedRequest）
- `selectedIds: Set` — 多选 checkbox 集合
- `expandedSessions: Set` — 当前展开的 session ID
- `sessionCache: Object` — session ID → label 缓存
- `providerList[]` / `upstreamList[]` — 从 `/api/upstreams` 加载
- `filterModel` / `filterSession` / `filterTimeFrom` / `filterTimeTo` / `currentPage` / `pageSize`

### 前端数据加载流程（`connect()` → init）

1. WebSocket 连接 → 推送首态（HookHistory、McpHistory、McpConfigChanged、UpstreamChanged、TeeStatusChanged）
2. `GET /api/upstreams` → 填充 upstream select + provider/upstream 列表
3. `GET /api/sessions` → 预热 sessionCache
4. `GET /api/requests?limit=2000` → 填充 requestRows + 渲染首屏（最新 session 自动展开）
5. `GET /api/mcp-destination` → 回填 MCP 目标地址
6. `GET /api/capture/status` → 同步 capture 状态
7. `GET /api/retention` → 同步 retention 设置

---

## 构建与运行

```bash
cargo build -p proxy-server --release    # 编译主服务
cargo build -p proxy-hook-agent --release # 编译 Hook CLI

./target/release/proxy-server config.toml  # 启动（默认端口 5000/8888/9999）
```

默认端口可通过 `config.toml` 的 `[server]` 段覆盖：
```toml
[server]
listen_address = "127.0.0.1"
http_port = 5000
proxy_port = 8888
mcp_proxy_port = 9999
```

### 配置 Claude Code 拦截

```bash
export ANTHROPIC_BASE_URL="http://localhost:8888"
```

---

## 持久化（`persist_config()`）

`/api/providers`、`/api/upstreams`、`/api/retention` 变更后 → 读取 `config.toml` 原文件 → 更新 TOML Value 中的 `providers[]`/`upstreams[]`/`active_upstream`/`request_retention_hours`/`session_max_count` → 移除 legacy `api_target` → 写回磁盘。通过 `broadcast_send(UpstreamChanged)` 通知所有 WS 客户端。

---

## 安全

- 所有端口仅监听 `127.0.0.1`
- `x-api-key`、`Authorization` header 自动脱敏为 `[REDACTED]`
- API token 存 TOML 文件，前端 `has_token: bool`（不暴露 token 内容）
- SQLite 本地存储，不对外暴露
