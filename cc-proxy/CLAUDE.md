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
| `proxy-server` | 组装层：axum 路由、proxy/mcp/ws/tee handler、main 入口 | axum, reqwest, tower-http, rust-embed, tracing |
| `proxy-hook-agent` | 独立 CLI：读取 stdin hook JSON → POST 到仪表盘 | clap, reqwest |

## 文件结构（按职责）

```
config.toml                          # 运行时配置（providers/upstreams/active_upstream）
data.db                              # SQLite 数据库
captures/                            # Tee Writer 旁路抓包输出

crates/proxy-core/src/
  config.rs       # Provider, TierRule, UpstreamConfig, ProxyConfig, ServerConfig
  models.rs       # ProxiedRequest, SseEvent, HookEvent, Session, ProviderInfo, UpstreamInfo, WsMessage
  db.rs           # Database — SQLite CRUD（sessions, requests, sse_events, hooks, mcp）
  sse.rs          # SseParser — SSE 字节流解析（content_block_delta, message_delta, usage…）
  export.rs       # export_json / export_har / export_markdown — 会话导出
  store.rs        # RingBuffer<T> — 内存环形缓冲区（已不用于持久化，SQLite 替代）
  lib.rs

crates/proxy-server/src/
  main.rs         # 入口 + AppState（providers, upstreams, active_upstream, db, broadcaster, tee_writer）
  api.rs          # REST API 路由表（/api/* 所有端点，Providers/Upstreams CRUD）
  proxy.rs        # Anthropic 代理 handler — 非流式/流式 SSE 转发、token 统计、Tier 路由
  mcp.rs          # MCP 代理 — JSON-RPC 透传
  ws.rs           # WebSocket handler — 10s ping / 60s timeout，broadcast 转发
  tee.rs          # TeeWriter — 旁路实时写入 capture 文件

crates/proxy-hook-agent/src/
  main.rs         # CLI — stdin → POST /api/hook-event

wwwroot/
  index.html      # SPA 骨架（5 个视图 tab）
  css/style.css   # 深色主题 CSS（变量、BEM 命名）
  js/app.js       # 前端全部逻辑（~1070 行）：WebSocket、表格渲染、filters、分页、Providers/Upstreams CRUD
```

---

## 核心概念速查

### Tier 路由（`UpstreamConfig.resolve()`）

```
请求 model → lower → high.keywords 匹配? → mid.keywords? → low.keywords? → default
匹配时：用 match 的 provider + model（model 为空则透传原 model）
```

- `TierRule` 需 provider 非空且至少一个非空 keyword 才视为 active
- 匹配是 case-insensitive 子串匹配

### 价格 / 费用（最近添加）

- `Provider.price_per_million_input` / `price_per_million_output`（`Option<f64>`, ¥/百万 token）
- `ProxiedRequest.total_input_tokens` / `total_output_tokens` — session 累计（每次请求完成时计算→存库）
- 前端 `formatCost(req)` 通过 model 匹配 provider 的 price 列表计算 ¥ 费用
- `fill_session_totals()` 在 `proxy.rs` 中每个请求完成时调用

### 数据库表

| 表 | 关键字段 |
|----|---------|
| `sessions` | id, label, started_at, ended_at, status |
| `requests` | id, session_id, model, input_tokens, output_tokens, total_input_tokens, total_output_tokens, duration_ms, ttft_ms, … |
| `sse_events` | request_id, event_type, data, seq |
| `hook_events` | id, timestamp, hook_event_name, session_id, cwd, exit_code, … |
| `mcp_requests` | id, timestamp, method, model, status_code, request/response_body |

### WebSocket 消息类型（`WsMessage` enum，tagged union）

`NewRequest` | `RequestUpdated` | `SseEvent` | `NewHook` | `NewMcp` | `Cleared` | `McpCleared` | `McpConfigChanged` | `UpstreamChanged` | `History` | `HookHistory` | `McpHistory` | `TeeStatusChanged` | `SessionStarted/Stopped/Updated`

### API 端点（见 `api.rs` → `build_router()`）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/ws` | WebSocket 升级 |
| GET | `/api/requests?limit=&session_id=&q=&from=&to=` | 请求列表 |
| DELETE | `/api/requests` | 批量删除 `{ids: []}` |
| GET/DELETE | `/api/request/:id` | 单条请求 |
| GET/POST | `/api/providers` | 列表/新增 |
| PUT/DELETE | `/api/providers/:name` | 更新/删除 Provider |
| GET/POST | `/api/upstreams` | 列表/新增 |
| PUT/DELETE | `/api/upstreams/:name` | 更新/删除 Upstream |
| POST | `/api/upstreams/:name/activate` | 切换 active upstream |
| GET | `/api/sessions?q=` | 会话列表 |
| GET/PUT/DELETE | `/api/session/:id` | 查看/重命名/删除 |
| GET | `/api/session/:id/export?format=json\|har\|markdown` | 导出 |
| POST | `/api/hook-event` | 接收 Hook 事件 |
| PUT | `/api/hook-event/:id` | 更新 Hook 响应 |
| GET/PUT | `/api/mcp-destination` | MCP 目标地址 |
| POST | `/api/capture` | 开关 Tee Writer |
| POST | `/api/clear`, `/api/clear-mcp`, `/api/clear-hooks` | 清空数据 |

---

## 前端视图（5 个 tab）

| Tab | 功能 |
|-----|------|
| **Inspector** | 请求表格（分页/过滤/多选删除/行内详情），表头: Time/Method/Path/Status/Model/Session/In·Out/Total In·Out/Cost/Duration/TTFT |
| **Conversation** | 实时时间轴（API+Hook+MCP 混合，按 session 过滤） |
| **MCP Observer** | MCP JSON-RPC 请求列表 + 目标地址配置 |
| **Hooks** | Hook 事件表格（Event/Session/CWD/ExitCode） |
| **Settings** | Providers CRUD（含价格） + Upstreams CRUD（High/Mid/Low/Default 四层 Tier） |

### 前端关键变量（`app.js`）

- `requestRows: Map` — 全部请求数据，客户端分页
- `providerList[]` / `upstreamList[]` — 从 `/api/upstreams` 加载
- `filterModel` / `filterSession` / `filterTimeFrom` / `filterTimeTo` / `currentPage` / `pageSize`

---

## 构建与运行

```bash
cargo build -p proxy-server --release    # 编译主服务
cargo build -p proxy-hook-agent --release # 编译 Hook CLI

./target/release/proxy-server config.toml  # 启动（默认端口 5000/8888/9999）
```

### 配置 Claude Code 拦截

```bash
export ANTHROPIC_BASE_URL="http://localhost:8888"
```

---

## 持久化（`persist_config()`）

`/api/providers` 或 `/api/upstreams` 变更后 → 读取 `config.toml` 原文件 → 更新 TOML Value 中的 `providers[]`/`upstreams[]`/`active_upstream` → 写回磁盘。通过 `broadcast_send(UpstreamChanged)` 通知所有 WS 客户端。

---

## 安全

- 所有端口仅监听 `127.0.0.1`
- `x-api-key`、`Authorization` header 自动脱敏为 `[REDACTED]`
- API token 存 TOML 文件，前端 `has_token: bool`（不暴露 token 内容）
- SQLite 本地存储，不对外暴露
