# API 端点 & WebSocket

## REST API

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
| GET/PUT | `/api/effort` | Effort 级别（auto/low/medium/high/xhigh/max/ultracode） |
| GET | `/api/costs?from=&to=` | 成本聚合（by_model + by_session），默认当天 |
| GET | `/api/sessions?q=` | 会话列表 |
| GET/PUT/DELETE | `/api/session/:id` | 查看/重命名/删除（rename 时 broadcast SessionUpdated） |
| GET | `/api/session/:id/export?format=json\|har\|markdown\|yaml` | 导出（带 content-disposition） |
| POST | `/api/hook-event` | 接收 Hook 事件（由 proxy-hook-agent 调用） |
| PUT | `/api/hook-event` | 更新 Hook 响应（按 body 中的 id 字段查找） |
| PUT | `/api/hook-event/:id` | 更新 Hook 响应（按 URL 路径 id 查找） |
| GET/PUT | `/api/mcp-destination` | MCP 目标地址 |
| POST | `/api/capture` | 开关录制 `{enabled: bool}` |
| GET | `/api/capture/status` | 录制状态 `{enabled: bool}` |
| GET/PUT | `/api/retention` | 数据保留设置 |
| POST | `/api/cleanup` | 手动触发清理 |
| POST | `/api/clear`, `/api/clear-mcp`, `/api/clear-hooks` | 清空数据 |

## WebSocket 消息

路径：`/ws`，Tagged union JSON（`{type, payload}`）

### 消息类型

| 类型 | Payload | 方向 |
|------|---------|------|
| `NewRequest` | `ProxiedRequest` | Server → Client |
| `RequestUpdated` | `ProxiedRequest` | Server → Client |
| `SseEvent` | `{request_id, event: SseEvent}` | Server → Client |
| `NewHook` | `HookEvent` | Server → Client |
| `NewMcp` | `ProxiedRequest` | Server → Client |
| `Cleared` | (unit) | Server → Client |
| `McpCleared` | (unit) | Server → Client |
| `McpConfigChanged` | `{destination_url: Option<String>}` | Server → Client |
| `UpstreamChanged` | `{active_upstream, upstreams[], providers[], active_effort}` | Server → Client |
| `History` | `{requests[]}` | Server → Client |
| `HookHistory` | `{events[]}` | Server → Client |
| `McpHistory` | `{requests[]}` | Server → Client |
| `SessionStarted` | `Session` | Server → Client |
| `SessionStopped` | `Session` | Server → Client |
| `SessionUpdated` | `{request_id}` | Server → Client |
| `TeeStatusChanged` | `{enabled: bool}` | Server → Client |

### 连接握手

WS 连接建立后，服务端立即推送 5 条初始状态：

1. `HookHistory` — 全部 hook 事件
2. `McpHistory` — 全部 MCP 请求
3. `McpConfigChanged` — 当前 MCP 目标
4. `UpstreamChanged` — upstreams + providers + active_effort
5. `TeeStatusChanged` — 录制开/关

**注意**：请求历史（`History`）不在 WS 首态中推送，由前端通过 `GET /api/requests` REST 加载，避免大量负载导致超时。

### 生命周期

- Ping/Pong：每 10s 发送 Ping，300s 无 Pong 则断开（在 200s/220s/240s 发出分级警告）
- 重连：前端指数退避 1s → 2s → 4s → ... → max 30s
- 静默检测：前端每 5s 检查，超过 180s 无消息则显示 "Connected (silent Ns)"
