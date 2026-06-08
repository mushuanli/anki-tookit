# 前端

## 技术栈

- Vanilla JS/HTML/CSS，通过 `rust-embed` 内嵌到二进制
- CSS：深色主题，BEM 命名，CSS 变量
- JS：~1756 行，原生 DOM + 模板字符串 + 事件委托

## 6 个视图 Tab

| Tab | 容器 ID | 功能 |
|-----|---------|------|
| **Inspector** | `#view-inspector` | 请求表格 — Session 分组折叠、多选删除、行内详情（Request/Response/SSE 三个子 tab）。工具栏含 Upstream 选择器、Effort 选择器、**Cost 统计面板**（当前 upstream 的今日/本月 tokens 和费用） |
| **Conversation** | `#view-conversation` | 实时时间轴（API + Hook + MCP 混合），按 session 过滤，最多 100 条，支持全屏 |
| **MCP Observer** | `#view-mcp` | MCP JSON-RPC 请求列表 + 目标地址配置 |
| **Hooks** | `#view-hooks` | Hook 事件表格（Event/Session/CWD/ExitCode），最多 200 条 |
| **Cost** | `#view-cost` | 成本分析 — 日期范围（今天/本周/本月预设）、摘要卡片、按 Session/Model/Provider 分组明细 |
| **Settings** | `#view-settings` | 三列网格：Providers CRUD + Upstreams CRUD + Data Retention |

## 关键状态变量

```javascript
// 数据
requestRows: Map<string, ProxiedRequest>   // id → 请求对象
selectedIds: Set<string>                    // 多选集合
expandedSessions: Set<string>              // 当前展开的 session
sessionCache: Object                        // session id → label

// 配置
providerList: Array<ProviderInfo>
upstreamList: Array<UpstreamInfo>
activeUpstream: string
activeEffort: string                       // 默认 "auto"

// 过滤 & 分页
filterModel: string                        // 默认 "__has_model__"（All Models）
filterSession: string                      // 默认 ""（All Sessions）
filterTimeFrom / filterTimeTo: string
currentPage: number                        // 默认 1
pageSize: number                           // 默认 50

// Effort
EFFORT_LEVELS: ['auto', 'low', 'medium', 'high', 'xhigh', 'max', 'ultracode']
```

## 过滤逻辑

### 模型过滤

| 值 | 标签 | 行为 |
|----|------|------|
| `""` | All | 显示所有请求（包括 model 为空的） |
| `"__has_model__"` | All Models | **默认**。只显示 model 非空的请求 |
| 具体模型名 | 动态 | 精确匹配 `req.model` |

### Session 过滤

| 值 | 标签 | 行为 |
|----|------|------|
| `"__all__"` | All | 不按 session 过滤，显示所有请求 |
| `""` | All Sessions | **默认**。只显示有 `session_id` 的请求 |
| 具体 session ID | 动态 | 精确匹配 `req.session_id` |

- "All" → 不做任何过滤，无自动展开
- "All Sessions" → 清除 `expandedSessions`，自动展开最新 session
- 特定 session → 仅展开该 session，显示 Export / Save YAML / Rename / Delete 操作按钮

### Session 标签获取

两步加载：
1. 启动时 `GET /api/sessions` 批量缓存
2. 新 session 以 5 个一批异步获取，防止服务器过载

## 数据加载流程

```
connect() → WebSocket 首态
  ├─ HookHistory, McpHistory, McpConfigChanged, UpstreamChanged, TeeStatusChanged
  └─ 然后 REST 加载：
       1. GET /api/upstreams      → upstream select + provider/upstream 列表
       2. GET /api/sessions        → 预热 sessionCache
       3. GET /api/requests?limit=2000 → 填充 requestRows，展开最新 session
       4. GET /api/mcp-destination  → MCP 目标地址
       5. GET /api/capture/status   → 录制开关状态
       6. GET /api/retention        → retention 设置
```

## 实时更新

WebSocket 消息驱动的前端更新：

| 消息 | 前端行为 |
|------|---------|
| `NewRequest` / `RequestUpdated` | `upsertRequestRow()` + 200ms 防抖渲染 + 500ms 防抖更新筛选下拉 + 加入时间线 |
| `SseEvent` | 若匹配当前打开的详情，实时追加 SSE 事件 |
| `NewHook` | 单行插入（最多 200 行），加入时间线 |
| `NewMcp` | 单行插入（最多 100 行），加入时间线 |
| `Cleared` | 清空全部表格和筛选 |
| `McpCleared` | 清空 MCP 表格 |
| `McpConfigChanged` | 同步 MCP 目标输入框 |
| `UpstreamChanged` | 刷新 provider/upstream/effort 列表和下拉 |
| `TeeStatusChanged` | 同步录制（Record）开关状态 |
| `History` / `HookHistory` / `McpHistory` | 仅 WS 首态处理，之后不再使用 |

## Inspector 工具栏 Cost 统计

在 Effort 选择器右侧，实时显示**当前上游（upstream）**的消耗统计：

| 统计项 | DOM ID | 含义 |
|--------|--------|------|
| 今日 Tokens | `#stat-today-tokens` | 当前 upstream 关联 provider(s) 今日 input/output token 总量 |
| 今日费用 | `#stat-today-cost` | 今日 token 消耗 × 模型定价 |
| 本月 Tokens | `#stat-month-tokens` | 当前 upstream 本月 token 总量 |
| 本月费用 | `#stat-month-cost` | 本月 token 消耗 × 模型定价 |

### 计算逻辑

1. **上游过滤**：`getActiveUpstreamProviders()` 从当前 `activeUpstream` 的 High/Mid/Low/Default tier 提取所有 provider 名称集合
2. **请求归属**：`isReqFromUpstreamProviders()` 通过 `req.model` 反查 `providerList`，判断该请求是否属于上述 provider
3. **日期切片**：`timestamp` 前缀匹配 `YYYY-MM-DD`（今日）或 `YYYY-MM`（本月）
4. **费用计算**：`input_tokens × price.in / 1e6 + output_tokens × price.out / 1e6`

### 更新时机

- `renderPage()` 末尾（每次表格渲染后）
- `applyUpstreamState()` 中（切换 upstream 或收到 provider 价格变更时）

### 关键函数

| 函数 | 职责 |
|------|------|
| `calcInspectorCostStats()` | 遍历 `requestRows`，按 upstream + 日期聚合 tokens 和费用 |
| `getActiveUpstreamProviders()` | 从当前 upstream 配置提取 provider 名称集合 |
| `isReqFromUpstreamProviders()` | 判断请求是否为当前 upstream 的请求 |
| `updateInspectorCostStats()` | 将计算结果写入 DOM

## Settings 面板

### Providers
- 列表：名称、URL、token 状态（钥匙图标）、模型数量、定价摘要
- 编辑表单：名称（新增可编辑/编辑禁用）、URL、Token（密码字段）、模型定价列表（每个 model：id + input ¥/M + output ¥/M + 删除按钮）
- 保存：POST（新增）或 PUT（编辑），token 为空字符串时清除

### Upstreams
- 四层 Tier 编辑：High（红色）/ Mid（黄色）/ Low（绿色）/ Default（灰色）
- 每层：关键词（逗号分隔）+ Provider 下拉 + Model 输入（带 datalist）
- Provider 变更时动态更新 model datalist
- 新建默认关键词：High="opus", Mid="sonnet", Low="haiku"

### Data Retention
- `request_retention_hours`（默认 72）、`session_max_count`（默认 20）
- "Clean Up Now" 按钮 + 上次清理时间显示
