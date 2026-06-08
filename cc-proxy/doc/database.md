# 数据库

## 表结构

### sessions

| 列 | 类型 | 约束 |
|----|------|------|
| `id` | TEXT | PRIMARY KEY |
| `label` | TEXT | |
| `started_at` | TEXT | NOT NULL |
| `ended_at` | TEXT | |
| `status` | TEXT | NOT NULL DEFAULT 'Recording' |

### requests

| 列 | 类型 | 约束 |
|----|------|------|
| `id` | TEXT | PRIMARY KEY |
| `session_id` | TEXT | FK → sessions(id) ON DELETE SET NULL |
| `timestamp` | TEXT | NOT NULL |
| `method` | TEXT | NOT NULL |
| `path` | TEXT | NOT NULL |
| `model` | TEXT | |
| `status_code` | INTEGER | |
| `input_tokens` | INTEGER | |
| `output_tokens` | INTEGER | |
| `cache_creation_input_tokens` | INTEGER | |
| `cache_read_input_tokens` | INTEGER | |
| `total_input_tokens` | INTEGER | session 累计（idempotent ALTER TABLE） |
| `total_output_tokens` | INTEGER | session 累计（idempotent ALTER TABLE） |
| `duration_ms` | INTEGER | |
| `ttft_ms` | INTEGER | time to first token |
| `stop_reason` | TEXT | |
| `message_id` | TEXT | |
| `error` | TEXT | |
| `request_headers` | TEXT | JSON 字符串 |
| `request_body` | TEXT | |
| `content_text` | TEXT | 合并后的响应文本 |
| `is_streaming` | INTEGER | NOT NULL DEFAULT 0 |

索引：`idx_requests_session`（session_id）、`idx_requests_timestamp`（timestamp）

### sse_events

| 列 | 类型 | 约束 |
|----|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT |
| `request_id` | TEXT | NOT NULL, FK → requests(id) ON DELETE CASCADE |
| `event_type` | TEXT | |
| `data` | TEXT | |
| `seq` | INTEGER | NOT NULL |

索引：`idx_sse_request`（request_id）

### hook_events

| 列 | 类型 | 约束 |
|----|------|------|
| `id` | TEXT | PRIMARY KEY |
| `timestamp` | TEXT | NOT NULL |
| `hook_event_name` | TEXT | NOT NULL |
| `session_id` | TEXT | NOT NULL |
| `cwd` | TEXT | NOT NULL DEFAULT '' |
| `permission_mode` | TEXT | NOT NULL DEFAULT '' |
| `transcript_path` | TEXT | NOT NULL DEFAULT '' |
| `hook_input` | TEXT | NOT NULL DEFAULT 'null' |
| `environment_variables` | TEXT | NOT NULL DEFAULT '{}' |
| `exit_code` | INTEGER | NOT NULL DEFAULT 0 |
| `stdout` | TEXT | NOT NULL DEFAULT '' |
| `stderr` | TEXT | NOT NULL DEFAULT '' |

索引：`idx_hooks_timestamp`（timestamp）

### mcp_requests

| 列 | 类型 | 约束 |
|----|------|------|
| `id` | TEXT | PRIMARY KEY |
| `timestamp` | TEXT | NOT NULL |
| `method` | TEXT | NOT NULL DEFAULT '' |
| `model` | TEXT | NOT NULL DEFAULT '' |
| `status_code` | INTEGER | |
| `request_body` | TEXT | |
| `response_body` | TEXT | |

索引：`idx_mcp_timestamp`（timestamp）

## PRAGMA 设置

```sql
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
```

## 数据清理

### 后台任务（`cleanup_loop`）

启动时执行一次，之后每 30 分钟运行。

### 保留策略

- `request_retention_hours` 小时后删除旧请求，但保留最新 session 的请求
- 默认 72 小时，0 = 不清理

### Session 限制

- 超过 `session_max_count` 时删除最旧的 sessions
- 默认 20，0 = 不限制

### 手动触发

`POST /api/cleanup`

## 聚合查询

### `sum_session_tokens(session_id) -> (u64, u64)`

统计 session 下所有已完成请求的 input/output token 总和。

### `get_cost_data(from, to) -> CostData`

按时间范围聚合成本数据，返回：
- `by_model: Vec<ModelCost>` — 按模型分组（input/output/cache tokens、请求数）
- `by_session: Vec<SessionCost>` — 按 session 分组（含 label、模型列表、时间范围）
