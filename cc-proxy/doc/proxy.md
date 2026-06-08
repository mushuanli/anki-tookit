# Proxy 代理

## 三种模式

| 模式 | 触发条件 | 行为 |
|------|---------|------|
| **CONNECT tunnel** | `method == CONNECT` | 建立 TCP 双向隧道（`tokio::io::copy_bidirectional`） |
| **Forward proxy** | URI 含 scheme（如 `https://`） | 客户端已确定目标 URL，注入 provider token + 翻译 model + effort |
| **Reverse proxy** | URI 不含 scheme（相对路径） | 从 upstream config 解析 provider base URL + 拼接路径（`ANTHROPIC_BASE_URL` 模式） |

## dispatch_upstream()

正向代理和反向代理共用 `dispatch_upstream()` 执行实际请求：

- **重试**：指数退避 200ms × 2^n，只对 connect/timeout 错误重试，默认最多 3 次
- **流式响应**：SseParser 实时解析 SSE 事件 → 广播 `SseEvent` → 完成后合并 delta 文本、计算 session token 总计、写入 DB、广播 `RequestUpdated`
- **非流式响应**：缓冲完整响应体，提取 usage 统计，广播 `NewRequest`
- 两种路径都会写入 tee 文件

## Effort 注入

当 `active_effort != "auto"` 时：
1. 将 `output_config.effort` 合并到请求 body JSON 中
2. 追加 beta header `effort-2025-11-24` 到 `anthropic-beta`

有效值：`auto`（透传）、`low`、`medium`、`high`、`xhigh`、`max`、`ultracode`

## SSE 解析

`SseParser` 解析 Anthropic SSE 字节流（`\n\n` / `\r\n\r\n` 分隔），提取：
- `event_kind` — 事件类型
- `delta_text` — 文本增量
- `usage_from_delta` — token 用量
- `stop_reason` / `message_id` / `model_from_start` / `input_tokens_from_start`

`merge_delta_text()` 处理三种 delta 类型：
- `text_delta` → 纯文本
- `thinking_delta` → `[Thinking]` 标记
- `input_json_delta` → `[Tool Use]` 标记

## Headers 处理

- `x-api-key` / `authorization` → 脱敏为 `[REDACTED]`
- `transfer-encoding` / `content-encoding` / `content-length` → 丢弃
- Session ID 从请求 body 的 `metadata.user_id.session_id` 提取（嵌套 JSON 解析）

## 模型价格

- 每个 `ModelInfo` 有独立 `price_per_million_input` / `price_per_million_output`（`Option<f64>`, ¥/百万 token）
- 前端 `lookupProviderPrice(model)` 在所有 providers 的 models 列表中查找匹配
- 默认价格：input = 5 ¥/M token, output = 25 ¥/M token
- `fill_session_totals()` 在请求完成时调用，通过 `db.sum_session_tokens()` 计算 session 累计值
- 累计值存储到 `requests.total_input_tokens` / `total_output_tokens`（idempotent ALTER TABLE）
