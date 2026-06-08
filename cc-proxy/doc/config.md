# 配置体系

## 配置结构

```
AppConfig { proxy: ProxyConfig, server: ServerConfig, logging: LoggingConfig }

ProxyConfig {
    active_upstream: String,
    active_effort: String,         // 默认 "auto"，可选 low/medium/high/xhigh/max/ultracode
    providers: Vec<Provider>,
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

Provider {
    name: String,
    url: String,
    token: Option<String>,
    models: Vec<ModelInfo>,
}

ServerConfig {
    listen_address: String,  // 默认 "127.0.0.1"
    http_port: u16,          // 默认 5000
    proxy_port: u16,         // 默认 8888
    mcp_proxy_port: u16,     // 默认 9999
}

LoggingConfig {
    level: String,           // 默认 "info"
}
```

`Config.migrate()` — 启动时确保 `active_upstream` 指向存在的 upstream，否则回退到第一个。

## Tier 路由

```
请求 model → lower → high.keywords 匹配? → mid.keywords? → low.keywords? → default
匹配时：用 match 的 provider + model（model 为空则透传原 model）
```

- `TierRule { keywords: Vec<String>, provider: String, model: String }`
- `TierRule.is_active()` — provider 非空且至少一个非空 keyword 才视为 active
- `TierRule.matches()` — case-insensitive 子串匹配
- `UpstreamConfig.resolve(request_model) -> (provider, model)` — 按 high → mid → low → default 顺序解析

## 持久化（`persist_config()`）

触发时机：`/api/providers`、`/api/upstreams`、`/api/retention`、`/api/effort` 变更

流程：
1. 读取 `config.toml` 原文件
2. 更新 TOML Value 中的 `providers[]` / `upstreams[]` / `active_upstream` / `active_effort` / `request_retention_hours` / `session_max_count`
3. 移除 legacy `api_target`
4. 写回磁盘
5. `broadcast_send(UpstreamChanged)` 通知所有 WS 客户端

Provider token 更新逻辑：
- payload 中存在 `"token"` 键且为空字符串或 null → 清除 token
- payload 中缺少 `"token"` 键 → 保留现有 token

Model 列表序列化：如果有定价数据则序列化为数组表格，否则序列化为普通字符串数组，保持 config.toml 紧凑。
