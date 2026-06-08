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

## 文档索引

| 文档 | 内容 |
|------|------|
| [架构总览](./doc/architecture.md) | 项目结构、3 端口架构、Crate 职责、AppState、文件树 |
| [配置体系](./doc/config.md) | ProxyConfig、Tier 路由、持久化（persist_config） |
| [Proxy 代理](./doc/proxy.md) | 三种代理模式、Effort 注入、重试、SSE 解析、模型价格 |
| [数据库](./doc/database.md) | 5 张表结构、数据清理机制、聚合查询 |
| [API & WebSocket](./doc/api.md) | 全部 REST 端点、WS 消息类型、握手流程 |
| [前端](./doc/frontend.md) | 6 个视图 Tab、状态变量、过滤逻辑、数据加载流程 |
| [构建 & 安全](./doc/build.md) | 构建命令、端口配置、安全注意事项 |
