
### 如何使用管理功能

编译完成后，你的二进制文件不仅是一个 Web 服务器，也是一个管理工具。

```bash
# 默认启动服务器
cargo run --bin vfs

# 或显式指定
cargo run --bin vfs server
```
# 用户管理
```bash
# 创建用户
cargo run --bin vfs user create -u admin -p admin123 -e admin@example.com -d "Administrator"

# 列出用户
cargo run --bin vfs user list

# 搜索用户
cargo run --bin vfs user list -s "admin"

# 重置密码
cargo run --bin vfs user reset-password -u admin -p newpassword

# 禁用用户
cargo run --bin vfs user disable -u testuser

# 启用用户
cargo run --bin vfs user enable -u testuser

```

# 数据库管理
```bash
# 查看数据库状态
cargo run --bin vfs db status

# 运行迁移
cargo run --bin vfs db migrate

```

# 测试运行
```bash
# 运行所有测试
cargo test

# 运行特定 crate 的测试
cargo test -p vfs-service

# 运行特定测试
cargo test -p vfs-service test_create_user

# 带输出运行测试
cargo test -p vfs-service -- --nocapture

```

# 架构总结
关键改进
- 服务层抽象 (services/)  
  - 每个服务独立可测试  
  - 业务逻辑与 HTTP 层分离  
  - 便于 mock 和单元测试  

- 服务容器 (ServiceContainer)  
  - 统一管理所有服务实例  
  - 支持依赖注入  
  - 便于测试时替换组件  

- 测试支持  
  - 每个服务都有对应的单元测试  
  - TestEnv 提供完整的测试环境  
  - 使用 tempfile 隔离测试数据  

- CLI 简化 (vfs-cmd)  
  - 仅调用服务层接口. 
  - 不包含业务逻辑  
  - 易于维护和扩展. 

#### 1. 查看状态 (Web 方式)

启动服务器：
```bash
# 默认启动服务器
cargo run
# 或者
cargo run -- server
```

查看状态：
*   **健康检查**: `curl http://localhost:8080/health` (查看是否 healthy)
*   **指标监控**: `curl http://localhost:8080/metrics` (Prometheus 格式)
*   **日志**: 直接查看终端输出的 stdout。

#### 2. 管理用户 (CLI 方式)

在**不停止**服务器的情况下（因为 SQLite 支持并发读取，WAL 模式下支持并发写，或者你可以在另一个终端操作），或者服务器停止时都可以运行：

**创建用户 (不再需要依赖开放的 API 注册接口)：**

```bash
cargo run -- user create --username admin --password secret --email admin@example.com --display-name "Administrator"
```

**重置密码：**

```bash
cargo run -- user reset-password --username admin --password newpassword123
```

**列出用户 (需要你完善 list_users SQL 逻辑)：**

```bash
cargo run -- user list
```

**查看帮助：**

```bash
cargo run -- --help
cargo run -- user --help
```

### 总结

通过引入 `clap` 并重构 `main.rs`，你成功将 **运维管理** 和 **业务服务** 分离了。这在生产环境中非常有用，因为你可以在服务器后台运行时，通过命令行快速创建管理员账号、修复数据或进行迁移，而无需通过 HTTP API。