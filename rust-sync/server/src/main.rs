// file: rustSync/server/src/main.rs

mod auth;
mod db;
mod service;

use tonic::{transport::Server, Request, Status, service::Interceptor};
use service::{MySyncService, proto::sync_service_server::SyncServiceServer};
use db::Db;

// 拦截器：验证 JWT 并注入到 Context
#[derive(Clone)]
struct AuthInterceptor;

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        // 放行登录接口
        // 注意：实际路径可能不同，建议打印 request.uri() 查看
        // 这里简单处理：如果有 Authorization 头就校验，没有就放行（让 Service 层自己决定是否报错）
        if let Some(token_val) = request.metadata().get("authorization") {
            let token_str = token_val.to_str().map_err(|_| Status::invalid_argument("Bad auth header"))?;
            // 去掉 "Bearer " 前缀
            let token = token_str.replace("Bearer ", "");
            
            match auth::decode_token(&token) {
                Ok(claims) => {
                    // 关键步骤：将 Claims 存入 Extensions
                    request.extensions_mut().insert(claims);
                    Ok(request)
                },
                Err(_) => Err(Status::unauthenticated("Invalid token")),
            }
        } else {
            // 没有 Token，继续传递，具体接口由 Service 内部逻辑决定是否由于缺少 Token 而报错
            Ok(request)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 初始化 DB
    let db_url = "sqlite:sync.db?mode=rwc"; // 自动创建文件
    let db = Db::new(db_url).await?;

    let addr = "[::1]:50051".parse()?;
    let service = MySyncService { db };

    println!("RustSync Server listening on {}", addr);

    // 2. 启动服务，挂载拦截器
    Server::builder()
        .layer(tonic::service::interceptor(AuthInterceptor))
        .add_service(SyncServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
