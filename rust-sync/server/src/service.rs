// file: rustSync/server/src/service.rs

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use crate::auth::{self, Claims};
use crate::db::Db;

// 引入 proto 生成的代码
pub mod proto {
    tonic::include_proto!("sync");
}
use proto::sync_service_server::SyncService;
use proto::{LoginRequest, LoginResponse, RegisterDeviceRequest, RegisterDeviceResponse, WhoAmIResponse, Empty,
    PullIndexRequest, PushIndexResponse, FileMeta};

pub struct MySyncService {
    pub db: Db,
}

#[tonic::async_trait]
impl SyncService for MySyncService {
    async fn login(&self, request: Request<LoginRequest>) -> Result<Response<LoginResponse>, Status> {
        let req = request.into_inner();
        
        // 1. 验证用户
        let user = self.db.get_user_by_name(&req.username).await
            .map_err(|e| Status::internal(e.to_string()))?;

        if let Some((uid, hash)) = user {
            if auth::verify_password(&req.password, &hash) {
                // 2. 自动注册设备 (简化流程，实际可能需要单独注册)
                self.db.register_device(uid, &req.device_id, "Unknown Device").await
                    .map_err(|_| Status::internal("Failed to register device"))?;

                // 3. 签发 Token，默认允许访问根目录 "/"
                let token = auth::create_token(&uid.to_string(), &req.device_id, "/")
                    .map_err(|_| Status::internal("Token creation failed"))?;

                return Ok(Response::new(LoginResponse {
                    token,
                    user_id: uid.to_string(),
                }));
            }
        }

        Err(Status::unauthenticated("Invalid username or password"))
    }

    async fn register_device(&self, request: Request<RegisterDeviceRequest>) -> Result<Response<RegisterDeviceResponse>, Status> {
        // 修复点 1: 这里加 .clone()
        // check_auth 返回 &Claims，我们克隆一份全新的 Claims 数据
        // 这样 claims 变量就拥有数据所有权，不再借用 request
        let claims = check_auth(&request)?.clone();
        
        // 现在可以安全地消耗 request 了
        let req = request.into_inner();

        let uid = claims.sub.parse::<i64>().unwrap_or(0);
        
        self.db.register_device(uid, &req.device_id, &req.device_name).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(RegisterDeviceResponse {
            success: true,
            message: "Device registered".into(),
        }))
    }

    async fn who_am_i(&self, request: Request<Empty>) -> Result<Response<WhoAmIResponse>, Status> {
        let claims = check_auth(&request)?;
        
        Ok(Response::new(WhoAmIResponse {
            // 修复点 4: claims.sub 是 String，不能从引用中移出，必须 clone
            user_id: claims.sub.clone(),
            device_id: claims.dev.clone(),
            allowed_scope: claims.scope.clone(),
        }))
    }

    // 1. PushIndex: 客户端上传流式元数据
    async fn push_index(
        &self,
        request: Request<Streaming<FileMeta>>,
    ) -> Result<Response<PushIndexResponse>, Status> {
        let claims = check_auth(&request)?.clone();
        let user_id = claims.sub.parse::<i64>().unwrap_or(0);
        
        let mut stream = request.into_inner();
        let mut count = 0;

        while let Some(meta_res) = stream.next().await {
            let meta = meta_res.map_err(|e| Status::internal(e.to_string()))?;
            
            // 安全检查：路径必须属于 Token 授权的 Scope
            if !meta.path.starts_with(&claims.scope) && claims.scope != "/" {
                // 这里可以选择报错或忽略，暂时忽略
                println!("Skipping path outside scope: {}", meta.path);
                continue;
            }

            self.db.upsert_file_index(user_id, &meta).await
                .map_err(|e| Status::internal(format!("DB Error: {}", e)))?;
            
            count += 1;
        }

        Ok(Response::new(PushIndexResponse {
            processed_count: count,
            success: true,
        }))
    }

    // 2. PullIndex: 服务器流式返回元数据
    type PullIndexStream = ReceiverStream<Result<FileMeta, Status>>;

    async fn pull_index(
        &self,
        request: Request<PullIndexRequest>,
    ) -> Result<Response<Self::PullIndexStream>, Status> {
        let claims = check_auth(&request)?.clone();
        let user_id = claims.sub.parse::<i64>().unwrap_or(0);
        let req = request.into_inner();

        // 确定查询前缀：Token Scope 和 请求 Prefix 取交集
        // 简单处理：如果 Scope 不是 "/"，则忽略请求的 prefix，强制使用 scope
        let search_prefix = if claims.scope == "/" {
            req.prefix
        } else {
            claims.scope.clone()
        };

        // 从 DB 获取数据 (注意：大量数据时应该使用 SQL 游标，这里用 fetch_all 简化)
        let files = self.db.get_file_indexes(user_id, &search_prefix).await
            .map_err(|e| Status::internal(e.to_string()))?;

        // 创建 channel 用于流式返回
        let (tx, rx) = mpsc::channel(files.len().max(1) + 1);

        tokio::spawn(async move {
            for file in files {
                if tx.send(Ok(file)).await.is_err() {
                    break; // 客户端断开
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

// 辅助函数：从请求中提取 Claims
fn check_auth<T>(req: &Request<T>) -> Result<&Claims, Status> {
    req.extensions()
        .get::<Claims>()
        .ok_or_else(|| Status::unauthenticated("Missing valid auth token"))
}
