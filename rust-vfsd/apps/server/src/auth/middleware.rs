// src/auth/middleware.rs

use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use vfs_core::error::{AppError, AppResult};
use vfs_storage::CachedDatabase;
use vfs_core::utils::CryptoUtils;
use super::jwt::{Claims, JwtService};

#[derive(Clone)]
pub struct AuthState {
    pub jwt_service: Arc<JwtService>,
    pub db: CachedDatabase,  // 添加数据库连接用于 API Token 验证
}

// 定义一个枚举来区分 Token 来源，以便复用验证逻辑
enum AuthInput {
    Header(String),
    Query(String),
}

/// 认证中间件
pub async fn auth_middleware(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // 1. 【关键修复】同步提取 Token 字符串。
    // 我们必须在这里获取 String 的所有权 (Clone)，这样 `request` 的借用就会立即结束。
    // 如果传递 &Request 给一个 async 函数并在其中 await，会导致 Future 不是 Send，
    // 因为 Request<Body> 的 Body 通常不是 Sync，导致 &Request 不是 Send。
    let auth_input = extract_auth_input(&request)?;

    // 2. 进行异步验证（此时不再持有 request 的引用）
    let claims = match auth_input {
        AuthInput::Header(header_str) => validate_auth_header(&header_str, &auth_state).await?,
        AuthInput::Query(token_str) => validate_jwt_token(&token_str, &auth_state)?,
    };

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

/// 同步辅助函数：仅提取，不验证，不 await
fn extract_auth_input(request: &Request) -> AppResult<AuthInput> {
    // 检查 Header
    if let Some(header) = request.headers().get(AUTHORIZATION) {
        let header_str = header.to_str()
            .map_err(|_| AppError::AuthError("Invalid authorization header encoding".to_string()))?;
        return Ok(AuthInput::Header(header_str.to_string()));
    }

    // 检查 Query
    if let Some(token) = extract_token_from_query(request) {
        return Ok(AuthInput::Query(token));
    }

    Err(AppError::AuthError("Missing authentication".to_string()))
}

/// 验证 Authorization header (支持 Bearer JWT 和 ApiKey)
async fn validate_auth_header(header: &str, auth_state: &AuthState) -> AppResult<Claims> {
    if header.starts_with("Bearer ") {
        let token = &header[7..];
        
        // 首先尝试作为 JWT 验证
        if let Ok(claims) = validate_jwt_token(token, auth_state) {
            return Ok(claims);
        }
        
        // JWT 验证失败，尝试作为 API Token 验证
        validate_api_token(token, auth_state).await
    } else if header.starts_with("ApiKey ") {
        // 显式 API Key 认证
        let token = &header[7..];
        validate_api_token(token, auth_state).await
    } else {
        Err(AppError::AuthError("Invalid authorization header format".to_string()))
    }
}

/// 验证 JWT Token (纯计算，无需 async，但为了统一接口保留)
fn validate_jwt_token(token: &str, auth_state: &AuthState) -> AppResult<Claims> {
    let token_data = auth_state.jwt_service.validate_token(token)?;
    Ok(token_data.claims)
}

/// 验证 API Token (需要查库，必须 async)
async fn validate_api_token(token: &str, auth_state: &AuthState) -> AppResult<Claims> {
    // 计算 token 哈希
    let token_hash = CryptoUtils::hash_token(token);
    
    // 从数据库查询 token
    let api_token = auth_state
        .db
        .get_token_by_hash(&token_hash)
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid API token".to_string()))?;
    
    // 检查 token 是否被撤销
    if api_token.is_revoked {
        return Err(AppError::AuthError("Token has been revoked".to_string()));
    }
    
    // 检查 token 是否过期
    if let Some(expires_at) = api_token.expires_at {
        if expires_at < chrono::Utc::now() {
            return Err(AppError::AuthError("Token has expired".to_string()));
        }
    }
    
    // 更新最后使用时间（异步，不等待）
    let db = auth_state.db.clone();
    let token_id = api_token.id;
    tokio::spawn(async move {
        if let Err(e) = db.update_token_last_used(token_id).await {
            tracing::warn!("Failed to update token last used time: {}", e);
        }
    });
    
    // 构造 Claims
    Ok(Claims {
        sub: api_token.user_id,
        username: String::new(), // API Token 没有用户名，可以后续查询
        device_id: api_token.device_id,
        permission_level: api_token.permission_level,
        path_permissions: api_token.path_permissions,
        exp: api_token.expires_at
            .map(|dt| dt.timestamp())
            .unwrap_or(i64::MAX),
        iat: api_token.created_at.timestamp(),
    })
}

/// 从查询参数中提取 token
fn extract_token_from_query(request: &Request) -> Option<String> {
    request.uri().query().and_then(|query| {
        query.split('&').find_map(|pair| {
            let mut parts = pair.split('=');
            match (parts.next(), parts.next()) {
                (Some("token"), Some(token)) => Some(token.to_string()),
                _ => None,
            }
        })
    })
}

