// src/auth/middleware.rs

use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::error::{AppError, AppResult};
use super::jwt::{Claims, JwtService};

#[derive(Clone)]
pub struct AuthState {
    pub jwt_service: Arc<JwtService>,
}

/// 认证中间件 - 提取并验证 JWT
pub async fn auth_middleware(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let token = extract_token(&request)?;
    let token_data = auth_state.jwt_service.validate_token(&token)?;
    
    // 将 claims 存入 request extensions
    request.extensions_mut().insert(token_data.claims);
    
    Ok(next.run(request).await)
}

/// 从请求中提取 token
fn extract_token(request: &Request) -> AppResult<String> {
    // 首先检查 Authorization header
    if let Some(auth_header) = request.headers().get(AUTHORIZATION) {
        let auth_str = auth_header
            .to_str()
            .map_err(|_| AppError::AuthError("Invalid authorization header".to_string()))?;
        
        if auth_str.starts_with("Bearer ") {
            return Ok(auth_str[7..].to_string());
        }
    }

    // 检查查询参数（用于 WebSocket）
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            let mut parts = pair.split('=');
            if let (Some("token"), Some(token)) = (parts.next(), parts.next()) {
                return Ok(token.to_string());
            }
        }
    }

    Err(AppError::AuthError("Missing authentication token".to_string()))
}

/// 从请求 extensions 中获取 claims
pub fn get_claims(request: &Request) -> AppResult<&Claims> {
    request
        .extensions()
        .get::<Claims>()
        .ok_or_else(|| AppError::AuthError("Authentication required".to_string()))
}
