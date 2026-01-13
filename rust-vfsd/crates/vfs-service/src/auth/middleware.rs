// crates/vfs-service/src/auth/middleware.rs

use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use vfs_core::error::{AppError, AppResult};
use vfs_core::utils::CryptoUtils;
use vfs_storage::CachedDatabase;

use super::jwt::{Claims, JwtService};

#[derive(Clone)]
pub struct AuthState {
    pub jwt_service: Arc<JwtService>,
    pub db: CachedDatabase,
}

enum AuthInput {
    Header(String),
    Query(String),
}

pub async fn auth_middleware(
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_input = extract_auth_input(&request)?;

    let claims = match auth_input {
        AuthInput::Header(header_str) => validate_auth_header(&header_str, &auth_state).await?,
        AuthInput::Query(token_str) => validate_jwt_token(&token_str, &auth_state)?,
    };

    request.extensions_mut().insert(claims);
    Ok(next.run(request).await)
}

fn extract_auth_input(request: &Request) -> AppResult<AuthInput> {
    if let Some(header) = request.headers().get(AUTHORIZATION) {
        let header_str = header.to_str()
            .map_err(|_| AppError::AuthError("Invalid authorization header encoding".to_string()))?;
        return Ok(AuthInput::Header(header_str.to_string()));
    }

    if let Some(token) = extract_token_from_query(request) {
        return Ok(AuthInput::Query(token));
    }

    Err(AppError::AuthError("Missing authentication".to_string()))
}

async fn validate_auth_header(header: &str, auth_state: &AuthState) -> AppResult<Claims> {
    if header.starts_with("Bearer ") {
        let token = &header[7..];
        
        if let Ok(claims) = validate_jwt_token(token, auth_state) {
            return Ok(claims);
        }
        
        validate_api_token(token, auth_state).await
    } else if header.starts_with("ApiKey ") {
        let token = &header[7..];
        validate_api_token(token, auth_state).await
    } else {
        Err(AppError::AuthError("Invalid authorization header format".to_string()))
    }
}

fn validate_jwt_token(token: &str, auth_state: &AuthState) -> AppResult<Claims> {
    let token_data = auth_state.jwt_service.validate_token(token)?;
    Ok(token_data.claims)
}

async fn validate_api_token(token: &str, auth_state: &AuthState) -> AppResult<Claims> {
    let token_hash = CryptoUtils::hash_token(token);
    
    let api_token = auth_state
        .db
        .get_token_by_hash(&token_hash)
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid API token".to_string()))?;
    
    if api_token.is_revoked {
        return Err(AppError::AuthError("Token has been revoked".to_string()));
    }
    
    if let Some(expires_at) = api_token.expires_at {
        if expires_at < chrono::Utc::now() {
            return Err(AppError::AuthError("Token has expired".to_string()));
        }
    }
    
    let db = auth_state.db.clone();
    let token_id = api_token.id;
    tokio::spawn(async move {
        if let Err(e) = db.update_token_last_used(token_id).await {
            tracing::warn!("Failed to update token last used time: {}", e);
        }
    });
    
    Ok(Claims {
        sub: api_token.user_id,
        username: String::new(),
        device_id: api_token.device_id,
        permission_level: api_token.permission_level,
        path_permissions: api_token.path_permissions,
        exp: api_token.expires_at
            .map(|dt| dt.timestamp())
            .unwrap_or(i64::MAX),
        iat: api_token.created_at.timestamp(),
    })
}

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
