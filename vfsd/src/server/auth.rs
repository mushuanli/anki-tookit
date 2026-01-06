// src/server/auth.rs
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{request::Parts, StatusCode},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::net::SocketAddr;
use std::sync::Arc;
use ipnetwork::IpNetwork;
use crate::types::{AppState, Claims, JWT_SECRET,RequestUserId};

// IP 检查辅助函数
async fn check_ip_allowed(db: &sqlx::Pool<sqlx::Sqlite>, user_id: i64, user_ip: std::net::IpAddr) -> bool {
    // 如果 user_id 为 0 (例如，某些公共接口，虽然这里不允许)，跳过 IP 检查
    if user_id == 0 { return true; }

    let rows = sqlx::query("SELECT ip_cidr FROM user_ips WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(db)
        .await
        .unwrap_or_default();
    
    if rows.is_empty() { return true; }
    
    for row in rows {
        let cidr: String = row.get("ip_cidr");
        if let Ok(net) = cidr.parse::<IpNetwork>() {
            if net.contains(user_ip) { return true; }
        }
    }
    
    // Log failure
    eprintln!("[Auth] IP blocked: User {} from IP {} is not in whitelist.", user_id, user_ip);
    false 
}

#[axum::async_trait]
impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, Self::Rejection> {
        let connect_info = parts.extensions.get::<ConnectInfo<SocketAddr>>()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let ip = connect_info.0.ip();

        // 1. Extract Token
        let header = parts.headers.get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        
        if !header.starts_with("Bearer ") { 
            eprintln!("[Auth] Failed: Missing 'Bearer' prefix from IP {}", ip);
            return Err(StatusCode::UNAUTHORIZED); 
        }
        let token = &header[7..].trim(); // [修复] 再次 trim 以防万一

        // --- Logic A: API Key (sk-...) ---
        if token.starts_with("sk-") {
            // Hash the provided token to compare with stored hash
            let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
            
            // Debug Log: 打印前几位方便调试 (不要打印完整 Token)
            // println!("[Auth] Checking API Key: {}... Hash: {}", &token[0..10.min(token.len())], token_hash);

            let sql = "
                SELECT u.id as uid, u.username, k.scope_path, k.permission 
                FROM api_keys k 
                JOIN users u ON k.user_id = u.id 
                WHERE k.key_hash = ? AND (k.expires_at = 0 OR k.expires_at > ?)";
            
            let row = sqlx::query(sql)
                .bind(&token_hash) // 使用引用
                .bind(chrono::Utc::now().timestamp())
                .fetch_optional(&state.db)
                .await
                .map_err(|e| {
                    eprintln!("[Auth] DB Error: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            if let Some(r) = row {
                let uid: i64 = r.get("uid");
                
                // IP Whitelist Check
                if !check_ip_allowed(&state.db, uid, ip).await { 
                    // Log the forbidden attempt?
                    return Err(StatusCode::FORBIDDEN); 
                }
                
                // Successfully authenticated via API Key
                let claims = Claims {
                    sub: r.get("username"),
                    uid,
                    ver: 0, // API keys don't have token versions in the same sense as JWTs
                    exp: 0, // API keys don't expire by default unless `expires_at` is set
                    is_api_key: true,
                    scope: r.get("scope_path"),
                    perm: r.get("permission"),
                };

                parts.extensions.insert(RequestUserId::Some(claims.uid));
                return Ok(claims);
            } else {
                eprintln!("[Auth] Failed: API Key not found or expired. IP: {}", ip);
                // 提示：这通常是因为 Token 字符串有多余空格或 hash 计算不一致
                return Err(StatusCode::UNAUTHORIZED);
            }
        }

        // --- Logic B: JWT (Web Login) ---
        let claims_result = decode::<Claims>(token, &DecodingKey::from_secret(JWT_SECRET), &Validation::default());

        let claims = match claims_result {
            Ok(token_data) => token_data.claims,
            Err(e) => {
                eprintln!("[Auth] JWT Decode Failed: {} IP: {}", e, ip);
                return Err(StatusCode::UNAUTHORIZED);
            },
        };

        // IP Whitelist Check
        if !check_ip_allowed(&state.db, claims.uid, ip).await { return Err(StatusCode::FORBIDDEN); }

        // Check for token version mismatch (session invalidation)
        let row_res = sqlx::query("SELECT token_version FROM users WHERE id = ?")
            .bind(claims.uid)
            .fetch_optional(&state.db)
            .await;

        match row_res {
            Ok(Some(r)) => {
                let db_token_version: i32 = r.get("token_version");
                if claims.ver != db_token_version {
                    eprintln!("[Auth] Token version mismatch (Revoked). User: {}", claims.sub);
                    return Err(StatusCode::UNAUTHORIZED);
                }
            },
            Ok(None) => {
                eprintln!("[Auth] User not found for ID: {}", claims.uid);
                return Err(StatusCode::FORBIDDEN);
            },
            Err(e) => {
                eprintln!("[Auth] DB Error during JWT check: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }


        // Store user ID in extensions for the logger middleware
        parts.extensions.insert(RequestUserId::Some(claims.uid));

        Ok(claims)
    }
}
