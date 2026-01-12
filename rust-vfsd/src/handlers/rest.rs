// src/handlers/rest.rs

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use base64::Engine as _;

use crate::auth::{Claims, PermissionChecker};
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::storage::{CachedDatabase, FileStore}; // 改用 CachedDatabase
use crate::sync::SyncEngine;
use crate::utils::CryptoUtils;

use std::sync::Arc;

// ==================== 应用状态 ====================

#[derive(Clone)]
pub struct AppState {
    pub db: CachedDatabase, // 这里从 Database 改为 CachedDatabase
    pub file_store: Arc<FileStore>,
    pub sync_engine: Arc<SyncEngine>,
}

// ==================== 认证相关 ====================

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserResponse,
}

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> AppResult<Json<LoginResponse>> {
    let user = state
        .db
        .get_user_by_username(&req.username)
        .await?
        .ok_or_else(|| AppError::AuthError("Invalid credentials".to_string()))?;

    if !CryptoUtils::verify_password(&req.password, &user.password_hash)? {
        return Err(AppError::AuthError("Invalid credentials".to_string()));
    }

    if !user.is_active {
        return Err(AppError::AuthError("Account is disabled".to_string()));
    }

    // 生成 JWT
    let jwt_service = crate::auth::JwtService::new(&crate::config::Config::default().auth);
    let token = jwt_service.generate_token(
        user.id_as_uuid(),
        &user.username,
        req.device_id,
        PermissionLevel::ReadWrite,
        None,
    )?;

    Ok(Json(LoginResponse {
        token,
        user: user.into(),
    }))
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> AppResult<(StatusCode, Json<UserResponse>)> {
    // 检查用户名是否已存在
    if state.db.get_user_by_username(&req.username).await?.is_some() {
        return Err(AppError::Conflict("Username already exists".to_string()));
    }

    let password_hash = CryptoUtils::hash_password(&req.password)?;
    let now = chrono::Utc::now();

    let user = User {
        id: Uuid::new_v4().to_string(),
        username: req.username,
        password_hash,
        email: req.email,
        display_name: req.display_name,
        storage_quota: 10 * 1024 * 1024 * 1024, // 10GB 默认配额
        storage_used: 0,
        is_active: true,
        created_at: now.to_rfc3339(),
        updated_at: now.to_rfc3339(),
    };

    state.db.create_user(&user).await?;

    Ok((StatusCode::CREATED, Json(user.into())))
}

// ==================== Token 管理 ====================

pub async fn create_token(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<(StatusCode, Json<CreateTokenResponse>)> {
    // 生成随机 token
    let raw_token = CryptoUtils::generate_token();
    let token_hash = CryptoUtils::hash_token(&raw_token);

    let expires_at = req.expires_in_days.map(|days| {
        chrono::Utc::now() + chrono::Duration::days(days)
    });

    let token = ApiToken {
        id: Uuid::new_v4(),
        user_id: claims.sub,
        name: req.name.clone(),
        token_hash,
        permission_level: req.permission_level.clone(),
        path_permissions: req.path_permissions.clone(),
        device_id: req.device_id.clone(),
        device_name: req.device_name.clone(),
        last_used_at: None,
        expires_at,
        is_revoked: false,
        created_at: chrono::Utc::now(),
    };

    state.db.create_token(&token).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreateTokenResponse {
            id: token.id,
            name: req.name,
            token: raw_token, // 只在创建时返回明文
            expires_at,
        }),
    ))
}

pub async fn list_tokens(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<TokenInfo>>> {
    let tokens = state.db.get_user_tokens(claims.sub).await?;
    Ok(Json(tokens.into_iter().map(TokenInfo::from).collect()))
}

pub async fn revoke_token(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(token_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let revoked = state.db.revoke_token(token_id, claims.sub).await?;
    
    if revoked {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound("Token not found".to_string()))
    }
}

// ==================== 同步相关 ====================

#[derive(Debug, Deserialize)]
pub struct SyncQuery {
    pub module_id: String,
    pub limit: Option<i64>,
    pub from_time: Option<i64>,
    pub to_time: Option<i64>,
}

pub async fn get_pending_changes(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Query(query): Query<SyncQuery>,
) -> AppResult<Json<Vec<SyncChange>>> {
    let device_id = claims.device_id.as_deref().unwrap_or("unknown");
    
    // 检查路径权限
    PermissionChecker::check_path_permission(
        &claims.permission_level,
        &claims.path_permissions,
        &format!("/{}", query.module_id),
        &PermissionLevel::ReadOnly,
    )?;

    let changes = state
        .sync_engine
        .get_pending_changes(
            claims.sub,
            device_id,
            &query.module_id,
            query.limit.unwrap_or(100),
            query.from_time,
            query.to_time,
        )
        .await?;

    Ok(Json(changes))
}

pub async fn get_content(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(content_hash): Path<String>,
) -> AppResult<Vec<u8>> {
    let content = state
        .sync_engine
        .get_content(claims.sub, &content_hash)
        .await?
        .ok_or_else(|| AppError::NotFound("Content not found".to_string()))?;

    Ok(content)
}

// ==================== 冲突管理 ====================

pub async fn list_conflicts(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<SyncConflict>>> {
    let conflicts = state.db.get_unresolved_conflicts(claims.sub).await?;
    Ok(Json(conflicts))
}

pub async fn resolve_conflict(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(conflict_id): Path<Uuid>,
    Json(req): Json<ResolveConflictRequest>,
) -> AppResult<StatusCode> {
    // 获取冲突详情
    let conflicts = state.db.get_unresolved_conflicts(claims.sub).await?;
    let conflict = conflicts
        .iter()
        .find(|c| c.id == conflict_id)
        .ok_or_else(|| AppError::NotFound("Conflict not found".to_string()))?;

    // 如果是合并解决，处理合并内容
    if req.resolution == ConflictResolution::Merged {
        let content_base64 = req.merged_content.as_ref()
            .ok_or_else(|| AppError::ValidationError(
                "Merged content is required for merge resolution".to_string()
            ))?;

        // 解码 Base64 内容
        let data = base64::engine::general_purpose::STANDARD
            .decode(content_base64)
            .map_err(|e| AppError::ValidationError(format!("Invalid base64: {}", e)))?;

        // 计算新的内容哈希
        let content_hash = CryptoUtils::hash_content(&data);

        // 保存合并后的内容
        let storage_path = state
            .file_store
            .save_content(claims.sub, &content_hash, &data)
            .await?;

        // 更新内容索引
        state
            .db
            .save_content_index(claims.sub, &content_hash, data.len() as i64, &storage_path)
            .await?;

        // 更新用户存储使用量
        state.db.update_user_storage(claims.sub, data.len() as i64).await?;

        // 创建同步日志记录合并后的变更
        let merged_change = SyncLog {
            id: 0,
            user_id: claims.sub,
            module_id: extract_module_id(&conflict.path),
            node_id: conflict.node_id.clone(),
            device_id: claims.device_id.clone().unwrap_or_else(|| "server".to_string()),
            operation: SyncOperation::Update,
            path: conflict.path.clone(),
            previous_path: None,
            content_hash: Some(content_hash),
            size: Some(data.len() as i64),
            metadata: None,
            version: std::cmp::max(
                conflict.local_change.version,
                conflict.remote_change.version
            ) + 1,
            vector_clock: merge_vector_clocks(
                &conflict.local_change.vector_clock,
                &conflict.remote_change.vector_clock
            ),
            created_at: chrono::Utc::now(),
        };

        state.db.save_log(&merged_change).await?;

        // 广播合并结果到所有设备
        broadcast_merge_result(&state, claims.sub, &merged_change).await;
    }

    // 更新冲突状态
    let resolved = state
        .db
        .resolve_conflict(conflict_id, claims.sub, req.resolution)
        .await?;

    if resolved {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound("Conflict not found".to_string()))
    }
}

/// 从路径提取模块 ID
fn extract_module_id(path: &str) -> String {
    path.split('/')
        .filter(|s| !s.is_empty())
        .next()
        .unwrap_or("default")
        .to_string()
}

/// 合并向量时钟
fn merge_vector_clocks(
    clock1: &std::collections::HashMap<String, i64>,
    clock2: &std::collections::HashMap<String, i64>,
) -> std::collections::HashMap<String, i64> {
    let mut merged = clock1.clone();
    for (peer, counter) in clock2 {
        let existing = merged.get(peer).copied().unwrap_or(0);
        merged.insert(peer.clone(), existing.max(*counter));
    }
    // 递增服务端计数
    let server_counter = merged.get("server").copied().unwrap_or(0);
    merged.insert("server".to_string(), server_counter + 1);
    merged
}

/// 广播合并结果
async fn broadcast_merge_result(state: &AppState, user_id: Uuid, change: &SyncLog) {
    let sync_change = SyncChange::from(change.clone());
    
    let packet = crate::sync::packet::SyncPacket {
        packet_id: Uuid::new_v4().to_string(),
        peer_id: "server".to_string(),
        module_id: change.module_id.clone(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        changes: vec![sync_change],
        inline_contents: None,
        chunk_refs: None,
        compression: None,
        signature: None,
    };

    let message = crate::sync::packet::WsMessage::SyncPacket {
        req_id: Uuid::new_v4().to_string(),
        payload: packet,
    };

    // 广播到所有设备
    state
        .sync_engine
        .session_manager()
        .broadcast_json_to_others(user_id, "", message)
        .await;
}

// ==================== 用户信息 ====================

pub async fn get_current_user(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<UserResponse>> {
    let user = state
        .db
        .get_user_by_id(claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(user.into()))
}

pub async fn update_current_user(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Json(req): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    let mut user = state  // 添加 mut
        .db
        .get_user_by_id(claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if let Some(email) = req.email {
        user.email = Some(email);
    }
    if let Some(display_name) = req.display_name {
        user.display_name = Some(display_name);
    }
    if let Some(password) = req.password {
        user.password_hash = CryptoUtils::hash_password(&password)?;
    }
    user.updated_at = chrono::Utc::now().to_rfc3339();  // 需要转换为字符串

    // TODO: 实现 update_user 方法
    // state.db.update_user(&user).await?;

    Ok(Json(user.into()))
}

// ==================== 设备管理 ====================

#[derive(Debug, Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_name: Option<String>,
    pub is_online: bool,
    pub last_sync_time: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn list_devices(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<DeviceInfo>>> {
    let online_devices = state.sync_engine.get_online_devices(claims.sub).await;
    
    // TODO: 从数据库获取所有设备信息并合并在线状态
    let devices: Vec<DeviceInfo> = online_devices
        .into_iter()
        .map(|device_id| DeviceInfo {
            device_id,
            device_name: None,
            is_online: true,
            last_sync_time: None,
        })
        .collect();

    Ok(Json(devices))
}
