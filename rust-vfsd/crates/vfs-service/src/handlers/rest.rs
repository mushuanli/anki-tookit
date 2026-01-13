// crates/vfs-service/src/handlers/rest.rs

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{Claims, PermissionChecker};
use crate::services::{ServiceContainer, AdminService};
use vfs_core::error::{AppError, AppResult};
use vfs_core::models::*;
use vfs_storage::{CachedDatabase, FileStore};
use vfs_sync::SyncEngine;

// ==================== 应用状态 ====================

#[derive(Clone)]
pub struct AppState {
    pub services: ServiceContainer,
    pub db: CachedDatabase,
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
    let login_req = crate::services::auth_service::LoginRequest {
        username: req.username,
        password: req.password,
        device_id: req.device_id,
        device_name: req.device_name,
    };

    let response = state.services.auth.login(login_req).await?;

    Ok(Json(LoginResponse {
        token: response.token,
        user: response.user.into(),
    }))
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> AppResult<(StatusCode, Json<UserResponse>)> {
    let user = state.services.user.create(req).await?;
    Ok((StatusCode::CREATED, Json(user.into())))
}

// ==================== Token 管理 ====================

pub async fn create_token(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<(StatusCode, Json<CreateTokenResponse>)> {
    let response = state.services.token.create(claims.sub, req).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn list_tokens(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<TokenInfo>>> {
    let tokens = state.services.token.list_by_user(claims.sub).await?;
    Ok(Json(tokens))
}

pub async fn revoke_token(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(token_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    let revoked = state.services.token.revoke(token_id, claims.sub).await?;
    
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
    
    PermissionChecker::check_path_permission(
        &claims.permission_level,
        &claims.path_permissions,
        &format!("/{}", query.module_id),
        &PermissionLevel::ReadOnly,
    )?;

    let changes = state.services.sync
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
    let content = state.services.sync
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
    let conflicts = state.services.sync.list_conflicts(claims.sub).await?;
    Ok(Json(conflicts))
}

pub async fn resolve_conflict(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(conflict_id): Path<Uuid>,
    Json(req): Json<ResolveConflictRequest>,
) -> AppResult<StatusCode> {
    let resolved = state.services.sync
        .resolve_conflict(claims.sub, conflict_id, req.resolution, req.merged_content)
        .await?;

    if resolved {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound("Conflict not found".to_string()))
    }
}

// ==================== 用户信息 ====================

pub async fn get_current_user(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<UserResponse>> {
    let user = state.services.user
        .get_by_id(claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(user.into()))
}

pub async fn update_current_user(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Json(req): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    let user = state.services.user.update(claims.sub, req).await?;
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

// crates/vfs-service/src/handlers/rest.rs (续)

pub async fn list_devices(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<DeviceInfo>>> {
    let online_devices = state.services.sync.get_online_devices(claims.sub).await;
    
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
