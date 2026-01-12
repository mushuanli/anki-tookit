// src/handlers/admin.rs

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::error::{AppError, AppResult};
use crate::models::*;
use crate::handlers::rest::AppState;

// ==================== 用户管理 ====================

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub search: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
}

pub async fn list_users(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Query(query): Query<ListUsersQuery>,
) -> AppResult<Json<PaginatedResponse<UserResponse>>> {
    // 检查管理员权限
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(20).max(1).min(100);
    let offset = (page - 1) * limit;

    // 假设我们在 Database 中实现了 list_users (下文实现)
    // 这里演示直接使用 sqlx 或者调用 db 方法
    let (users, total) = state.db.list_users(limit, offset, query.search.as_deref()).await?;

    let user_responses: Vec<UserResponse> = users.into_iter().map(UserResponse::from).collect();

    Ok(Json(PaginatedResponse {
        data: user_responses,
        total,
        page,
        limit,
    }))
}

pub async fn get_user(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<UserResponse>> {
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    let user = state
        .db
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(user.into()))
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserAdminRequest {
    pub is_active: Option<bool>,
    pub storage_quota: Option<i64>,
}

pub async fn update_user_admin(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<UpdateUserAdminRequest>,
) -> AppResult<Json<UserResponse>> {
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    let mut user = state
        .db
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if let Some(active) = req.is_active {
        user.is_active = active;
    }
    if let Some(quota) = req.storage_quota {
        user.storage_quota = quota;
    }
    user.updated_at = chrono::Utc::now().to_rfc3339();

    // 需要在 CachedDatabase/Database 中实现此方法
    state.db.update_user(&user).await?;

    Ok(Json(user.into()))
}

pub async fn delete_user(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    let user = state.db.get_user_by_id(user_id).await?;
    if user.is_none() {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    // 1. 清理文件 (物理删除)
    // 需要 FileStore 实现 delete_user_files
    // state.file_store.delete_user_files(user_id).await?;

    // 2. 删除数据库记录 (级联删除会处理 logs, tokens 等)
    state.db.delete_user(user_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ==================== 系统统计 ====================

#[derive(Debug, Serialize)]
pub struct SystemStats {
    pub total_users: i64,
    pub active_users: i64,
    pub total_storage_used: i64,
    pub total_sync_logs: i64,
    pub active_connections: i64,
}

pub async fn get_system_stats(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<SystemStats>> {
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    // 需要在 Database 中实现 get_stats
    let stats = state.db.get_system_stats().await?;

    Ok(Json(stats))
}
