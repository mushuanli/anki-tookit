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
    State(_state): State<AppState>, // Fixed: unused variable
    Query(query): Query<ListUsersQuery>,
) -> AppResult<Json<PaginatedResponse<UserResponse>>> {
    // 检查管理员权限
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    // TODO: 实现分页查询
    let users: Vec<UserResponse> = vec![];
    
    Ok(Json(PaginatedResponse {
        data: users,
        total: 0,
        page: query.page.unwrap_or(1),
        limit: query.limit.unwrap_or(20),
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
    Json(_req): Json<UpdateUserAdminRequest>, // Fixed: unused variable
) -> AppResult<Json<UserResponse>> {
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    let user = state
        .db
        .get_user_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // TODO: 实现更新逻辑

    Ok(Json(user.into()))
}

pub async fn delete_user(
    Extension(claims): Extension<Claims>,
    State(_state): State<AppState>, // Fixed: unused variable
    Path(_user_id): Path<Uuid>,     // Fixed: unused variable
) -> AppResult<StatusCode> {
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    // TODO: 实现删除用户及其所有数据

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
    State(_state): State<AppState>, // Fixed: unused variable
) -> AppResult<Json<SystemStats>> {
    if claims.permission_level != PermissionLevel::Admin {
        return Err(AppError::PermissionDenied("Admin access required".to_string()));
    }

    // TODO: 实现统计查询

    Ok(Json(SystemStats {
        total_users: 0,
        active_users: 0,
        total_storage_used: 0,
        total_sync_logs: 0,
        active_connections: 0,
    }))
}
