// crates/vfs-service/src/handlers/admin.rs

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Claims;
use crate::handlers::rest::AppState;
use crate::services::admin_service::{PaginatedResponse, UpdateUserAdminRequest};
use vfs_core::error::AppResult;
use vfs_core::models::*;

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub search: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedUsersResponse {
    pub data: Vec<UserResponse>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
}

pub async fn list_users(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Query(query): Query<ListUsersQuery>,
) -> AppResult<Json<PaginatedUsersResponse>> {
    state.services.admin.check_admin(&claims.permission_level)?;

    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20);

    let result = state.services.admin
        .list_users(page, limit, query.search.as_deref())
        .await?;

    Ok(Json(PaginatedUsersResponse {
        data: result.data,
        total: result.total,
        page: result.page,
        limit: result.limit,
    }))
}

pub async fn get_user(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<Json<UserResponse>> {
    state.services.admin.check_admin(&claims.permission_level)?;

    let user = state.services.admin.get_user(user_id).await?;
    Ok(Json(user.into()))
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserAdminRequestDto {
    pub is_active: Option<bool>,
    pub storage_quota: Option<i64>,
}

pub async fn update_user_admin(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
    Json(req): Json<UpdateUserAdminRequestDto>,
) -> AppResult<Json<UserResponse>> {
    state.services.admin.check_admin(&claims.permission_level)?;

    let update_req = UpdateUserAdminRequest {
        is_active: req.is_active,
        storage_quota: req.storage_quota,
    };

    let user = state.services.admin.update_user(user_id, update_req).await?;
    Ok(Json(user.into()))
}

pub async fn delete_user(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> AppResult<StatusCode> {
    state.services.admin.check_admin(&claims.permission_level)?;

    state.services.admin.delete_user(user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_system_stats(
    Extension(claims): Extension<Claims>,
    State(state): State<AppState>,
) -> AppResult<Json<SystemStats>> {
    state.services.admin.check_admin(&claims.permission_level)?;

    let stats = state.services.admin.get_system_stats().await?;
    Ok(Json(stats))
}
