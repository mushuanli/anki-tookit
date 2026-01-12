// src/sync/conflict.rs

use std::collections::HashMap;
use uuid::Uuid;

use crate::error::AppResult;
use crate::models::{ConflictType, SyncChange, SyncConflict, VectorClock};
use crate::utils::vector_clock::VectorClockUtils;

pub struct ConflictDetector;

impl ConflictDetector {
    /// 检测两个变更之间是否存在冲突
    pub fn detect(
        local_clock: &VectorClock,
        remote_change: &SyncChange,
    ) -> ConflictResult {
        let relation = VectorClockUtils::compare(local_clock, &remote_change.vector_clock);

        match relation {
            ClockRelation::Ancestor => ConflictResult::ApplyRemote,
            ClockRelation::Descendant => ConflictResult::KeepLocal,
            ClockRelation::Equal => ConflictResult::KeepLocal,
            ClockRelation::Concurrent => ConflictResult::Conflict,
        }
    }

    /// 确定冲突类型
    pub fn determine_type(change: &SyncChange) -> ConflictType {
        match change.operation {
            crate::models::SyncOperation::Delete => ConflictType::Delete,
            crate::models::SyncOperation::Move => ConflictType::Move,
            crate::models::SyncOperation::MetadataUpdate
            | crate::models::SyncOperation::TagAdd
            | crate::models::SyncOperation::TagRemove => ConflictType::Metadata,
            _ => ConflictType::Content,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConflictResult {
    ApplyRemote,
    KeepLocal,
    Conflict,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClockRelation {
    Equal,
    Ancestor,     // local 更旧
    Descendant,   // local 更新
    Concurrent,   // 并发修改
}
