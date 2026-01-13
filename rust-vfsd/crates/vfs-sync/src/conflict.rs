// src/sync/conflict.rs

use vfs_core::models::{ConflictType, SyncChange, VectorClock};

/// 向量时钟比较结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockRelation {
    Equal,      // 相等
    Ancestor,   // 本地是远程的祖先（本地更旧）
    Descendant, // 本地是远程的后代（本地更新）
    Concurrent, // 并发（冲突）
}

/// 冲突检测结果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConflictResult {
    ApplyRemote, // 应用远程变更
    KeepLocal,   // 保持本地
    Conflict,    // 存在冲突，需要解决
}

pub struct ConflictDetector;

impl ConflictDetector {
    /// 检测冲突
    pub fn detect(local_clock: &VectorClock, remote_change: &SyncChange) -> ConflictResult {
        let relation = Self::compare_clocks(local_clock, &remote_change.vector_clock);

        match relation {
            ClockRelation::Equal => ConflictResult::KeepLocal,
            ClockRelation::Ancestor => ConflictResult::ApplyRemote,
            ClockRelation::Descendant => ConflictResult::KeepLocal,
            ClockRelation::Concurrent => ConflictResult::Conflict,
        }
    }

    /// 比较两个向量时钟
    pub fn compare_clocks(clock1: &VectorClock, clock2: &VectorClock) -> ClockRelation {
        let mut has_greater = false;
        let mut has_less = false;

        // 收集所有 peer
        let all_peers: std::collections::HashSet<&String> =
            clock1.keys().chain(clock2.keys()).collect();

        for peer in all_peers {
            let c1 = clock1.get(peer).copied().unwrap_or(0);
            let c2 = clock2.get(peer).copied().unwrap_or(0);

            if c1 > c2 {
                has_greater = true;
            }
            if c1 < c2 {
                has_less = true;
            }
        }

        match (has_greater, has_less) {
            (false, false) => ClockRelation::Equal,
            (true, false) => ClockRelation::Descendant, // clock1 更新
            (false, true) => ClockRelation::Ancestor,   // clock1 更旧
            (true, true) => ClockRelation::Concurrent,  // 并发
        }
    }

    /// 确定冲突类型
    pub fn determine_type(change: &SyncChange) -> ConflictType {
    use vfs_core::models::SyncOperation;
    
    match &change.operation {
        SyncOperation::Delete => ConflictType::Delete,
        SyncOperation::Move => ConflictType::Move,
        SyncOperation::MetadataUpdate 
        | SyncOperation::TagAdd 
        | SyncOperation::TagRemove => ConflictType::Metadata,
        SyncOperation::Create 
        | SyncOperation::Update 
        | SyncOperation::Copy => ConflictType::Content,
    }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_compare_equal_clocks() {
        let mut clock1 = HashMap::new();
        clock1.insert("a".to_string(), 1);
        clock1.insert("b".to_string(), 2);

        let clock2 = clock1.clone();

        assert_eq!(
            ConflictDetector::compare_clocks(&clock1, &clock2),
            ClockRelation::Equal
        );
    }

    #[test]
    fn test_compare_ancestor_clock() {
        let mut clock1 = HashMap::new();
        clock1.insert("a".to_string(), 1);

        let mut clock2 = HashMap::new();
        clock2.insert("a".to_string(), 2);

        assert_eq!(
            ConflictDetector::compare_clocks(&clock1, &clock2),
            ClockRelation::Ancestor
        );
    }

    #[test]
    fn test_compare_concurrent_clocks() {
        let mut clock1 = HashMap::new();
        clock1.insert("a".to_string(), 2);
        clock1.insert("b".to_string(), 1);

        let mut clock2 = HashMap::new();
        clock2.insert("a".to_string(), 1);
        clock2.insert("b".to_string(), 2);

        assert_eq!(
            ConflictDetector::compare_clocks(&clock1, &clock2),
            ClockRelation::Concurrent
        );
    }
}
