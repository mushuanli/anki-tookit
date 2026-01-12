// src/utils/vector_clock.rs

use std::collections::HashMap;

use crate::models::VectorClock;
use crate::sync::conflict::ClockRelation;

pub struct VectorClockUtils;

impl VectorClockUtils {
    /// 递增向量时钟
    pub fn increment(clock: &VectorClock, peer_id: &str) -> VectorClock {
        let mut new_clock = clock.clone();
        let counter = new_clock.get(peer_id).copied().unwrap_or(0);
        new_clock.insert(peer_id.to_string(), counter + 1);
        new_clock
    }

    /// 合并两个向量时钟
    pub fn merge(local: &VectorClock, remote: &VectorClock) -> VectorClock {
        let mut merged = local.clone();
        for (peer, counter) in remote {
            let local_counter = merged.get(peer).copied().unwrap_or(0);
            merged.insert(peer.clone(), local_counter.max(*counter));
        }
        merged
    }

    /// 比较两个向量时钟
    pub fn compare(clock1: &VectorClock, clock2: &VectorClock) -> ClockRelation {
        let mut has_greater = false;
        let mut has_less = false;

        // 收集所有 peer
        let all_peers: std::collections::HashSet<&String> = clock1
            .keys()
            .chain(clock2.keys())
            .collect();

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
            (true, false) => ClockRelation::Descendant,  // clock1 更新
            (false, true) => ClockRelation::Ancestor,    // clock1 更旧
            (true, true) => ClockRelation::Concurrent,   // 并发
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment() {
        let mut clock = HashMap::new();
        clock.insert("device_a".to_string(), 1);

        let new_clock = VectorClockUtils::increment(&clock, "device_a");
        assert_eq!(new_clock.get("device_a"), Some(&2));

        let new_clock = VectorClockUtils::increment(&clock, "device_b");
        assert_eq!(new_clock.get("device_b"), Some(&1));
    }

    #[test]
    fn test_compare() {
        let mut clock1 = HashMap::new();
        clock1.insert("a".to_string(), 1);
        clock1.insert("b".to_string(), 2);

        let mut clock2 = HashMap::new();
        clock2.insert("a".to_string(), 1);
        clock2.insert("b".to_string(), 2);

        assert_eq!(VectorClockUtils::compare(&clock1, &clock2), ClockRelation::Equal);

        clock1.insert("a".to_string(), 2);
        assert_eq!(VectorClockUtils::compare(&clock1, &clock2), ClockRelation::Descendant);

        clock2.insert("b".to_string(), 3);
        assert_eq!(VectorClockUtils::compare(&clock1, &clock2), ClockRelation::Concurrent);
    }
}
