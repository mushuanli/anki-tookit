use std::collections::VecDeque;
use std::sync::RwLock;

use crate::models::HasId;

/// Thread-safe bounded ring buffer with automatic eviction.
pub struct RingBuffer<T> {
    inner: RwLock<VecDeque<T>>,
    capacity: usize,
}

impl<T: Clone> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(VecDeque::with_capacity(capacity)),
            capacity,
        }
    }

    /// Push an item; evicts oldest if over capacity.
    pub fn push(&self, item: T) {
        let mut q = self.inner.write().expect("RingBuffer lock poisoned");
        q.push_back(item);
        while q.len() > self.capacity {
            q.pop_front();
        }
    }

    /// Snapshot of all items (newest last).
    pub fn get_all(&self) -> Vec<T> {
        let q = self.inner.read().expect("RingBuffer lock poisoned");
        q.iter().cloned().collect()
    }

    /// Find by string id.
    pub fn get_by_id(&self, id: &str) -> Option<T>
    where
        T: HasId,
    {
        let q = self.inner.read().expect("RingBuffer lock poisoned");
        q.iter().find(|item| item.id() == id).cloned()
    }

    pub fn clear(&self) {
        let mut q = self.inner.write().expect("RingBuffer lock poisoned");
        q.clear();
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("RingBuffer lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
