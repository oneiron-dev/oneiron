//! Deterministic, explicitly advanced clock for hosts and tests.
use super::{Clock, IdGen, StoreClock};
use std::sync::{Arc, Mutex};

/// A controllable source, not a process-wide override. Each store retains its
/// own monotonic floor when the source is moved backwards.
pub struct ManualClock {
    now: Mutex<u64>,
    next: Mutex<u64>,
}
impl ManualClock {
    pub fn new(now: u64) -> Arc<Self> {
        Arc::new(Self {
            now: Mutex::new(now),
            next: Mutex::new(1),
        })
    }
    pub fn set(&self, now: u64) {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = now;
    }
    pub fn bundle(self: &Arc<Self>) -> StoreClock {
        StoreClock::new(self.clone(), self.clone())
    }
}
impl Clock for ManualClock {
    fn now_recorded_at(&self) -> u64 {
        *self
            .now
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
impl IdGen for ManualClock {
    fn ulid(&self) -> [u8; 16] {
        let mut next = self
            .next
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut bytes = [0x71; 16];
        bytes[8..].copy_from_slice(&next.to_be_bytes());
        *next = next.saturating_add(1);
        bytes
    }
}
