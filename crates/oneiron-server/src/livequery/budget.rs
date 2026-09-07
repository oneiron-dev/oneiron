//! Retained app state has both a session ceiling and a shared hub ceiling.
use super::AppError;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) const SESSION_BYTES: usize = 8 * 1024 * 1024;
pub(super) const HUB_BYTES: usize = 64 * 1024 * 1024;

pub(super) struct Budget {
    used: AtomicUsize,
    limit: usize,
}
impl Budget {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicUsize::new(0),
            limit,
        })
    }
    fn take(&self, bytes: usize) -> bool {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.limit)
            })
            .is_ok()
    }
    fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }
}

pub(super) struct Reservation {
    session: Arc<Budget>,
    hub: Arc<Budget>,
    bytes: usize,
}
impl Reservation {
    pub(super) fn new(
        session: Arc<Budget>,
        hub: Arc<Budget>,
        bytes: usize,
    ) -> Result<Self, AppError> {
        let mut reservation = Self {
            session,
            hub,
            bytes: 0,
        };
        reservation.resize(bytes)?;
        Ok(reservation)
    }
    pub(super) fn resize(&mut self, bytes: usize) -> Result<(), AppError> {
        if bytes > self.bytes {
            let extra = bytes - self.bytes;
            if !self.session.take(extra) {
                return Err(exhausted());
            }
            if !self.hub.take(extra) {
                self.session.release(extra);
                return Err(exhausted());
            }
        } else {
            self.session.release(self.bytes - bytes);
            self.hub.release(self.bytes - bytes);
        }
        self.bytes = bytes;
        Ok(())
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.session.release(self.bytes);
        self.hub.release(self.bytes);
    }
}
fn exhausted() -> AppError {
    AppError::bad_request(
        "live-query retention byte budget exceeded",
        Some("scopedView"),
    )
}

/// Conservative heap estimate, including Value slots and map-node overhead.
pub(super) fn value_bytes(value: &serde_json::Value) -> usize {
    use serde_json::Value;
    std::mem::size_of::<Value>()
        + match value {
            Value::String(s) => s.capacity(),
            Value::Array(a) => {
                a.capacity() * std::mem::size_of::<Value>()
                    + a.iter().map(value_bytes).sum::<usize>()
            }
            Value::Object(o) => o
                .iter()
                .map(|(k, v)| 128 + k.capacity() + value_bytes(v))
                .sum(),
            _ => 0,
        }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn session_and_hub_admission_roll_back_and_drop_reclaims_bytes() {
        let hub = Budget::new(10);
        let first = Budget::new(8);
        let second = Budget::new(8);
        let mut a = Reservation::new(first.clone(), hub.clone(), 7).unwrap();
        assert!(a.resize(9).is_err());
        assert!(Reservation::new(second.clone(), hub.clone(), 4).is_err());
        assert_eq!(second.used.load(Ordering::Acquire), 0);
        a.resize(3).unwrap();
        let b = Reservation::new(second, hub.clone(), 7).unwrap();
        drop(a);
        drop(b);
        assert_eq!(first.used.load(Ordering::Acquire), 0);
        assert_eq!(hub.used.load(Ordering::Acquire), 0);
    }
}
