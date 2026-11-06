//! The store clock's reads, observed through what a caller gets back.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use super::{Clock, IdGen, StoreClock};

/// A source that, while it is read, notes whether another caller could take
/// the store clock's floor at that moment.
struct Probe {
    floor: OnceLock<Arc<Mutex<u64>>>,
    floor_free_during_read: AtomicBool,
}

impl Clock for Probe {
    fn now_recorded_at(&self) -> u64 {
        if let Some(floor) = self.floor.get() {
            self.floor_free_during_read
                .store(floor.try_lock().is_ok(), Ordering::SeqCst);
        }
        30
    }
}

impl IdGen for Probe {
    fn ulid(&self) -> [u8; 16] {
        [0x71; 16]
    }
}

/// A peek reads the floor and the source under one lock, so no other caller
/// observes the clock between the two reads, and it observes nothing itself:
/// the floor is where it was.
#[test]
fn a_peek_reads_the_floor_and_the_source_under_one_lock() {
    let probe = Arc::new(Probe {
        floor: OnceLock::new(),
        floor_free_during_read: AtomicBool::new(true),
    });
    let clock = StoreClock::new(probe.clone(), probe.clone());
    probe
        .floor
        .set(Arc::clone(&clock.floor))
        .expect("the probe sees one floor");
    assert_eq!(clock.peek_recorded_at(), 30);
    assert!(
        !probe.floor_free_during_read.load(Ordering::SeqCst),
        "another caller could observe the clock in the middle of a peek"
    );
    assert_eq!(*clock.floor.lock().expect("floor"), 0);
}
