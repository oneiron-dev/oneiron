//! A store clock reads elapsed time in one clock domain for its whole life
//! (review round 1 of #9778, FIX-LIST AUTHORITY-CLOCK-NO-TEST-SEAM). Only the
//! difference between two readings of one store clock means anything, so a
//! source that starts or stops giving its own monotonic reading after the
//! store clock was made never moves the vault's elapsed time to another
//! origin: the authority log would persist that jump on its next write.
//! In the source's domain, the reading that chose it is the store clock's
//! first floor (review round 2 of #9778).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use oneiron_store::store_clock::{Clock, IdGen, StoreClock};

/// Far from any host's monotonic reading since the store clock was made.
const OWN_READING: Duration = Duration::from_secs(1_000_002);

/// A source whose own monotonic reading the test switches on or off and
/// sets.
struct SwitchedSource {
    offers_reading: AtomicBool,
    reading_secs: AtomicU64,
}

impl SwitchedSource {
    fn new(offers_reading: bool) -> Arc<Self> {
        Arc::new(Self {
            offers_reading: AtomicBool::new(offers_reading),
            reading_secs: AtomicU64::new(OWN_READING.as_secs()),
        })
    }

    fn offer_reading(&self, offers_reading: bool) {
        self.offers_reading.store(offers_reading, Ordering::SeqCst);
    }

    fn set_reading(&self, reading: Duration) {
        self.reading_secs.store(reading.as_secs(), Ordering::SeqCst);
    }
}

impl Clock for SwitchedSource {
    fn now_recorded_at(&self) -> u64 {
        1_800_000_000
    }

    fn monotonic_now(&self) -> Option<Duration> {
        self.offers_reading
            .load(Ordering::SeqCst)
            .then(|| Duration::from_secs(self.reading_secs.load(Ordering::SeqCst)))
    }
}

struct FixedIds;

impl IdGen for FixedIds {
    fn ulid(&self) -> [u8; 16] {
        [7; 16]
    }
}

fn store_clock(source: &Arc<SwitchedSource>) -> StoreClock {
    StoreClock::new(source.clone(), Arc::new(FixedIds))
}

#[test]
fn a_source_that_starts_offering_its_reading_moves_no_elapsed_time() {
    let source = SwitchedSource::new(false);
    let clock = store_clock(&source);
    let first = clock.monotonic_now();
    source.offer_reading(true);
    let second = clock.monotonic_now();
    assert!(
        second >= first && second - first < Duration::from_secs(60),
        "the store clock moved to the source's origin: first {first:?}, second {second:?}"
    );
}

#[test]
fn a_source_that_stops_offering_its_reading_moves_no_elapsed_time() {
    let source = SwitchedSource::new(true);
    let clock = store_clock(&source);
    let first = clock.monotonic_now();
    source.offer_reading(false);
    let second = clock.monotonic_now();
    assert!(
        second >= first && second - first < Duration::from_secs(60),
        "the store clock moved to the host's origin: first {first:?}, second {second:?}"
    );
}

#[test]
fn a_source_that_gives_no_reading_at_the_first_call_reads_the_first_floor() {
    let source = SwitchedSource::new(true);
    let clock = store_clock(&source);
    source.offer_reading(false);
    assert_eq!(
        clock.monotonic_now(),
        OWN_READING,
        "the store clock dropped the reading it was made with"
    );
    source.set_reading(OWN_READING + Duration::from_secs(1));
    source.offer_reading(true);
    assert_eq!(
        clock.monotonic_now(),
        OWN_READING + Duration::from_secs(1),
        "one second on the source is one second on the store clock"
    );
}

#[test]
fn a_source_set_back_before_the_first_call_holds_the_first_floor() {
    let source = SwitchedSource::new(true);
    let clock = store_clock(&source);
    source.set_reading(OWN_READING - Duration::from_secs(10));
    assert_eq!(
        clock.monotonic_now(),
        OWN_READING,
        "the store clock read below the reading it was made with"
    );
}
