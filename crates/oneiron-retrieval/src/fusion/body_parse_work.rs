//! Door for `oneiron`'s `tests/blend_body_parsed_once.rs` (row
//! [RECALL-EXPANDED-ROW-FACTS-REREAD]): counts, on this thread and per entity
//! body, the blend's reads of a candidate's body for its salience and
//! confidence and the MessagePack parses of that body. A test can then hold
//! each read to one parse without timing anything. Compiled only under
//! `--cfg oneiron_test_support`.

use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    static BODIES: RefCell<BTreeMap<Vec<u8>, BodyParseWork>> =
        const { RefCell::new(BTreeMap::new()) };
}

/// The work one run did on one entity body on this thread.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BodyParseWork {
    /// Reads of the body for its blend scalars (salience and confidence).
    pub scalar_reads: usize,
    /// MessagePack parses of the body.
    pub parses: usize,
}

/// Runs `run` and returns its value with the work it did on each entity body
/// on this thread, keyed by the body's bytes.
pub fn count_body_parse_work<T>(run: impl FnOnce() -> T) -> (T, BTreeMap<Vec<u8>, BodyParseWork>) {
    BODIES.with(|bodies| bodies.borrow_mut().clear());
    let value = run();
    let work = BODIES.with(RefCell::take);
    (value, work)
}

/// The count point of a blend's read of `body` for its scalars.
pub fn record_scalar_read(body: &[u8]) {
    BODIES.with(|bodies| {
        let mut bodies = bodies.borrow_mut();
        let work = bodies.entry(body.to_vec()).or_default();
        work.scalar_reads = work.scalar_reads.saturating_add(1);
    });
}

/// The count point of a MessagePack parse of `body`.
pub(super) fn record_body_parse(body: &[u8]) {
    BODIES.with(|bodies| {
        let mut bodies = bodies.borrow_mut();
        let work = bodies.entry(body.to_vec()).or_default();
        work.parses = work.parses.saturating_add(1);
    });
}
