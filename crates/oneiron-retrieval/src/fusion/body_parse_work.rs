//! Door for `oneiron`'s `tests/blend_body_parsed_once.rs` (row
//! [RECALL-EXPANDED-ROW-FACTS-REREAD]): counts, on this thread and per entity
//! body, the blend's reads of a candidate's body for its salience and
//! confidence and the MessagePack parses of that body. A test can then hold
//! each read to one parse without timing anything. Compiled only under
//! `--cfg oneiron_test_support`.

use std::cell::RefCell;
use std::collections::BTreeMap;

thread_local! {
    /// The per-body counts while [`count_body_parse_work`] runs on this
    /// thread, and `None` otherwise: a count point outside a counted run
    /// records nothing.
    static BODIES: RefCell<Option<BTreeMap<Vec<u8>, BodyParseWork>>> =
        const { RefCell::new(None) };
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
    BODIES.with(|bodies| *bodies.borrow_mut() = Some(BTreeMap::new()));
    let value = run();
    let work = BODIES
        .with(|bodies| bodies.borrow_mut().take())
        .unwrap_or_default();
    (value, work)
}

/// The count point of a blend's read of `body` for its scalars.
pub fn record_scalar_read(body: &[u8]) {
    record(body, |work| {
        work.scalar_reads = work.scalar_reads.saturating_add(1);
    });
}

/// The count point of a MessagePack parse of `body`.
pub(super) fn record_body_parse(body: &[u8]) {
    record(body, |work| {
        work.parses = work.parses.saturating_add(1);
    });
}

/// Applies `count` to `body`'s entry while a counted run is armed.
fn record(body: &[u8], count: impl FnOnce(&mut BodyParseWork)) {
    BODIES.with(|bodies| {
        if let Some(bodies) = bodies.borrow_mut().as_mut() {
            count(bodies.entry(body.to_vec()).or_default());
        }
    });
}
