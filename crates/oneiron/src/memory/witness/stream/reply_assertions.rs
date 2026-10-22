//! A model stream's reply assertions at its terminal (OF-063, FIX 3416).
//!
//! The host hands a model stream's finalize the typed records its reply
//! cited or created, from its own evidence for that reply. A new MESSAGE's
//! terminal witnesses them with its text: the witness program reads each
//! through the writer's own lane, opened before the writer, and one the
//! writer cannot read refuses the whole reply. The set it admits is kept on
//! the generation's own receipt (FIX 10258, FIX 10260), and is copied, as a
//! convenience no reader takes for proof, into the MESSAGE's object
//! metadata under `reply_assertions` unless its caller put that key there
//! itself (FIX 10259): a caller's own value is never overwritten. A
//! continuation's terminal judges its set through the same check, its lane
//! opened before its writer; its MESSAGE's envelope was fixed at birth, so
//! only its receipt keeps the set. A Retry's reply never takes the set of
//! the reply it answers again.

use std::cell::Cell;

use serde_json::Value;

use super::super::program::unread_assertion_in;
use super::*;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::error::Error;
use crate::memory::{MemoryError, MemoryResult, WitnessAssertions, WitnessTurn};

/// The MESSAGE metadata key a reply's admitted assertions are copied under:
/// a noncanonical projection, the receipt being the record (FIX 10259).
const REPLY_ASSERTIONS_KEY: &str = "reply_assertions";

fn silent(assertions: &WitnessAssertions) -> bool {
    assertions.cited.is_empty() && assertions.created.is_empty()
}

/// The turn a new MESSAGE's terminal witnesses: its seed's, asserting the
/// seed's records and `assertions`, the terminal's, and copying the
/// terminal's into the MESSAGE's metadata when it is an object (or none)
/// that holds no such key of its caller's. The seed itself is never
/// changed, so a refused finalize leaves it as it was.
pub(super) fn terminal_turn(
    seed: &Seed,
    text: String,
    assertions: &WitnessAssertions,
) -> MessageStreamResult<WitnessTurn> {
    let mut turn = seed.turn(text);
    if silent(assertions) {
        return Ok(turn);
    }
    let WitnessAssertions { cited, created } = &mut turn.assertions;
    cited.extend(assertions.cited.iter().cloned());
    created.extend(assertions.created.iter().cloned());
    let kept = serde_json::to_value(assertions)
        .map_err(|_| Error::InvariantViolation("reply assertions did not encode"))?;
    // Metadata that is no object keeps no key; its records are judged all
    // the same.
    let fields = turn.messages.first_mut().and_then(|message| {
        message
            .metadata
            .get_or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
    });
    if let Some(fields) = fields {
        fields.entry(REPLY_ASSERTIONS_KEY).or_insert(kept);
    }
    Ok(turn)
}

/// A continuation's lane for the records its terminal asserts: the
/// writer's own read, opened before its writer as the witness program
/// opens one, since it takes its own snapshot. `None` when it asserts none.
pub(super) fn continuation_lane<'m>(
    memory: &'m Memory<'_>,
    assertions: &WitnessAssertions,
) -> MemoryResult<Option<ScopedRead<'m>>> {
    if silent(assertions) {
        return Ok(None);
    }
    memory.read_lane(ClaimReadStatus::Recorded).map(Some)
}

/// Judges a continuation's asserted records in its writer's snapshot,
/// before anything stages: the first `lane` cannot read refuses the
/// terminal, its pointer left in `refused` (OF-063).
pub(super) fn judge_in_txn(
    lane: Option<&ScopedRead<'_>>,
    txn: &heed::RoTxn<'_>,
    assertions: &WitnessAssertions,
    refused: &Cell<Option<String>>,
) -> MessageStreamResult<()> {
    if let Some(lane) = lane
        && let Some(pointer) = unread_assertion_in(lane, txn, assertions)?
    {
        refused.set(Some(pointer));
        let refusal = "a record the reply asserts does not resolve for this writer";
        return Err(MemoryError::bad_request(refusal).into());
    }
    Ok(())
}

/// A terminal writer's result once it has closed: a refused assertion is
/// receipted on its own write, as the witness program receipts one, and
/// answers for the terminal.
pub(super) fn settle(
    memory: &Memory<'_>,
    refused: &Cell<Option<String>>,
    written: MessageStreamResult<()>,
) -> MessageStreamResult<()> {
    match refused.take() {
        Some(pointer) => Err(memory.settle_refused_assertion(&pointer).into()),
        None => written,
    }
}

/// Drops the set a Retry's reply copied from the reply it answers again:
/// the new reply asserts only its own records. Metadata the key alone
/// filled goes with it.
pub(super) fn drop_copied(metadata: &mut Option<Value>) {
    let Some(fields) = metadata.as_mut().and_then(Value::as_object_mut) else {
        return;
    };
    if fields.remove(REPLY_ASSERTIONS_KEY).is_some() && fields.is_empty() {
        *metadata = None;
    }
}
