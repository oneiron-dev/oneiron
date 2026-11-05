//! Lenient raw TASK terminal and deadline checks used at storage admission.

use oneiron_base::error::{Error, RecordError, Result};
use rmpv::Value;
use std::io::Cursor;

/// Refuses a TASK body that is born already expired, at the PUBLIC raw doors.
///
/// `validate_task_create` settles this for everything that arrives through the
/// facade: a deadline already past is not a task with a TTL, it is a task
/// nothing will ever act on, and the board projects it `Expired` the instant
/// it exists. But `Vault::batch().put(..)` takes a body as BYTES and never
/// passes through that door, so the invariant held on one road to a TASK row
/// and not on the other.
///
/// The SYNC door deliberately does not run this — see the STO-03 note in the
/// TASK arm of `put_apply`. A peer's row has already been written on the peer;
/// refusing it here would leave the two vaults holding different histories,
/// and storage convergence outranks an invariant on a row that already exists.
/// Its board simply derives `Expired`, which is the truth about that row.
///
/// Read leniently on purpose. This door sees every TASK body of every role,
/// and most carry no `ttl` at all; a body it cannot read is not this check's
/// to reject (the same door's streak check already refuses unreadable bodies
/// outright). Only a `ttl` map carrying a readable `deadline_at` is judged.
pub fn reject_born_expired_task_deadline(data: &[u8], now: u64) -> Result<()> {
    match raw_task_deadline_at(data) {
        // Same predicate as the facade's, so the two doors cannot disagree
        // about which deadlines are in the future.
        Some(deadline_at) if deadline_at <= now => Err(Error::Record(
            RecordError::InvalidTaskBody("a task deadline must be in the future"),
        )),
        _ => Ok(()),
    }
}

/// Refuses a raw TASK body whose terminal record claims `countered` without
/// naming the counter, or names one without claiming it.
///
/// The decoder already holds this rule — a body that breaks it fails
/// `tasks.terminal.ladder` on the way OUT. That is the wrong end to hold it:
/// the row persists, and every later read of that task fails instead of the
/// write that made it wrong. Joining the invariant to the admission door is
/// the same move the streak and born-expired checks make, and for the same
/// reason: a body no reader can decode should never have been stored.
///
/// Read leniently, exactly like the sibling checks. This door sees every TASK
/// body of every role and most carry no terminal at all; only a readable
/// terminal map is judged, and an unreadable one is not this check's to
/// reject.
pub fn reject_incoherent_task_terminal(data: &[u8]) -> Result<()> {
    let Some((countered, names_counter)) = raw_task_terminal_counter_shape(data) else {
        return Ok(());
    };
    if countered != names_counter {
        // The same error family the decoder raises for this field, so the two
        // doors cannot disagree about what is wrong.
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "tasks.terminal.ladder",
        )));
    }
    Ok(())
}

/// `(ladder == countered, counter_task_ref present)` from a raw TASK body, or
/// `None` when the body carries no readable terminal record.
fn raw_task_terminal_counter_shape(data: &[u8]) -> Option<(bool, bool)> {
    let mut cursor = Cursor::new(data);
    let Value::Map(entries) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    // `state` holds the execution map, and the terminal record hangs off it —
    // `state.terminal`, not a body-level key.
    let state = task_body_optional(&entries, "state").ok()??.as_map()?;
    let terminal = task_body_optional(state, "terminal").ok()??.as_map()?;
    let countered = task_body_optional(terminal, "ladder")
        .ok()?
        .and_then(Value::as_str)
        .is_some_and(|token| token == "countered");
    let names_counter = task_body_optional(terminal, "counter_task_ref")
        .ok()?
        .is_some();
    Some((countered, names_counter))
}

/// `ttl.deadline_at` from a raw TASK body, or `None` when the body carries no
/// readable one.
fn raw_task_deadline_at(data: &[u8]) -> Option<u64> {
    let mut cursor = Cursor::new(data);
    let Value::Map(entries) = rmpv::decode::read_value(&mut cursor).ok()? else {
        return None;
    };
    let ttl = task_body_optional(&entries, "ttl").ok()??.as_map()?;
    task_body_field(ttl, "deadline_at").ok()?.as_u64()
}

pub fn task_body_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let value = values
        .next()
        .ok_or(Error::Record(RecordError::InvalidTaskBody(
            "tasks.create.body",
        )))?;
    if values.next().is_some() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "tasks.create.body",
        )));
    }
    Ok(value)
}

pub fn task_body_optional<'a>(
    entries: &'a [(Value, Value)],
    name: &str,
) -> Result<Option<&'a Value>> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "tasks.create.body",
        )));
    }
    Ok(match value {
        Value::Nil => None,
        value => Some(value),
    })
}
