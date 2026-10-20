//! The rows a parked call's delivered reply was derived from (FIX 5455).
//!
//! A held `connector.call` parks its run on a durable wait; the settler's
//! reply lists the rows the call's passes picked beside it
//! ([`super::WaitDelivery::source_rows`]). When the run resumes from that
//! reply, the parked call's recorded outcome keeps them under a `rows` entry,
//! so every read of the run's served rows ([`super::agent_verb_rows_of`])
//! counts them and every rewrite of the record keeps them. A wait whose reply
//! listed none adds none, as before.
//!
//! A verb's answer an erase of its run's actor took (FIX 5718) keeps the
//! rows it was served from the same way, under its erased outcome's `rows`
//! entry (nil for an answer that kept no set), so the run's served rows
//! read as they did before the erase.

use rmpv::Value;

use super::storage::RESPONSE_ERASED;
use super::support::{decode_array, entity_id_value, entity_value};
use crate::entity_id::EntityId;

const KIND: &str = "kind";
const DURABLE_WAIT: &str = "durable_wait";
const FAILED: &str = "failed";
const ERROR: &str = "error";
const WAIT_ID: &str = "wait_id";
const ROWS: &str = "rows";

/// The entries of `outcome` when it records a durable wait.
fn wait_entries(outcome: &Value) -> Option<&[(Value, Value)]> {
    let Value::Map(entries) = outcome else {
        return None;
    };
    let kind = entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(KIND)).then_some(value))?;
    (kind.as_str() == Some(DURABLE_WAIT)).then_some(entries.as_slice())
}

fn entry<'a>(entries: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

/// Whether `outcome` records a park on `wait_id`.
pub(crate) fn parks_on(outcome: &Value, wait_id: EntityId) -> bool {
    wait_entries(outcome)
        .and_then(|entries| entry(entries, WAIT_ID))
        .and_then(|value| entity_value(value).ok())
        == Some(wait_id)
}

/// The rows the durable wait recorded in `outcome` kept from its delivered
/// reply; `None` for a wait that kept none, and for any other outcome.
pub(crate) fn wait_rows(outcome: &Value) -> Option<Vec<EntityId>> {
    let rows = entry(wait_entries(outcome)?, ROWS)?;
    decode_array(rows, entity_value).ok()
}

/// Keeps `rows` among the rows the durable wait recorded in `outcome` kept,
/// each once. Any other outcome is left as it is.
pub(crate) fn keep_wait_rows(outcome: &mut Value, rows: &[EntityId]) {
    let mut kept = wait_rows(outcome).unwrap_or_default();
    if wait_entries(outcome).is_none() {
        return;
    }
    kept.extend_from_slice(rows);
    kept.sort_unstable();
    kept.dedup();
    let value = Value::Array(kept.into_iter().map(entity_id_value).collect());
    let Value::Map(entries) = outcome else {
        return;
    };
    match entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(ROWS))
    {
        Some((_, held)) => *held = value,
        None => entries.push((Value::from(ROWS), value)),
    }
}

/// The served rows an answer an erase took kept (FIX 5718): `Some(Some(_))`
/// when the answer listed them, `Some(None)` when it kept no set (unknown,
/// so no caller off this device is released the run's answers), and `None`
/// for any other outcome.
pub(crate) fn erased_answer_rows(outcome: &Value) -> Option<Option<Vec<EntityId>>> {
    let Value::Map(entries) = outcome else {
        return None;
    };
    let erased = entry(entries, KIND)?.as_str() == Some(FAILED)
        && entry(entries, ERROR)?.as_str() == Some(RESPONSE_ERASED);
    if !erased {
        return None;
    }
    match entry(entries, ROWS)? {
        Value::Nil => Some(None),
        rows => Some(decode_array(rows, entity_value).ok()),
    }
}

/// Keeps `rows`, the rows an answer an erase took was served from (`None`
/// when it kept no set), on its erased outcome (FIX 5718).
pub(crate) fn keep_erased_answer_rows(outcome: &mut Value, rows: Option<&[EntityId]>) {
    let Value::Map(entries) = outcome else {
        return;
    };
    let rows = rows.map_or(Value::Nil, |rows| {
        Value::Array(rows.iter().copied().map(entity_id_value).collect())
    });
    entries.push((Value::from(ROWS), rows));
}
