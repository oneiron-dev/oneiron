//! Door for `tests/dreamer_answer_schema_switch.rs` (HOUSE-SCHEMA-SWITCH): the
//! answer-schema switch in force, the owner's setting alone, suspensions, the live hold,
//! the events, and the params a TURN extraction request carries while in force and those
//! a NOTE review request carries (never the schema).

use std::collections::BTreeMap;

use crate::Vault;
use crate::dreamer_consolidation::answer_schema::{
    AnswerSchemaSuspension, answer_schema_in_force_in_txn, events_for_test, hold_event_for_test,
    request_over_params_for_test, suspend_answer_schema_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// One answer-schema event as `(id, kind, at)`: `kind` is `suspended_window`,
/// `suspended_grammar` or `rearmed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerSchemaEventView {
    pub id: EntityId,
    pub kind: String,
    pub at: u64,
}

/// Whether the answer schema is in force on `vault`: the setting reads `true` and no live
/// engine hold.
///
/// # Errors
///
/// Storage faults.
pub fn in_force(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    answer_schema_in_force_in_txn(vault, &txn)
}

/// The owner's setting alone on `vault`, without the hold: `true` unless the owner turned
/// it off or an unreadable deciding row fell back to `false`.
///
/// # Errors
///
/// Storage faults.
pub fn setting(vault: &Vault) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::dreamer_consolidation::setting_keys::ANSWER_SCHEMA
        .read_in_txn(vault, &txn, &[], None)?
        .value)
}

/// Pauses the answer schema for a 7-night window suspension. Returns the event id, the
/// receipt id the report line carries; while a hold is live returns the live hold's id.
///
/// # Errors
///
/// Storage faults.
pub fn suspend_window(
    vault: &Vault,
    d: f64,
    lower: f64,
    upper: f64,
    pairs: u32,
    nights: u32,
    now: u64,
) -> Result<EntityId> {
    let suspension = AnswerSchemaSuspension::Window {
        d,
        lower,
        upper,
        pairs,
        nights,
    };
    vault.with_write_txn_grouped(|txn| suspend_answer_schema_in_txn(vault, txn, suspension, now))
}

/// Pauses the answer schema for a grammar-faults suspension on `night` (YYYY-MM-DD).
/// Returns the event id, or the live hold's id while a hold is live.
///
/// # Errors
///
/// Storage faults.
pub fn suspend_grammar_faults(
    vault: &Vault,
    night: &str,
    faults: u32,
    now: u64,
) -> Result<EntityId> {
    let suspension = AnswerSchemaSuspension::GrammarFaults {
        night: night.to_owned(),
        faults,
    };
    vault.with_write_txn_grouped(|txn| suspend_answer_schema_in_txn(vault, txn, suspension, now))
}

/// The live hold's event id, if any.
///
/// # Errors
///
/// Storage faults.
pub fn hold(vault: &Vault) -> Result<Option<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    hold_event_for_test(vault, &txn)
}

/// Every decodable event, oldest first.
///
/// # Errors
///
/// Storage faults.
pub fn events(vault: &Vault) -> Result<Vec<AnswerSchemaEventView>> {
    let txn = vault.store.env.read_txn()?;
    Ok(events_for_test(vault, &txn)?
        .into_iter()
        .map(|(id, kind, at)| AnswerSchemaEventView { id, kind, at })
        .collect())
}

/// The params a TURN extraction request carries on `vault`: with the answer schema while
/// the switch is in force, without it otherwise. Reads in-force in a short read txn, as
/// the callers do, then builds them as `request_over` does for a TURN call.
///
/// # Errors
///
/// Storage faults; the shipped schema file does not parse.
pub fn turn_params(vault: &Vault) -> Result<BTreeMap<String, serde_json::Value>> {
    let in_force = {
        let txn = vault.store.env.read_txn()?;
        answer_schema_in_force_in_txn(vault, &txn)?
    };
    request_over_params_for_test(false, in_force)
}

/// The params a NOTE review request carries, built as `request_over` builds them for a NOTE
/// review whose caller passed `answer_schema`: never the schema.
///
/// # Errors
///
/// `answer_schema` asked for on a NOTE review: refused.
pub fn note_params(answer_schema: bool) -> Result<BTreeMap<String, serde_json::Value>> {
    request_over_params_for_test(true, answer_schema)
}
