//! The answer-schema switch (HOUSE-SCHEMA-SWITCH): the owner's setting
//! `dreamer.extraction.answer_schema`, the engine's hold while it is paused, and the
//! content-free events the morning report carries, one per suspension or re-arm.
//!
//! The nightly check (HOUSE-SCHEMA-CHECK) lives in the child modules: the capture of TURN
//! calls ([`capture`]), the over-budget latch ([`overrun`]), the draw ([`draw`]), the shadow
//! pairs ([`pair`]), the suspension rules ([`rule`]), the receipts ([`receipt`]), the run
//! ([`check`]), its house calls ([`send`]) and their spend ([`spend`]).

pub(crate) mod capture;
pub mod check;
pub(crate) mod draw;
pub(crate) mod overrun;
pub(crate) mod pair;
pub(crate) mod receipt;
pub(crate) mod rule;
pub(crate) mod send;
pub(crate) mod spend;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use super::executor::extraction::extraction_request_params;
use super::support::invalid_consolidation;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::setting::{Setter, SettingChange};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

#[doc(hidden)]
pub use oneiron_verb_wire::dreamer_consolidation::answer_schema::{
    ANSWER_SCHEMA_GROUP, ANSWER_SCHEMA_VIEW, DigestAnswerSchema, DigestAnswerSchemaItem,
};

const HOLD: SideTable<(), AnswerSchemaHold, Named> =
    SideTable::new(&side_table::DREAMER_ANSWER_SCHEMA_HOLD);
const EVENTS: SideTable<EntityId, AnswerSchemaEvent, Named> =
    SideTable::new(&side_table::DREAMER_ANSWER_SCHEMA_EVENT);

/// On: the Dreamer holds its claim extraction answer to the answer's JSON Schema. The default
/// of `dreamer.extraction.answer_schema`.
pub(super) const fn answer_schema_on() -> bool {
    true
}

/// Off: no schema, today's measured recipe. What an unreadable deciding row reads as.
pub(super) const fn answer_schema_off() -> bool {
    false
}

/// Why the engine paused the answer schema, as typed data (no free prose).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AnswerSchemaSuspension {
    /// Schema nights scored lower over the 7-night window.
    Window {
        d: f64,
        lower: f64,
        upper: f64,
        pairs: u32,
        nights: u32,
    },
    /// On `night` (YYYY-MM-DD), `faults` schema replies did not come back whole while their
    /// no-schema replies did.
    GrammarFaults { night: String, faults: u32 },
}

/// What an answer-schema event records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AnswerSchemaEventKind {
    Suspended(AnswerSchemaSuspension),
    Rearmed,
}

/// The engine's live hold on the answer schema: the suspension that caused it and the event
/// that records it. Absence = no hold.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnswerSchemaHold {
    pub(crate) event: EntityId,
    pub(crate) suspended_at: u64,
    pub(crate) suspension: AnswerSchemaSuspension,
}

/// One content-free answer-schema event, kept for the owner's history and the morning report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AnswerSchemaEvent {
    /// Time-ordered: the events table reads in the order they happened.
    pub(crate) id: EntityId,
    /// The vault's recorded clock.
    pub(crate) at: u64,
    pub(crate) kind: AnswerSchemaEventKind,
}

/// Whether the answer schema is in force: the setting reads `true` and no live engine hold.
/// Reads both in one read txn.
///
/// # Errors
///
/// An unreadable deciding row on a key that names no strictest value (this key names one);
/// storage errors.
pub(crate) fn answer_schema_in_force_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let enabled = super::setting_keys::ANSWER_SCHEMA
        .read_in_txn(vault, txn, &[], None)?
        .value;
    if !enabled {
        return Ok(false);
    }
    Ok(HOLD.get(&vault.store, txn, &())?.is_none())
}

/// Pauses the answer schema for `suspension`: one hold row plus one event row, in one write
/// txn. Returns the event id, which is the receipt id the report line carries. While a hold
/// is live writes nothing new and returns the live hold's id. Never writes the owner's
/// setting.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn suspend_answer_schema_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    suspension: AnswerSchemaSuspension,
    now: u64,
) -> Result<EntityId> {
    if let Some(hold) = HOLD.get(&vault.store, txn, &())? {
        return Ok(hold.event);
    }
    let id = vault.store.clock.entity_id()?;
    EVENTS.put(
        &vault.store,
        txn,
        &id,
        &AnswerSchemaEvent {
            id,
            at: now,
            kind: AnswerSchemaEventKind::Suspended(suspension.clone()),
        },
    )?;
    HOLD.put(
        &vault.store,
        txn,
        &(),
        &AnswerSchemaHold {
            event: id,
            suspended_at: now,
            suspension,
        },
    )?;
    Ok(id)
}

/// The params of `ConsolidationExecutor::request_over`: `extraction_request_params`, with the
/// answer schema when the caller read the switch in force. A NOTE review (`note_review`) never
/// carries it, and asking for it there is refused.
///
/// # Errors
///
/// A NOTE review that asks for the schema; the shipped schema file does not parse.
pub(super) fn request_over_params(
    note_review: bool,
    answer_schema: bool,
) -> Result<BTreeMap<String, JsonValue>> {
    if note_review && answer_schema {
        return Err(invalid_consolidation(
            "a NOTE review never carries the answer schema",
        ));
    }
    extraction_request_params(answer_schema)
}

/// [`request_over_params`] for `test_doors::dreamer_answer_schema`.
#[cfg(oneiron_test_support)]
pub(crate) fn request_over_params_for_test(
    note_review: bool,
    answer_schema: bool,
) -> Result<BTreeMap<String, JsonValue>> {
    request_over_params(note_review, answer_schema)
}

/// The hook of `dreamer.extraction.answer_schema`: the owner's own write re-arms. When the
/// change's setter is the literal [`Setter::Owner`] and a hold is live, deletes the hold and,
/// if the key now reads on (the new value is `true`, or the row was cleared and the key reads
/// its default, on), writes a `Rearmed` event (its id is the receipt id), so the morning
/// report says the schema is back. If the new value is `false`, deletes the hold and writes no
/// event (the owner turned it off). Any other setter changes nothing.
pub(super) fn rearm_answer_schema_on_change(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    if !matches!(change.setter, Setter::Owner) {
        return Ok(());
    }
    if HOLD.get(&vault.store, txn, &())?.is_none() {
        return Ok(());
    }
    HOLD.delete(&vault.store, txn, &())?;
    let re_armed = change
        .value
        .as_ref()
        .map_or(Some(answer_schema_on()), |value| value.decode::<bool>())
        == Some(true);
    if re_armed {
        let id = vault.store.clock.entity_id()?;
        EVENTS.put(
            &vault.store,
            txn,
            &id,
            &AnswerSchemaEvent {
                id,
                at: change.at,
                kind: AnswerSchemaEventKind::Rearmed,
            },
        )?;
    }
    Ok(())
}

/// The answer-schema events after `seen`, the newest event an earlier line carried, as one
/// line; `None` when there are none to report. An event row that does not decode is no event
/// of the line.
///
/// # Errors
///
/// Storage faults.
pub(crate) fn unseen_answer_schema_line_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    seen: Option<EntityId>,
) -> Result<Option<DigestAnswerSchema>> {
    let mut items = Vec::new();
    let mut through = None;
    for row in EVENTS.iter_raw_from(store, txn, &[])? {
        let (_, value) = row?;
        let Ok(event) = EVENTS.decode_value(&value) else {
            continue;
        };
        if seen.is_some_and(|seen| event.id <= seen) {
            continue;
        }
        let (kind, summary) = match &event.kind {
            AnswerSchemaEventKind::Suspended(AnswerSchemaSuspension::Window {
                d, pairs, ..
            }) => (
                "paused",
                format!(
                    "Answer schema paused: schema nights scored lower than without it over the \
                     last 7 nights (d={d:+.3}, n={pairs}). Turn it back on in Settings."
                ),
            ),
            AnswerSchemaEventKind::Suspended(AnswerSchemaSuspension::GrammarFaults {
                night,
                faults,
            }) => (
                "paused",
                format!(
                    "Answer schema paused: on {night}, {faults} schema replies did not come back \
                     whole while the same calls without it did. Turn it back on in Settings."
                ),
            ),
            AnswerSchemaEventKind::Rearmed => (
                "rearmed",
                "Answer schema turned back on by you in Settings.".to_owned(),
            ),
        };
        items.push(DigestAnswerSchemaItem {
            event: event.id.to_hex(),
            kind: kind.to_owned(),
            summary,
            at: event.at,
        });
        through = through.max(Some(event.id));
    }
    Ok(through.map(|through| DigestAnswerSchema {
        items,
        through,
        view: ANSWER_SCHEMA_VIEW.to_owned(),
    }))
}

/// The live hold's event id, if any, for `test_doors::dreamer_answer_schema`.
#[cfg(oneiron_test_support)]
pub(crate) fn hold_event_for_test(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<EntityId>> {
    Ok(HOLD.get(&vault.store, txn, &())?.map(|hold| hold.event))
}

/// Every decodable event as `(id, kind, at)`, oldest first, for
/// `test_doors::dreamer_answer_schema`. `kind` is `suspended_window`,
/// `suspended_grammar` or `rearmed`.
#[cfg(oneiron_test_support)]
pub(crate) fn events_for_test(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, String, u64)>> {
    let mut out = Vec::new();
    for row in EVENTS.iter_raw_from(&vault.store, txn, &[])? {
        let (_, value) = row?;
        let Ok(event) = EVENTS.decode_value(&value) else {
            continue;
        };
        let kind = match &event.kind {
            AnswerSchemaEventKind::Suspended(AnswerSchemaSuspension::Window { .. }) => {
                "suspended_window"
            }
            AnswerSchemaEventKind::Suspended(AnswerSchemaSuspension::GrammarFaults { .. }) => {
                "suspended_grammar"
            }
            AnswerSchemaEventKind::Rearmed => "rearmed",
        };
        out.push((event.id, kind.to_owned(), event.at));
    }
    out.sort_by_key(|(id, _, _)| *id);
    Ok(out)
}
