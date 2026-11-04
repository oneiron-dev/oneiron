//! The source principal named in a project drafter's briefing (FIX 4979).
//! Entry: `principal_owned`, `principal_erased_in`, `erase_project_principal`.
//!
//! A project detection dispatches the house mind to draft a card with a
//! briefing by reference (`agent_dispatch/project_proposal.rs`): its JSON
//! names the source's principal. That principal is neither the dispatch's
//! target (the house agent) nor its asker, so an erase of either leaves
//! the briefing whole; the erased principal's own erase redacts just that
//! member, to [`ERASED_CALL_IDENTITY`], and every other reference and
//! input member stays, so each strict reader reads the erased row.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::agent_dispatch::{decode_agent_dispatch_input, record_dispatch_input};
use crate::attempt_queue::dispatch_payload::AGENT_DISPATCH_ATTEMPT_TYPE;
use crate::dreamer_runner::{decode_dreamer_attempt_payload, encode_dreamer_attempt_payload};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::store::Store;
use crate::store::dreamer_attempt_kind::DREAMER_RUNNER_ATTEMPT_KIND;

use super::super::types::AttemptRecord;
use super::{KEY_BRIEFING, KEY_CONTEXT_SPEC, unrewritable};

/// The briefing member that holds the project references, and its
/// principal member, as `dispatch_drafter` serializes them.
const KEY_PROJECT_PROPOSAL: &str = "project_proposal";
const KEY_PRINCIPAL: &str = "principal";

/// The principal a project briefing names, as its stored hex spelling.
/// `None` for a briefing that is not a project briefing.
fn briefing_principal(briefing: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(briefing)
        .ok()?
        .get(KEY_PROJECT_PROPOSAL)?
        .get(KEY_PRINCIPAL)?
        .as_str()
        .map(str::to_owned)
}

/// The principal `record`'s briefing names. `None` for a row that is no
/// agent dispatch, carries no project briefing, or names an erased
/// principal already.
fn record_principal(record: &AttemptRecord) -> Option<EntityId> {
    let input = record_dispatch_input(record)?;
    let briefing = input.context_spec.as_ref()?.briefing.as_deref()?;
    EntityId::from_hex(&briefing_principal(briefing)?).ok()
}

/// Whether `record`'s briefing names a principal among `actors`.
pub(super) fn principal_owned(record: &AttemptRecord, actors: &BTreeSet<EntityId>) -> bool {
    record_principal(record).is_some_and(|principal| actors.contains(&principal))
}

/// Whether a hard erase took the principal `record`'s briefing names,
/// read in `txn`. The late write's fence reads it; a marker that does not
/// read is logged without content and reads as none, so the fence never
/// fails its write.
pub(super) fn principal_erased_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &AttemptRecord,
) -> bool {
    record_principal(record).is_some_and(|principal| {
        store
            .port_deletion_marked(txn, DeletionMarker::HardDelete, &principal)
            .unwrap_or_else(|_| {
                tracing::warn!(
                    "attempt payload fence: a project principal's hard-delete marker could not be read"
                );
                false
            })
    })
}

/// Leaves `record`'s project briefing naming no principal: its principal
/// member becomes the erased marker, every other member of the briefing,
/// the context spec and the dispatch input staying. `false` when the row
/// carries no project principal, so an erased row is not written again.
/// `record` changes only on success.
pub(super) fn erase_project_principal(record: &mut AttemptRecord) -> Result<bool> {
    if record.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(false);
    }
    let mut payload = decode_dreamer_attempt_payload(&record.payload)?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(false);
    }
    let input = decode_agent_dispatch_input(&payload.input)?;
    let briefing = input
        .context_spec
        .as_ref()
        .and_then(|spec| spec.briefing.as_deref());
    if briefing.and_then(briefing_principal).is_none() {
        return Ok(false);
    }
    let Value::Map(entries) = &mut payload.input else {
        return Err(unrewritable());
    };
    for (key, value) in entries.iter_mut() {
        if key.as_str() == Some(KEY_CONTEXT_SPEC) {
            *value = Value::from(without_principal(value)?);
        }
    }
    // The strict decoder every reader uses reads the erased input, its
    // briefing naming the erased marker and no principal.
    let erased = decode_agent_dispatch_input(&payload.input)?;
    let principal = erased
        .context_spec
        .as_ref()
        .and_then(|spec| spec.briefing.as_deref())
        .and_then(briefing_principal);
    if principal.as_deref() != Some(ERASED_CALL_IDENTITY) {
        return Err(unrewritable());
    }
    record.payload = encode_dreamer_attempt_payload(&payload)?;
    Ok(true)
}

/// The serialized context spec in `value` with its briefing's principal
/// the erased marker; every other member keeps its place.
fn without_principal(value: &Value) -> Result<String> {
    let json = value.as_str().ok_or_else(unrewritable)?;
    let mut spec: serde_json::Value = serde_json::from_str(json).map_err(|_| unrewritable())?;
    let slot = spec.get_mut(KEY_BRIEFING).ok_or_else(unrewritable)?;
    let mut briefing: serde_json::Value =
        serde_json::from_str(slot.as_str().ok_or_else(unrewritable)?)
            .map_err(|_| unrewritable())?;
    let principal = briefing
        .get_mut(KEY_PROJECT_PROPOSAL)
        .and_then(|proposal| proposal.get_mut(KEY_PRINCIPAL))
        .ok_or_else(unrewritable)?;
    *principal = serde_json::Value::from(ERASED_CALL_IDENTITY);
    *slot = serde_json::Value::from(serde_json::to_string(&briefing).map_err(|_| unrewritable())?);
    serde_json::to_string(&spec).map_err(|_| unrewritable())
}
