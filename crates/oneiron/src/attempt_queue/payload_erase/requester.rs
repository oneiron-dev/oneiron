//! A hard-erased requester's standing, out of the agent dispatch payloads
//! that keep it (FIX 11689).
//!
//! A dispatch a credential caller's request queued keeps its requester: the
//! caller and the instrument the request stood on (FIX 11592), the slip with
//! its holder's proof among them. A hard erase of that requester leaves an
//! erased marker in place of the standing, in every state and retry
//! generation, by one deterministic rewrite, as a turn action's requester
//! erase leaves its slip out (FIX 10668). The marker is kept rather than the
//! key dropped, so the work reads as withdrawn by its typed reason
//! (`requester_withdrawn:requester_erased`) and never as work no request
//! queued; every other input member and every row field stay.

use std::collections::BTreeSet;

use rmpv::Value;

use crate::agent_dispatch::{
    AGENT_DISPATCH_INPUT_KEYS, RequesterStanding, decode_agent_dispatch_input,
    record_dispatch_input,
};
use crate::dreamer_runner::{decode_dreamer_attempt_payload, encode_dreamer_attempt_payload};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;

use super::super::types::AttemptRecord;
use super::unrewritable;

/// The input member that holds a dispatch's requester.
const KEY_REQUESTER: &str = AGENT_DISPATCH_INPUT_KEYS[23];

/// Leaves `record`'s requester as the erased marker when that requester is
/// among `actors`. `false` when the row is no agent dispatch, keeps no
/// requester, keeps another's, or already keeps the marker, so an erased row
/// is not written again. `record` changes only on success.
pub(super) fn erase_dispatch_requester(
    record: &mut AttemptRecord,
    actors: &BTreeSet<EntityId>,
) -> Result<bool> {
    erase_requester_if(record, |actor| actors.contains(actor))
}

/// The late write's fence for a dispatch whose requester bears the permanent
/// hard-delete marker: its standing leaves before it is encoded, as the pass
/// leaves it, so a copy read before the erase writes back no slip. A marker
/// that cannot be read, or a payload that cannot be rewritten, leaves
/// `record` as it was and is logged without its content: the fence never
/// fails the write it stands in.
pub(super) fn scrub_erased_requester_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    record: &mut AttemptRecord,
) {
    let Some(requester) = record_dispatch_input(record).and_then(|input| input.requester) else {
        return;
    };
    if requester.standing == RequesterStanding::Erased {
        return;
    }
    let id = record.id;
    let attempt = || crate::entity_id::bytes_to_hex_lower(id.as_bytes());
    match store.port_deletion_marked(txn, DeletionMarker::HardDelete, &requester.actor) {
        Ok(false) => {}
        Ok(true) => {
            if erase_requester_if(record, |_| true).is_err() {
                tracing::warn!(
                    attempt = %attempt(),
                    "attempt payload fence: an erased requester's standing could not be removed"
                );
            }
        }
        Err(_) => tracing::warn!(
            attempt = %attempt(),
            "attempt payload fence: the requester's hard-delete marker could not be read"
        ),
    }
}

/// [`erase_dispatch_requester`] for a requester `erased` names.
fn erase_requester_if(
    record: &mut AttemptRecord,
    erased: impl Fn(&EntityId) -> bool,
) -> Result<bool> {
    let Some(mut requester) = record_dispatch_input(record).and_then(|input| input.requester)
    else {
        return Ok(false);
    };
    let actor = requester.actor;
    if !erased(&actor) || !requester.erase_standing_of(&actor) {
        return Ok(false);
    }
    let mut payload = decode_dreamer_attempt_payload(&record.payload)?;
    let marker = serde_json::to_string(&requester).map_err(|_| unrewritable())?;
    let Value::Map(entries) = &mut payload.input else {
        return Err(unrewritable());
    };
    let slot = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(KEY_REQUESTER))
        .ok_or_else(unrewritable)?;
    slot.1 = Value::from(marker);
    // The strict decoder every reader uses reads the marker.
    let reread = decode_agent_dispatch_input(&payload.input)?;
    if reread.requester.map(|requester| requester.standing) != Some(RequesterStanding::Erased) {
        return Err(unrewritable());
    }
    record.payload = encode_dreamer_attempt_payload(&payload)?;
    Ok(true)
}
