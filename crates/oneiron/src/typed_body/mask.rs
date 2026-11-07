//! A typed-body call that would write a new secret (FIX 2372; OF-067).
//!
//! A typed body's history is its receipt ledger: a call's operations stay
//! under the call's own fresh peer, and its receipt covers exactly them, so
//! no handle can replace what an operation wrote. When the body a call
//! leaves reads a secret the body did not hold before, the call is landed
//! again from the body as the call found it: the call's changes, read as one
//! diff, with each string they write admitted as the batch door admits a
//! text field (each secret its text rules place goes to custody and leaves
//! its handle), applied and committed under the same peer ([`land_masked`]).
//! The stored operations, the receipt and every snapshot then hold only the
//! handles. A secret no string's admission places (one split across what the
//! body held and what the call wrote) still refuses the call.

use heed::RwTxn;
use loro::event::{Diff, DiffBatch, ListDiffItem};
use loro::{CommitOptions, Frontiers, LoroDoc, LoroValue, TextDelta, ValueOrContainer};

use crate::Vault;
use crate::batch::secret_scan::{Lifted, Part, admit_parts_in_txn};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Where a typed body's masked strings were found, for their custody records.
const TYPED_BODY_PLACE: &str = "text:typed_body";

/// `call`'s changes from `before` to its state, each string they write
/// admitted (module docs). `None` when no string changed: the caller keeps
/// the door's refusal.
pub(super) fn masked_call_diff(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: EntityId,
    call: &LoroDoc,
    before: &Frontiers,
) -> Result<Option<DiffBatch>> {
    let diff = call
        .diff(before, &call.state_frontiers())
        .map_err(|_| super::invalid("typed body call diff"))?;
    // One plan for the call: a value it writes twice keeps one handle.
    let mut lifted = Lifted::default();
    let mut masked = DiffBatch::default();
    let mut changed = false;
    for (container, change) in diff.iter() {
        let mut change = change.clone();
        match &mut change {
            Diff::Text(delta) => {
                for item in delta.iter_mut() {
                    if let TextDelta::Insert { insert, .. } = item {
                        changed |= admit_text(vault, txn, entity, insert, &mut lifted)?;
                    }
                }
            }
            Diff::List(items) => {
                for item in items.iter_mut() {
                    if let ListDiffItem::Insert { insert, .. } = item {
                        for value in insert.iter_mut() {
                            if let ValueOrContainer::Value(value) = value {
                                changed |= admit_value(vault, txn, entity, value, &mut lifted)?;
                            }
                        }
                    }
                }
            }
            Diff::Map(map) => {
                for value in map.updated.values_mut() {
                    if let Some(ValueOrContainer::Value(value)) = value {
                        changed |= admit_value(vault, txn, entity, value, &mut lifted)?;
                    }
                }
            }
            // A tree's moves and a counter's steps write no string; a node's
            // fields are its own map's changes above.
            _ => {}
        }
        masked
            .push(container.clone(), change)
            .map_err(|_| Error::InvariantViolation("a typed body diff names a container twice"))?;
    }
    Ok(changed.then_some(masked))
}

/// The body as `call` found it at `before`, with `masked` applied and
/// committed under the call's own `peer`: its operations, its receipt and the
/// peer-keyed values the call wrote (a deck's log entries and allocation
/// keys) all name that one peer.
///
/// Applying a diff creates each container it adds afresh and maps the diff's
/// container to the new one, following the map on every later lookup. Under
/// the call's peer on a fork at `before`, the new containers would reuse the
/// counters of the call's dropped operations, so one could take the identity
/// of a container the diff still names: the map would then send a container
/// to itself (a lookup that never ends) or to another's replacement. So the
/// diff lands first under a scratch peer the call never used, and that
/// state's own diff then lands under the call's peer. At each step the
/// containers the diff names and the containers it makes belong to different
/// peers.
pub(super) fn land_masked(
    call: &LoroDoc,
    before: &Frontiers,
    peer: u64,
    masked: DiffBatch,
    options: CommitOptions,
) -> Result<LoroDoc> {
    let fork = || {
        call.fork_at(before)
            .map_err(|_| super::invalid("unknown typed body frontier"))
    };
    let scratch = fork()?;
    let scratch_peer = LoroDoc::new().peer_id();
    if scratch_peer == peer {
        return Err(super::invalid("typed body peer"));
    }
    scratch
        .set_peer_id(scratch_peer)
        .map_err(|_| super::invalid("typed body peer"))?;
    scratch
        .apply_diff(masked)
        .map_err(|_| super::invalid("typed body masked call"))?;
    scratch.commit();
    let diff = scratch
        .diff(before, &scratch.state_frontiers())
        .map_err(|_| super::invalid("typed body masked call"))?;
    let landed = fork()?;
    landed.set_record_timestamp(true);
    landed
        .set_peer_id(peer)
        .map_err(|_| super::invalid("typed body peer"))?;
    landed
        .apply_diff(diff)
        .map_err(|_| super::invalid("typed body masked call"))?;
    landed.commit_with(options);
    Ok(landed)
}

/// `text` admitted as the batch door admits a text field; whether it changed.
fn admit_text(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: EntityId,
    text: &mut String,
    lifted: &mut Lifted,
) -> Result<bool> {
    admit_parts_in_txn(
        vault,
        txn,
        entity,
        &mut [(TYPED_BODY_PLACE, Part::Text(text))],
        lifted,
    )
}

/// Each string `value` holds, at any depth, admitted as [`admit_text`]
/// admits one; whether one changed.
fn admit_value(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: EntityId,
    value: &mut LoroValue,
    lifted: &mut Lifted,
) -> Result<bool> {
    Ok(match value {
        LoroValue::String(text) => admit_text(vault, txn, entity, text.make_mut(), lifted)?,
        LoroValue::List(items) => {
            let mut changed = false;
            for item in items.make_mut() {
                changed |= admit_value(vault, txn, entity, item, lifted)?;
            }
            changed
        }
        LoroValue::Map(entries) => {
            let mut changed = false;
            for item in entries.make_mut().values_mut() {
                changed |= admit_value(vault, txn, entity, item, lifted)?;
            }
            changed
        }
        _ => false,
    })
}
