//! FIX 2691 (OF-505 slice D): an office artifact's proposals on the window
//! plane.
//!
//! A DOCX or XLSX fork joins a proposal on its artifact, and a settlement
//! closes it (`office_body::consent`). Those rows never left the machine
//! that wrote them. Each proposal now rides the base window's
//! `office_proposals` map beside its artifact, as a MESSAGE's document rides
//! `message_docs`. Only the owner's machines take the map: a federated or
//! guest window copies none of it.
//!
//! - A proposal rides as its whole record under its artifact and its id.
//!   Its forks' memberships are rebuilt from its members where it lands,
//!   never carried.
//! - Reverse rematerialization mirrors each proposal of an artifact the
//!   window carries, and the live mirror does once a settlement queues the
//!   artifact. A copy is written only where the window holds none, or where
//!   this machine's holds all of the window's and more: no machine's copy
//!   overwrites another's.
//! - Forward rematerialization, Observer B and the live mirror merge each
//!   carried proposal into this vault's
//!   (`Vault::merge_carried_office_proposal_in_txn`): proposals union by id,
//!   a decided member beats a waiting one, and a settled proposal beats an
//!   open one. Two copies that diverge are quarantined, and both stand. The
//!   merge writes the rows only: no holder is asked, no fork lands or goes.
//! - A proposal whose artifact has not landed here waits in the window; the
//!   live mirror merges it as the artifact's row commits.
//! - Admission refuses every insert into the map that is not a whole
//!   proposal filed under its own key, in the latest state, at a snapshot's
//!   root and in every retained operation.
//! - Every export, and the erase sweep, drop each proposal of an artifact
//!   this vault removed or the window does not carry, and a copy naming an
//!   actor this vault erased takes this vault's form.

pub(super) mod checkpoint;

use std::collections::BTreeSet;

use loro::event::MapDelta;
use loro::{CommitOptions, LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use super::bridge::BRIDGE_ORIGIN;
use super::loro_support::{map_contains_binary, map_delete, map_get_bytes, map_insert_bytes};
use super::quarantine::{QuarantineContainer, quarantine_rejected_op_in_txn};
use super::types::WindowKey;
use crate::Vault;
use crate::entity_doc::DocumentMerge;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::office_body::OfficeBodyProposal;

/// The base window root map that carries office proposals.
pub(crate) const OFFICE_PROPOSALS_MAP: &str = "office_proposals";

/// The largest proposal a window carries: one carrier part (a call; canon is
/// silent). A larger one stays on its machine, logged.
const MAX_PROPOSAL_BYTES: usize = super::carrier_parts::PART_BYTES;

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("office proposal refused: {reason}"))
}

fn encode(record: &OfficeBodyProposal) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(record).map_err(|_| refused("does not encode"))
}

/// Decodes a carried proposal. A proposal has one spelling.
fn decode(bytes: &[u8]) -> Result<OfficeBodyProposal> {
    if bytes.len() > MAX_PROPOSAL_BYTES {
        return Err(refused("too large"));
    }
    let record: OfficeBodyProposal =
        rmp_serde::from_slice(bytes).map_err(|_| refused("not a proposal"))?;
    if encode(&record)? != bytes {
        return Err(refused("not in its one spelling"));
    }
    Ok(record)
}

/// The key `record` rides under: its artifact, then its own id.
fn carrier_key(record: &OfficeBodyProposal) -> String {
    format!(
        "{}/{}",
        record.header.artifact.to_hex(),
        record.header.proposal.to_hex()
    )
}

/// The artifact `map_key` names, when it is a proposal's key with both ids
/// in their one spelling.
fn artifact_of(map_key: &str) -> Option<EntityId> {
    let named = |hex: &str| EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex);
    let (artifact, proposal) = map_key.split_once('/')?;
    named(proposal)?;
    named(artifact)
}

/// Admits one insert into a window's `office_proposals` map: a whole
/// proposal of a base window filed under its own key.
pub(crate) fn admit_office_proposal_carrier(
    key: Option<&WindowKey>,
    map_key: &str,
    value: &LoroValue,
) -> Result<()> {
    if key.is_some_and(|key| key.world().is_some()) {
        return Err(refused("in a world window"));
    }
    let LoroValue::Binary(bytes) = value else {
        return Err(refused("not bytes"));
    };
    if carrier_key(&decode(bytes)?) != map_key {
        return Err(refused("filed under another key"));
    }
    Ok(())
}

/// [`admit_office_proposal_carrier`] over every row `map` holds.
pub(crate) fn admit_office_proposal_map(key: Option<&WindowKey>, map: &LoroMap) -> Result<()> {
    let mut rows = Vec::new();
    let mut nested = false;
    map.for_each(|map_key, value| match value {
        ValueOrContainer::Value(value) => rows.push((map_key.to_owned(), value)),
        ValueOrContainer::Container(_) => nested = true,
    });
    if nested {
        return Err(refused("nested container"));
    }
    for (map_key, value) in &rows {
        admit_office_proposal_carrier(key, map_key, value)?;
    }
    Ok(())
}

/// Writes into `doc`, window `window`'s document, each proposal on
/// `artifact` this vault holds that adds to the window's copy: one the
/// window lacks, or one that holds all of the window's copy and more. A
/// window copy that holds what this vault's lacks stands, merged here as it
/// lands. The window is pinned history-free before a copy naming an actor
/// this vault erased changes (FIX 4872). Returns whether it wrote; the
/// caller commits.
pub(crate) fn mirror_office_proposals(
    vault: &Vault,
    doc: &LoroDoc,
    window: &WindowKey,
    artifact: &EntityId,
) -> Result<bool> {
    let (writes, pin) = {
        let rtxn = vault.store.env.read_txn()?;
        let held = vault.office_proposals_in_txn(&rtxn, artifact)?;
        if held.is_empty() {
            return Ok(false);
        }
        let map = doc.get_map(OFFICE_PROPOSALS_MAP);
        let mut writes = Vec::new();
        let mut pin = false;
        for record in &held {
            let key = carrier_key(record);
            let bytes = encode(record)?;
            if bytes.len() > MAX_PROPOSAL_BYTES {
                tracing::warn!(
                    key = %key,
                    "office proposal past the carrier bound; it stays on this machine"
                );
                continue;
            }
            let carried = map_get_bytes(&map, &key);
            if carried.as_deref() == Some(bytes.as_slice()) {
                continue;
            }
            if let Some(carried) = carried.and_then(|carried| decode(&carried).ok()) {
                if !record.covers(&carried) {
                    continue;
                }
                pin |= carried.clone().carried_here(vault, &rtxn)?.as_ref() != Some(&carried);
            }
            writes.push((key, bytes));
        }
        (writes, pin)
    };
    if writes.is_empty() {
        return Ok(false);
    }
    if pin {
        super::window::require_history_free_window(vault, window)?;
    }
    let map = doc.get_map(OFFICE_PROPOSALS_MAP);
    for (key, bytes) in &writes {
        map_insert_bytes(&map, key, bytes)?;
    }
    Ok(true)
}

/// Merges every proposal window `key`'s document carries into this vault's,
/// as a window open does. A proposal that fails is logged and left; it never
/// stops the open.
pub(crate) fn apply_office_proposal_map(vault: &Vault, doc: &LoroDoc, key: &WindowKey) {
    if key.world().is_some() || !holds_office_proposal_map(doc) {
        return;
    }
    let rows = proposal_rows(&doc.get_map(OFFICE_PROPOSALS_MAP), |_| true);
    merge_rows(vault, key.as_str(), rows);
}

/// Observer B for the office proposal map: each proposal an import brought.
pub(crate) fn materialize_office_proposals_from_delta(
    _doc: &LoroDoc,
    delta: &MapDelta<'_>,
    vault: &Vault,
    window_key: &str,
    _lease_vault_id: u64,
) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    for (map_key, value) in &delta.updated {
        if let Some(ValueOrContainer::Value(LoroValue::Binary(bytes))) = value {
            rows.push((map_key.to_string(), bytes.to_vec()));
        }
    }
    merge_rows(vault, window_key, rows);
    Some(Vec::new())
}

/// Merges the proposals window `key`'s document carries for the artifacts
/// among `rows`, just committed here: a proposal that waited for its
/// artifact's row finds it.
pub(crate) fn merge_committed_office_proposals(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
    rows: &BTreeSet<EntityId>,
) {
    if key.world().is_some() || !holds_office_proposal_map(doc) {
        return;
    }
    let carried = proposal_rows(&doc.get_map(OFFICE_PROPOSALS_MAP), |map_key| {
        artifact_of(map_key).is_some_and(|artifact| rows.contains(&artifact))
    });
    merge_rows(vault, key.as_str(), carried);
}

/// Whether `doc` holds an office proposal map. Looking a root up by name
/// creates it: look first.
fn holds_office_proposal_map(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(OFFICE_PROPOSALS_MAP))
}

/// Each proposal `map` holds whose key `keep` takes, with its value.
fn proposal_rows(map: &LoroMap, keep: impl Fn(&str) -> bool) -> Vec<(String, Vec<u8>)> {
    let mut rows = Vec::new();
    map.for_each(|map_key, value| {
        if keep(map_key)
            && let ValueOrContainer::Value(LoroValue::Binary(bytes)) = value
        {
            rows.push((map_key.to_owned(), bytes.to_vec()));
        }
    });
    rows
}

/// Merges each carried proposal into this vault's, one write each, so a
/// refusal stays with its proposal. A copy that diverges from the one held
/// here is quarantined in the same write, and both copies stand.
fn merge_rows(vault: &Vault, window: &str, rows: Vec<(String, Vec<u8>)>) {
    let mut merged = 0_usize;
    for (map_key, bytes) in rows {
        let record = match decode(&bytes) {
            Ok(record) if carrier_key(&record) == map_key => record,
            _ => {
                tracing::warn!(window, key = %map_key, "office proposal malformed; left out");
                continue;
            }
        };
        let outcome = vault.with_write_txn_grouped(|txn| {
            let merge = vault.merge_carried_office_proposal_in_txn(txn, &record)?;
            if merge == DocumentMerge::Conflict {
                quarantine_rejected_op_in_txn(
                    vault,
                    txn,
                    window,
                    QuarantineContainer::OfficeProposals,
                    &map_key,
                    &refused("decisions diverge"),
                    &bytes,
                )?;
            }
            Ok(merge)
        });
        match outcome {
            Ok(DocumentMerge::Written) => merged += 1,
            Ok(DocumentMerge::Held) => {}
            Ok(DocumentMerge::Waiting) => {
                tracing::debug!(window, key = %map_key, "office proposal waits for its artifact");
            }
            Ok(DocumentMerge::Conflict) => tracing::warn!(
                window,
                key = %map_key,
                "office proposal diverges; quarantined, and the one held here stands"
            ),
            Ok(DocumentMerge::Refused(reason) | DocumentMerge::Deferred(reason)) => {
                tracing::debug!(window, key = %map_key, reason, "office proposal left out");
            }
            Err(error) => {
                tracing::warn!(window, key = %map_key, error = %error, "office proposal not merged");
            }
        }
    }
    if merged > 0 {
        tracing::debug!(window, merged, "office proposals merged");
    }
}

/// Drops from `doc` each proposal of an artifact this vault removed or the
/// window does not carry: erase wins over a proposal, and a proposal never
/// rides where its artifact does not. A copy naming an actor this vault
/// erased takes this vault's form, naming no one, or goes with the member it
/// held (FIX 3520). A live doc keeps the old copies in its history, so
/// `history_free` names the window pinned history-free before any row goes
/// or changes, as `room_facts::scrub_room_facts` does; the sweep, whose
/// shallow cut drops that history, passes `None`. Returns whether a row went
/// or changed, committed.
pub(crate) fn scrub_office_proposals(
    vault: &Vault,
    doc: &LoroDoc,
    history_free: Option<&WindowKey>,
) -> Result<bool> {
    if !holds_office_proposal_map(doc) {
        return Ok(false);
    }
    let map = doc.get_map(OFFICE_PROPOSALS_MAP);
    let entities = doc.get_map("entities");
    let mut changed = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        for (map_key, bytes) in proposal_rows(&map, |_| true) {
            let Ok(record) = decode(&bytes) else {
                continue;
            };
            let artifact = record.header.artifact;
            if !map_contains_binary(&entities, &artifact.to_hex())
                || crate::ports::removed_in_txn(&vault.store, &rtxn, &artifact)?
            {
                changed.push((map_key, None));
                continue;
            }
            match record.clone().carried_here(vault, &rtxn)? {
                Some(here) if here == record => {}
                Some(here) => changed.push((map_key, Some(encode(&here)?))),
                None => changed.push((map_key, None)),
            }
        }
    }
    if changed.is_empty() {
        return Ok(false);
    }
    if let Some(key) = history_free {
        super::window::require_history_free_window(vault, key)?;
    }
    for (map_key, bytes) in &changed {
        match bytes {
            Some(bytes) => map_insert_bytes(&map, map_key, bytes)?,
            None => map_delete(&map, map_key)?,
        }
    }
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    Ok(true)
}
