//! A restored agent's own diary (RESTORED-AGENT-KEEPS-IMPORTED-DIARY; the
//! lead's ruling IMPORTED-DIARY-RESUBMISSION-INTENT = B, 21 Nov 2026: "a
//! restore should bring things back as they were").
//!
//! A whole-vault import brings an agent's diary back as imported evidence:
//! each entry keeps its source author as
//! [`crate::note::NoteActor::Imported`] and gets no `AuthoredBy` edge, and
//! the agent's definition comes back disabled and proposed until the owner
//! reviews it. When a write first makes that
//! restored definition stand (active, approved and switched on: the owner's
//! review, since only the owner widens a definition), the same write adds
//! the `AuthoredBy` edge of each live imported diary entry whose source
//! author is that agent. The entry's stored row stays as it was born;
//! [`crate::note::diary_author_in`] reads an imported author with that edge
//! as the entry's author, so the agent's own reads, the diary gate and its
//! link re-submission follow.

use oneiron_contracts::affect::Vad;

use super::doors::stands;
use super::types::AgentDefinition;
use crate::Vault;
use crate::batch::BatchOp;
use crate::claim::ClaimSource;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::note::NoteKind;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_NOTE;
use crate::store::EngineScan;
use crate::store::scan_count::ScanCount;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The imported diary entries the write of `next`, agent `agent`'s
/// definition, names the agent the author of: none unless `next` is a
/// restored definition that stands while the stored one does not. Each is a
/// live diary NOTE whose source author is `agent` and which has no
/// `AuthoredBy` edge yet. A NOTE that does not decode names no author and
/// is left as it is.
///
/// # Errors
/// The stored definition's decode refusal; storage faults.
pub(super) fn restored_diary_entries_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: &EntityId,
    next: &AgentDefinition,
) -> Result<Vec<EntityId>> {
    if next.source != ClaimSource::Imported || !stands(next) {
        return Ok(Vec::new());
    }
    match vault.read_agent_definition_in_txn(txn, agent) {
        Ok(stored) if stands(&stored) => return Ok(Vec::new()),
        Ok(_) | Err(Error::EntityNotFound) => {}
        Err(error) => return Err(error),
    }
    let mut count = ScanCount::start(
        &vault.store,
        txn,
        EngineScan::TypeIndexRows,
        &[ENTITY_TYPE_NOTE],
    )?;
    let mut entries = Vec::new();
    for note in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_NOTE, None)?
    {
        count.row();
        let note = note?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_NOTE,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &note)?
        else {
            continue;
        };
        let Ok(core) = crate::note::decode_note_core_in_txn(&vault.store, txn, &body) else {
            continue;
        };
        if core.kind == NoteKind::Diary
            && core.author_ref.imported() == Some(*agent)
            && !vault.store.port_edge_present(
                txn,
                &note,
                EdgeDirection::Out,
                EdgeKind::AuthoredBy,
                agent,
            )?
        {
            entries.push(note);
        }
    }
    count.finish(vault);
    Ok(entries)
}

/// The edge that names `agent` the author of its imported diary entry
/// `note`, at the weight every diary write gives it.
pub(super) fn authored_by(note: &EntityId, agent: &EntityId) -> BatchOp {
    BatchOp::Edge {
        src: *note,
        kind: EdgeKind::AuthoredBy,
        tgt: *agent,
        weight: EdgeKind::AuthoredBy.default_weight().unwrap_or(1.0),
        vad: Vad::NEUTRAL,
    }
}
