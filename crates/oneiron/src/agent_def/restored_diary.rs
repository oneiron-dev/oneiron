//! A restored agent's own diary (RESTORED-AGENT-KEEPS-IMPORTED-DIARY; the
//! lead's ruling IMPORTED-DIARY-RESUBMISSION-INTENT = B, 21 Nov 2026: "a
//! restore should bring things back as they were").
//!
//! A whole-vault import brings an agent's diary back as imported evidence:
//! each entry keeps its source author as
//! [`crate::note::NoteActor::Imported`] and gets no `AuthoredBy` edge, and
//! the agent's definition comes back disabled and proposed until the owner
//! reviews it. Once that restored definition stands (active, approved and
//! switched on: the owner's review, since only the owner widens a
//! definition), [`crate::note::diary_author_in`] reads each imported diary
//! entry whose source author is that agent as the agent's own, so its reads,
//! the diary gate and its link re-submission follow. The evidence is the
//! stored definition itself, judged at each read, whatever door enabled it:
//! an `AuthoredBy` edge proves nothing about an imported entry, since a
//! peer's sync update can land one (REVIEW-9994 round 1). No row is
//! rewritten, and disabling the agent again withholds the entries again.

use super::doors::stands;
use crate::Vault;
use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::note::NoteKind;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_NOTE};
use crate::store::EngineScan;
use crate::store::scan_count::ScanCount;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Whether `agent` is a restored agent the owner's review made stand: its
/// live stored definition came from an import and stands. A definition that
/// does not decode stands for no one.
///
/// # Errors
/// Storage faults.
pub(crate) fn restored_agent_stands_in(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    agent: &EntityId,
) -> Result<bool> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_AGENT_DEF,
        body,
    } = live_entity_row_in_txn(store, txn, agent)?
    else {
        return Ok(false);
    };
    Ok(
        crate::store::agent_definition_codec::decode_agent_definition(&body).is_ok_and(
            |definition| definition.source == ClaimSource::Imported && stands(&definition),
        ),
    )
}

/// The live imported diary entries whose source author is `agent`, in id
/// order: the entries a listing of a restored agent's diary adds to those
/// its `AuthoredBy` edges name. A NOTE that does not decode names no author
/// and is left out.
///
/// # Errors
/// Storage faults.
pub(crate) fn imported_diary_entries_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: &EntityId,
) -> Result<Vec<EntityId>> {
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
        if core.kind == NoteKind::Diary && core.author_ref.imported() == Some(*agent) {
            entries.push(note);
        }
    }
    count.finish(vault);
    Ok(entries)
}
