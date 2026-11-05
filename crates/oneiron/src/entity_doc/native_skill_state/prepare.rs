//! Preparing a native state witness in a fresh, transaction-owned document.

use loro::{CommitOptions, LoroDoc, VersionVector};

use super::super::{EntityDoc, storage};
use super::codec::SkillStateFact;
use super::register::{CURRENT, ROOT, read_fact};
use crate::EntityId;
use crate::batch::NativeSkillPostGate;
use crate::error::{Error, Result};

/// The scratch document and next witness have no exporter or persistence
/// terminal. Only the native publisher can consume their private fields.
pub(super) struct PreparedSkillState {
    pub(super) head: storage::Head,
    pub(super) document: EntityDoc,
    pub(super) before: VersionVector,
    pub(super) next: SkillStateFact,
}

/// Actual local stored source: load the original head and replay into a fresh
/// owned document, never a registry/shared cached handle. Incoming or restored
/// witnesses still need their real source admission before this path can run.
pub(super) fn prepare_in_txn(
    admitted: &NativeSkillPostGate<'_>,
    txn: &mut heed::RwTxn<'_>,
) -> Result<PreparedSkillState> {
    admitted.recheck_in_txn(txn)?;
    let store = &admitted.vault().store;
    let entity = admitted.entity();
    let head = storage::head(store, txn, &entity)?;
    let document = storage::load(store, txn, &head)?;
    let document_id = EntityId::from_hex(&head.document)?;
    let before = document.doc.oplog_vv();
    let previous = read_fact(&document)?;
    let next =
        SkillStateFact::from_post_gate(admitted, txn, document_id, &document, previous.as_ref())?;
    document
        .doc
        .set_peer_id(LoroDoc::new().peer_id())
        .map_err(|_| Error::CorruptedIndex("native SKILL state writing peer"))?;
    let actor_stamp = match admitted.actor() {
        Some(actor) => {
            super::super::forks::bind_actor(
                admitted.vault(),
                txn,
                &document,
                actor,
                admitted.recorded_at(),
            )?;
            Some(crate::provenance::actor_stamp_in_txn(
                admitted.vault(),
                txn,
                actor,
            )?)
        }
        None => None,
    };
    document
        .doc
        .get_map(ROOT)
        .insert(CURRENT, next.encode()?.as_slice())
        .map_err(|_| Error::CorruptedIndex("native SKILL state register write"))?;
    if let Some(stamp) = actor_stamp {
        super::super::document::stamp(&document.doc, stamp, admitted.recorded_at(), "skill_state")?;
    } else {
        // Native engine provenance is not a fabricated owner/System caller.
        let timestamp = i64::try_from(admitted.recorded_at())
            .map_err(|_| Error::InvariantViolation("native SKILL state timestamp overflow"))?;
        document.doc.commit_with(
            CommitOptions::new()
                .commit_msg("native_skill_state")
                .timestamp(timestamp),
        );
    }
    Ok(PreparedSkillState {
        head,
        document,
        before,
        next,
    })
}
