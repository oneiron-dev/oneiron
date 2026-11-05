//! Preparing a native state witness in a fresh, transaction-owned document.

use loro::{CommitOptions, LoroDoc, VersionVector};

use super::super::{EntityDoc, storage};
use super::admission::{LocalSkillStateAdmission, LocalSkillStateSource};
use super::codec::SkillStateFact;
use super::register::{CURRENT, ROOT};
use crate::EntityId;
use crate::batch::NativeSkillFinalInput;
use crate::error::{Error, Result};

/// The scratch document and next witness have no exporter or persistence
/// terminal. Only the native publisher can consume their private fields.
pub(super) struct PreparedSkillState {
    pub(super) head: storage::Head,
    pub(super) document: EntityDoc,
    pub(super) before: VersionVector,
    pub(super) next: SkillStateFact,
    admission: LocalSkillStateAdmission,
}

/// Actual local stored source: load the original head and replay into a fresh
/// owned document, never a registry/shared cached handle. Incoming or restored
/// witnesses still need their real source admission before this path can run.
pub(super) fn prepare_in_txn(
    input: &NativeSkillFinalInput<'_>,
    txn: &mut heed::RwTxn<'_>,
) -> Result<PreparedSkillState> {
    let (source, head, document) = LocalSkillStateSource::capture_in_txn(input, txn)?;
    let store = &input.vault().store;
    let entity = input.entity();
    let document_id = EntityId::from_hex(&head.document)?;
    let before = document.doc.oplog_vv();
    let (local, actor_stamp) =
        SkillStateFact::from_final_input(input, txn, document_id, &document, source.previous())?;
    let next = local.fact();
    document
        .doc
        .set_peer_id(LoroDoc::new().peer_id())
        .map_err(|_| Error::CorruptedIndex("native SKILL state writing peer"))?;
    if let Some(actor) = input.actor() {
        super::super::forks::bind_actor(input.vault(), txn, &document, actor, input.recorded_at())?;
    }
    document
        .doc
        .get_map(ROOT)
        .insert(CURRENT, next.encode()?.as_slice())
        .map_err(|_| Error::CorruptedIndex("native SKILL state register write"))?;
    if let Some(stamp) = actor_stamp {
        super::super::document::stamp(&document.doc, stamp, input.recorded_at(), "skill_state")?;
    } else {
        // Native engine provenance is not a fabricated owner/System caller.
        let timestamp = i64::try_from(input.recorded_at())
            .map_err(|_| Error::InvariantViolation("native SKILL state timestamp overflow"))?;
        document.doc.commit_with(
            CommitOptions::new()
                .commit_msg(super::ANONYMOUS_COMMIT)
                .timestamp(timestamp),
        );
    }
    // The Binary witness also retains this opaque token when its commit
    // message later falls below a shallow floor. Keep its ordinary hold use
    // in this writer, without resolving the token or asserting permission.
    let admission = source.admit_local(&document, &local)?;
    admission.recheck_in_txn(input.vault(), txn)?;
    crate::provenance::record_actor_stamp_uses_in_txn(store, txn, &entity, next.writer_token()?)?;
    Ok(PreparedSkillState {
        head,
        document,
        before,
        next: next.clone(),
        admission,
    })
}
