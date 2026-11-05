//! Preparing a native state witness in a fresh, transaction-owned document.

use loro::{CommitOptions, LoroDoc, VersionVector};

use super::super::{EntityDoc, storage};
use super::codec::SkillStateFact;
use super::register::{CURRENT, ROOT, read_fact};
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
}

/// Actual local stored source: load the original head and replay into a fresh
/// owned document, never a registry/shared cached handle. Incoming or restored
/// witnesses still need their real source admission before this path can run.
pub(super) fn prepare_in_txn(
    input: &NativeSkillFinalInput<'_>,
    txn: &mut heed::RwTxn<'_>,
) -> Result<PreparedSkillState> {
    input.recheck_in_txn(txn)?;
    let store = &input.vault().store;
    let entity = input.entity();
    let head = storage::head(store, txn, &entity)?;
    let document = storage::load(store, txn, &head)?;
    let document_id = EntityId::from_hex(&head.document)?;
    let before = document.doc.oplog_vv();
    let previous = read_fact(&document)?;
    let (next, actor_stamp) =
        SkillStateFact::from_final_input(input, txn, document_id, &document, previous.as_ref())?;
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
    crate::provenance::record_actor_stamp_uses_in_txn(store, txn, &entity, next.writer_token()?)?;
    Ok(PreparedSkillState {
        head,
        document,
        before,
        next,
    })
}
