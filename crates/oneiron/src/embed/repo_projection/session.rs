//! A mask change's room-staged media vectors (FIX 7608 S3F, FIX 10407).
//!
//! A room keeps its media vectors in RAM, as overlay rows and as
//! turn-owned `MediaVector` journal entries a promotion replays. When a
//! writer adds marks or spans to blobs, every live room (and retained
//! sealed stretch) drops its cached vectors of the records those blobs
//! reach: the base records and the texts derived from them, and every
//! record the room itself staged whose media bytes are one of those blobs.
//! The room's next media pass embeds their copy anew, through the copy
//! check it lands by. Room state stays in RAM: no room id, byte or pending
//! marker is written to base.
//!
//! A room's own text index takes a caption or transcript a model derived
//! from a marked blob (FIX 10405) as the sealed-file placeholder, never its
//! words ([`apply_ops_session_projected`]): its record, edges and turn stay
//! as written, and a promotion's batch makes its base copy pending.

use std::collections::BTreeSet;

use heed::RwTxn;

use crate::Vault;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::origin::secret_projection::index::{
    RepoIndexMarks, opaque_index_text, repo_derived_index_sources_in,
};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
use crate::session_overlay::{JournalEntry, SessionWriteRoute};
use crate::store::SessionStoreView;

/// Drops, in every live room, the cached media vectors of each record in
/// `affected` and of each room ASSET whose media bytes are, by their whole
/// BLAKE3, a blob in `sources`, in `wtxn`, the writer that changed the
/// marks. A room that cannot be read or is gone keeps its landing check.
///
/// # Errors
/// A storage error of `wtxn`.
pub(crate) fn refresh_repo_session_index_projection_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    sources: &BTreeSet<[u8; 32]>,
    affected: &BTreeSet<EntityId>,
) -> Result<()> {
    for overlay in vault.store.off_record_sessions.live_overlay_handles() {
        let mut ids = affected.clone();
        match overlay.snapshot() {
            Ok(snapshot) => {
                for entry in snapshot.journal_entries() {
                    if let BatchOp::Put {
                        id,
                        entity_type: ENTITY_TYPE_ASSET,
                        data,
                        ..
                    } = &entry.op
                        && super::repo_media_bytes(data)
                            .is_some_and(|bytes| sources.contains(blake3::hash(&bytes).as_bytes()))
                    {
                        ids.insert(*id);
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "a room's staged media copies stay to its landing check");
                continue;
            }
        }
        if ids.is_empty() {
            continue;
        }
        let keys =
            crate::embed::space::repo_projection::media_row_keys_in(&vault.store, wtxn, &ids)?;
        if let Err(error) = overlay.invalidate_repo_media_copies(&keys, &ids) {
            tracing::warn!(error = %error, "a room's staged media copies stay to its landing check");
        }
    }
    Ok(())
}

/// [`crate::batch::apply_ops_session`] of one room entry, a text index
/// entry of a derived text with a marked source (its record and edges as
/// `view` holds them, the room's own included) taking the placeholder in
/// every field. Every other entry applies as it is. Never a refusal: marks
/// that cannot be read leave such a text on the placeholder.
///
/// # Errors
/// As the session apply, or a storage error of `wtxn`.
pub(crate) fn apply_ops_session_projected(
    vault: &Vault,
    view: &SessionStoreView<'_>,
    route: &SessionWriteRoute,
    wtxn: &mut RwTxn<'_>,
    mut entry: JournalEntry,
) -> Result<()> {
    if let BatchOp::Text { id, fields } = &mut entry.op
        && view
            .port_entity_record(wtxn, id)?
            .is_some_and(|record| record.entity_type == ENTITY_TYPE_ASSET_TEXT)
        && derived_in_room(vault, view, wtxn, id)?
    {
        *fields = super::repo_derived_fields(std::mem::take(fields), opaque_index_text());
    }
    crate::batch::apply_ops_session(
        view,
        route,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![entry],
    )
}

/// Whether room text `id` has a marked source as `view` holds it; `true`
/// when the marks or a source's copy cannot be read.
fn derived_in_room(
    vault: &Vault,
    view: &SessionStoreView<'_>,
    wtxn: &RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let derived = match RepoIndexMarks::read_scoped_in_txn(vault, wtxn) {
        Ok(marks) => repo_derived_index_sources_in(vault, view, wtxn, &marks, id),
        Err(error) => Err(error),
    };
    match derived {
        Ok(sources) => Ok(sources.is_some()),
        Err(error) if super::is_storage_error(&error) => Err(error),
        Err(_) => Ok(true),
    }
}
