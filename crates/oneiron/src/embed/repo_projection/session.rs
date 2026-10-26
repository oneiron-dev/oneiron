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

use std::collections::BTreeSet;

use heed::RwTxn;

use crate::Vault;
use crate::batch::BatchOp;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_ASSET;

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
