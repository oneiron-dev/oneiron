//! The host adapters every window release and admission goes through (FIX
//! 7608 slice 4, part 3).
//!
//! A release reads this vault's copies once and hands the outgoing blob to
//! [`SyncSecretProjection::release_window_blob`]; it runs before pad
//! preparation, so a marked row is never sealed, referenced or carried raw
//! for a peer. An admission runs after the peer's pads are admitted and
//! before anything persists, imports, relays or acknowledges: a copy edit
//! lands on its source, and a ruled hold is kept as its held record, never
//! applied (FIX 10598). A vault with no marked repo item answers both as
//! today.

use std::borrow::Cow;

use loro::LoroDoc;

use super::SyncSecretProjection;
use super::frames::WindowAdmission;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// What a peer's window blob becomes on this device.
#[derive(Debug)]
pub enum RepoSyncAdmission<'a> {
    /// Persist, import and relay these bytes as today: the blob as it came,
    /// or its copy edits translated onto their sources.
    Admit(Cow<'a, [u8]>),
    /// An edit of a copy the visible diff holds on a ruled cause
    /// (`projection_edit_conflict` / `sealed_file_edited`): its held record
    /// is written (the owner's `sync_doctor` lists it), and nothing of the
    /// blob persists, imports or relays. A home acknowledges it so the device
    /// stops sending it (FIX 10598); no edit of it is ever applied.
    Held,
}

/// `payload`, a window blob leaving this device for a sync peer, as the peer
/// gets it; `context` holds an update's dependencies. `None` when it carries
/// no marked repo item: send it as it is.
///
/// # Errors
/// A store failure, or a blob carrying a marked item that cannot be masked:
/// the caller withholds it, and keeps it owed (nothing retires it).
pub fn prepare_repo_sync_frame(
    vault: &Vault,
    payload: &[u8],
    context: Option<&LoroDoc>,
) -> Result<Option<Vec<u8>>> {
    SyncSecretProjection::read(vault)?.release_window_blob(&vault.store, payload, context, false)
}

/// [`prepare_repo_sync_frame`] for a device's send to its home, `context`
/// its window: an update that goes as it is also carries each marked
/// snapshot ASSET's current copy re-authored under a fresh id, so a re-masked
/// copy reaches a home that already holds an older one (FIX 10729).
///
/// # Errors
/// As [`prepare_repo_sync_frame`].
pub fn prepare_repo_sync_frame_for_home(
    vault: &Vault,
    payload: &[u8],
    context: Option<&LoroDoc>,
) -> Result<Option<Vec<u8>>> {
    SyncSecretProjection::read(vault)?.release_window_blob(&vault.store, payload, context, true)
}

/// `payload`, a window blob of `window` a peer sent, as this window takes
/// it; `context` is this window. Call it after the blob's pads are admitted
/// and before it persists. A ruled hold's record is written before it
/// answers [`RepoSyncAdmission::Held`].
///
/// # Errors
/// A store failure (the hold's record included), or the visible diff's own
/// failure.
pub fn admit_repo_sync_frame<'a>(
    vault: &Vault,
    window: &str,
    payload: &'a [u8],
    context: Option<&LoroDoc>,
) -> Result<RepoSyncAdmission<'a>> {
    let projection = SyncSecretProjection::read(vault)?;
    Ok(
        match projection.admit_window_blob(&vault.store, payload, context)? {
            WindowAdmission::Admit(bytes) => RepoSyncAdmission::Admit(bytes),
            WindowAdmission::Held(held) => {
                for edit in &held {
                    tracing::warn!(
                        window,
                        source = %edit.source.to_hex(),
                        cause = ?edit.cause,
                        "sync: a copy edit is held on its ruled cause; its held record is kept"
                    );
                }
                super::held::record_held_edits(vault, window, &held)?;
                RepoSyncAdmission::Held
            }
        },
    )
}

/// The generation of the masked repo copies `doc`'s state carries; `None`
/// when it carries no marked repo item. A peer last sent another generation
/// gets the window's replacement, even at an equal version vector (C3).
///
/// # Errors
/// A store failure, or a mark that does not decode.
pub fn repo_copy_generation(vault: &Vault, doc: &LoroDoc) -> Result<Option<[u8; 32]>> {
    Ok(SyncSecretProjection::read(vault)?.window_generation(doc))
}

/// A self-contained window update (a detached selector document's) as a
/// peer gets it.
///
/// # Errors
/// As [`prepare_repo_sync_frame`].
pub(crate) fn released_update(vault: &Vault, update: Vec<u8>) -> Result<Vec<u8>> {
    Ok(prepare_repo_sync_frame(vault, &update, None)?.unwrap_or(update))
}

/// The row a residence read returns for `item`: `read` looks the row up
/// under its stored id (a copy id resolves to its source), and a marked
/// item's row is its copy.
///
/// # Errors
/// A store failure, or `read`'s own.
pub(crate) fn released_item_blob<F>(
    vault: &Vault,
    item: EntityId,
    read: F,
) -> Result<Option<Vec<u8>>>
where
    F: FnOnce(EntityId) -> Result<Option<Vec<u8>>>,
{
    let projection = SyncSecretProjection::read(vault)?;
    let source = projection.source_of_copy(&item).unwrap_or(item);
    Ok(read(source)?.map(|raw| {
        projection
            .project_row(&source, &raw)
            .released(source, raw)
            .1
    }))
}
