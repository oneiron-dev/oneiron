//! Owner review and keep-held resolution for a repo-manifest conflict.
//!
//! The review reads durable window state. Discarding requires that window
//! closed and revalidates its version, both manifests and the owner in the
//! same transaction that persists the deletion. Other heads and unrelated
//! parts stay untouched. The returned update is not queued automatically.

use super::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_from, import_doc,
};
use super::types::WindowKey;
use super::{
    persist_window_doc_in_txn, prune_subsumed_window_updates_in_txn, write_window_svf_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result, SyncError};
use crate::origin::{RepoManifest, RepoPortableId};
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::sync::repo_manifests::conflicts::{
    carried_manifest_for_portable, delete_carrier_for_portable,
};
use crate::sync::window_rows::WINDOW_UPDATE;
use loro::{LoroDoc, VersionVector};

/// One exact reviewed portable manifest conflict in one window's durable
/// state: the window, the portable id, the exact raw held manifest, the
/// bound joined carried manifest it conflicts with and the whole version
/// vector the durable document had when reviewed. The vector compares
/// semantically, never as raw encoded bytes. A review names durable state
/// only, never the current contents of a live window.
#[derive(Debug, Clone)]
pub struct RepoManifestConflictReview {
    window: WindowKey,
    portable: RepoPortableId,
    held: RepoManifest,
    carried: RepoManifest,
    version: VersionVector,
}

impl RepoManifestConflictReview {
    /// The reviewed window.
    #[must_use]
    pub fn window(&self) -> &WindowKey {
        &self.window
    }

    /// The reviewed portable id.
    #[must_use]
    pub fn portable(&self) -> &RepoPortableId {
        &self.portable
    }

    /// The exact raw held manifest the review kept.
    #[must_use]
    pub fn held(&self) -> &RepoManifest {
        &self.held
    }

    /// The bound joined carried manifest the review found it conflicts with.
    #[must_use]
    pub fn carried(&self) -> &RepoManifest {
        &self.carried
    }

    /// Encodes the exact reviewed state for a caller to return unchanged.
    /// The binding describes a revision; it grants no authority.
    pub fn encode_binding(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec(&(
            self.window.as_str(),
            self.portable,
            self.held.encode()?,
            self.carried.encode()?,
            self.version.encode(),
        ))
        .map_err(|_| invalid_review_binding())
    }

    /// Decodes a complete current binding without resolving newer state.
    /// The discard door still checks its owner and all reviewed facts.
    pub fn decode_binding(bytes: &[u8]) -> Result<Self> {
        let binding: (String, RepoPortableId, Vec<u8>, Vec<u8>, Vec<u8>) =
            rmp_serde::from_slice(bytes).map_err(|_| invalid_review_binding())?;
        if rmp_serde::to_vec(&binding).map_err(|_| invalid_review_binding())? != bytes {
            return Err(invalid_review_binding());
        }
        let (window, portable, held, carried, version) = binding;
        Ok(Self {
            window: WindowKey::try_new(window).ok_or_else(invalid_review_binding)?,
            portable,
            held: RepoManifest::decode(&held).ok_or_else(invalid_review_binding)?,
            carried: RepoManifest::decode(&carried).ok_or_else(invalid_review_binding)?,
            version: VersionVector::decode(&version).map_err(|source| {
                Error::Sync(SyncError::CrdtDecodeError {
                    context: "decode repo manifest review version vector",
                    source,
                })
            })?,
        })
    }
}

fn invalid_review_binding() -> Error {
    Error::InvalidConfig("invalid repo manifest conflict review binding".to_owned())
}

/// What discarding one reviewed carrier did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepoManifestConflictDiscard {
    /// The carried head plus its unshared parts went in one grouped write.
    /// `update` is the raw ordinary window delta since the reviewed vector,
    /// returned only after the commit. The caller owns it and routes it
    /// through an existing admitted sync channel such as the durable
    /// [`crate::sync::SyncQueue`]; nothing here queues or delivers it, and
    /// it claims no global resolution or physical history erasure.
    Discarded {
        /// The raw window update bytes since the reviewed version.
        update: Vec<u8>,
    },
    /// The durable state moved since the review: another vector, another
    /// held or carried copy, another binding or another CODE liveness.
    /// Nothing was written. Read the conflict again.
    Stale,
    /// The window is live here: registered, retained by an orphaned handle
    /// or fenced by another closer. Nothing was written and nothing was
    /// unloaded. Retry after the window unloads through the existing
    /// lifecycle, such as [`crate::sync::WindowManager::unload_window`].
    WindowLive,
}

/// Reviews the portable manifest conflict under `portable` in window `key`'s
/// durable state: its snapshot plus every pending update, a window with only
/// pending updates included, read with the raw held manifest and both CODE
/// anchors live in the same read transaction. No live window is opened,
/// created or registered, and no whole vault scan runs.
///
/// Returns `Some` only for a present, canonical, joined and
/// map-key, head and manifest bound actual conflict, where the held and
/// carried CODE entities or their `minted_at` differ. Returns `None` for a
/// missing, pending, unbound or non-conflicting row. Store faults propagate.
/// The review names durable state only, never the current contents of a live
/// window, and it adopts no identity and delivers nothing.
///
/// # Errors
///
/// A store, CRDT decode or held-read fault.
pub fn review_repo_manifest_conflict(
    vault: &Vault,
    key: &WindowKey,
    portable: &RepoPortableId,
) -> Result<Option<RepoManifestConflictReview>> {
    let rtxn = vault.store.env.read_txn()?;
    let address = WindowAddress::new(key.as_str());
    let snapshot = vault
        .store
        .port_window_doc_with_raw(&rtxn, address, |raw| Ok(raw.to_vec()))?;
    let updates = vault
        .store
        .port_window_updates(&rtxn, address, |row, bytes| (row, bytes.to_vec()))?
        .collect::<Result<Vec<_>>>()?;
    if snapshot.is_none() && updates.is_empty() {
        return Ok(None);
    }
    let doc = match &snapshot {
        Some(bytes) => doc_from_snapshot(bytes)?,
        None => LoroDoc::new(),
    };
    for (_, bytes) in &updates {
        import_doc(&doc, bytes)?;
    }
    let Some(carried) = carried_manifest_for_portable(&doc, portable) else {
        return Ok(None);
    };
    let Some(held) = vault.repo_manifest_conflict_held_in_txn(&rtxn, portable, &carried)? else {
        return Ok(None);
    };
    Ok(Some(RepoManifestConflictReview {
        window: key.clone(),
        portable: *portable,
        held,
        carried,
        version: doc.oplog_vv(),
    }))
}

/// Discards one reviewed carrier, keeping the raw held manifest unchanged.
///
/// The existing closed-window fence excludes registered or retained live
/// documents. A grouped writer checks the owner, version and both manifests
/// before deleting the head and its unshared parts on a detached document.
/// The snapshot, imported-update prune and final freshness flag commit
/// together. An error changes neither durable nor live window state.
///
/// The caller routes the returned ordinary window delta through an admitted
/// sync channel. This action does not adopt a different identity, change
/// another window or erase prior bytes from CRDT history.
///
/// # Errors
/// A store or CRDT fault, or an owner proof that no longer holds.
pub fn discard_reviewed_repo_manifest_carrier_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    review: &RepoManifestConflictReview,
) -> Result<RepoManifestConflictDiscard> {
    let fenced = vault.while_window_closed(review.window(), || {
        vault.with_write_txn_grouped(|wtxn| {
            owner.revalidate_in_txn(vault, &*wtxn)?;
            let address = WindowAddress::new(review.window().as_str());
            let snapshot = vault
                .store
                .port_window_doc_with_raw(wtxn, address, |raw| Ok(raw.to_vec()))?;
            let updates = vault
                .store
                .port_window_updates(wtxn, address, |row, bytes| (row, bytes.to_vec()))?
                .collect::<Result<Vec<_>>>()?;
            if snapshot.is_none() && updates.is_empty() {
                return Ok(None);
            }
            let doc = match &snapshot {
                Some(bytes) => doc_from_snapshot(bytes)?,
                None => LoroDoc::new(),
            };
            for (_, bytes) in &updates {
                import_doc(&doc, bytes)?;
            }
            if doc.oplog_vv() != review.version {
                return Ok(None);
            }
            let Some(current) = carried_manifest_for_portable(&doc, review.portable()) else {
                return Ok(None);
            };
            if current != *review.carried() {
                return Ok(None);
            }
            let Some(held) =
                vault.repo_manifest_conflict_held_in_txn(wtxn, review.portable(), &current)?
            else {
                return Ok(None);
            };
            if held != *review.held() {
                return Ok(None);
            }
            if !delete_carrier_for_portable(&doc, review.portable())? {
                return Ok(None);
            }
            let delta = export_updates_from(&doc, &review.version)?;
            let state = export_snapshot(&doc)?;
            let vv = doc_version_vector(&doc);
            persist_window_doc_in_txn(vault, wtxn, review.window(), &state, &vv)?;
            let mut subsumed = Vec::with_capacity(updates.len());
            for (row, _) in &updates {
                subsumed.push(
                    String::from_utf8(WINDOW_UPDATE.key_bytes(row))
                        .expect("window update keys are ASCII"),
                );
            }
            prune_subsumed_window_updates_in_txn(vault, wtxn, review.window(), &subsumed)?;
            write_window_svf_in_txn(vault, wtxn, review.window())?;
            Ok(Some(delta))
        })
    });
    match fenced {
        None => Ok(RepoManifestConflictDiscard::WindowLive),
        Some(Ok(None)) => Ok(RepoManifestConflictDiscard::Stale),
        Some(Ok(Some(update))) => Ok(RepoManifestConflictDiscard::Discarded { update }),
        Some(Err(error)) => Err(error),
    }
}
