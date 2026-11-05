//! A vault's own drafter artifact keys (FIX 12569): each sealed artifact of
//! one drafter version is sealed under an erasable key of its own
//! (`key_custody::erasable`, purpose `DrafterArtifact`), whose parent is the
//! version and whose incarnation is derived from the artifact's random id.
//! The version's record names the key by its random ref only, never by its
//! bytes.
//!
//! A key is minted in the writer that rechecks that the version may still
//! take an artifact, synced and journaled before that writer commits, and
//! its ref row is put in the same write. An erase stages the retirement of
//! every key of the version, an aborted writer's orphans included, in the
//! erase's own transaction; custody's finisher retires them after commit
//! (`Store::finish_erasable_retirements`, run at housekeeping). A staged
//! retirement denies every read from its commit on, and a restored earlier
//! image cannot open a retired key. A retained version keeps its key: no
//! eviction runs here.

use std::collections::BTreeSet;
use std::path::PathBuf;

use heed::{RoTxn, RwTxn};
use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result, StoreError};
use crate::store::Store;
use crate::store::key_custody::{
    CustodyKind, EntryState, ErasableItem, ErasablePurpose, delete_erasable_ref_in_txn,
    erasable_refs_of_in_txn, put_erasable_ref_in_txn, retirement_in_txn,
    stage_erasable_retirement_in_txn,
};

/// The context an artifact's 16-byte id derives its key incarnation under.
const DRAFTER_INCARNATION_CONTEXT: &str = "oneiron/drafter-artifact/erasable-incarnation/v1";

/// The directory under the vault root that sealed drafter artifacts live in.
const DRAFTER_ARTIFACT_DIR: &str = "drafter-artifacts";

/// The directory under the vault root that a serving host materialises a
/// drafter's plaintext load set in (FIX 14976).
const DRAFTER_SERVING_DIR: &str = "drafter-serving";

/// The directory under the vault root that an evaluator materialises a
/// drafter's plaintext load set in for its evaluator workers (FIX 14975),
/// apart from the serving host's: a serving pass never removes it.
const DRAFTER_EVALUATION_DIR: &str = "drafter-evaluation";

/// The directory under the vault root that sealed drafter corpora live in
/// (FIX 14973): one directory per version, sealed files only, never a key.
const DRAFTER_CORPUS_DIR: &str = "drafter-corpora";

impl Store {
    /// This vault's sealed drafter artifacts, `drafter-artifacts/` under the
    /// root it opened at: sealed files only, never a key.
    pub(crate) fn drafter_artifact_dir(&self) -> PathBuf {
        self.owner._registered_path.path.join(DRAFTER_ARTIFACT_DIR)
    }

    /// This vault's materialised drafter plaintext, `drafter-serving/` under
    /// the root it opened at: what a serving worker loads, never a key.
    pub(crate) fn drafter_serving_dir(&self) -> PathBuf {
        self.owner._registered_path.path.join(DRAFTER_SERVING_DIR)
    }

    /// This vault's drafter plaintext materialised for evaluation,
    /// `drafter-evaluation/` under the root it opened at: what an evaluator
    /// worker loads, never a key.
    pub(crate) fn drafter_evaluation_dir(&self) -> PathBuf {
        self.owner
            ._registered_path
            .path
            .join(DRAFTER_EVALUATION_DIR)
    }

    /// This vault's sealed drafter corpus directory, `drafter-corpora/`
    /// under the root it opened at.
    pub(crate) fn drafter_corpus_dir(&self) -> PathBuf {
        self.owner._registered_path.path.join(DRAFTER_CORPUS_DIR)
    }
}

/// The incarnation of the key that seals artifact `artifact`.
fn incarnation(artifact: &[u8; 16]) -> [u8; 32] {
    blake3::derive_key(DRAFTER_INCARNATION_CONTEXT, artifact)
}

fn unknown_key() -> Error {
    CustodyKind::ErasableKey.corrupt()
}

/// One artifact key, open in this process: its ref and its 32 bytes, held
/// in memory only and zeroed when dropped.
pub(crate) struct DrafterArtifactKey {
    pub(crate) key_ref: [u8; 32],
    pub(crate) secret: Zeroizing<[u8; 32]>,
}

/// `item`'s key from custody's `secret`: exactly 32 bytes.
fn opened(item: &ErasableItem, secret: &[u8]) -> Result<DrafterArtifactKey> {
    if secret.len() != 32 {
        return Err(unknown_key());
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes.copy_from_slice(secret);
    Ok(DrafterArtifactKey {
        key_ref: item.key_ref,
        secret: bytes,
    })
}

/// Mints the key that artifact `artifact` of drafter version `version` is
/// sealed under, in `w`, the writer that rechecked that the version may
/// still take it, with the custody binding pinned there: synced and
/// journaled before this returns, its ref row put in `w`. A retry finds and
/// keeps the key an earlier attempt minted; a retired one is refused.
///
/// # Errors
/// An archived vault, whose custody is its replacement's; a retired key;
/// custody faults.
pub(crate) fn mint_drafter_artifact_key_in_txn(
    s: &Store,
    w: &mut RwTxn<'_>,
    version: &EntityId,
    artifact: &[u8; 16],
) -> Result<DrafterArtifactKey> {
    if s.core.gate_custody_archived() {
        return Err(Error::Store(StoreError::ArchivedVault));
    }
    s.core.key_custody.pin_in_txn(s, w)?;
    let custody = s.core.key_custody.bind_in_txn(s, w)?;
    let (item, secret) = custody.mint_erasable(
        ErasablePurpose::DrafterArtifact,
        version.as_bytes(),
        &incarnation(artifact),
    )?;
    put_erasable_ref_in_txn(s, w, &item)?;
    opened(&item, secret.expose())
}

/// The key ref `key_ref` names for drafter version `version`, when it stands
/// live in `txn`: no custody, no key, a standing retirement or a retired key
/// read as `None`. A key of another purpose or version is damaged.
fn live_item(
    s: &Store,
    txn: &RoTxn<'_>,
    version: &EntityId,
    key_ref: &[u8; 32],
) -> Result<Option<ErasableItem>> {
    let Some(custody) = s.core.key_custody.local() else {
        return Ok(None);
    };
    let Some(item) = custody.erasable_by_ref(key_ref)? else {
        return Ok(None);
    };
    if item.purpose != ErasablePurpose::DrafterArtifact || item.parent != *version.as_bytes() {
        return Err(unknown_key());
    }
    if retirement_in_txn(s, txn, &item.subject(&custody)?)?.is_some() {
        return Ok(None);
    }
    Ok((custody.erasable_state(&item)? == EntryState::Live).then_some(item))
}

/// Whether the key `key_ref` of drafter version `version` still stands live
/// in `txn`: the artifact it seals is retained.
///
/// # Errors
/// A damaged key, and custody and storage faults.
pub(crate) fn drafter_artifact_retained_in_txn(
    s: &Store,
    txn: &RoTxn<'_>,
    version: &EntityId,
    key_ref: &[u8; 32],
) -> Result<bool> {
    Ok(live_item(s, txn, version, key_ref)?.is_some())
}

/// The live key `key_ref` of drafter version `version`, opened in this
/// process for the host that loads the artifact; `None` once it is retired
/// or its retirement is staged.
///
/// # Errors
/// A damaged key, and custody and storage faults.
pub(crate) fn drafter_artifact_key_in_txn(
    s: &Store,
    txn: &RoTxn<'_>,
    version: &EntityId,
    key_ref: &[u8; 32],
) -> Result<Option<DrafterArtifactKey>> {
    let Some(item) = live_item(s, txn, version, key_ref)? else {
        return Ok(None);
    };
    let custody = s.core.key_custody.local().ok_or_else(unknown_key)?;
    let secret = custody.read_erasable(&item)?;
    opened(&item, secret.expose()).map(Some)
}

/// Stages the retirement of the one key `key_ref` names, in `w`, and drops
/// its ref row: a publication its recheck refused. An archived vault, one
/// with no custody yet, or a ref custody holds no key for stages nothing.
///
/// # Errors
/// A key of another purpose, and custody and storage faults.
pub(crate) fn retire_drafter_artifact_key_in_txn(
    s: &Store,
    w: &mut RwTxn<'_>,
    key_ref: &[u8; 32],
) -> Result<()> {
    if s.core.gate_custody_archived() {
        return Ok(());
    }
    let Some(custody) = s.core.key_custody.local() else {
        return Ok(());
    };
    let Some(item) = custody.erasable_by_ref(key_ref)? else {
        return Ok(());
    };
    if item.purpose != ErasablePurpose::DrafterArtifact {
        return Err(unknown_key());
    }
    stage_erasable_retirement_in_txn(s, w, &custody, &item)?;
    delete_erasable_ref_in_txn(s, w, &item)
}

/// Stages the retirement of every key custody holds for drafter version
/// `version`, each ref row's and each orphan an aborted writer left, in `w`,
/// the erase's own transaction, then drops the version's ref rows. An
/// archived vault's custody is its replacement's: its rows go, its keys are
/// not touched.
///
/// # Errors
/// Storage and custody faults.
pub(crate) fn retire_drafter_artifact_keys_in_txn(
    s: &Store,
    w: &mut RwTxn<'_>,
    version: &EntityId,
) -> Result<()> {
    let purpose = ErasablePurpose::DrafterArtifact;
    let mut items: BTreeSet<ErasableItem> =
        erasable_refs_of_in_txn(s, w, purpose, version.as_bytes())?
            .into_iter()
            .collect();
    if !s.core.gate_custody_archived()
        && let Some(custody) = s.core.key_custody.local()
    {
        items.extend(custody.erasable_keys_of(purpose, version.as_bytes())?);
        for item in &items {
            stage_erasable_retirement_in_txn(s, w, &custody, item)?;
        }
    }
    for item in &items {
        delete_erasable_ref_in_txn(s, w, item)?;
    }
    Ok(())
}
