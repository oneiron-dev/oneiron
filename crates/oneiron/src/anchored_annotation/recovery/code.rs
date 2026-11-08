//! Reattach offers and one-click reattach on a code artifact (FIX 7905). A
//! code artifact's head is its current snapshot, the tree at its repo_ref
//! commit: an offer is each exact place in one of that tree's files where an
//! unattached comment's words read again, and a reattach lands only at the
//! current commit, on that commit's file for the path, where the words read
//! exactly. Each file reads from the ASSET its hash names, as a code locator
//! reads it, and a path the snapshot's custody withholds is never read. The
//! words are found with the plain-text search, so a span counts characters
//! as every code locator does.

use super::super::anchor_text::{MAX_OFFERS, UnitFormat, find_text};
use super::super::code_units::{
    CodeFile, FileHash, code_span_words_in_txn, file_bytes_by_hash_in_txn, file_hash_hex,
};
use super::super::model::{CODE_ANCHOR_VERSION, Locator};
use super::{ReattachOffer, UnattachedThread};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::secret_custody::SecretSight;

/// Every exact place in `artifact`'s current snapshot where the words of
/// each of `unattached` read again, with its files read in `txn` through
/// `sight`. Offers come in thread order, and each thread's places in path
/// order, then file order, at most [`MAX_OFFERS`] a thread, as one blob
/// search lists them. A path the snapshot's custody withholds, or one whose
/// file `reads` refuses, is skipped; a file that is not text holds no place.
/// No snapshot offers nothing. A resource refusal is the engine's error
/// (FIX 10587), never empty offers.
pub(super) fn code_reattach_offers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    unattached: &[UnattachedThread],
    sight: SecretSight,
    reads: impl Fn(&FileHash) -> Result<bool>,
) -> Result<Vec<ReattachOffer>> {
    let wanted: Vec<(EntityId, &str)> = unattached
        .iter()
        .filter_map(|thread| Some((thread.thread.thread_id, thread.snapshot.as_deref()?)))
        .collect();
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let Some(snapshot) = vault.get_codebase_snapshot_in_txn(txn, artifact)? else {
        return Ok(Vec::new());
    };
    let Some(commit) = snapshot.repo_ref.commit_hash() else {
        return Ok(Vec::new());
    };
    let withheld = vault.codebase_withheld_paths_in_txn(txn, &snapshot.fork_hash)?;
    let limits = vault.text_limits_in_txn(txn)?;
    let mut places: Vec<Vec<Locator>> = vec![Vec::new(); wanted.len()];
    for entry in &snapshot.files {
        // Each file is read once, for every thread that still has room.
        if places.iter().all(|found| found.len() >= MAX_OFFERS) {
            break;
        }
        if withheld.contains(&entry.path) || !reads(&entry.content_hash)? {
            continue;
        }
        let Some(bytes) = file_bytes_by_hash_in_txn(vault, txn, &entry.content_hash, sight)? else {
            continue;
        };
        let hash = file_hash_hex(&entry.content_hash);
        for ((_, words), found) in wanted.iter().zip(places.iter_mut()) {
            if found.len() >= MAX_OFFERS {
                continue;
            }
            for span in find_text(&bytes, UnitFormat::Text, words, &limits)? {
                let Locator::Text {
                    char_start,
                    char_end,
                } = span
                else {
                    continue;
                };
                // A path past the locator bound has no code span.
                if let Ok(locator) = Locator::code(
                    commit,
                    entry.path.as_str(),
                    hash.clone(),
                    char_start,
                    char_end,
                ) {
                    found.push(locator);
                }
                if found.len() >= MAX_OFFERS {
                    break;
                }
            }
        }
    }
    Ok(wanted
        .iter()
        .zip(places)
        .flat_map(|(&(thread_id, _), found)| {
            found.into_iter().map(move |locator| ReattachOffer {
                thread_id,
                version: CODE_ANCHOR_VERSION,
                locator,
            })
        })
        .collect())
}

/// The words a one-click reattach at `locator` on the code artifact
/// `artifact` would land on, read in `txn` through the owner's sight, as the
/// blob arm reads its version's stored bytes. Refused unless `locator` is a
/// code locator that names the artifact's current repo_ref commit and that
/// commit's file hash for its path. `None` when the path is withheld or the
/// span does not read.
pub(super) fn code_reattach_words_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    locator: &Locator,
) -> Result<Option<String>> {
    let Some(file) = CodeFile::of(locator) else {
        return Err(Error::Artifact(ArtifactError::InvalidAnchor(
            "a code artifact reattaches only at a code locator",
        )));
    };
    let current = vault
        .get_codebase_snapshot_in_txn(txn, artifact)?
        .is_some_and(|snapshot| {
            snapshot.repo_ref.commit_hash() == Some(file.commit)
                && snapshot
                    .files
                    .binary_search_by(|entry| entry.path.as_str().cmp(file.path))
                    .is_ok_and(|at| snapshot.files[at].content_hash == file.hash)
        });
    if !current {
        return Err(Error::Artifact(ArtifactError::InvalidAnchor(
            "a code reattach names the artifact's current commit and that commit's file hash",
        )));
    }
    code_span_words_in_txn(vault, txn, artifact, locator, SecretSight::Owner)
}

impl Vault {
    /// [`Vault::annotation_reattach_offers`] on a code artifact (FIX 7905):
    /// the files read through the owner's sight, as the blob arm reads its
    /// head's stored bytes.
    pub(super) fn code_annotation_reattach_offers(
        &self,
        artifact_id: &EntityId,
        unattached: &[UnattachedThread],
    ) -> Result<Vec<ReattachOffer>> {
        // The files are found inside the read below: every body is pinned
        // before it opens (FIX 5399).
        let _bodies = self.pin_all_result_bodies();
        let rtxn = self.store.env.read_txn()?;
        code_reattach_offers_in_txn(
            self,
            &rtxn,
            artifact_id,
            unattached,
            SecretSight::Owner,
            |_| Ok(true),
        )
    }
}
