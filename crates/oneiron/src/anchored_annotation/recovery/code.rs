//! Reattach offers and one-click reattach on a code artifact (FIX 7905). A
//! code artifact's head is its current snapshot, the tree at its repo_ref
//! commit: an offer is each exact place in one of that tree's files where an
//! unattached comment's words read again, and a reattach lands only at the
//! current commit, on that commit's file for the path, where the words read
//! exactly. Each file reads from the ASSET its hash names, as a code locator
//! reads it, and a path the snapshot's custody withholds is never read. The
//! words are found with the plain-text search, so a span counts characters
//! as every code locator does. A place is found in the projection the words
//! were read through, offered in the caller's text, and lands at the owner's
//! offsets (FIX 22109).

use super::super::anchor_text::{MAX_OFFERS, UnitFormat, find_text, text_span};
use super::super::code_units::{
    CodeFile, CodeSpace, FileHash, code_locator_shown_in_txn, code_raw_locator_in_txn,
    code_span_words_in_txn, file_bytes_by_hash_in_txn, file_hash_hex,
};
use super::super::model::{CODE_ANCHOR_VERSION, Locator};
use super::{ReattachOffer, UnattachedThread};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::secret_custody::SecretSight;

/// Every exact place in `artifact`'s current snapshot where the words of
/// each of `unattached` read again, with its files read in `txn` through
/// `found_in`, the projection the threads' words were read through. Offers
/// come in thread order, and each thread's places in path order, then file
/// order, at most [`MAX_OFFERS`] a thread, as one blob search lists them. A
/// path the snapshot's custody withholds, or one whose file `reads` refuses,
/// is skipped; a file that is not text holds no place. A place holds the
/// raw words the thread's pin held, compared in memory and never stored,
/// and a thread whose pinned words no longer read is offered nothing.
/// Each thread's locator is the stored one, at the owner's offsets; a place
/// is found in `found_in`'s text, its raw words are read at the owner's
/// offsets it translates to, and it is offered in `sight`'s text, the
/// caller's, so a span that does not translate is no place (FIX 22109). No
/// snapshot offers nothing. A resource refusal is the engine's error (FIX
/// 10587), never empty offers.
pub(super) fn code_reattach_offers_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    unattached: &[UnattachedThread],
    found_in: SecretSight,
    sight: SecretSight,
    reads: impl Fn(&FileHash) -> Result<bool>,
) -> Result<Vec<ReattachOffer>> {
    // Equal words in one projection are not the same words: a masked secret
    // and literal filler read alike. Each place must hold the raw words the
    // thread's pin held (review #6752).
    let mut wanted: Vec<(EntityId, &str, String)> = Vec::new();
    for thread in unattached {
        let Some(words) = thread.snapshot.as_deref() else {
            continue;
        };
        let Some(pinned) = raw_words_in_txn(vault, txn, artifact, &thread.thread.anchor.locator)?
        else {
            continue;
        };
        wanted.push((thread.thread.thread_id, words, pinned));
    }
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
        let Some(bytes) = file_bytes_by_hash_in_txn(vault, txn, &entry.content_hash, found_in)?
        else {
            continue;
        };
        let hash = file_hash_hex(&entry.content_hash);
        // The file's raw bytes, how `found_in`'s offsets translate to them,
        // and how they translate to `sight`'s, read once and only when a
        // place is found.
        let mut raw: Option<Option<(Vec<u8>, CodeSpace, Option<CodeSpace>)>> = None;
        for ((_, words, pinned), found) in wanted.iter().zip(places.iter_mut()) {
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
                if raw.is_none() {
                    raw = Some(file_spaces_in_txn(
                        vault,
                        txn,
                        &entry.content_hash,
                        &bytes,
                        found_in,
                        sight,
                    )?);
                }
                let Some((raw_bytes, found_space, shown_space)) =
                    raw.as_ref().and_then(Option::as_ref)
                else {
                    continue;
                };
                let Some((start, end)) = found_space.raw_span(char_start, char_end) else {
                    continue;
                };
                if text_span(raw_bytes, start, end).as_deref() != Some(pinned.as_str()) {
                    continue;
                }
                // The place in the caller's text.
                let place = match shown_space {
                    None => Some((char_start, char_end)),
                    Some(space) => space.shown_span(start, end),
                };
                let Some((place_start, place_end)) = place else {
                    continue;
                };
                // A path past the locator bound has no code span.
                if let Ok(locator) = Locator::code(
                    commit,
                    entry.path.as_str(),
                    hash.clone(),
                    place_start,
                    place_end,
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
        .flat_map(|(&(thread_id, _, _), found)| {
            found.into_iter().map(move |locator| ReattachOffer {
                thread_id,
                version: CODE_ANCHOR_VERSION,
                locator,
            })
        })
        .collect())
}

/// The stored bytes of the file `hash` names, read in `txn`, with how the
/// offsets of `found`, its bytes as `found_in` reads them, translate to
/// them, and how they translate to `sight`'s text: `None` for that when
/// `sight` is `found_in`. `None` when the stored bytes are gone.
fn file_spaces_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hash: &FileHash,
    found: &[u8],
    found_in: SecretSight,
    sight: SecretSight,
) -> Result<Option<(Vec<u8>, CodeSpace, Option<CodeSpace>)>> {
    let Some(stored) = file_bytes_by_hash_in_txn(vault, txn, hash, SecretSight::Owner)? else {
        return Ok(None);
    };
    let found_space = CodeSpace::between(&stored, found);
    let shown_space = if sight == found_in {
        None
    } else {
        Some(match file_bytes_by_hash_in_txn(vault, txn, hash, sight)? {
            Some(shown) => CodeSpace::between(&stored, &shown),
            None => CodeSpace::Unmappable,
        })
    };
    Ok(Some((stored, found_space, shown_space)))
}

/// The words a one-click reattach at `locator` on the code artifact
/// `artifact` would land on, with the locator it lands at. `locator` reads
/// in `sight`'s text, the sight of the offers it came from, and lands at the
/// owner's offsets it translates to (FIX 22109). The words are read in
/// `txn` at that landing through the masked projection, the one the
/// Unattached list's snapshot words were read through
/// (`record_detached_in_txn`), so the two compare in one projection and no
/// plaintext secret is returned to compare them. Refused unless `locator`
/// is a code locator that names the artifact's current repo_ref commit and
/// that commit's file hash for its path. `None` when the path is withheld,
/// the span does not read or translate, or its raw words are not the raw
/// words `pinned` (the thread's stored pin) held: equal masked words are
/// not the same words, and the raw words are compared in memory only
/// (review #6752).
pub(super) fn code_reattach_words_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    pinned: &Locator,
    locator: &Locator,
    sight: SecretSight,
) -> Result<Option<(String, Locator)>> {
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
    let Some(landed) = code_raw_locator_in_txn(vault, txn, artifact, locator, sight)? else {
        return Ok(None);
    };
    let Some(words) = code_span_words_in_txn(vault, txn, artifact, &landed, SecretSight::Masked)?
    else {
        return Ok(None);
    };
    let pinned_raw = raw_words_in_txn(vault, txn, artifact, pinned)?;
    let same =
        pinned_raw.is_some() && raw_words_in_txn(vault, txn, artifact, &landed)? == pinned_raw;
    Ok(same.then_some((words, landed)))
}

/// The raw words under `locator`, a locator at the owner's offsets, on
/// `artifact`, read through the owner's sight for an in-memory comparison
/// only: never stored, and never returned to a reader.
fn raw_words_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    locator: &Locator,
) -> Result<Option<String>> {
    code_span_words_in_txn(vault, txn, artifact, locator, SecretSight::Owner)
}

/// Puts each code thread's stored locator in `unattached` on `artifact`
/// into `sight`'s text, read in `txn` (FIX 22109), for a reader of the
/// Unattached list; a reattach offer reads the stored locators.
pub(super) fn code_threads_shown_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    unattached: &mut [UnattachedThread],
    sight: SecretSight,
) -> Result<()> {
    for row in unattached {
        if matches!(row.thread.anchor.locator, Locator::Code { .. }) {
            row.thread.anchor.locator =
                code_locator_shown_in_txn(vault, txn, artifact, &row.thread.anchor.locator, sight)?;
        }
    }
    Ok(())
}

impl Vault {
    /// [`Vault::annotation_reattach_offers`] on a code artifact (FIX 7905):
    /// the files read through the masked projection, the one the stored
    /// snapshot words were read through, so an offer is a place where those
    /// words read again and its reattach takes it. Each place reads in
    /// `sight`'s text, the caller's, as the reattach that takes it reads it
    /// (FIX 22109).
    pub(super) fn code_annotation_reattach_offers(
        &self,
        artifact_id: &EntityId,
        unattached: &[UnattachedThread],
        sight: SecretSight,
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
            SecretSight::Masked,
            sight,
            |_| Ok(true),
        )
    }
}
