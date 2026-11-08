//! Code artifacts (FIX 7905, OF-511; ARCH-0078 "a tree at a commit"). A
//! code locator names the commit the artifact's repo_ref pins, a file's path
//! and the file's content hash, and a character span over the file's decoded
//! text, counted as a plain-text span is. The words read from the ASSET the
//! hash names, so a thread whose commit the tree has moved past still reads
//! them. When the tree moves to a new commit, a span moves with the line and
//! character diff a plain-text span uses.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use super::anchor_text::{decoded, remap_text_span, text_span, text_units};
use super::model::{AnnotationThread, CODE_ANCHOR_VERSION, Locator, ReanchorOutcome};
use crate::Vault;
use crate::codebase::{
    CODEBASE_CONTENT_HASH_LEN, CodebaseSnapshot, read_asset_blob_sighted_in_txn,
};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::secret_custody::SecretSight;

/// A code file's content hash.
pub(super) type FileHash = [u8; CODEBASE_CONTENT_HASH_LEN];

/// The file a code locator names: the commit it was read at, its path there
/// and its content hash.
#[derive(Debug, Clone, Copy)]
pub(super) struct CodeFile<'a> {
    pub(super) commit: &'a str,
    pub(super) path: &'a str,
    pub(super) hash: FileHash,
}

impl<'a> CodeFile<'a> {
    /// The file `locator` names; `None` for another format's locator.
    pub(super) fn of(locator: &'a Locator) -> Option<Self> {
        let Locator::Code {
            commit,
            path,
            file_hash,
            ..
        } = locator
        else {
            return None;
        };
        Some(Self {
            commit,
            path,
            hash: file_hash_bytes(file_hash)?,
        })
    }
}

/// The lowercase hex spelling of a file hash, as a code locator holds it.
pub(super) fn file_hash_hex(hash: &FileHash) -> String {
    bytes_to_hex_lower(hash)
}

/// The bytes of a 64-character lowercase hex file hash.
fn file_hash_bytes(hex: &str) -> Option<FileHash> {
    if hex.len() != CODEBASE_CONTENT_HASH_LEN * 2 {
        return None;
    }
    let mut out = [0_u8; CODEBASE_CONTENT_HASH_LEN];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The bytes of the snapshot ASSET `hash` names, as `sight` reads them, in
/// the caller's `txn`, as the snapshot file face reads a file: the owner
/// reads the stored bytes; any other sight reads a file a repo mark covers
/// as its masked copy, before its bytes are read, and every other file
/// masked as it is read (FIX 7608, FIX 8964). `None` when that ASSET is
/// gone.
pub(super) fn file_bytes_by_hash_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    hash: &FileHash,
    sight: SecretSight,
) -> Result<Option<Vec<u8>>> {
    let marked = if sight == SecretSight::Owner {
        Ok(None)
    } else {
        vault.repo_marked_asset_copy_in_txn(txn, hash)
    };
    let read = marked.and_then(|marked| match marked {
        Some(copy) => Ok(copy.into_bytes()),
        None => read_asset_blob_sighted_in_txn(vault, txn, hash, sight),
    });
    match read {
        Ok(bytes) => Ok(Some(bytes)),
        Err(Error::EntityNotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// [`file_bytes_by_hash_in_txn`] in a read of its own, for a reader that
/// already holds the tree it found `hash` in, as a snapshot mount reads a
/// file.
pub(super) fn file_bytes_by_hash(
    vault: &Vault,
    hash: &FileHash,
    sight: SecretSight,
) -> Result<Option<Vec<u8>>> {
    // A file holding these bytes is named by their hash: pinned before the
    // snapshot that finds its row opens (FIX 5399).
    let _body = vault.pin_result_body(*hash);
    let txn = vault.store.env.read_txn()?;
    file_bytes_by_hash_in_txn(vault, &txn, hash, sight)
}

/// The bytes of the code file `file` names on `artifact`, as `sight` reads
/// them, in the caller's `txn`. They read from the ASSET the file's hash
/// names, so a locator whose commit is not the artifact's current repo_ref
/// commit still reads its words. When the artifact's current snapshot is at
/// the file's commit, a path its custody withholds reads as absent, as a
/// snapshot mount reads it. `None` when the path is withheld or the ASSET is
/// gone.
pub(super) fn code_file_bytes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    file: &CodeFile<'_>,
    sight: SecretSight,
) -> Result<Option<Vec<u8>>> {
    if let Some(snapshot) = vault.get_codebase_snapshot_in_txn(txn, artifact)?
        && snapshot.repo_ref.commit_hash() == Some(file.commit)
        && vault
            .codebase_withheld_paths_in_txn(txn, &snapshot.fork_hash)?
            .contains(file.path)
    {
        return Ok(None);
    }
    file_bytes_by_hash_in_txn(vault, txn, &file.hash, sight)
}

/// The words under a code locator on `artifact`, as `sight` reads them, in
/// the caller's `txn`; `None` for another format's locator or a spot that
/// does not read.
pub(super) fn code_span_words_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    locator: &Locator,
    sight: SecretSight,
) -> Result<Option<String>> {
    let (
        Some(file),
        Locator::Code {
            char_start,
            char_end,
            ..
        },
    ) = (CodeFile::of(locator), locator)
    else {
        return Ok(None);
    };
    Ok(code_file_bytes_in_txn(vault, txn, artifact, &file, sight)?
        .and_then(|bytes| text_span(&bytes, *char_start, *char_end)))
}

/// [`code_span_words_in_txn`] in a read of its own.
pub(super) fn code_span_words(
    vault: &Vault,
    artifact: &EntityId,
    locator: &Locator,
    sight: SecretSight,
) -> Result<Option<String>> {
    let Some(file) = CodeFile::of(locator) else {
        return Ok(None);
    };
    // Pinned before the read that finds the file's row opens (FIX 5399).
    let _body = vault.pin_result_body(file.hash);
    let txn = vault.store.env.read_txn()?;
    code_span_words_in_txn(vault, &txn, artifact, locator, sight)
}

/// The whole-file unit of the code file `bytes` hold at `commit` and
/// `path`: a span over all of its decoded text. `None` when the bytes are
/// not text or the path is too long for a code locator.
pub(super) fn code_file_unit(
    commit: &str,
    path: &str,
    hash: &FileHash,
    bytes: &[u8],
) -> Option<Locator> {
    let text = decoded(bytes)?;
    Locator::code(
        commit,
        path,
        file_hash_hex(hash),
        0,
        text.chars().count() as u64,
    )
    .ok()
}

/// One unit per line of the code file `bytes` hold, split as a plain-text
/// file's lines are: each line's code span and its words. `None` when the
/// bytes are not text.
pub(super) fn code_line_units(
    commit: &str,
    path: &str,
    hash: &FileHash,
    bytes: &[u8],
) -> Result<Option<Vec<(Locator, Option<String>)>>> {
    let Some(lines) = text_units(bytes) else {
        return Ok(None);
    };
    let hash = file_hash_hex(hash);
    lines
        .into_iter()
        .map(|(line, words)| {
            let Locator::Text {
                char_start,
                char_end,
            } = line
            else {
                return Err(Error::InvariantViolation("a text line unit is a text span"));
            };
            Ok((
                Locator::code(commit, path, hash.clone(), char_start, char_end)?,
                words,
            ))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// The code side of one re-anchor sweep: the tree a code artifact just moved
/// to, and the text of each file a moving span is diffed over.
pub(super) struct CodeReanchor {
    /// The new tree's commit.
    commit: String,
    /// The new tree's file hash at each path a moving thread names, for the
    /// paths it holds and does not withhold.
    files: HashMap<String, FileHash>,
    /// The decoded text of each file a moving span is diffed over; `None`
    /// when it does not read as text or its ASSET is gone.
    texts: HashMap<FileHash, Option<String>>,
}

impl CodeReanchor {
    /// Reads what moving `threads` onto `snapshot` needs, when a live
    /// thread's code locator names another commit; `None` otherwise, so a
    /// tree put with no thread to move reads nothing more. The files read
    /// as the owner reads them: the engine diffs the stored bytes.
    pub(super) fn load(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        snapshot: &CodebaseSnapshot,
        threads: &[AnnotationThread],
    ) -> Result<Option<Self>> {
        let Some(commit) = snapshot.repo_ref.commit_hash() else {
            return Ok(None);
        };
        let moving: Vec<CodeFile<'_>> = threads
            .iter()
            .filter(|thread| !thread.is_drifted() && thread.anchor.version == CODE_ANCHOR_VERSION)
            .filter_map(|thread| CodeFile::of(&thread.anchor.locator))
            .filter(|file| file.commit != commit)
            .collect();
        if moving.is_empty() {
            return Ok(None);
        }
        let withheld = vault.codebase_withheld_paths_in_txn(txn, &snapshot.fork_hash)?;
        let mut files = HashMap::new();
        let mut texts = HashMap::new();
        for file in &moving {
            if withheld.contains(file.path) {
                continue;
            }
            let Ok(at) = snapshot
                .files
                .binary_search_by(|entry| entry.path.as_str().cmp(file.path))
            else {
                continue;
            };
            let hash = snapshot.files[at].content_hash;
            files.insert(file.path.to_owned(), hash);
            if hash == file.hash {
                continue;
            }
            for read in [file.hash, hash] {
                if let Entry::Vacant(slot) = texts.entry(read) {
                    let bytes = file_bytes_by_hash_in_txn(vault, txn, &read, SecretSight::Owner)?;
                    slot.insert(bytes.and_then(|bytes| decoded(&bytes).map(str::to_owned)));
                }
            }
        }
        Ok(Some(Self {
            commit: commit.to_owned(),
            files,
            texts,
        }))
    }

    /// Whether the sweep moves `locator`: a code locator at another commit.
    pub(super) fn moves(&self, locator: &Locator) -> bool {
        matches!(locator, Locator::Code { commit, .. } if *commit != self.commit)
    }

    /// The span's place in the new tree. A path the tree lacks or withholds
    /// drifts; the same file hash keeps its span at the new commit; any
    /// other file moves the span by the text diff, and it drifts when none
    /// of its characters survives or either file does not read as text.
    pub(super) fn rebind(&self, locator: &Locator) -> ReanchorOutcome {
        let (
            Some(file),
            Locator::Code {
                char_start,
                char_end,
                ..
            },
        ) = (CodeFile::of(locator), locator)
        else {
            return ReanchorOutcome::Drifted;
        };
        let Some(hash) = self.files.get(file.path) else {
            return ReanchorOutcome::Drifted;
        };
        let span = if *hash == file.hash {
            Some((*char_start, *char_end))
        } else {
            match (self.text(&file.hash), self.text(hash)) {
                (Some(before), Some(after)) => {
                    remap_text_span(before, after, *char_start, *char_end)
                }
                _ => None,
            }
        };
        match span.and_then(|(start, end)| {
            Locator::code(
                self.commit.clone(),
                file.path,
                file_hash_hex(hash),
                start,
                end,
            )
            .ok()
        }) {
            Some(locator) => ReanchorOutcome::Mapped(locator),
            None => ReanchorOutcome::Drifted,
        }
    }

    fn text(&self, hash: &FileHash) -> Option<&str> {
        self.texts.get(hash)?.as_deref()
    }
}
