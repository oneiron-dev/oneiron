//! The DOCX author-token lookup (FIX 12403): each token to the canonical
//! export rows that name it.
//!
//! A copy leaving the vault reads each token it carries through the export
//! and per-group author rows. The index holds, per token, only the sorted
//! canonical row keys: an export row's version key and a revision-author
//! row's (artifact, version, group) key. It keeps no actor and no display
//! author, so an actor's erase never touches it, and every read resolves
//! the current canonical row and rechecks its token: the index is a lookup,
//! never a second authority.
//!
//! Every canonical write maintains its refs in the same writer
//! ([`note_export_put`], [`note_author_put`], [`unref_export`],
//! [`unref_author`]); a key's token never changes, so noting a put is
//! idempotent and erasing an actor is a no-op. Artifact erase unrefs before
//! its deletes; checkpoint restore unrefs the rows it overwrites and notes
//! the restored rows at those exact keys.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::super::{EXPORT_AUTHORS, EXPORTS, OfficeBodyExportAuthor, OfficeBodyExportRecord};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{Named, SideTable};
use crate::store::ManifestDbs;

/// One token's canonical row keys, each set in canonical key order: export
/// keys compare as bytes, and author tuples order as their key bytes do
/// (an id orders by its bytes, a version by its big-endian bytes).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TokenIndexRow {
    exports: BTreeSet<Vec<u8>>,
    authors: BTreeSet<(EntityId, u64, u64)>,
}

impl TokenIndexRow {
    fn is_empty(&self) -> bool {
        self.exports.is_empty() && self.authors.is_empty()
    }
}

const TOKEN_INDEX: SideTable<String, TokenIndexRow, Named> =
    SideTable::new(&crate::side_table::OFFICE_BODY_EXPORT_TOKEN_INDEX);

/// Notes `key`'s put under `token` in the caller's writer. Idempotent: a
/// key's token never changes, so a merge's re-put notes the same ref.
/// Empty tokens name no row and are skipped.
///
/// # Errors
///
/// Storage errors.
pub(in crate::office_body) fn note_export_put(
    dbs: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    key: &Vec<u8>,
    token: &str,
) -> Result<()> {
    if token.is_empty() {
        return Ok(());
    }
    let owned = token.to_owned();
    let mut row = TOKEN_INDEX.get(dbs, wtxn, &owned)?.unwrap_or_default();
    row.exports.insert(key.clone());
    TOKEN_INDEX.put(dbs, wtxn, &owned, &row)
}

/// Notes one revision-author row's put under its token in the caller's
/// writer. Idempotent, like [`note_export_put`]; empty tokens are skipped.
///
/// # Errors
///
/// Storage errors.
pub(in crate::office_body) fn note_author_put(
    dbs: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    key: &(EntityId, u64, u64),
    token: &str,
) -> Result<()> {
    if token.is_empty() {
        return Ok(());
    }
    let owned = token.to_owned();
    let mut row = TOKEN_INDEX.get(dbs, wtxn, &owned)?.unwrap_or_default();
    row.authors.insert(*key);
    TOKEN_INDEX.put(dbs, wtxn, &owned, &row)
}

/// Drops `key`'s ref under `token` in the caller's writer: the artifact
/// erase and the checkpoint restore before they overwrite. A token with no
/// row, and a ref it does not hold, are already gone. The row goes once
/// both sets are empty.
///
/// # Errors
///
/// Storage errors.
pub(in crate::office_body) fn unref_export(
    dbs: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    token: &str,
    key: &Vec<u8>,
) -> Result<()> {
    if token.is_empty() {
        return Ok(());
    }
    let owned = token.to_owned();
    let Some(mut row) = TOKEN_INDEX.get(dbs, wtxn, &owned)? else {
        return Ok(());
    };
    row.exports.remove(key);
    if row.is_empty() {
        TOKEN_INDEX.delete(dbs, wtxn, &owned)?;
    } else {
        TOKEN_INDEX.put(dbs, wtxn, &owned, &row)?;
    }
    Ok(())
}

/// Drops one revision-author row's ref under `token`, like [`unref_export`].
///
/// # Errors
///
/// Storage errors.
pub(in crate::office_body) fn unref_author(
    dbs: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    token: &str,
    key: &(EntityId, u64, u64),
) -> Result<()> {
    if token.is_empty() {
        return Ok(());
    }
    let owned = token.to_owned();
    let Some(mut row) = TOKEN_INDEX.get(dbs, wtxn, &owned)? else {
        return Ok(());
    };
    row.authors.remove(key);
    if row.is_empty() {
        TOKEN_INDEX.delete(dbs, wtxn, &owned)?;
    } else {
        TOKEN_INDEX.put(dbs, wtxn, &owned, &row)?;
    }
    Ok(())
}

/// Every export row `tokens` name, in canonical key order: each row read
/// from its canonical table and kept only when its token still matches. A
/// token that is not UTF-8, a row that is gone and a token that no longer
/// matches are skipped, as a missing binding is: the index never invents
/// a row.
///
/// # Errors
///
/// Storage errors.
pub(super) fn lookup_exports(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    tokens: &BTreeSet<Vec<u8>>,
) -> Result<Vec<(Vec<u8>, OfficeBodyExportRecord)>> {
    let mut pairs = Vec::new();
    for token in tokens {
        let Ok(key) = String::from_utf8(token.clone()) else {
            continue;
        };
        let Some(row) = TOKEN_INDEX.get(dbs, txn, &key)? else {
            continue;
        };
        for export in &row.exports {
            let Some(record) = EXPORTS.get(dbs, txn, export)? else {
                continue;
            };
            if !record
                .token
                .as_deref()
                .is_some_and(|named| named.as_bytes() == token.as_slice())
            {
                continue;
            }
            pairs.push((export.clone(), record));
        }
    }
    // The sets concatenate grouped by token; the readers fold (the
    // resolver) or carry (the gather) in scan order, so restore it here.
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(pairs)
}

/// Every revision-author row `tokens` name, in canonical key order, read
/// and rechecked like [`lookup_exports`].
///
/// # Errors
///
/// Storage errors.
pub(super) fn lookup_authors(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    tokens: &BTreeSet<Vec<u8>>,
) -> Result<Vec<((EntityId, u64, u64), OfficeBodyExportAuthor)>> {
    let mut pairs = Vec::new();
    for token in tokens {
        let Ok(key) = String::from_utf8(token.clone()) else {
            continue;
        };
        let Some(row) = TOKEN_INDEX.get(dbs, txn, &key)? else {
            continue;
        };
        for author in &row.authors {
            let Some(record) = EXPORT_AUTHORS.get(dbs, txn, author)? else {
                continue;
            };
            if record.token.as_bytes() != token.as_slice() {
                continue;
            }
            pairs.push((*author, record));
        }
    }
    pairs.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(pairs)
}
