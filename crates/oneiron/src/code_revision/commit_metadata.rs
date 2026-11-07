//! Canonical metadata values and codecs are defined in the store layer.
//!
//! The author is erasable attribution, outside the integrity fold (FIX
//! 6258): an actor erase clears it in place, and every writer clears a name
//! this vault erased before it persists.

use std::borrow::Cow;

use heed::RoTxn;

use super::CodeRevision;
use super::keys::RECORDS;
use super::proposals::{decode as decode_proposal, encode_proposal};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
use crate::store::Store;

pub use crate::store::code_commit_metadata::CodeCommitMetadata;
pub(super) use crate::store::code_revision_record::commit_metadata::{
    from_value, integrity_value, to_value, validate,
};

/// The author `revision` names, if any.
pub(crate) fn named_author(revision: &CodeRevision) -> Option<EntityId> {
    revision
        .commit_metadata
        .as_ref()
        .and_then(|meta| meta.author)
}

/// Clears `revision`'s author when it names `actor`; `true` when it did.
pub(crate) fn clear_author(revision: &mut CodeRevision, actor: &EntityId) -> bool {
    match revision.commit_metadata.as_mut() {
        Some(meta) if meta.author.as_ref() == Some(actor) => {
            meta.author = None;
            true
        }
        _ => false,
    }
}

/// `revision` without the author this vault erased: the local hard-delete
/// marker of a named author clears it. Borrowed when nothing changes.
///
/// # Errors
/// A store failure.
pub(crate) fn erased_author_cleared<'a>(
    store: &Store,
    txn: &RoTxn<'_>,
    revision: &'a CodeRevision,
) -> Result<Cow<'a, CodeRevision>> {
    let Some(author) = named_author(revision) else {
        return Ok(Cow::Borrowed(revision));
    };
    if !store.port_deletion_marked(txn, DeletionMarker::HardDelete, &author)? {
        return Ok(Cow::Borrowed(revision));
    }
    let mut cleared = revision.clone();
    clear_author(&mut cleared, &author);
    Ok(Cow::Owned(cleared))
}

/// Whether a stored `existing` revision and an `incoming` retry are the same
/// revision: equal in every field but attribution, where an erased author on
/// either side matches, and two different named authors never do.
pub(crate) fn same_revision_content(existing: &CodeRevision, incoming: &CodeRevision) -> bool {
    let unnamed = |revision: &CodeRevision| {
        let mut revision = revision.clone();
        if let Some(meta) = revision.commit_metadata.as_mut() {
            meta.author = None;
        }
        revision
    };
    match (named_author(existing), named_author(incoming)) {
        (Some(stored), Some(retried)) if stored != retried => false,
        (Some(_), None) | (None, Some(_)) => unnamed(existing) == unnamed(incoming),
        _ => existing == incoming,
    }
}

/// How an owner archive's finalized or stranded revision row lands here
/// (FIX 6258).
pub(crate) enum ArchivedRevisionRow {
    /// A stored twin equal to it but for an erased author; the stored row
    /// stays.
    Unchanged,
    /// The row to restore, the author this vault erased cleared.
    Restore(Vec<u8>),
    /// A stored row with other content or another named author.
    Collides,
}

/// Lands one archived revision row, `proposal` for the stranded table and
/// else the finalized one, against the `stored` bytes under its key: an
/// import never brings back an author this vault erased, and an erased
/// author on either side still matches its twin.
///
/// # Errors
/// A row that does not decode, or a store failure.
pub(crate) fn land_archived_revision_row_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    proposal: bool,
    archived: &[u8],
    stored: Option<&[u8]>,
) -> Result<ArchivedRevisionRow> {
    if proposal {
        let mut incoming = decode_proposal(archived)?;
        let cleared = match erased_author_cleared(store, txn, &incoming.revision)? {
            Cow::Owned(revision) => Some(revision),
            Cow::Borrowed(_) => None,
        };
        let changed = cleared.is_some();
        if let Some(revision) = cleared {
            incoming.revision = revision;
        }
        return Ok(match stored.map(decode_proposal).transpose()? {
            Some(live) => {
                if live.head_revision_id == incoming.head_revision_id
                    && live.head_fold == incoming.head_fold
                    && live.proposed_fold == incoming.proposed_fold
                    && live.artifact_body == incoming.artifact_body
                    && same_revision_content(&live.revision, &incoming.revision)
                {
                    ArchivedRevisionRow::Unchanged
                } else {
                    ArchivedRevisionRow::Collides
                }
            }
            None if changed => ArchivedRevisionRow::Restore(encode_proposal(&incoming)?),
            None => ArchivedRevisionRow::Restore(archived.to_vec()),
        });
    }
    let incoming = RECORDS.decode_value(archived)?;
    let incoming = erased_author_cleared(store, txn, &incoming)?;
    Ok(
        match stored
            .map(|bytes| RECORDS.decode_value(bytes))
            .transpose()?
        {
            Some(live) if same_revision_content(&live, &incoming) => ArchivedRevisionRow::Unchanged,
            Some(_) => ArchivedRevisionRow::Collides,
            None => match incoming {
                Cow::Owned(revision) => {
                    ArchivedRevisionRow::Restore(RECORDS.encode_value(&revision)?)
                }
                Cow::Borrowed(_) => ArchivedRevisionRow::Restore(archived.to_vec()),
            },
        },
    )
}
