//! A TURN's text revision: the revision that pins the words a turn serves.
//!
//! A TURN's text is its messages' (ARCH-0004), which its own row does not
//! hold, so the row's revision pins none of it. The text revision commits to
//! the row revision read and to each source message's own (ARCH-0002: one
//! frontier per source): the message's row revision and stored row and, for
//! a message whose text lives in an entity document, that document's
//! frontier. One text revision is one set of words; an edit to any source
//! makes another.
//!
//! A read pinned at a text revision resolves while every source still stands
//! as it was read, at whichever retained revision of the turn's row it named,
//! and refuses once a source has moved, as a pin whose revision is gone does:
//! it never serves other words under the revision it showed.

use super::storage::{entity_owns_revision_in_txn, reference, row_revisions_in_txn, state};
use super::{ReadMode, RevisionRef};
use crate::error::Result;
use crate::{EntityId, Vault};
use heed::RoTxn;

/// The text revision of `turn` with its row at `row`, read in `txn`, or
/// `None` for a turn with no source message, whose row revision pins all
/// the text it has.
pub(crate) fn turn_text_revision_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    row: RevisionRef,
) -> Result<Option<RevisionRef>> {
    Ok(sources_in_txn(vault, txn, turn)?.map(|sources| text_revision(turn, row, &sources)))
}

/// The revision a read of `turn` at `mode` serves its text under: the text
/// revision of the row it reads. A pin that is already a text revision of
/// the turn's current sources stays as it is.
pub(crate) fn served_turn_revision_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    mode: ReadMode,
) -> Result<Option<RevisionRef>> {
    let row = match mode {
        ReadMode::Pinned(revision) => {
            if !entity_owns_revision_in_txn(&vault.store, txn, turn, revision)?
                && turn_row_for_text_revision_in_txn(vault, txn, turn, revision)?.is_some()
            {
                return Ok(Some(revision));
            }
            revision
        }
        ReadMode::Live | ReadMode::Indexed => {
            let Some(raw) =
                crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, turn)?
            else {
                return Ok(None);
            };
            state(&vault.store, txn, turn)?.map_or_else(
                || reference(turn, &raw),
                |current| match mode {
                    ReadMode::Indexed => current.indexed,
                    _ => current.live,
                },
            )
        }
    };
    Ok(Some(
        turn_text_revision_in_txn(vault, txn, turn, row)?.unwrap_or(row),
    ))
}

/// The row revision `revision` was read at, when it is a text revision of
/// `turn` whose sources still stand as they were read. The row may have
/// moved since; any revision of it the vault retains still resolves. `None`
/// when `revision` is not such a revision, or no longer.
pub(crate) fn turn_row_for_text_revision_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    turn: &EntityId,
    revision: RevisionRef,
) -> Result<Option<RevisionRef>> {
    let Some(sources) = sources_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    Ok(row_revisions_in_txn(&vault.store, txn, turn)?
        .into_iter()
        .find(|row| text_revision(turn, *row, &sources) == revision))
}

fn text_revision(turn: &EntityId, row: RevisionRef, sources: &[u8; 32]) -> RevisionRef {
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:turn-text-revision:v1");
    digest.update(turn.as_bytes());
    digest.update(&row.0);
    digest.update(sources);
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finalize().as_bytes()[..16]);
    RevisionRef(bytes)
}

/// What the turn's source messages stand at, as one digest; `None` for a
/// turn with none.
fn sources_in_txn(vault: &Vault, txn: &RoTxn<'_>, turn: &EntityId) -> Result<Option<[u8; 32]>> {
    let Some(messages) = crate::tagging::turn_messages_in_txn(vault, txn, turn)? else {
        return Ok(None);
    };
    if messages.is_empty() {
        return Ok(None);
    }
    let mut digest = blake3::Hasher::new();
    for message in messages {
        let id = EntityId::from_hex(&message.id)?;
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
        else {
            continue;
        };
        // The row as stored too: a migration into an entity document replaces
        // it without moving its revision.
        let stored = reference(&id, &raw);
        let revision = state(&vault.store, txn, &id)?.map_or(stored, |current| current.live);
        digest.update(id.as_bytes());
        digest.update(&revision.0);
        digest.update(&stored.0);
        #[cfg(feature = "sync")]
        let frontier = crate::entity_doc::source_frontier_in_txn(&vault.store, txn, &id)?;
        #[cfg(not(feature = "sync"))]
        let frontier: Option<Vec<u8>> = None;
        if let Some(frontier) = frontier {
            digest.update(&(frontier.len() as u64).to_be_bytes());
            digest.update(&frontier);
        }
    }
    Ok(Some(*digest.finalize().as_bytes()))
}
