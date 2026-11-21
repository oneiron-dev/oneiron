//! Who a projected MESSAGE's words are attributed to (FIX 15412): the
//! `AuthoredBy` binding its author bucket admits, and the source speaker an
//! imported MESSAGE names, read apart from its role. A branch pins both and
//! a retained citation binds again only to the same ones.

use super::super::support::invalid_consolidation;
use crate::gate::{WITNESS_AUTHOR_COUNTERPARTY, WITNESS_AUTHOR_SYSTEM};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{EntityId, Result, Vault};
use oneiron_contracts::fingerprint::{LegacyDigest, purposes};

/// The source speaker a MESSAGE's sorted `AuthoredBy` targets `authors`
/// name, when they are the binding its `author` bucket admits. A native
/// row's byline is its writer: one for a user or companion row, none for a
/// system or counterparty one, and it names no source speaker. An imported
/// row's is none, or the one PERSON its source names as the speaker, read
/// as that PERSON's one live canonical head: none when it has none, as when
/// it was erased or split, or when this replica does not hold it yet. The
/// edge is never the writer. Any other binding refuses.
pub(super) fn admitted_speaker_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    author: &str,
    imported: bool,
    authors: &[EntityId],
) -> Result<Option<EntityId>> {
    let changed = || invalid_consolidation("witnessed turn message binding changed");
    if !imported {
        let bylines = usize::from(!matches!(
            author,
            WITNESS_AUTHOR_SYSTEM | WITNESS_AUTHOR_COUNTERPARTY
        ));
        return if authors.len() == bylines {
            Ok(None)
        } else {
            Err(changed())
        };
    }
    match authors {
        [] => Ok(None),
        [person] => {
            if vault
                .store
                .port_entity_record(txn, person)?
                .is_some_and(|row| row.entity_type != ENTITY_TYPE_PERSON)
            {
                return Err(changed());
            }
            crate::memory::source_speaker_in_txn(vault, txn, authors)
        }
        _ => Err(changed()),
    }
}

/// The source attribution a MESSAGE slice pins, when its MESSAGE carries
/// one: an imported MESSAGE's sorted raw `AuthoredBy` targets and the source
/// speaker they were read as, as one hash. None for a native MESSAGE, whose
/// edge is its writer, and for an import with no edge: they name no source
/// speaker, and their slices pin no attribution. A merge, an erase or
/// another edge changes it while the words stay the same.
pub(super) fn attribution_hash(
    imported: bool,
    authors: &[EntityId],
    speaker: Option<EntityId>,
) -> Option<[u8; 32]> {
    if !imported || authors.is_empty() {
        return None;
    }
    let mut hash = LegacyDigest::new(purposes::dreamer_consolidation::MESSAGE_ATTRIBUTION);
    hash.len_u64_be(authors.len());
    for author in authors {
        hash.raw(author.as_bytes());
    }
    match speaker {
        Some(speaker) => {
            hash.raw(&[1]);
            hash.raw(speaker.as_bytes());
        }
        None => {
            hash.raw(&[0]);
        }
    }
    Some(hash.finish())
}

/// [`attribution_hash`] for the K door
/// (`test_doors::fingerprint_keep_dreamer_consolidation_digests`). Not API.
#[cfg(oneiron_test_support)]
pub(crate) fn attribution_hash_for_test(
    imported: bool,
    authors: &[EntityId],
    speaker: Option<EntityId>,
) -> Option<[u8; 32]> {
    attribution_hash(imported, authors, speaker)
}
