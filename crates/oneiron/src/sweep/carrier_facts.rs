//! What the compaction scrub reads in an owning adapter's carrier, kept
//! for each carrier body file the vault admits (FIX 22091, Engine call
//! C2 = A).
//!
//! The scrub removes a window's ASSET carrier whose holder an erase took,
//! or whose birth source or receipt archive copies an erased id, and widens
//! the erase to a carrier its holder owns. It reads those facts in the
//! carrier's bytes. A carrier that lives in a body file is a manifest in the
//! window, and its file may be released before the window is compacted, so
//! the facts are kept when the file is admitted: the holder, the birth
//! child, whether it is a receipt archive, whether its id is the one its
//! holder's kind derives, and a 16-byte fingerprint of each lowercase
//! ASCII-hex 32-byte window a birth source or receipt archive holds. No
//! payload is kept: the fingerprints match an erased id's hex and recover
//! nothing. Every admitted body file keeps its row, an empty one too, so a
//! scrub never takes a peer's word for a file's kind. The facts stay for
//! the vault's lifetime, as a window can.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::side_table::{self, Named, SideTable};
use crate::store::{AssetFileKind, Store};
use crate::sync::asset_body::references::AssetBodyRef;

/// Key: the carrier's id, then the BLAKE3 of the body its file holds.
const FACTS: SideTable<(EntityId, [u8; 32]), CarrierScrubFacts, Named> =
    SideTable::new(&side_table::ASSET_CARRIER_SCRUB_FACTS);

#[doc(hidden)]
use oneiron_records::sweep::carrier_facts::copied_id_fingerprint;

/// What the scrub reads in one carrier's bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CarrierScrubFacts {
    /// The holder an owning adapter's carrier names: a hub source's, a
    /// birth source's child, a receipt archive's or a refinement receipt's,
    /// the first present.
    holder: Option<EntityId>,
    /// The child a birth source names, kept apart from the holder: an erase
    /// of its derived source id removes the carrier too.
    birth_child: Option<EntityId>,
    /// The bytes open as a receipt archive source.
    receipt_archive: bool,
    /// The carrier's id is the one its holder's kind derives from these
    /// bytes: an erase of the holder takes the carrier's id too.
    owns_id: bool,
    /// Sorted, distinct fingerprints of each lowercase ASCII-hex 32-byte
    /// window of a birth source or receipt archive.
    copied: Vec<[u8; 16]>,
}

impl CarrierScrubFacts {
    /// What the scrub reads in `body`, the bytes of ASSET `id`'s carrier,
    /// as its pass over a window's inline carriers reads them.
    pub(super) fn of_carrier(id: &EntityId, body: &[u8]) -> Self {
        let skill_holder = crate::skill_hub::source_carrier_holder(body);
        let birth_child = crate::agent_def::birth_source_holder(body);
        let receipt_holder = crate::receipt::receipt_archive_holder(body);
        let refinement_holder = crate::skill_hub::refinement_carrier_holder(body);
        let holder = skill_holder
            .or(birth_child)
            .or(receipt_holder)
            .or(refinement_holder);
        let receipt_archive = crate::receipt::is_receipt_archive_source(body);
        let owns_id = holder.is_some()
            && (crate::skill_hub::source_carrier_matches_id(body, id)
                || crate::receipt::receipt_archive_matches_id(body, id)
                || crate::skill_hub::refinement_carrier_matches_id(body, id)
                || birth_child
                    .is_some_and(|child| crate::agent_def::birth_source_matches_id(&child, id)));
        let copied = if birth_child.is_some() || receipt_archive {
            body.windows(32)
                .filter_map(copied_id_fingerprint)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };
        Self {
            holder,
            birth_child,
            receipt_archive,
            owns_id,
            copied,
        }
    }

    /// Whether the scrub removes this carrier when the ids `erased` are
    /// erased (`erased_copied` their fingerprints), and whether the
    /// carrier's own id joins the erase, as the scrub decides for an inline
    /// carrier.
    pub(super) fn verdict(
        &self,
        erased: &BTreeSet<EntityId>,
        erased_copied: &BTreeSet<[u8; 16]>,
    ) -> (bool, bool) {
        let holder_erased = self.holder.is_some_and(|holder| erased.contains(&holder));
        let copied_erased = self
            .copied
            .iter()
            .any(|fingerprint| erased_copied.contains(fingerprint));
        let birth_erased = self.birth_child.is_some_and(|child| {
            crate::agent_def::birth_source_id(&child).is_ok_and(|id| erased.contains(&id))
                || copied_erased
        });
        let archive_erased = self.receipt_archive && copied_erased;
        let removed = holder_erased || birth_erased || archive_erased;
        (removed, removed && holder_erased && self.owns_id)
    }
}

/// The fingerprints of the erased ids' hex, as [`CarrierScrubFacts::verdict`]
/// reads them.
pub(super) fn erased_fingerprints(erased: &BTreeSet<EntityId>) -> BTreeSet<[u8; 16]> {
    erased
        .iter()
        .filter_map(|id| copied_id_fingerprint(id.to_hex().as_bytes()))
        .collect()
}

/// Keeps what the scrub reads in the body file (`digest`, of `kind`) that
/// ASSET `id`'s put binds in `txn`, so a later scrub of a window that names
/// the file reads none of its bytes (FIX 22091): what `body`, the bytes the
/// put read for its adapter checks, holds; with no bytes read, nothing for
/// a file this vault's stager judged no carrier, as it files no body an
/// owning adapter reads under another kind. Empty facts are kept too: they
/// are the scrub's local proof that the file names no holder.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn stage_carrier_scrub_facts_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
    (digest, kind): (&[u8; 32], AssetFileKind),
    body: Option<&[u8]>,
) -> Result<()> {
    let facts = match body {
        Some(body) => CarrierScrubFacts::of_carrier(id, body),
        // A carrier file's put reads its bytes; one that read none keeps no
        // facts, and its scrub reads its live file or fails.
        None if kind == AssetFileKind::Carrier => return Ok(()),
        None => CarrierScrubFacts::default(),
    };
    FACTS.put(store, txn, &(*id, *digest), &facts)
}

/// What the scrub reads in the body `reference` names in a window, whatever
/// kind the window's writer gave it: the facts its admission kept; with
/// none, what the live row of its id holds while that row holds the same
/// body: its bytes when they are in the row or in a carrier file, nothing
/// for a file of another kind, which this vault's stager judged. The caller
/// opened `txn` under the custody guard after pinning the result bodies.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] for a body with neither kept facts nor a live
/// row that holds it: the window's sweep fails and is owed again, never
/// read as holding no holder. Storage and filesystem errors.
pub(super) fn historical_carrier_facts_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    reference: &AssetBodyRef,
) -> Result<CarrierScrubFacts> {
    let store = &vault.store;
    if let Some(facts) = FACTS.get(store, txn, &(reference.id, reference.body_blake3))? {
        return Ok(facts);
    }
    if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &reference.id)?
        && EntityMetadataHeader::parse(&raw)
            .is_some_and(|header| header.entity_type == ENTITY_TYPE_ASSET)
        && let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..)
    {
        match crate::store::asset_file_in_txn(store, txn, &reference.id, body)? {
            Some(manifest) if manifest.facts.blake3 == reference.body_blake3 => {
                if manifest.kind != AssetFileKind::Carrier {
                    return Ok(CarrierScrubFacts::default());
                }
                let carrier =
                    crate::store::asset_carrier_body_in_txn(store, txn, &reference.id, body)?;
                return Ok(CarrierScrubFacts::of_carrier(&reference.id, &carrier));
            }
            None if *blake3::hash(body).as_bytes() == reference.body_blake3 => {
                return Ok(CarrierScrubFacts::of_carrier(&reference.id, body));
            }
            _ => {}
        }
    }
    Err(Error::CorruptedIndex(
        "historical asset carrier scrub facts",
    ))
}
