//! Exact citation dependency indexes shared by sync and featureless erasure.

use crate::side_table::{self, HexId, LegacyJson, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::side_keys::{HexHexHash, HexPair, HexTriple};

#[derive(Serialize, Deserialize)]
pub(super) struct PinRefs {
    #[serde(with = "super::id_codec")]
    document: EntityId,
    #[serde(with = "super::id_codec")]
    claim: EntityId,
}

/// Reverse citation-pin index keyed by the citing document; value points at
/// [`NOTE_PIN_SOURCE`]'s key.
pub(super) const NOTE_PIN_CITING: SideTable<HexHexHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PIN_CITING);
/// Reverse citation-pin index keyed by the cited claim; value points at
/// [`NOTE_PIN_SOURCE`]'s key.
pub(super) const NOTE_PIN_CLAIM: SideTable<HexHexHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PIN_CLAIM);
/// Reverse citation-pin row keyed by the cited source document.
pub(super) const NOTE_PIN_SOURCE: SideTable<HexHexHash, super::NotePin, LegacyJson> =
    SideTable::new(&side_table::NOTE_PIN_SOURCE);
/// Pending (pre-admission) citation-request dependency, keyed by the citing document.
pub(super) const NOTE_PIN_REQUEST_CITING: SideTable<HexPair, PinRefs, LegacyJson> =
    SideTable::new(&side_table::NOTE_PIN_REQUEST_CITING);
/// Pending citation-request index keyed by the cited claim.
pub(super) const NOTE_PIN_REQUEST_CLAIM: SideTable<HexTriple, (), Raw> =
    SideTable::new(&side_table::NOTE_PIN_REQUEST_CLAIM);
/// Pending citation-request index keyed by the cited source document.
pub(super) const NOTE_PIN_REQUEST_SOURCE: SideTable<HexTriple, (), Raw> =
    SideTable::new(&side_table::NOTE_PIN_REQUEST_SOURCE);

pub(super) fn remove_citing(store: &Store, txn: &mut heed::RwTxn<'_>, id: EntityId) -> Result<()> {
    let key_prefix = format!("{}:", id.to_hex()).into_bytes();
    for (citing_key, source_key) in NOTE_PIN_CITING.scan_from(store, txn, &key_prefix)? {
        let source_k = source_key
            .strip_prefix(NOTE_PIN_SOURCE.decl().prefix)
            .and_then(HexHexHash::decode_key)
            .ok_or(Error::CorruptedIndex("NOTE reverse pin source missing"))?;
        let pin = NOTE_PIN_SOURCE
            .get(store, txn, &source_k)?
            .ok_or(Error::CorruptedIndex("NOTE reverse pin source missing"))?;
        let claim_key = HexHexHash(HexId(pin.claim), HexId(id), source_k.2.clone());
        NOTE_PIN_CLAIM.delete(store, txn, &claim_key)?;
        NOTE_PIN_SOURCE.delete(store, txn, &source_k)?;
        NOTE_PIN_CITING.delete(store, txn, &citing_key)?;
    }
    Ok(())
}

pub(super) fn dependents(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let key_prefix = format!("{}:", id.to_hex()).into_bytes();
    let mut out = BTreeSet::new();
    for HexHexHash(_, citing, _) in NOTE_PIN_SOURCE.scan_keys(store, txn, &key_prefix)? {
        out.insert(citing.0);
    }
    for HexHexHash(_, citing, _) in NOTE_PIN_CLAIM.scan_keys(store, txn, &key_prefix)? {
        out.insert(citing.0);
    }
    for HexTriple(_, citing, _) in NOTE_PIN_REQUEST_SOURCE.scan_keys(store, txn, &key_prefix)? {
        out.insert(citing.0);
    }
    for HexTriple(_, citing, _) in NOTE_PIN_REQUEST_CLAIM.scan_keys(store, txn, &key_prefix)? {
        out.insert(citing.0);
    }
    Ok(out)
}

pub(crate) fn citation_delete_scope_exists(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(!dependents(store, txn, *id)?.is_empty())
}

#[cfg(feature = "sync")]
pub(crate) fn track_citation_request(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    citing: EntityId,
    request: EntityId,
    pin: &super::NotePin,
) -> Result<()> {
    pin.validate()?;
    NOTE_PIN_REQUEST_CITING.put(
        store,
        txn,
        &HexPair(HexId(citing), HexId(request)),
        &PinRefs {
            document: pin.document,
            claim: pin.claim,
        },
    )?;
    NOTE_PIN_REQUEST_SOURCE.put(
        store,
        txn,
        &HexTriple(HexId(pin.document), HexId(citing), HexId(request)),
        &(),
    )?;
    NOTE_PIN_REQUEST_CLAIM.put(
        store,
        txn,
        &HexTriple(HexId(pin.claim), HexId(citing), HexId(request)),
        &(),
    )?;
    Ok(())
}

pub(crate) fn remove_citation_request(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    citing: EntityId,
    request: EntityId,
) -> Result<()> {
    let key = HexPair(HexId(citing), HexId(request));
    if let Some(refs) = NOTE_PIN_REQUEST_CITING.get(store, txn, &key)? {
        NOTE_PIN_REQUEST_SOURCE.delete(
            store,
            txn,
            &HexTriple(HexId(refs.document), HexId(citing), HexId(request)),
        )?;
        NOTE_PIN_REQUEST_CLAIM.delete(
            store,
            txn,
            &HexTriple(HexId(refs.claim), HexId(citing), HexId(request)),
        )?;
        NOTE_PIN_REQUEST_CITING.delete(store, txn, &key)?;
    }
    Ok(())
}

pub(super) fn remove_citing_requests(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    citing: EntityId,
) -> Result<()> {
    let key_prefix = format!("{}:", citing.to_hex()).into_bytes();
    for key in NOTE_PIN_REQUEST_CITING.scan_keys(store, txn, &key_prefix)? {
        remove_citation_request(store, txn, citing, (key.1).0)?;
    }
    Ok(())
}
