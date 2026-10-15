//! HardErase pierces refcounting (ARCH-0005a; ARCH-0038 carrier 13).
//!
//! A plain delete drops one artifact's hold on its version bytes, and the bytes stay while another
//! artifact holds them. A hard erase (`user_hard_delete`, `gdpr_delete`, `policy_delete`) takes the
//! bytes and every reference to them in the transaction that erases the artifact, on every vault
//! that applies it. Each `blob.version` claim naming the bytes becomes an erased reference, valued
//! with the erase's tombstone. Every hold on the bytes goes, so the artifact's own delete releases
//! them, and each holder's fingerprint tree over them goes too. A version whose claim is an erased
//! reference reads as erased, never as missing and never as its old bytes.
//!
//! The erasing vault tombstones each reference and the ASSET under the erase's own request, so a
//! replica pierces the bytes from any one of them, even one that never saw the erased artifact. A
//! reference arriving after the erase is pierced on arrival and never stored, and the bytes are
//! never stored again under any id.

use heed::{RoTxn, RwTxn};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;

use super::lifecycle::held_hashes;
use super::provenance::BLOB_VERSION_CLAIM_PREDICATE;
use super::references::{
    artifact_is_live, forget_hold, holders, live_holders, version_claim_reference,
    version_claim_version,
};
use super::store_keys::{ASSET_REF, BLOB_ARTIFACT_CONTENT_HASH_LEN};
use super::versions::{VERSIONS, blob_artifact_asset_entity_id};

type ContentHash = [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN];

/// The `blob.version` claims a hard erase took, each valued with that erase's tombstone wire
/// value. Key: id16 (claim).
const ERASED_REFERENCE: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_ERASED_REFERENCE);

/// The ASSETs carrying bytes a hard erase took here, each valued with that erase's tombstone wire
/// value: an ASSET row the walk tore, or the id the bytes' hash names where no row stood. Never
/// another kind's row. A text derived from one goes with it. Key: id16 (ASSET).
const ERASED_ASSET: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_ERASED_ASSET);

/// The texts a DerivedFrom edge named as derived from an erased ASSET before their bodies arrived
/// here: each body is scrubbed and fenced on arrival. Key: id16 (the text); value: id16 (the
/// ASSET).
const ERASED_DERIVATION: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_ERASED_DERIVATION);

/// The bytes a hard erase took, each valued with that erase's tombstone wire value. A reference to
/// them that arrives later arrives erased, and they are never stored here again. Key: bytes32.
const ERASED_CONTENT: SideTable<ContentHash, Vec<u8>, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_ERASED_CONTENT);

/// The carriers a hard erase's first destructive transaction took, kept for the transaction that
/// writes its receipt and sweep row: that first scrub drops the rows a later walk finds them by.
/// Key: id16 (the erased record); value: the carriers' id16s.
const ERASE_SCOPE: SideTable<EntityId, Vec<u8>, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_ERASE_SCOPE);

/// One version-byte object an artifact holds, and the other artifacts holding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Holding {
    hash: ContentHash,
    /// The ASSET carrying the bytes.
    pub(crate) asset: EntityId,
    /// The other artifacts whose hold keeps the bytes past a plain delete: a local `asset_ref`
    /// row, or a live artifact's version claim.
    pub(crate) others: Vec<EntityId>,
}

/// The bytes `artifact` holds, each with the other artifacts holding it, read in the caller's
/// snapshot before any delete tears a row.
pub(crate) fn holdings_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Vec<Holding>> {
    let mut holdings = Vec::new();
    for hash in held_hashes(store, txn, artifact)? {
        let asset = blob_artifact_asset_entity_id(&hash)?;
        let others = live_holders(store, txn, &hash, &[*artifact, asset])?;
        holdings.push(Holding {
            hash,
            asset,
            others,
        });
    }
    Ok(holdings)
}

/// `holdings` less the bytes a walk here already took.
pub(crate) fn unerased_holdings_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    holdings: Vec<Holding>,
) -> Result<Vec<Holding>> {
    let mut kept = Vec::with_capacity(holdings.len());
    for holding in holdings {
        if !ERASED_CONTENT.contains(store, txn, &holding.hash)? {
            kept.push(holding);
        }
    }
    Ok(kept)
}

/// Every reference here to `holdings`' bytes: each `blob.version` claim naming them, and the claim
/// id of each version record of `artifact` or of a holder whose bytes they are, even where that
/// claim's row is gone. `artifact`'s own references are among them.
pub(crate) fn references_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    holdings: &[Holding],
) -> Result<Vec<EntityId>> {
    let mut references = Vec::new();
    for claim in crate::claim::claim_ids_for_predicate_bounded_in_txn(
        store,
        txn,
        BLOB_VERSION_CLAIM_PREDICATE,
        usize::MAX,
    )? {
        let Some(raw) = store.entities.get(txn, claim.as_bytes())? else {
            continue;
        };
        if raw.len() <= ENTITY_METADATA_HEADER_LEN || raw[0] != ENTITY_TYPE_CLAIM {
            continue;
        }
        // A body no reader can decode names no bytes anyone can read.
        let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            continue;
        };
        if version_claim_reference(&body).is_some_and(|(_, hash)| names(holdings, &hash)) {
            references.push(claim);
        }
    }
    let mut artifacts = vec![*artifact];
    for holding in holdings {
        artifacts.extend(holders(
            store,
            txn,
            &holding.hash,
            &[*artifact, holding.asset],
        )?);
    }
    artifacts.sort_unstable();
    artifacts.dedup();
    for holder in artifacts {
        for row in VERSIONS.iter_from(store, txn, holder.as_bytes())? {
            let (_, record) = row?;
            if names(holdings, &record.content_hash) {
                references.push(record.claim_id);
            }
        }
    }
    references.sort_unstable();
    references.dedup();
    Ok(references)
}

fn names(holdings: &[Holding], hash: &ContentHash) -> bool {
    holdings.iter().any(|holding| &holding.hash == hash)
}

/// Takes every hold on `holdings`' bytes but `artifact`'s own, which its delete drops next and
/// so releases the bytes, and records `references` as erased with `tombstone`. From here those
/// references read as erased, and a copy of one sent again records no hold. A holder's fingerprint
/// tree computed over the bytes goes with them. Returns the holders it reached.
pub(crate) fn erase_holds_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    holdings: &[Holding],
    references: &[EntityId],
    tombstone: &[u8],
) -> Result<Vec<EntityId>> {
    for reference in references {
        if !ERASED_REFERENCE.contains(store, wtxn, reference)? {
            ERASED_REFERENCE.put(store, wtxn, reference, &tombstone.to_vec())?;
        }
    }
    let mut reached = Vec::new();
    for holding in holdings {
        if !ERASED_CONTENT.contains(store, wtxn, &holding.hash)? {
            ERASED_CONTENT.put(store, wtxn, &holding.hash, &tombstone.to_vec())?;
        }
        for holder in holders(store, wtxn, &holding.hash, &[*artifact, holding.asset])? {
            ASSET_REF.delete(store, wtxn, &(holding.hash, holder))?;
            forget_hold(store, wtxn, &holding.hash, &holder)?;
            if crate::ingest::blob_fingerprint_asset_hash(store, wtxn, &holder)?
                == Some(holding.hash)
            {
                crate::ingest::invalidate_blob_fingerprint(store, wtxn, &holder)?;
            }
            reached.push(holder);
        }
    }
    reached.sort_unstable();
    reached.dedup();
    Ok(reached)
}

/// The holding a `blob.version` claim names: a hard erase of the claim takes the bytes, as one of
/// the artifact's would. A replica learns which bytes another vault's erase took from the
/// tombstones it publishes for each reference it pierced. `None` for any other claim.
pub(crate) fn claim_holding_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    body: &[u8],
) -> Result<Option<Holding>> {
    let Ok(body) = crate::claim::decode_claim_body(body, true) else {
        return Ok(None);
    };
    let Some((_, hash)) = version_claim_reference(&body) else {
        return Ok(None);
    };
    let asset = blob_artifact_asset_entity_id(&hash)?;
    Ok(Some(Holding {
        hash,
        asset,
        others: live_holders(store, txn, &hash, &[asset])?,
    }))
}

/// The holding of a blob erased directly: `asset` is the stored ASSET of `body`, its own bytes,
/// and every artifact holding them is another reference.
pub(crate) fn asset_holding_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    asset: &EntityId,
    body: &[u8],
) -> Result<Option<Holding>> {
    let hash = *blake3::hash(body).as_bytes();
    if blob_artifact_asset_entity_id(&hash)? != *asset {
        return Ok(None);
    }
    Ok(Some(Holding {
        hash,
        asset: *asset,
        others: live_holders(store, txn, &hash, &[*asset])?,
    }))
}

/// A `blob.version` claim that arrives after the hard erase that took the bytes it names, or after
/// a hard erase of its artifact was decided here: a vault learns which bytes an erase took only
/// from the bodies naming them, and one can arrive after the erase, or between its publication
/// and its purge.
#[derive(Debug)]
#[cfg_attr(not(any(feature = "sync", test)), allow(dead_code))]
pub(crate) struct LateReference {
    pub(crate) holding: Holding,
    /// The erase's tombstone wire value.
    pub(crate) erase: Vec<u8>,
    pub(crate) reach: LateReach,
}

/// What a late reference newly teaches this vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(any(feature = "sync", test)), allow(dead_code))]
pub(crate) enum LateReach {
    /// The erase already took this reference: nothing.
    Taken,
    /// A walk here already took the bytes: only this reference is new.
    Reference,
    /// The first word here of which bytes the erase took: its walk runs for them now.
    Bytes,
}

/// The erase `claim` arrives after, when it is a late reference ([`LateReference`]).
///
/// Only typed evidence counts, as an erase is never walked back: `claim` among the references a
/// walk here took, the bytes it names among those a walk here took, or its artifact's hard erase
/// decided here where a version chain was recorded for it ([`artifact_erase_in_txn`]). A bare
/// hard-delete marker proves nothing about any bytes, on the claim's id, its subject or the id the
/// bytes' hash names: a peer can cause one on an id it controls, and a row of any kind can stand
/// at those ids.
pub(crate) fn late_reference_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    claim: &EntityId,
    body: &ClaimBody,
) -> Result<Option<LateReference>> {
    let Some((artifact, hash)) = version_claim_reference(body) else {
        return Ok(None);
    };
    let (erase, reach) = if let Some(erase) = ERASED_REFERENCE.get(store, txn, claim)? {
        (erase, LateReach::Taken)
    } else if let Some(erase) = ERASED_CONTENT.get(store, txn, &hash)? {
        (erase, LateReach::Reference)
    } else if let Some(erase) = artifact_erase_in_txn(store, txn, &artifact)? {
        (erase, LateReach::Bytes)
    } else {
        return Ok(None);
    };
    let asset = blob_artifact_asset_entity_id(&hash)?;
    Ok(Some(LateReference {
        holding: Holding {
            hash,
            asset,
            others: live_holders(store, txn, &hash, &[artifact, asset])?,
        },
        erase,
        reach,
    }))
}

/// The tombstone wire value of a hard erase of `artifact` decided here, published or in flight,
/// when a version chain was recorded for it here: its high-water mark, kept after its delete,
/// shows it was an artifact. A hard-delete marker on any other id names no artifact.
fn artifact_erase_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Option<Vec<u8>>> {
    if !super::versions::versioned_here(store, txn, artifact)? {
        return Ok(None);
    }
    if let Some(erase) = crate::deletion::HARD_DELETE_MARKER.get(store, txn, &HexId(*artifact))? {
        return Ok(Some(erase));
    }
    crate::deletion::hard_delete_in_flight_in_txn(store, txn, artifact)
}

/// Whether a hard erase here took `body`'s bytes.
pub(crate) fn bytes_erased(store: &Store, txn: &RoTxn<'_>, body: &[u8]) -> Result<bool> {
    ERASED_CONTENT.contains(store, txn, blake3::hash(body).as_bytes())
}

/// Releases each of `holdings`' bytes nothing holds any more but `holder`, which a hard erase is
/// taking: a no-op while `holder`'s own hold stands, which its delete then drops.
pub(crate) fn release_erased_bytes_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    holder: &EntityId,
    holdings: &[Holding],
) -> Result<()> {
    for holding in holdings {
        super::lifecycle::release_bytes_of_deleted_artifact(store, wtxn, holder, &holding.hash)?;
    }
    Ok(())
}

/// Keeps `carriers` for the transaction that writes `id`'s erase receipt and sweep row.
pub(crate) fn record_erase_scope_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    carriers: &[EntityId],
) -> Result<()> {
    if carriers.is_empty() {
        return Ok(());
    }
    let mut scope = take_erase_scope_in_txn(store, wtxn, id)?;
    scope.extend(carriers);
    scope.sort_unstable();
    scope.dedup();
    let raw: Vec<u8> = scope.iter().flat_map(EntityId::as_bytes).copied().collect();
    ERASE_SCOPE.put(store, wtxn, id, &raw)
}

/// Takes the carriers [`record_erase_scope_in_txn`] kept for `id`.
pub(crate) fn take_erase_scope_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<Vec<EntityId>> {
    let Some(raw) = ERASE_SCOPE.get(store, wtxn, id)? else {
        return Ok(Vec::new());
    };
    ERASE_SCOPE.delete(store, wtxn, id)?;
    let chunks = raw.chunks_exact(16);
    if !chunks.remainder().is_empty() {
        return Err(Error::CorruptedIndex("blob artifact erase scope"));
    }
    chunks
        .map(|chunk| {
            EntityId::from_bytes(
                chunk
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("blob artifact erase scope"))?,
            )
        })
        .collect()
}

/// The erase stamp of bytes a hard erase took here.
pub(crate) fn content_erased(
    store: &Store,
    txn: &RoTxn<'_>,
    hash: &ContentHash,
) -> Result<Option<Vec<u8>>> {
    ERASED_CONTENT.get(store, txn, hash)
}

/// Each version of another live artifact that names one of `holdings`' bytes, as (ASSET,
/// artifact, version): what a hard erase of `id` takes beside it, for the delete preview.
pub(crate) fn other_versions_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    id: &EntityId,
    holdings: &[Holding],
) -> Result<Vec<(EntityId, EntityId, u64)>> {
    let mut found = std::collections::BTreeSet::new();
    if holdings.is_empty() {
        return Ok(Vec::new());
    }
    for claim in crate::claim::claim_ids_for_predicate_bounded_in_txn(
        store,
        txn,
        BLOB_VERSION_CLAIM_PREDICATE,
        usize::MAX,
    )? {
        let Some(raw) = store.entities.get(txn, claim.as_bytes())? else {
            continue;
        };
        if raw.len() <= ENTITY_METADATA_HEADER_LEN || raw[0] != ENTITY_TYPE_CLAIM {
            continue;
        }
        let Ok(body) = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
        else {
            continue;
        };
        let (Some((artifact, hash)), Some(version)) =
            (version_claim_reference(&body), version_claim_version(&body))
        else {
            continue;
        };
        if artifact != *id
            && let Some(holding) = holdings.iter().find(|holding| holding.hash == hash)
            && artifact_is_live(store, txn, &artifact)?
        {
            found.insert((holding.asset, artifact, version));
        }
    }
    for holding in holdings {
        for other in &holding.others {
            for row in VERSIONS.iter_from(store, txn, other.as_bytes())? {
                let (_, record) = row?;
                if record.content_hash == holding.hash {
                    found.insert((holding.asset, *other, record.version));
                }
            }
        }
    }
    Ok(found.into_iter().collect())
}

/// Whether a hard erase took the reference `claim` is.
pub(crate) fn reference_erased(store: &Store, txn: &RoTxn<'_>, claim: &EntityId) -> Result<bool> {
    ERASED_REFERENCE.contains(store, txn, claim)
}

/// Marks `assets`, the ASSET ids a hard erase's walk owned (an ASSET row it tears, or the id the
/// bytes' hash names where no row stands), as erased with `tombstone`.
pub(crate) fn mark_erased_assets_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    assets: &[EntityId],
    tombstone: &[u8],
) -> Result<()> {
    for asset in assets {
        if !ERASED_ASSET.contains(store, wtxn, asset)? {
            ERASED_ASSET.put(store, wtxn, asset, &tombstone.to_vec())?;
        }
    }
    Ok(())
}

/// Whether a hard erase's walk here took the ASSET `asset`.
#[cfg(feature = "sync")]
pub(crate) fn asset_erased(store: &Store, txn: &RoTxn<'_>, asset: &EntityId) -> Result<bool> {
    ERASED_ASSET.contains(store, txn, asset)
}

/// Keeps the obligation a DerivedFrom edge leaves when it names `text`, not stored here yet, as
/// derived from `asset`, an ASSET a hard erase took: `text`'s body is scrubbed on arrival.
#[cfg(feature = "sync")]
pub(crate) fn record_erased_derivation_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    text: &EntityId,
    asset: &EntityId,
) -> Result<()> {
    if ERASED_DERIVATION.contains(store, wtxn, text)? {
        return Ok(());
    }
    ERASED_DERIVATION.put(store, wtxn, text, &asset.as_bytes().to_vec())
}

/// Whether a DerivedFrom edge left the obligation to scrub `text` on arrival.
pub(crate) fn erased_derivation_pending(
    store: &Store,
    txn: &RoTxn<'_>,
    text: &EntityId,
) -> Result<bool> {
    ERASED_DERIVATION.contains(store, txn, text)
}

/// Discharges the obligation [`record_erased_derivation_in_txn`] kept for `text`.
#[cfg(any(feature = "sync", test))]
pub(crate) fn discharge_erased_derivation_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    text: &EntityId,
) -> Result<()> {
    ERASED_DERIVATION.delete(store, wtxn, text)?;
    Ok(())
}

#[cfg(test)]
mod tests;
