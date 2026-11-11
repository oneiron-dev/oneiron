//! The proof that a file-plane ASSET's body came to this machine from its
//! home (FIX 14534, Engine 11-06 19:59 call). The own-device client writes it
//! in the commit that lands a body its proven home served; no server,
//! federation or offline landing writes one. The owner's discard of a world
//! copy releases a file-plane ASSET only while its stored manifest still
//! names the body proved here and the row stands at the revision that
//! landed it: the home could serve those exact bytes, so this copy is not
//! their only one. This install's own body write forgets the proof
//! (`Vault::put_asset_body_in_txn`), whatever bytes it writes. A body this
//! machine wrote, a row written again since, and one no proof names, stay. The proof is this install's own evidence:
//! no checkpoint images it and a restore drops it.

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::vault::entity_revision::{ReadMode, RevisionRef, revision_for_mode_in_txn};

/// The body an ASSET's file holds that its home served, by the ASSET's id:
/// the home machine (16 bytes), the carrier's BLAKE3 (32), the body's BLAKE3
/// (32), its length (u64 big-endian) and the row's live revision the landing
/// wrote (16). Key: hex32 (ASSET id).
const FROM_HOME: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_ASSET_BODY_FROM_HOME);

/// A proof's bytes: home, carrier, body, length, revision.
const PROOF_LEN: usize = 16 + 32 + 32 + 8 + 16;

/// A body the home served for one ASSET.
pub(crate) struct HomeBodyProof {
    /// The machine the client's connection proved as its home.
    pub(crate) home: EntityId,
    /// BLAKE3 of the whole carrier the window bound the body to.
    pub(crate) carrier_blake3: [u8; 32],
    pub(crate) body_blake3: [u8; 32],
    pub(crate) len: u64,
    /// The row's live revision the landing wrote.
    pub(crate) revision: RevisionRef,
}

impl HomeBodyProof {
    fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(PROOF_LEN);
        raw.extend_from_slice(self.home.as_bytes());
        raw.extend_from_slice(&self.carrier_blake3);
        raw.extend_from_slice(&self.body_blake3);
        raw.extend_from_slice(&self.len.to_be_bytes());
        raw.extend_from_slice(&self.revision.0);
        raw
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != PROOF_LEN {
            return None;
        }
        Some(Self {
            home: EntityId::from_bytes(raw[..16].try_into().ok()?).ok()?,
            carrier_blake3: raw[16..48].try_into().ok()?,
            body_blake3: raw[48..80].try_into().ok()?,
            len: u64::from_be_bytes(raw[80..88].try_into().ok()?),
            revision: RevisionRef(raw[88..104].try_into().ok()?),
        })
    }
}

/// Records that the home served `proof`'s body for the ASSET `asset`, in
/// the commit that landed it.
pub(super) fn record_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    asset: EntityId,
    proof: &HomeBodyProof,
) -> Result<()> {
    FROM_HOME.put(store, txn, &HexId(asset), &proof.encode())
}

/// Whether this machine received from its home the body of `len` bytes
/// under `body_blake3` that the ASSET `asset` stores now, with the row still
/// at the revision that landing wrote. A proof that does not decode proves
/// nothing.
pub(crate) fn received_from_home_in(
    store: &Store,
    txn: &RoTxn<'_>,
    asset: EntityId,
    body_blake3: &[u8; 32],
    len: u64,
) -> Result<bool> {
    let Some(proof) = FROM_HOME
        .get(store, txn, &HexId(asset))?
        .and_then(|raw| HomeBodyProof::decode(&raw))
    else {
        return Ok(false);
    };
    let revision = revision_for_mode_in_txn(store, txn, &asset, ReadMode::Live)?;
    Ok(proof.body_blake3 == *body_blake3 && proof.len == len && revision == Some(proof.revision))
}

/// Forgets the proof for the ASSET `asset`, whose row the owner's discard
/// takes.
pub(crate) fn forget_in_txn(store: &Store, txn: &mut RwTxn<'_>, asset: EntityId) -> Result<()> {
    FROM_HOME.delete(store, txn, &HexId(asset))?;
    Ok(())
}
