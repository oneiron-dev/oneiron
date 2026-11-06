//! The proof that a file-plane ASSET's body came to this machine from its
//! home (FIX 14534, Engine 11-06 19:59 call). The own-device client writes it
//! in the commit that lands a body its proven home served; no server,
//! federation or offline landing writes one. The owner's discard of a world
//! copy releases a file-plane ASSET only while its stored manifest still
//! names the body proved here: the home could serve those exact bytes, so
//! this copy is not their only one. A body this machine wrote, or one no
//! proof names, stays.

use heed::{RoTxn, RwTxn};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;

/// The body an ASSET's file holds that its home served, by the ASSET's id:
/// the home machine (16 bytes), the carrier's BLAKE3 (32), the body's BLAKE3
/// (32) and its length (u64 big-endian). Key: hex32 (ASSET id).
const FROM_HOME: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_ASSET_BODY_FROM_HOME);

/// A body the home served for one ASSET.
pub(crate) struct HomeBodyProof {
    /// The machine the client's connection proved as its home.
    pub(crate) home: EntityId,
    /// BLAKE3 of the whole carrier the window bound the body to.
    pub(crate) carrier_blake3: [u8; 32],
    pub(crate) body_blake3: [u8; 32],
    pub(crate) len: u64,
}

impl HomeBodyProof {
    fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(88);
        raw.extend_from_slice(self.home.as_bytes());
        raw.extend_from_slice(&self.carrier_blake3);
        raw.extend_from_slice(&self.body_blake3);
        raw.extend_from_slice(&self.len.to_be_bytes());
        raw
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != 88 {
            return None;
        }
        Some(Self {
            home: EntityId::from_bytes(raw[..16].try_into().ok()?).ok()?,
            carrier_blake3: raw[16..48].try_into().ok()?,
            body_blake3: raw[48..80].try_into().ok()?,
            len: u64::from_be_bytes(raw[80..88].try_into().ok()?),
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
/// under `body_blake3` that the ASSET `asset` stores now. A proof that
/// does not decode proves nothing.
pub(crate) fn received_from_home_in(
    store: &Store,
    txn: &RoTxn<'_>,
    asset: EntityId,
    body_blake3: &[u8; 32],
    len: u64,
) -> Result<bool> {
    Ok(FROM_HOME
        .get(store, txn, &HexId(asset))?
        .and_then(|raw| HomeBodyProof::decode(&raw))
        .is_some_and(|proof| proof.body_blake3 == *body_blake3 && proof.len == len))
}

/// Forgets the proof for the ASSET `asset`, whose row the owner's discard
/// takes.
pub(crate) fn forget_in_txn(store: &Store, txn: &mut RwTxn<'_>, asset: EntityId) -> Result<()> {
    FROM_HOME.delete(store, txn, &HexId(asset))?;
    Ok(())
}
