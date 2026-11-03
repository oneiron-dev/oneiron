//! The target index's seal (FIX 4296): a running digest over every control
//! put one target's machine-history index takes, kept in the writer that
//! takes it, so it commits or rolls back with the put.
//!
//! Each put chains the control's id and its body as the codec writes it.
//! Two equal seals name the same puts in the same order, and a control's
//! row is immutable under its content-addressed id, so a reader that carried
//! what it read at one seal reads only what was put since
//! (`history_advance`). A control's delete scatters its target's seal and a
//! history's retire drops it, so no carried read outlives its row.

use rand_core::RngCore;

use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::Result;
use crate::side_table::{Raw, SideTable};
use crate::store::Store;

use super::ClaimBody;
use super::history_store::machine_history_kind;

const SEAL: SideTable<EntityId, [u8; 40], Raw> =
    SideTable::new(&crate::side_table::CLAIM_MACHINE_HISTORY_SEAL);
const SEAL_DOMAIN: &str = "oneiron/machine-history-index-seal/v1";

/// How many control puts a target's index took, and their chained digest.
/// The default is a target no put reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IndexSeal {
    puts: u64,
    digest: [u8; 32],
}

impl IndexSeal {
    /// The seal after one more put: the control `id`, whose body digest
    /// ([`control_body_digest`]) is `body`.
    pub(crate) fn after(self, id: EntityId, body: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(SEAL_DOMAIN);
        hasher.update(&self.digest);
        hasher.update(id.as_bytes());
        hasher.update(body);
        Self {
            puts: self.puts.saturating_add(1),
            digest: *hasher.finalize().as_bytes(),
        }
    }

    fn encode(self) -> [u8; 40] {
        let mut out = [0; 40];
        out[..8].copy_from_slice(&self.puts.to_be_bytes());
        out[8..].copy_from_slice(&self.digest);
        out
    }

    fn decode(bytes: [u8; 40]) -> Self {
        let mut puts = [0; 8];
        puts.copy_from_slice(&bytes[..8]);
        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes[8..]);
        Self {
            puts: u64::from_be_bytes(puts),
            digest,
        }
    }
}

/// The digest a control's put chains into its target's seal: its body as
/// the claim codec writes it.
pub(crate) fn control_body_digest(body: &ClaimBody) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&super::encode_claim_body(body)?).as_bytes())
}

/// `target`'s index seal in `txn`.
pub(crate) fn read_index_seal(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<IndexSeal> {
    Ok(SEAL
        .get(store, txn, &target)?
        .map(IndexSeal::decode)
        .unwrap_or_default())
}

/// Chains one control put, `id` with `body`, into `target`'s seal, in the
/// writer that puts it.
pub(crate) fn chain_index_seal_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    id: EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let seal = read_index_seal(store, wtxn, target)?.after(id, &control_body_digest(body)?);
    SEAL.put(store, wtxn, &target, &seal.encode())
}

/// Drops `target`'s seal with its index, when its history retires.
pub(crate) fn drop_index_seal_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
) -> Result<()> {
    SEAL.delete(store, wtxn, &target)?;
    Ok(())
}

/// Before the row at `id` is deleted: when it is a machine-history control,
/// its target's seal, if any, takes a random digest, so no read carried at
/// an earlier seal stands for the deleted row. Any other row is left alone.
pub(crate) fn scatter_index_seal_for_delete(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, id)? else {
        return Ok(());
    };
    if !EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
    {
        return Ok(());
    }
    let Ok(body) = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
        return Ok(());
    };
    let (Some(_), super::ClaimSubject::Entity(target)) =
        (machine_history_kind(&body.predicate), body.subject)
    else {
        return Ok(());
    };
    let Some(stored) = SEAL.get(store, wtxn, &target)? else {
        return Ok(());
    };
    let mut seal = IndexSeal::decode(stored);
    rand_core::OsRng.fill_bytes(&mut seal.digest);
    SEAL.put(store, wtxn, &target, &seal.encode())
}
