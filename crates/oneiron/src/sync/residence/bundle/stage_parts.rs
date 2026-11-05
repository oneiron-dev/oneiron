//! One staged upload's immutable identity and its parts (FIX 9254).
//!
//! Every stage header carries a 16-byte identity minted when its upload starts
//! (offset 0); the upload's parts live under that identity, not under the
//! mutable (machine, object) pair, so a detached header keeps reading its exact
//! bytes while the machine stages its next upload. A header update (offset > 0)
//! retains its identity; a restart (offset 0) mints an independent one whose
//! part prefix is unused in the writer. Ordinary idle/restart/commit drops read
//! the header first and delete only its identity's parts, then the header.

use super::{
    STAGE_LEN, STAGE_PARTS, STAGES, SealedBundleObject, SealedBundleStage, decode_stage, hex,
    stage_key,
};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};

const IDENTITIES: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_COMMIT_RECEIPT);

fn identity_key(id: &[u8; 16]) -> String {
    format!("stage-identity:{}", hex(id))
}

pub(super) fn reserve_identity(vault: &Vault, txn: &mut heed::RwTxn<'_>) -> Result<[u8; 16]> {
    loop {
        let id = crate::world_keys::SealedBundleGeneration::fresh(0)?.nonce;
        if IDENTITIES
            .get_bytes(&vault.store, txn, &identity_key(&id))?
            .is_some()
        {
            continue;
        }
        let occupied = STAGE_PARTS
            .iter_raw_from(&vault.store, txn, stage_parts_prefix(&id).as_bytes())?
            .next()
            .transpose()?
            .is_some();
        if occupied {
            continue;
        }
        IDENTITIES.put(&vault.store, txn, &identity_key(&id), &vec![0])?;
        return Ok(id);
    }
}

pub(super) fn release_identity(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &[u8; 16],
) -> Result<()> {
    IDENTITIES.delete(&vault.store, txn, &identity_key(id))?;
    Ok(())
}

/// The identity a stage header names: its last 16 bytes.
pub(super) fn stage_identity(header: &[u8]) -> Result<[u8; 16]> {
    if header.len() != STAGE_LEN {
        return Err(Error::InvalidKey);
    }
    header[80..96].try_into().map_err(|_| Error::InvalidKey)
}

/// The [`STAGE_PARTS`] prefix one identity's parts live under, trailing colon.
pub(super) fn stage_parts_prefix(identity: &[u8; 16]) -> String {
    format!("{}:", hex(identity))
}

/// Drops one staged upload: its identity's parts, then its header. Reads the
/// header first; a header that names no identity drops its row alone.
pub(super) fn drop_stage_in(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, key: &str) -> Result<()> {
    if let Some(header) = STAGES.get_bytes(&vault.store, wtxn, &key.to_owned())?
        && let Ok(identity) = stage_identity(&header)
    {
        STAGE_PARTS.delete_from(&vault.store, wtxn, stage_parts_prefix(&identity).as_bytes())?;
        release_identity(vault, wtxn, &identity)?;
    }
    STAGES.delete(&vault.store, wtxn, &key.to_owned())?;
    Ok(())
}

/// The object one header's identity staged whole: every part from offset 0,
/// contiguous, its total long, its digest matching. `None` otherwise. The
/// header may be an ordinary row or a detached one the caller holds.
pub(super) fn retained_stage_whole(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    header: &[u8],
    object: SealedBundleObject,
) -> Result<Option<(SealedBundleStage, Vec<u8>)>> {
    let Ok((_, stage, _)) = decode_stage(header, object) else {
        return Ok(None);
    };
    let Ok(identity) = stage_identity(header) else {
        return Ok(None);
    };
    let prefix = stage_parts_prefix(&identity);
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(usize::try_from(stage.total).map_err(|_| Error::InvalidKey)?)
        .map_err(|_| Error::InvalidKey)?;
    for row in STAGE_PARTS.iter_raw_from(&vault.store, txn, prefix.as_bytes())? {
        let (row_key, part) = row?;
        if row_key != format!("{prefix}{:016x}", bytes.len()).into_bytes()
            || bytes.len() as u64 + part.len() as u64 > stage.total
        {
            return Ok(None);
        }
        bytes.extend_from_slice(&part);
    }
    Ok(
        (bytes.len() as u64 == stage.total && *blake3::hash(&bytes).as_bytes() == stage.digest)
            .then_some((stage, bytes)),
    )
}

/// The object the machine staged whole under `object`, with its binding: every
/// part from offset 0, contiguous, its total long, its digest matching. `None`
/// otherwise.
pub(super) fn staged_whole(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    machine: EntityId,
    object: SealedBundleObject,
) -> Result<Option<(SealedBundleStage, Vec<u8>)>> {
    let key = stage_key(machine, object);
    let Some(header) = STAGES.get_bytes(&vault.store, txn, &key)? else {
        return Ok(None);
    };
    retained_stage_whole(vault, txn, &header, object)
}
