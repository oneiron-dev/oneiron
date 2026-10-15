//! Shared-bytes impact for the delete preview: whether the record is the last holder of its
//! bytes or one of several. Read-only; release itself stays with the owning lifecycles.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// One content hash the previewed record holds, and every other record in this vault that keeps
/// the same bytes from release. A default delete drops only this record's hold. When the
/// previewed record is the bytes' carrier (the content-addressed ASSET), the other holders are
/// every record that reads them through it: a plain delete of it takes the bytes from all of
/// them, and the erase door refuses it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldBytes {
    content_hash: [u8; 32],
    other_holders: Vec<EntityId>,
}

impl HeldBytes {
    pub fn content_hash(&self) -> [u8; 32] {
        self.content_hash
    }

    /// The other holders, sorted. These are the records an erase with the same-bytes flag
    /// also erases.
    pub fn other_holders(&self) -> &[EntityId] {
        &self.other_holders
    }

    /// N in "one of N": this record and every other holder.
    pub fn holders(&self) -> usize {
        self.other_holders.len() + 1
    }

    /// No other record holds these bytes: deleting this record releases them.
    pub fn is_last_reference(&self) -> bool {
        self.other_holders.is_empty()
    }
}

/// One distinct chunk of the previewed LFS object, and every other owner that keeps it from
/// collection. Another owner holds different contents that share this chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfsChunkImpact {
    chunk_hash: [u8; 32],
    other_owners: Vec<EntityId>,
}

impl LfsChunkImpact {
    pub fn chunk_hash(&self) -> [u8; 32] {
        self.chunk_hash
    }

    pub fn other_owners(&self) -> &[EntityId] {
        &self.other_owners
    }

    /// N in "one of N": this object and every other owner.
    pub fn owners(&self) -> usize {
        self.other_owners.len() + 1
    }

    /// No other owner holds this chunk: deleting the object lets it be collected.
    pub fn is_last_reference(&self) -> bool {
        self.other_owners.is_empty()
    }
}

/// Both impact lists for the stored record `raw` at `id`, read in `txn`.
pub(super) fn bytes_impact_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<(Vec<HeldBytes>, Vec<LfsChunkImpact>)> {
    let mut held = Vec::new();
    for content_hash in
        crate::blob_artifact::held_content_hashes_in_txn(&vault.store, txn, id, raw)?
    {
        let mut other_holders =
            crate::blob_artifact::content_holders_in_txn(&vault.store, txn, &content_hash)?;
        other_holders.retain(|holder| holder != id);
        held.push(HeldBytes {
            content_hash,
            other_holders,
        });
    }
    let chunks = crate::origin::lfs::lfs_chunk_owners_in_txn(&vault.store, txn, id, raw)?
        .into_iter()
        .map(|(chunk_hash, other_owners)| LfsChunkImpact {
            chunk_hash,
            other_owners,
        })
        .collect();
    Ok((held, chunks))
}
