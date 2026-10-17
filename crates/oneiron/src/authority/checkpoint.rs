//! The checkpoint v2 images this vault built and keeps (OF-469): each image's
//! canonical bytes keyed by its id, and the head of the local chain. A kept
//! image is decoded and checked on every read, never trusted: trust is a
//! quorum attestation and an adoption. Raw history is retained.
//!
//! The host writes an image and then attests it with its own root, in two
//! phases: the image is kept even when attesting fails, and the attested head
//! moves only once the stored attestations reach the policy's quorum.
use serde::Deserialize;

use super::checkpoint_image::{AuthorityCheckpointV2, checkpoint_image_id};
use super::*;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_AUTHORITY_LOG;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{
    Vault,
    error::{Error, Result},
};

/// The id of the newest image of this vault's local checkpoint chain. Key: ().
const CHECKPOINT_HEAD: SideTable<(), [u8; 32], Raw> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_V2_HEAD);
/// One checkpoint v2 image's canonical bytes. Key: the image id.
const CHECKPOINT_IMAGE: SideTable<[u8; 32], Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHORITY_CHECKPOINT_V2_IMAGE);

/// The rows an image's bytes account for, read without the rest of it.
#[derive(Deserialize)]
struct AccountedOnly {
    covered: Vec<AuthorityEntryHash>,
    unresolved: HeldOnly,
}

#[derive(Deserialize)]
struct HeldOnly {
    held: Vec<AuthorityEntryHash>,
}

/// The id of this vault's newest kept image, unchecked.
pub(super) fn checkpoint_head_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<[u8; 32]>> {
    CHECKPOINT_HEAD.get(store, txn, &())
}

/// Keeps `bytes` at `id` and makes it the head, in the caller's transaction.
/// The caller has checked that `id` is the id of `bytes`.
pub(super) fn keep_checkpoint_head_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
    bytes: Vec<u8>,
) -> Result<()> {
    CHECKPOINT_IMAGE.put(store, wtxn, id, &bytes)?;
    CHECKPOINT_HEAD.put(store, wtxn, &(), id)
}

/// Whether this vault holds authority rows its head image does not account
/// for. An image accounts for every row held when it was built, each either
/// covered or named in `unresolved.held`, and raw rows are retained, so a
/// larger held count is new history. With no head, any held row is growth.
fn authority_rows_grown_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<bool> {
    let mut held = 0_usize;
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_AUTHORITY_LOG, None)? {
        id?;
        held += 1;
    }
    let Some(head) = CHECKPOINT_HEAD.get(store, txn, &())? else {
        return Ok(held > 0);
    };
    let bytes = CHECKPOINT_IMAGE
        .get(store, txn, &head)?
        .ok_or_else(invalid_authority)?;
    let accounted: AccountedOnly = bytes
        .strip_prefix(AUTHORITY_CHECKPOINT_V2_DOMAIN)
        .and_then(|body| rmp_serde::from_slice(body).ok())
        .ok_or_else(invalid_authority)?;
    Ok(held > accounted.covered.len() + accounted.unresolved.held.len())
}

/// One kept image's canonical bytes, unchecked.
pub(super) fn checkpoint_image_bytes_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    CHECKPOINT_IMAGE.get(store, txn, id)
}

/// The local checkpoint head and the rows its image covers, read without
/// trusting it: naming a hash as covered history to fetch is not trust.
pub(super) fn checkpoint_head_coverage_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<([u8; 32], Vec<AuthorityEntryHash>)>> {
    let Some(head) = CHECKPOINT_HEAD.get(store, txn, &())? else {
        return Ok(None);
    };
    let covered = match CHECKPOINT_IMAGE.get(store, txn, &head)? {
        Some(bytes) => super::checkpoint_image::covered_of(&bytes)?,
        None => Vec::new(),
    };
    Ok(Some((head, covered)))
}

impl Vault {
    /// Builds this vault's checkpoint v2 image, links it after the current
    /// head and keeps it as the new head, then attests it with `issuer`'s host
    /// root; returns its id. The write compares the head again: a moved head
    /// refuses, and the caller builds again. A chain never forgets coverage:
    /// an image covering less than the head refuses.
    ///
    /// Two phases: the image is kept once its transaction commits, and an
    /// attesting failure after that returns the error with the image kept
    /// unattested. The attested head moves only when the stored attestations
    /// reach the policy's quorum ([`Vault::host_attest_authority_checkpoint`]).
    pub fn write_authority_checkpoint_v2(&self, issuer: &HostSlipIssuer) -> Result<[u8; 32]> {
        let (image, head) = {
            let txn = self.store.env.read_txn()?;
            let mut image = self.build_authority_checkpoint_v2_in_txn(&txn)?;
            let head = CHECKPOINT_HEAD.get(&self.store, &txn, &())?;
            if let Some(head) = head {
                let bytes = CHECKPOINT_IMAGE
                    .get(&self.store, &txn, &head)?
                    .ok_or_else(invalid_authority)?;
                let parent = AuthorityCheckpointV2::decode(&bytes)?;
                if checkpoint_image_id(&bytes) != head
                    || parent.vault_id != image.vault_id
                    || parent
                        .covered
                        .iter()
                        .any(|hash| image.covered.binary_search(hash).is_err())
                {
                    return Err(invalid_authority());
                }
            }
            image.parent = head;
            (image, head)
        };
        let bytes = image.encode()?;
        let id = checkpoint_image_id(&bytes);
        let mut txn = self.store.env.write_txn()?;
        if CHECKPOINT_HEAD.get(&self.store, &txn, &())? != head {
            return Err(Error::ConcurrentWrite("authority checkpoint head moved"));
        }
        keep_checkpoint_head_in_txn(&self.store, &mut txn, &id, bytes)?;
        txn.commit()?;
        self.host_attest_authority_checkpoint(issuer, id)?;
        Ok(id)
    }

    /// The host's checkpoint upkeep (OF-469): when this vault holds authority
    /// rows its head image does not account for, writes and host-attests a
    /// new image ([`Vault::write_authority_checkpoint_v2`]) and returns its
    /// id; otherwise None. A vault that adopted an image writes none: its
    /// builder folds held rows only and cannot extend the adopted baseline.
    pub fn upkeep_authority_checkpoint(&self, issuer: &HostSlipIssuer) -> Result<Option<[u8; 32]>> {
        let due = {
            let txn = self.store.env.read_txn()?;
            !super::checkpoint_adopt::checkpoint_adopted_in_txn(&self.store, &txn)?
                && authority_rows_grown_in_txn(&self.store, &txn)?
        };
        if !due {
            return Ok(None);
        }
        self.write_authority_checkpoint_v2(issuer).map(Some)
    }

    /// The kept image `id` names, decoded and checked against its id. Not
    /// trusted: an attestation and an adoption decide trust.
    pub fn authority_checkpoint_v2(&self, id: &[u8; 32]) -> Result<Option<AuthorityCheckpointV2>> {
        let txn = self.store.env.read_txn()?;
        let Some(bytes) = CHECKPOINT_IMAGE.get(&self.store, &txn, id)? else {
            return Ok(None);
        };
        let image = AuthorityCheckpointV2::decode(&bytes)?;
        if checkpoint_image_id(&bytes) != *id {
            return Err(invalid_authority());
        }
        Ok(Some(image))
    }

    /// The id of this vault's newest kept image.
    pub fn authority_checkpoint_v2_head(&self) -> Result<Option<[u8; 32]>> {
        let txn = self.store.env.read_txn()?;
        CHECKPOINT_HEAD.get(&self.store, &txn, &())
    }
}
