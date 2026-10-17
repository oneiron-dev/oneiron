//! The checkpoint v2 images this vault built and keeps (OF-469): each image's
//! canonical bytes keyed by its id, and the head of the local chain. A kept
//! image is decoded and checked on every read, never trusted: trust is a
//! quorum attestation and an adoption. Raw history is retained.
use super::checkpoint_image::{AuthorityCheckpointV2, checkpoint_image_id};
use super::*;
use crate::side_table::{self, Raw, SideTable};
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
    /// head and keeps it as the new head; returns its id. The write compares
    /// the head again: a moved head refuses, and the caller builds again. A
    /// chain never forgets coverage: an image covering less than the head
    /// refuses.
    pub fn write_authority_checkpoint_v2(&self) -> Result<[u8; 32]> {
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
        CHECKPOINT_IMAGE.put(&self.store, &mut txn, &id, &bytes)?;
        CHECKPOINT_HEAD.put(&self.store, &mut txn, &(), &id)?;
        txn.commit()?;
        Ok(id)
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
