//! The compartments a capture seals its owners under (KS7-5): each owner's
//! active incarnation, or a newly minted one, and the leaf at its
//! generation, minted while unpublished in one write of their own. The
//! write is a backup's bookkeeping, never content: the backup watermark
//! does not read it as a change.

use std::collections::BTreeSet;

use heed::RwTxn;
use zeroize::Zeroizing;

use super::instance::{self, PayloadInstance};
use super::rows::OwnerRef;
use crate::error::Result;
use crate::store::{BackupWriteClass, Callback, Rows, Store};

/// One compartment a capture seals under: its incarnation and its leaf key.
pub(crate) type CaptureCompartment = (PayloadInstance, Zeroizing<[u8; 32]>);

impl Store {
    /// The compartment each of `owners` is sealed under, with its leaf key.
    /// An owner erased since is left out: its rows are omitted, and no leaf
    /// is minted for it. `None` for an archived vault, whose custody is its
    /// replacement's: its image is taken whole, as with no payload. The
    /// caller holds the custody read guard from before this write until its
    /// last seal ([`Self::checkpoint_payload_keys_in_txn`]).
    ///
    /// # Errors
    ///
    /// Storage and custody faults, and an incarnation whose retirement is
    /// staged.
    pub(crate) fn checkpoint_payload_compartments(
        &self,
        owners: &BTreeSet<OwnerRef>,
    ) -> Result<Option<Vec<CaptureCompartment>>> {
        if self.core.gate_custody_archived() {
            return Ok(None);
        }
        if owners.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let class = BackupWriteClass::BackupMetadata;
        self.group_write_classed(Callback::Opaque, class, |txn| {
            let compartments = self.compartments_in_txn(txn, owners);
            match compartments {
                Ok(compartments) => Rows::Commit(Some(compartments)),
                Err(error) => Rows::Discard(Err(error)),
            }
        })
    }

    fn compartments_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        owners: &BTreeSet<OwnerRef>,
    ) -> Result<Vec<CaptureCompartment>> {
        let mut instances = Vec::with_capacity(owners.len());
        for owner in owners {
            if let Some(found) =
                instance::active_or_mint_in_txn(self, wtxn, owner.subtype, &owner.owner32)?
            {
                instances.push(found);
            }
        }
        let keys = self.checkpoint_payload_keys_in_txn(wtxn, &instances)?;
        Ok(instances.into_iter().zip(keys).collect())
    }
}
