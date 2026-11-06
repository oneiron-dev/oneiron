//! The compartments a capture seals its owners under (KS7-5): each owner's
//! active incarnation, or a newly minted one, and the leaf at its
//! generation, minted while unpublished in one write of their own. The
//! write is a backup's bookkeeping, never content: the backup watermark
//! does not read it as a change.

use std::collections::{BTreeMap, BTreeSet};

use heed::RwTxn;
use zeroize::Zeroizing;

use super::Subtype;
use super::instance::{self, PayloadInstance, PayloadSource};
use super::retirement::{PayloadDisposition, settle_owner_in_txn};
use super::rows::OwnerRef;
use crate::EntityId;
use crate::error::Result;
use crate::ports::{DeletionMarker, TombstoneStoreRead};
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
        source_originals: &BTreeMap<EntityId, EntityId>,
    ) -> Result<Option<Vec<CaptureCompartment>>> {
        if self.core.gate_custody_archived() {
            return Ok(None);
        }
        if owners.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let class = BackupWriteClass::BackupMetadata;
        self.group_write_classed(Callback::Opaque, class, |txn| {
            let compartments = self.compartments_in_txn(txn, owners, source_originals);
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
        source_originals: &BTreeMap<EntityId, EntityId>,
    ) -> Result<Vec<CaptureCompartment>> {
        let mut originals = instance::scoped_touch_sources_in_txn(self, wtxn)?;
        for (&entity, &original) in source_originals {
            if originals
                .insert(entity, original)
                .is_some_and(|known| known != original)
            {
                return Err(super::corrupt());
            }
        }
        let mut instances = Vec::with_capacity(owners.len());
        for owner in owners {
            let source = match owner.subtype {
                Subtype::EntityTree | Subtype::AttachmentOccurrence => {
                    let entity = EntityId::from_bytes(
                        owner.owner32[..16]
                            .try_into()
                            .map_err(|_| super::corrupt())?,
                    )?;
                    originals
                        .get(&entity)
                        .map_or(PayloadSource::Unbound, |original| {
                            PayloadSource::ScopedTouch(*original)
                        })
                }
                Subtype::CodeDocument | Subtype::OutboundCall => PayloadSource::Unbound,
            };
            if let PayloadSource::ScopedTouch(original) = source
                && self
                    .port_deletion_marker(wtxn, DeletionMarker::HardDelete, &original)?
                    .as_deref()
                    .and_then(crate::deletion::privacy_erasure_info)
                    .is_some()
            {
                settle_owner_in_txn(
                    self,
                    wtxn,
                    owner.subtype,
                    &owner.owner32,
                    PayloadDisposition::Erase,
                )?;
                continue;
            }
            if let Some(found) =
                instance::active_or_mint_in_txn(self, wtxn, owner.subtype, &owner.owner32, source)?
            {
                instances.push(found);
            }
        }
        let keys = self.checkpoint_payload_keys_in_txn(wtxn, &instances)?;
        Ok(instances.into_iter().zip(keys).collect())
    }
}
