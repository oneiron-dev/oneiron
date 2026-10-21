//! A restored credential row sealed again (KS-6 part 1, CALLS `KS-6 reseal
//! fault keeps image carrier`, Engine 10-21 19:5x).
//!
//! A part-1 image carries each credential row in its plaintext DTO form, as
//! on main, and the restore seals each again under the destination's
//! custody, one row per writer, so one row whose key custody cannot take
//! never leaves the others in the clear. A row that does not seal stays
//! pending in the carrier form it landed in, internal to this store (no new
//! wire), and is never opened from it on a custody fault: its open takes
//! its key from this vault's custody first and answers the typed
//! `credential_leaf_unreadable` (retry, or re-enter it) while custody still
//! faults. The custody pass, and the row's next write, seal it again. The
//! restore itself never refuses for it.

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::store::Store;
use crate::vault::Vault;

use super::{StoredValue, decode_stored_custody_body, sealed_body_in_txn};

/// What a restored credential row custody could not seal again is (CALLS
/// `KS-6 reseal fault keeps image carrier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyResealPending {
    /// It keeps the carrier form it landed in, here alone, and opens only
    /// once this vault's custody takes its key: never from its carrier on a
    /// custody fault, which answers `credential_leaf_unreadable`. The
    /// custody pass and its next write seal it again; the restore goes on.
    KeepCarrierOpenOnlyThroughCustody,
}

pub(crate) const CUSTODY_RESEAL_PENDING: CustodyResealPending =
    CustodyResealPending::KeepCarrierOpenOnlyThroughCustody;

/// Retries, for an open of pending record `id`, the key its seal takes at
/// `generation`: read, or minted, published and journaled, under this
/// store's custody, with no LMDB write and no guard. An error, the opener's
/// `credential_leaf_unreadable`, while custody still faults.
pub(super) fn retry_pending_key(store: &Store, id: &EntityId, generation: u32) -> Result<()> {
    match CUSTODY_RESEAL_PENDING {
        CustodyResealPending::KeepCarrierOpenOnlyThroughCustody => {}
    }
    store.retake_credential_value_leaf(id, generation)
}

/// Seals again pending row `id` in `wtxn`, keeping its times: whether it
/// was one.
fn reseal_row_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(raw) = vault.store.port_entity_raw_wiped(wtxn, id)? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("secret custody entity header"))?;
    let stored = decode_stored_custody_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    let StoredValue::Carrier(value) = stored.value else {
        return Ok(false);
    };
    let mut record = stored.record;
    record.value_bytes = value.to_vec();
    let data = sealed_body_in_txn(&vault.store, wtxn, id, &record);
    zeroize::Zeroize::zeroize(&mut record.value_bytes);
    let occurred = crate::temporal::TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    super::super::doors::apply_custody_body_in_txn(
        &super::super::doors::CustodyWrite::of(vault),
        wtxn,
        id,
        &record,
        data?,
        (occurred, header.learned_at),
    )?;
    Ok(true)
}

/// What one pass sealed again, and what stays pending.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ResealPass {
    pub(crate) sealed: usize,
    pub(crate) pending: usize,
}

impl Vault {
    /// Seals again, under this vault's custody, each credential row still
    /// in a checkpoint image's carrier form (KS-6 part 1: images carry the
    /// opened value until part 2), each in a writer of its own, keeping its
    /// times: a restored value rests sealed as every other does. A row
    /// custody cannot take a key for stays pending, warned by key and kind,
    /// and the rest are sealed all the same.
    ///
    /// # Errors
    /// Storage faults listing the rows; never a row's own.
    pub(crate) fn reseal_credential_carriers(&self) -> Result<ResealPass> {
        let carriers = {
            let txn = self.store.env.read_txn()?;
            let mut carriers = Vec::new();
            for entry in
                self.store
                    .port_entity_ids_by_type(&txn, ENTITY_TYPE_SECRET_CUSTODY, None)?
            {
                let id = entry?;
                if super::read_stored_custody_in_txn(&self.store, &txn, &id).is_ok_and(|stored| {
                    stored.is_some_and(|stored| matches!(stored.value, StoredValue::Carrier(_)))
                }) {
                    carriers.push(id);
                }
            }
            carriers
        };
        let mut pass = ResealPass::default();
        for id in carriers {
            match self.with_write_txn(|wtxn| reseal_row_in_txn(self, wtxn, &id)) {
                Ok(true) => pass.sealed = pass.sealed.saturating_add(1),
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        credential = %id.to_hex(),
                        kind = ?error.kind(),
                        "a restored credential row was not sealed again; it stays pending, never \
                         opened from its carrier on a custody fault"
                    );
                    pass.pending = pass.pending.saturating_add(1);
                }
            }
        }
        Ok(pass)
    }

    /// [`Self::reseal_credential_carriers`] for a pass that must not stop
    /// on it (a restore's landing, the custody pass): a fault is warned by
    /// kind and leaves every pending row as it is, for the next pass.
    pub(crate) fn reseal_credential_carriers_warned(&self) {
        match self.reseal_credential_carriers() {
            Ok(ResealPass { pending: 0, .. }) => {}
            Ok(ResealPass { sealed, pending }) => tracing::warn!(
                sealed,
                pending,
                "restored credential rows stay pending until custody takes their keys"
            ),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                "restored credential rows were not sealed again this pass; each stays pending"
            ),
        }
    }
}
