//! Where a receipt query reads its served forms (FIX 7355): base, or a room's
//! view.
//!
//! A canonical query reads base. A query in a room reads the room's overlay ∪
//! base, so the served forms the room's own reads kept there join the family
//! before it is ordered, screened, refilled and cut, and each row a served
//! form names is placed as the room holds it. The world settings, the scan
//! thresholds and every other family's source stay the vault's. The mirror is
//! one-way: the room sees the vault and itself; the vault never sees the room,
//! and no scan check the vault keeps counts a row of the room.

use super::kernel::{ReceiptQuery, ReceiptRecord};
use super::record::served_form_receipts;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::scan_check::PendingScanChecks;
use crate::settings::ReadDestination;
use crate::store::{ManifestDbs, StoreRead};

/// The content target a receipt query's served forms are read from, and the
/// scan checks their walk raises.
#[derive(Clone, Copy)]
pub(crate) struct ReceiptContent<'a> {
    read: StoreRead<'a>,
    pending: &'a PendingScanChecks,
}

impl<'a> ReceiptContent<'a> {
    /// The vault's own store, for every canonical query.
    pub(crate) fn base(vault: &'a Vault) -> Self {
        Self {
            read: vault.store.read(),
            pending: ManifestDbs::pending_scan_checks(&vault.store),
        }
    }

    /// A room read's content target `read` (`ScopedRead::store_read`): its
    /// overlay ∪ base, whose scan checks wait with the room in
    /// `room_pending`. Where the read's key reads base alone, so does this
    /// target, and its checks are the vault's.
    pub(crate) fn of_room(read: StoreRead<'a>, room_pending: &'a PendingScanChecks) -> Self {
        let pending = if read.is_union() {
            room_pending
        } else {
            ManifestDbs::pending_scan_checks(read.base())
        };
        Self { read, pending }
    }

    /// The served-form receipts `query` matches, read from this target in
    /// `txn`, newest first up to its limit.
    pub(super) fn served_forms(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        query: &ReceiptQuery,
    ) -> Result<Vec<ReceiptRecord>> {
        served_form_receipts(vault, &self.read, txn, query, self.pending)
    }

    /// Of `rows`, the ones a read toward `destination` may name, each placed
    /// as this target holds it, under the vault's world settings.
    pub(super) fn off_device_readable(
        &self,
        vault: &Vault,
        rows: Vec<EntityId>,
        destination: &ReadDestination,
    ) -> Result<Vec<EntityId>> {
        crate::settings::off_device_readable_in(vault, &self.read, rows, destination)
    }
}
