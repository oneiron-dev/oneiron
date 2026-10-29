//! The host's delivery of an export-first removal's archive to its removed
//! holder (FIX 3215, 3396), beside the pull doors. A removed device opens a
//! delivery session with the same proof the pull doors take: the slip its
//! removal revoked, its holder's signature over a fresh request challenge,
//! the nonce spent once. Nothing of live membership is consulted or given
//! back. The bytes a session releases are the pull doors' own, read by
//! their readers: the removed Owner's stored copy, or a transferred holder's
//! copy cut down to what its caveats admit.
//!
//! The ledger keeps, per archive and holder, the delivery each was last
//! sent and the one it acknowledged, never an archive byte. A delivery's
//! version is the archive's own `delivered_at`, so a remaining Owner's
//! re-run of the removal makes it owed again. A holder is Acked once it
//! acknowledged the archive's current version, Delivered once that version
//! was sent to it, and Pending otherwise, a holder never seen included:
//! an offline device stays Pending, and no removal waits on it.

use super::*;
use crate::side_table::{self, Named, SideTable};

/// Each holder's delivery of each removal archive. Key: hex32 (removed
/// person) ":" hex32 (receipt id) ":" hex64 (holder binding key).
const REMOVAL_DELIVERY: SideTable<String, DeliveryCursor, Named> =
    SideTable::new(&side_table::SHARED_ACT_REMOVAL_DELIVERY);

/// Where one holder stands with one archive: the delivery versions it was
/// last sent and last acknowledged, each the archive's `delivered_at`.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryCursor {
    delivered: u64,
    acked: u64,
}

/// The ledger key of `holder`'s delivery of `person`'s archive `receipt_id`.
fn delivery_key(person: EntityId, receipt_id: &str, holder: [u8; 32]) -> String {
    format!(
        "{}:{receipt_id}:{}",
        person.to_hex(),
        crate::entity_id::bytes_to_hex_lower(&holder)
    )
}

impl Vault {
    /// The archives owed to the holder of `slip`, under the same proof as
    /// [`Vault::removed_owner_exports`] (the nonce spent once), with the
    /// person the slip names. Each is the copy that door answers, within its
    /// term, with its delivery version; one the holder acknowledged at its
    /// current version is not sent again. Each sent is Delivered at that
    /// version from now, in the same writer that spends the nonce.
    pub fn removal_deliveries(
        &self,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
    ) -> Result<(EntityId, Vec<(u64, RemovalExportCopy)>)> {
        let mut txn = self.store.env.write_txn()?;
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let now = self.store.clock.now_recorded_at();
        let copies = match slip.transferred_bounds() {
            None => self.removal_exports_in_txn(&txn, person, now)?,
            Some(bounds) => {
                let admits = transferred_admission(bounds, now);
                self.projected_removal_exports_in_txn(&txn, person, now, &admits)?
            }
        };
        let holder = slip.current_binding_key();
        let mut owed = Vec::new();
        for copy in copies {
            let key = delivery_key(person, &copy.receipt_id, holder);
            let mut cursor = REMOVAL_DELIVERY
                .get(&self.store, &txn, &key)?
                .unwrap_or_default();
            let version = copy.delivered_at;
            if cursor.acked >= version {
                continue;
            }
            cursor.delivered = cursor.delivered.max(version);
            REMOVAL_DELIVERY.put(&self.store, &mut txn, &key, &cursor)?;
            owed.push((version, copy));
        }
        txn.commit()?;
        Ok((person, owed))
    }

    /// The holder of `slip` acknowledges `version` of the archive the
    /// removal receipt `receipt_id` delivered, under the same proof (the
    /// nonce spent once; a malformed `receipt_id` is refused before it is).
    /// `true` once the holder stands Acked at the archive's current version;
    /// `false` when the archive is gone or past its term, or was delivered
    /// anew since `version`, which leaves it owed. An ack of an older
    /// version never moves the cursor back.
    pub fn ack_removal_delivery(
        &self,
        slip: &CapabilitySlip,
        request_timestamp: u64,
        signature: &[u8],
        request_nonce: &[u8],
        receipt_id: &str,
        version: u64,
    ) -> Result<bool> {
        let receipt = EntityId::from_hex(receipt_id)?;
        let mut txn = self.store.env.write_txn()?;
        let person =
            self.left_person_in_txn(&mut txn, slip, request_timestamp, signature, request_nonce)?;
        let now = self.store.clock.now_recorded_at();
        // Only the archive's version is read: the ack answers no byte.
        let current = self
            .removal_export_in_txn(&txn, person, receipt, now)?
            .map(|copy| copy.delivered_at);
        let acked = match current {
            Some(current) if version == current => {
                let key = delivery_key(person, &receipt.to_hex(), slip.current_binding_key());
                let mut cursor = REMOVAL_DELIVERY
                    .get(&self.store, &txn, &key)?
                    .unwrap_or_default();
                cursor.delivered = cursor.delivered.max(version);
                cursor.acked = cursor.acked.max(version);
                REMOVAL_DELIVERY.put(&self.store, &mut txn, &key, &cursor)?;
                true
            }
            _ => false,
        };
        txn.commit()?;
        Ok(acked)
    }

    /// The host's reconciliation at its start (FIX 3396): drops each ledger
    /// row whose archive is gone or past its term, and answers how many of
    /// the rest a holder has not acknowledged at the archive's current
    /// version. An archive no holder was sent yet has no row: it is Pending
    /// for each of them until one opens a session. It reads first, and opens
    /// a writer only when a row is to go.
    pub fn reconcile_removal_deliveries(&self) -> Result<usize> {
        let (owed, gone) = {
            let txn = self.store.env.read_txn()?;
            let now = self.store.clock.now_recorded_at();
            let mut owed = 0;
            let mut gone = Vec::new();
            for (key, cursor) in REMOVAL_DELIVERY.scan(&self.store, &txn)? {
                match self.delivery_version_in_txn(&txn, &key, now)? {
                    None => gone.push(key),
                    Some(current) if cursor.acked < current => owed += 1,
                    Some(_) => {}
                }
            }
            (owed, gone)
        };
        if !gone.is_empty() {
            let mut txn = self.store.env.write_txn()?;
            let now = self.store.clock.now_recorded_at();
            for key in gone {
                // An archive a re-run delivered anew in between keeps its row.
                if self.delivery_version_in_txn(&txn, &key, now)?.is_none() {
                    REMOVAL_DELIVERY.delete(&self.store, &mut txn, &key)?;
                }
            }
            txn.commit()?;
        }
        Ok(owed)
    }

    /// Drops every ledger row of the archive the export row `export_key`
    /// names (`person:receipt`), in the caller's writer: each holder's
    /// delivery of it goes with its archive.
    pub(crate) fn drop_removal_deliveries_for_export_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        export_key: &str,
    ) -> Result<()> {
        let prefix = format!("{export_key}:");
        for (key, _) in REMOVAL_DELIVERY.scan_from(&self.store, &*txn, prefix.as_bytes())? {
            REMOVAL_DELIVERY.delete(&self.store, &mut *txn, &key)?;
        }
        Ok(())
    }

    /// The current delivery version of the archive the ledger row `key`
    /// names, `None` when it is gone or past its term at `now`, or the key
    /// names none.
    fn delivery_version_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        key: &str,
        now: u64,
    ) -> Result<Option<u64>> {
        let mut parts = key.splitn(3, ':');
        let (Some(Ok(person)), Some(Ok(receipt))) = (
            parts.next().map(EntityId::from_hex),
            parts.next().map(EntityId::from_hex),
        ) else {
            return Ok(None);
        };
        Ok(self
            .removal_export_in_txn(txn, person, receipt, now)?
            .map(|copy| copy.delivered_at))
    }
}
