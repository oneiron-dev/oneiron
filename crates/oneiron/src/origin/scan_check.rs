//! Origin scans never refuse for how many rows they read (rule 5: ARCH-0044
//! C5, OF-520).
//!
//! Each origin scan over a table that grows with use has a threshold row. A
//! scan that reads past its row raises one [`OriginScanCheck`] for its scope
//! and reads on: the check is evidence for the host's "is everything okay"
//! question, never a refusal. Only machine floors (disk, memory) stop a scan.

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;

/// Rows one origin scan reads past which it asks whether everything is
/// okay: ten times the count each of these scans once refused at.
pub const DEFAULT_ORIGIN_SCAN_CHECK_THRESHOLD: u64 = 1_000_000;

/// Device-local threshold row of one scan. Key: the scan's tag.
const POLICY: SideTable<[u8; 1], u64, Raw> = SideTable::new(&side_table::ORIGIN_SCAN_POLICY);
/// The check one scan raised for one scope. Key: the scan's tag, then the
/// repository's id, or nothing for the vault-wide publication journal.
const CHECK: SideTable<([u8; 1], Vec<u8>), OriginScanCheck, Named> =
    SideTable::new(&side_table::ORIGIN_SCAN_CHECK);

/// Each origin scan whose table grows with use, and so each that once
/// refused past a row count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OriginScan {
    /// One repository's receive-pack intents: its pending pushes, and any
    /// settled one the scan prunes on its way.
    ReceivePackIntents,
    /// The vault's publication journal, every repository's history.
    PublicationRows,
    /// One repository's visible-ref slots: one per ref name it publishes.
    VisibleRefRows,
    /// One repository's keep-ref owners, every kind.
    KeepOwnerRows,
}

impl OriginScan {
    /// Every scan, the list the check that none refuses for a count reads.
    pub const ALL: [Self; 4] = [
        Self::ReceivePackIntents,
        Self::PublicationRows,
        Self::VisibleRefRows,
        Self::KeepOwnerRows,
    ];

    /// The closed code the scan's row, check and log line name it by.
    pub const fn code(self) -> &'static str {
        match self {
            Self::ReceivePackIntents => "receive_pack_intents",
            Self::PublicationRows => "publication_rows",
            Self::VisibleRefRows => "visible_ref_rows",
            Self::KeepOwnerRows => "keep_owner_rows",
        }
    }

    const fn tag(self) -> [u8; 1] {
        [match self {
            Self::ReceivePackIntents => 1,
            Self::PublicationRows => 2,
            Self::VisibleRefRows => 3,
            Self::KeepOwnerRows => 4,
        }]
    }
}

/// OF-520 question one origin scan raised for one scope, the first time it
/// read more rows than its threshold. Evidence for the host, never a
/// refusal: the scan read on and served.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginScanCheck {
    /// The scan ([`OriginScan::code`]).
    pub scan: String,
    /// The repository the scan read, or `None` for the vault-wide
    /// publication journal.
    pub repo_id: Option<String>,
    /// The threshold in force at the crossing.
    pub threshold: u64,
    /// Rows the scan read when it crossed it.
    pub rows: u64,
    /// Unix seconds of the crossing.
    pub raised_at: u64,
}

impl OriginScanCheck {
    /// Machine-readable check discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "origin_scan_size";
}

fn threshold_in_txn(store: &Store, txn: &RoTxn<'_>, scan: OriginScan) -> Result<u64> {
    Ok(POLICY
        .get(store, txn, &scan.tag())?
        .unwrap_or(DEFAULT_ORIGIN_SCAN_CHECK_THRESHOLD))
}

fn check_key(scan: OriginScan, repo_id: Option<EntityId>) -> ([u8; 1], Vec<u8>) {
    (
        scan.tag(),
        repo_id.map_or_else(Vec::new, |id| id.as_bytes().to_vec()),
    )
}

/// One scan's rows, counted against its threshold row.
pub(in crate::origin) struct ScanCount {
    scan: OriginScan,
    repo_id: Option<EntityId>,
    threshold: u64,
    rows: u64,
}

impl ScanCount {
    /// Starts counting `scan` of `repo_id`, under the row `txn` reads.
    pub(in crate::origin) fn start(
        store: &Store,
        txn: &RoTxn<'_>,
        scan: OriginScan,
        repo_id: Option<EntityId>,
    ) -> Result<Self> {
        Ok(Self {
            scan,
            repo_id,
            threshold: threshold_in_txn(store, txn, scan)?,
            rows: 0,
        })
    }

    /// Counts one row read.
    pub(in crate::origin) fn row(&mut self) {
        self.rows = self.rows.saturating_add(1);
    }

    /// Raises the scan's check when it read past its row, once per scope.
    /// Call it after the scan's read transaction has closed. The scan has
    /// served either way, so a check that could not be kept is dropped.
    pub(in crate::origin) fn finish(self, vault: &Vault) {
        if self.rows <= self.threshold {
            return;
        }
        if let Err(error) = vault.raise_origin_scan_check(&self) {
            tracing::warn!(
                kind = ?error.kind(),
                scan = self.scan.code(),
                "an origin scan check was not kept; the scan served"
            );
        }
    }
}

impl Vault {
    fn raise_origin_scan_check(&self, count: &ScanCount) -> Result<()> {
        let key = check_key(count.scan, count.repo_id);
        {
            let txn = self.store.env.read_txn()?;
            if CHECK.contains(&self.store, &txn, &key)? {
                return Ok(());
            }
        }
        let check = OriginScanCheck {
            scan: count.scan.code().to_owned(),
            repo_id: count.repo_id.map(|id| id.to_hex()),
            threshold: count.threshold,
            rows: count.rows,
            raised_at: crate::unix_seconds_now(),
        };
        let raised = self.with_write_txn_grouped(|wtxn| {
            if CHECK.contains(&self.store, wtxn, &key)? {
                return Ok(false);
            }
            CHECK.put(&self.store, wtxn, &key, &check)?;
            Ok(true)
        })?;
        if raised {
            tracing::warn!(
                kind = OriginScanCheck::KIND,
                scan = count.scan.code(),
                threshold = count.threshold,
                rows = count.rows,
                "an origin scan read past its threshold row and served; is everything okay?"
            );
        }
        Ok(())
    }

    /// The threshold row of one origin scan.
    pub fn origin_scan_threshold(&self, scan: OriginScan) -> Result<u64> {
        let txn = self.store.env.read_txn()?;
        threshold_in_txn(&self.store, &txn, scan)
    }

    /// Sets one origin scan's device-local threshold row. Crossing it raises
    /// a check; no value makes the scan refuse.
    pub fn set_origin_scan_threshold(&self, scan: OriginScan, threshold: u64) -> Result<()> {
        self.with_write_txn_grouped(|wtxn| {
            POLICY.put(&self.store, wtxn, &scan.tag(), &threshold)?;
            Ok(())
        })
    }

    /// Every OF-520 check an origin scan raised. Checks are local-only.
    pub fn origin_scan_checks(&self) -> Result<Vec<OriginScanCheck>> {
        let txn = self.store.env.read_txn()?;
        CHECK
            .iter_from(&self.store, &txn, &[])?
            .map(|row| row.map(|(_, check)| check))
            .collect()
    }
}
