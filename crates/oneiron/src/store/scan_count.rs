//! Row counting and deferred scan-threshold crossings.

use heed::RoTxn;

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::store::{EngineScan, ManifestDbs, PendingScanChecks, ScanCheck};

mod engine_scan_table;
pub(crate) use engine_scan_table::EngineScanThreshold;

pub(crate) const POLICY: SideTable<[u8; 1], u64, Raw> =
    SideTable::new(&side_table::ORIGIN_SCAN_POLICY);

pub(crate) fn threshold_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    scan: EngineScan,
) -> Result<u64> {
    Ok(policy_row_in_txn(store, txn, scan.tag())?.unwrap_or(scan.default_threshold()))
}

thread_local! {
    /// The policy rows one recall on this thread has read, for one committed
    /// snapshot ([`crate::ports::recall_memo_key`]).
    static POLICY_ROWS: std::cell::RefCell<PolicyRows> =
        std::cell::RefCell::new(PolicyRows::default());
}

/// Scan policy rows kept for one recall's committed snapshot: a recall
/// counts many adjacency scans of one kind, and each reads the same row, so
/// later counts read it back instead of from the store (L15 recall speed).
/// A read error is never kept.
#[derive(Default)]
struct PolicyRows {
    at: Option<(u64, usize, usize)>,
    rows: Vec<([u8; 1], Option<u64>)>,
}

/// The policy row of the scan tagged `tag` as `txn` reads it, if any.
fn policy_row_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    tag: [u8; 1],
) -> Result<Option<u64>> {
    let Some(key) = crate::ports::recall_memo_key(store, txn) else {
        return POLICY.get(store, txn, &tag);
    };
    let kept = POLICY_ROWS.with(|memo| {
        let mut memo = memo.borrow_mut();
        if memo.at != Some(key) {
            memo.at = Some(key);
            memo.rows.clear();
        }
        memo.rows
            .iter()
            .find(|(kept, _)| *kept == tag)
            .map(|(_, row)| *row)
    });
    if let Some(row) = kept {
        return Ok(row);
    }
    let row = POLICY.get(store, txn, &tag)?;
    POLICY_ROWS.with(|memo| {
        let mut memo = memo.borrow_mut();
        if memo.at == Some(key) {
            memo.rows.push((tag, row));
        }
    });
    Ok(row)
}

/// One scan's rows, counted against its threshold row.
#[must_use = "a count raises its check only when it is finished"]
pub(crate) struct ScanCount {
    scan: EngineScan,
    scope: Vec<u8>,
    threshold: u64,
    rows: u64,
}

impl ScanCount {
    /// Starts counting `scan` of `scope` (empty for a vault-wide scan), under
    /// the row `txn` reads.
    pub(crate) fn start(
        store: &impl ManifestDbs,
        txn: &RoTxn<'_>,
        scan: EngineScan,
        scope: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            scan,
            scope: scope.to_vec(),
            threshold: threshold_in_txn(store, txn, scan)?,
            rows: 0,
        })
    }

    /// Starts counting `scan` of `scope` against `threshold`, for a scan
    /// whose caller's own policy row names when it asks.
    pub(crate) fn start_at(scan: EngineScan, scope: &[u8], threshold: u64) -> Self {
        Self {
            scan,
            scope: scope.to_vec(),
            threshold,
            rows: 0,
        }
    }

    /// Counts one row read.
    pub(crate) fn row(&mut self) {
        self.rows = self.rows.saturating_add(1);
    }

    /// Counts `rows` rows read at once, for a scan that holds its rows.
    pub(crate) fn rows(&mut self, rows: usize) {
        self.rows = self
            .rows
            .saturating_add(u64::try_from(rows).unwrap_or(u64::MAX));
    }

    /// Raises the scan's check when it read past its row, once per scope:
    /// the vault's next write keeps it. The scan has served either way.
    pub(crate) fn finish(self, vault: &Vault) {
        self.defer(&vault.store);
    }

    /// [`Self::finish`] through a read target, for a scan that holds a
    /// store or a room's view rather than the vault.
    pub(crate) fn defer(self, store: &impl ManifestDbs) {
        self.defer_to(store.pending_scan_checks());
    }

    /// [`Self::defer`] into `pending`, crossings held apart from the vault's
    /// own: a live room's (FIX 4280), which the host's read of the checks
    /// lists while the room lives and which close drops; none is ever kept
    /// in the vault, so no check names a room's row there.
    pub(crate) fn defer_to(self, pending: &PendingScanChecks) {
        if self.rows <= self.threshold {
            return;
        }
        let check = self.check();
        pending.park((self.scan.tag(), self.scope), check);
    }

    fn check(&self) -> ScanCheck {
        ScanCheck {
            scan: self.scan.code().to_owned(),
            scope: (!self.scope.is_empty()).then(|| bytes_to_hex_lower(&self.scope)),
            threshold: self.threshold,
            rows: self.rows,
            raised_at: crate::unix_seconds_now(),
        }
    }
}
