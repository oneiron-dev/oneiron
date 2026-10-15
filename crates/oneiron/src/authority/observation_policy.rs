//! Device-local authority observation policy and its versioned duration row.

use crate::Vault;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

/// Named maximum age of an approval based on a subsequently revoked roster.
pub const DEFAULT_STALE_ROSTER_WINDOW_SECS: u64 = 24 * 60 * 60;
/// Advisory check threshold, deliberately above ordinary fleet-scale bursts.
pub const DEFAULT_AUTHORITY_INGEST_CHECK_THRESHOLD: u64 = 1_000_000;
/// Width of the local monotonic ingest observation window.
pub const DEFAULT_AUTHORITY_INGEST_WINDOW_SECS: u64 = 60 * 60;
/// Rows one signer no slip issuer vouches for stores before its next rows
/// wait, far above fleet scale (H72).
pub const DEFAULT_AUTHORITY_LOG_SIGNER_BOUND: u64 = super::MAX_AUTHORITY_ROWS_PER_SIGNER as u64;
/// Counted rows one fold reads before the log raises its
/// `authority_log_fold_headroom` check for rows. The fold still reads every
/// row: only its memory floor refuses (rule 5).
pub const DEFAULT_AUTHORITY_LOG_HEADROOM_ROWS: u64 = super::MAX_AUTHORITY_ROWS_PER_SIGNER as u64;
/// Slip issuers' handoffs one fold probes before the log raises the check
/// for handoffs. Each one costs a fold of its line.
pub const DEFAULT_AUTHORITY_LOG_HEADROOM_HANDOFFS: u64 = 16;
/// Counted ancestor pairs one fold indexes before the log raises the check
/// for pairs. A one-chain log of n counted rows holds n·(n−1)/2 of them.
pub const DEFAULT_AUTHORITY_LOG_HEADROOM_ANCESTOR_PAIRS: u64 = 8 * 1024 * 1024;
/// The `authority_log_fold_memory_floor` row: the bytes one fold may project
/// to hold at its peak. A log whose fold would pass it is the one count the
/// fold refuses, with a typed issue naming the floor.
pub const DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Device-local authority observation policy durations. Key: ().
const POLICY: SideTable<(), AuthorityObservationPolicy, Raw> =
    SideTable::new(&side_table::AUTHLOG_OBSERVATION_POLICY);

/// Version-one local observation policy. Durations use elapsed monotonic time,
/// never an entry timestamp. The ingest threshold raises a check, not a stop.
/// A row written before the log's bounds existed reads with their defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityObservationPolicy {
    /// Inclusive age at which a pre-revocation approval remains usable.
    pub stale_roster_window_secs: u64,
    /// Length of one peer's local observation window.
    pub ingest_window_secs: u64,
    /// Raise one typed check when the count becomes strictly greater than this.
    pub ingest_check_threshold: u64,
    /// The `authority_log_signer_bound` row: rows a signer stores before the
    /// rest of what it signs waits, unless a slip issuer signed or cosigned
    /// them (H72). Raising it lands the waiting rows on the next drain.
    pub log_signer_bound: u64,
    /// The `authority_log_fold_headroom` row for counted rows: the log
    /// raises that check once it stores this many.
    pub log_headroom_rows: u64,
    /// The `authority_log_fold_headroom` row for slip issuers' handoffs.
    pub log_headroom_handoffs: u64,
    /// The `authority_log_fold_headroom` row for counted ancestor pairs.
    pub log_headroom_ancestor_pairs: u64,
    /// The `authority_log_fold_memory_floor` row, in bytes.
    pub log_fold_memory_floor_bytes: u64,
}

impl Default for AuthorityObservationPolicy {
    fn default() -> Self {
        Self {
            stale_roster_window_secs: DEFAULT_STALE_ROSTER_WINDOW_SECS,
            ingest_window_secs: DEFAULT_AUTHORITY_INGEST_WINDOW_SECS,
            ingest_check_threshold: DEFAULT_AUTHORITY_INGEST_CHECK_THRESHOLD,
            log_signer_bound: DEFAULT_AUTHORITY_LOG_SIGNER_BOUND,
            log_headroom_rows: DEFAULT_AUTHORITY_LOG_HEADROOM_ROWS,
            log_headroom_handoffs: DEFAULT_AUTHORITY_LOG_HEADROOM_HANDOFFS,
            log_headroom_ancestor_pairs: DEFAULT_AUTHORITY_LOG_HEADROOM_ANCESTOR_PAIRS,
            log_fold_memory_floor_bytes: DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES,
        }
    }
}

impl AuthorityObservationPolicy {
    fn validate(self) -> Result<()> {
        if self.ingest_window_secs == 0 {
            return Err(Error::InvalidConfig(
                "authority ingest observation window must be positive".to_owned(),
            ));
        }
        if self.log_signer_bound == 0
            || self.log_headroom_rows == 0
            || self.log_headroom_handoffs == 0
            || self.log_headroom_ancestor_pairs == 0
            || self.log_fold_memory_floor_bytes == 0
        {
            return Err(Error::InvalidConfig(
                "authority log bounds must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

impl RawValue for AuthorityObservationPolicy {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut raw = Vec::with_capacity(64);
        for value in [
            self.stale_roster_window_secs,
            self.ingest_window_secs,
            self.ingest_check_threshold,
            self.log_signer_bound,
            self.log_headroom_rows,
            self.log_headroom_handoffs,
            self.log_headroom_ancestor_pairs,
            self.log_fold_memory_floor_bytes,
        ] {
            raw.extend_from_slice(&value.to_be_bytes());
        }
        Ok(raw)
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        // Rows written before the log's bounds (24 bytes) or before its
        // fold's pair and memory rows (48) read with their defaults.
        if ![24, 48, 64].contains(&raw.len()) {
            return Err(Error::CorruptedIndex("authority observation policy").into());
        }
        let mut values = [
            0,
            0,
            0,
            DEFAULT_AUTHORITY_LOG_SIGNER_BOUND,
            DEFAULT_AUTHORITY_LOG_HEADROOM_ROWS,
            DEFAULT_AUTHORITY_LOG_HEADROOM_HANDOFFS,
            DEFAULT_AUTHORITY_LOG_HEADROOM_ANCESTOR_PAIRS,
            DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES,
        ];
        for (slot, bytes) in values.iter_mut().zip(raw.chunks_exact(8)) {
            *slot = u64::from_be_bytes(
                bytes
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("authority observation policy"))?,
            );
        }
        let policy = Self {
            stale_roster_window_secs: values[0],
            ingest_window_secs: values[1],
            ingest_check_threshold: values[2],
            log_signer_bound: values[3],
            log_headroom_rows: values[4],
            log_headroom_handoffs: values[5],
            log_headroom_ancestor_pairs: values[6],
            log_fold_memory_floor_bytes: values[7],
        };
        policy.validate()?;
        Ok(policy)
    }
}

pub(super) fn authority_observation_policy_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityObservationPolicy> {
    Ok(POLICY.get(store, txn, &())?.unwrap_or_default())
}

impl Vault {
    /// Reads the local duration-v1 authority observation policy.
    pub fn authority_observation_policy(&self) -> Result<AuthorityObservationPolicy> {
        let txn = self.store.env.read_txn()?;
        authority_observation_policy_in_txn(&self.store, &txn)
    }

    /// Writes duration-v1 policy for subsequent folds and observations. This
    /// local configuration never changes signed entries or their advisory `ts`.
    pub fn set_authority_observation_policy(
        &self,
        policy: AuthorityObservationPolicy,
    ) -> Result<()> {
        policy.validate()?;
        self.with_write_txn_grouped(|txn| {
            POLICY.put(&self.store, txn, &(), &policy)?;
            Ok(())
        })
    }
}
