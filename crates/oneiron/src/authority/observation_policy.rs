//! Device-local authority observation policy: the `authority.observation_policy` Setting key
//! (DESIGN 15-setting-primitive, stage 1), an install key.

use serde::{Deserialize, Serialize};

use super::setting_keys::AUTHORITY_OBSERVATION_POLICY;
use crate::Vault;
use crate::error::{Error, Result};
use crate::setting::SettingValue;
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
/// The most the `authority_log_fold_memory_floor` row's default reaches: the
/// bytes one fold may project to hold at its peak. A log whose fold would
/// pass the floor is the one count the fold refuses, with a typed issue
/// naming it. With no row, the floor is a quarter of this machine's physical
/// memory, at least 1 GiB and at most this: a one-chain log of about 5,000
/// counted rows reaches it, and one agent enrolled per row measured 4.4 GB
/// at 4,000 rows.
pub const DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// This machine's authority observation policy. Durations use elapsed monotonic
/// time, never an entry timestamp. The ingest threshold raises a check, not a
/// stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The `authority_log_fold_memory_floor` row, in bytes. None reads a
    /// quarter of this machine's physical memory, from 1 GiB up to
    /// [`DEFAULT_AUTHORITY_LOG_FOLD_MEMORY_FLOOR_BYTES`].
    pub log_fold_memory_floor_bytes: Option<u64>,
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
            log_fold_memory_floor_bytes: None,
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
            || self.log_fold_memory_floor_bytes == Some(0)
        {
            return Err(Error::InvalidConfig(
                "authority log bounds must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

/// The policy is a Setting value (`authority.observation_policy`, DESIGN 15-setting-primitive,
/// stage 1): its validation is the check.
impl SettingValue for AuthorityObservationPolicy {
    fn check(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }
}

pub(super) fn authority_observation_policy_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityObservationPolicy> {
    let policy = AUTHORITY_OBSERVATION_POLICY
        .read_in_dbs_txn(store, txn, &[], None)?
        .value;
    // The setting door checks every policy it stores, so a stored row that
    // fails the check is store damage, not a setting to refuse (ARCH-0006a
    // #list-read-built).
    policy
        .validate()
        .map_err(|_| Error::CorruptedIndex("authority observation policy"))?;
    Ok(policy)
}

impl Vault {
    /// Reads this machine's authority observation policy. The owner changes it
    /// through `vault.settings.set`; it never changes signed entries or their
    /// advisory `ts`.
    pub fn authority_observation_policy(&self) -> Result<AuthorityObservationPolicy> {
        let txn = self.store.env.read_txn()?;
        authority_observation_policy_in_txn(&self.store, &txn)
    }
}
