//! Device-local authority observation policy and its versioned duration row.

use crate::Vault;
use crate::error::{Error, Result};
use crate::store::Store;

/// Named maximum age of an approval based on a subsequently revoked roster.
pub const DEFAULT_STALE_ROSTER_WINDOW_SECS: u64 = 24 * 60 * 60;
/// Advisory check threshold, deliberately above ordinary fleet-scale bursts.
pub const DEFAULT_AUTHORITY_INGEST_CHECK_THRESHOLD: u64 = 1_000_000;
/// Width of the local monotonic ingest observation window.
pub const DEFAULT_AUTHORITY_INGEST_WINDOW_SECS: u64 = 60 * 60;
const POLICY_KEY: &str = "authlog:observation_policy:duration_v1";

/// Version-one local observation policy. Durations use elapsed monotonic time,
/// never an entry timestamp. The ingest threshold raises a check, not a stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorityObservationPolicy {
    /// Inclusive age at which a pre-revocation approval remains usable.
    pub stale_roster_window_secs: u64,
    /// Length of one peer's local observation window.
    pub ingest_window_secs: u64,
    /// Raise one typed check when the count becomes strictly greater than this.
    pub ingest_check_threshold: u64,
}

impl Default for AuthorityObservationPolicy {
    fn default() -> Self {
        Self {
            stale_roster_window_secs: DEFAULT_STALE_ROSTER_WINDOW_SECS,
            ingest_window_secs: DEFAULT_AUTHORITY_INGEST_WINDOW_SECS,
            ingest_check_threshold: DEFAULT_AUTHORITY_INGEST_CHECK_THRESHOLD,
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
        Ok(())
    }
}

pub(super) fn authority_observation_policy_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityObservationPolicy> {
    let Some(raw) = store.sync_state.get(txn, POLICY_KEY)? else {
        return Ok(AuthorityObservationPolicy::default());
    };
    if raw.len() != 24 {
        return Err(Error::CorruptedIndex("authority observation policy"));
    }
    let mut values = [0_u64; 3];
    for (slot, bytes) in values.iter_mut().zip(raw.chunks_exact(8)) {
        *slot = u64::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| Error::CorruptedIndex("authority observation policy"))?,
        );
    }
    let policy = AuthorityObservationPolicy {
        stale_roster_window_secs: values[0],
        ingest_window_secs: values[1],
        ingest_check_threshold: values[2],
    };
    policy.validate()?;
    Ok(policy)
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
        let mut raw = Vec::with_capacity(24);
        for value in [
            policy.stale_roster_window_secs,
            policy.ingest_window_secs,
            policy.ingest_check_threshold,
        ] {
            raw.extend_from_slice(&value.to_be_bytes());
        }
        self.with_write_txn(|txn| {
            self.store.sync_state.put(txn, POLICY_KEY, &raw)?;
            Ok(())
        })
    }
}
