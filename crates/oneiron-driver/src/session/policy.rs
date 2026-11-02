//! The host's side of the sitting policy (FIX 8600). The idle floor and the
//! hard lifetime ceiling are the vault owner's rows
//! (`session_idle_floor_seconds`, shipped 1,200 s; and
//! `session_lifetime_ceiling_seconds`, shipped 43,200 s), re-read for every
//! expiry decision and again inside the close's own transaction. A host
//! narrows them by setting values here; a value it leaves unset stays the
//! owner's, so "unset" and "set to the shipped value" stay different.

use oneiron::session_lifecycle::SessionExpiryPolicy;
use oneiron::{Result, SessionClosePredicate, Vault};

use super::DEFAULT_SESSION_ACTIVITY_ROLLUP_GAP_MS;

/// Driver session policy knobs, in unix SECONDS (the engine's clock
/// convention).
///
/// The driver carries no ceiling constant of its own: the hard lifetime
/// ceiling is a security backstop (H-S4) whose value is the vault owner's
/// row, and a host whose threat model needs a narrower wall states it here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLifecycleConfig {
    /// The host's idle floor: a sitting ends after this many seconds without
    /// activity when the vault's row allows no longer. `None` leaves the
    /// vault's row in force.
    pub idle_floor_secs: Option<u64>,
    /// The host's hard wall-clock lifetime ceiling, measured from
    /// `started_at` and INDEPENDENT of activity hints, when the vault's row
    /// allows no longer. `None` leaves the vault's row in force.
    pub lifetime_ceiling_secs: Option<u64>,
    /// Activity-period rollup gap in milliseconds for durable period storage.
    /// This never participates in expiry, queue coalescing, or ordering
    /// decisions.
    pub activity_rollup_gap_ms: u64,
}

impl SessionLifecycleConfig {
    /// The host's explicit narrowing of the vault's idle floor and lifetime
    /// ceiling; `None` leaves that row in force.
    #[must_use]
    pub fn new(idle_floor_secs: Option<u64>, lifetime_ceiling_secs: Option<u64>) -> Self {
        Self {
            idle_floor_secs,
            lifetime_ceiling_secs,
            activity_rollup_gap_ms: DEFAULT_SESSION_ACTIVITY_ROLLUP_GAP_MS,
        }
    }

    /// Overrides the Activity period rollup gap. `0` retains every delivery
    /// without storage merging.
    #[must_use]
    pub fn with_activity_rollup_gap_ms(mut self, activity_rollup_gap_ms: u64) -> Self {
        self.activity_rollup_gap_ms = activity_rollup_gap_ms;
        self
    }

    /// Rejects host values that would disable a close path: a zero floor or
    /// ceiling would end every session instantly, and a ceiling at or below
    /// the floor means the "backstop vs cap" split the hardening requires
    /// cannot exist.
    pub fn validate(&self) -> Result<()> {
        if self.idle_floor_secs == Some(0) {
            return Err(oneiron::Error::InvalidConfig(
                "session idle_floor_secs must be > 0".into(),
            ));
        }
        if self.lifetime_ceiling_secs == Some(0) {
            return Err(oneiron::Error::InvalidConfig(
                "session lifetime_ceiling_secs must be > 0".into(),
            ));
        }
        if let (Some(idle), Some(ceiling)) = (self.idle_floor_secs, self.lifetime_ceiling_secs)
            && ceiling <= idle
        {
            return Err(oneiron::Error::InvalidConfig(format!(
                "session lifetime_ceiling_secs ({ceiling}) must exceed idle_floor_secs ({idle}): \
                 the ceiling is the hard cap the idle floor is not"
            )));
        }
        Ok(())
    }

    /// The policy in force now: the vault's current rows, narrowed by the
    /// host's explicit values.
    pub(super) fn resolve(&self, vault: &Vault) -> Result<SessionExpiryPolicy> {
        Ok(vault
            .session_expiry_policy()?
            .narrowed_by(self.idle_floor_secs, self.lifetime_ceiling_secs))
    }

    /// The expiry predicate a close carries: only the host's narrowing, since
    /// the close re-reads the vault's rows in its own transaction.
    pub(super) fn expiry_predicate(&self) -> SessionClosePredicate {
        SessionClosePredicate::Expiry {
            idle_floor_secs: self.idle_floor_secs,
            lifetime_ceiling_secs: self.lifetime_ceiling_secs,
        }
    }
}

/// When a sitting closes under `policy`, in unix MILLISECONDS: the earlier of
/// `last_activity + idle floor` and `started_at + ceiling`.
pub(super) fn expiry_ms(policy: SessionExpiryPolicy, started_at: u64, last_activity: u64) -> u64 {
    policy
        .close_at(started_at, last_activity)
        .0
        .saturating_mul(1_000)
}
