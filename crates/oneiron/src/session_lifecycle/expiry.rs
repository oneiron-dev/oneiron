//! A sitting's expiry policy (FIX 8600): the vault's own idle-floor and
//! lifetime-ceiling rows, narrowed by whatever the host explicitly set, and
//! re-read in the very snapshot that judges and stamps a close.

use super::{SessionClosePredicate, SessionEndReason, SessionLifecycleRecord};
use crate::Vault;
use crate::error::Result;

/// The idle floor and hard lifetime ceiling a sitting closes by, in
/// store-clock seconds: the vault's `session_idle_floor_seconds` and
/// `session_lifetime_ceiling_seconds` rows, else the shipped 1,200 and
/// 43,200, then narrowed by a host's explicit choices
/// ([`Self::narrowed_by`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionExpiryPolicy {
    pub idle_floor_secs: u64,
    pub lifetime_ceiling_secs: u64,
}

impl SessionExpiryPolicy {
    /// This policy under a host's explicit choices: a value the host set can
    /// shorten its axis, never lengthen it, and an unset one leaves the
    /// owner's row in force. Unset is not the shipped value: a host that
    /// states 1,200 seconds keeps that floor when the owner later widens the
    /// row.
    #[must_use]
    pub fn narrowed_by(
        self,
        idle_floor_secs: Option<u64>,
        lifetime_ceiling_secs: Option<u64>,
    ) -> Self {
        Self {
            idle_floor_secs: idle_floor_secs
                .map_or(self.idle_floor_secs, |host| host.min(self.idle_floor_secs)),
            lifetime_ceiling_secs: lifetime_ceiling_secs
                .map_or(self.lifetime_ceiling_secs, |host| {
                    host.min(self.lifetime_ceiling_secs)
                }),
        }
    }

    /// When a sitting that started at `started_at` and was last active at
    /// `last_activity` closes, and why: the earlier of
    /// `last_activity + idle floor` and `started_at + ceiling`. "First to
    /// fire" names the reason; a ceiling due at or before the idle floor
    /// closes as the ceiling however fresh the (possibly forged) activity
    /// clock looks (H-S4).
    #[must_use]
    pub fn close_at(self, started_at: u64, last_activity: u64) -> (u64, SessionEndReason) {
        let idle_due = last_activity.saturating_add(self.idle_floor_secs);
        let ceiling_due = started_at.saturating_add(self.lifetime_ceiling_secs);
        if ceiling_due <= idle_due {
            (ceiling_due, SessionEndReason::LifetimeCeiling)
        } else {
            (idle_due, SessionEndReason::IdleFloor)
        }
    }
}

/// When and why a close is due, as one snapshot judges it.
#[derive(Debug, Clone, Copy)]
pub(super) struct CloseDue {
    pub(super) reason: SessionEndReason,
    /// The instant the close is stamped at: the policy's due instant for an
    /// expiry, the caller's `now` for an explicit end.
    pub(super) at: u64,
}

impl SessionClosePredicate {
    /// When and why this predicate closes `record` at `now`, judged at
    /// `txn`'s revision: an expiry re-reads the vault's policy there and
    /// narrows it by the host's explicit choices. `None` when the close is
    /// not (or no longer) due.
    pub(super) fn close_due_in(
        self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        record: &SessionLifecycleRecord,
        now: u64,
    ) -> Result<Option<CloseDue>> {
        match self {
            Self::Explicit => Ok(Some(CloseDue {
                reason: SessionEndReason::Explicit,
                at: now,
            })),
            Self::Expiry {
                idle_floor_secs,
                lifetime_ceiling_secs,
            } => {
                let policy = vault
                    .session_expiry_policy_in(txn)?
                    .narrowed_by(idle_floor_secs, lifetime_ceiling_secs);
                let (at, reason) = policy.close_at(record.started_at, record.last_activity);
                Ok((now >= at).then_some(CloseDue { reason, at }))
            }
        }
    }
}

impl Vault {
    /// The vault's sitting policy now (FIX 8600), before any host narrows it.
    pub fn session_expiry_policy(&self) -> Result<SessionExpiryPolicy> {
        let rtxn = self.store.env.read_txn()?;
        self.session_expiry_policy_in(&rtxn)
    }

    /// [`Self::session_expiry_policy`] at `txn`'s revision.
    fn session_expiry_policy_in(&self, txn: &heed::RoTxn<'_>) -> Result<SessionExpiryPolicy> {
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        Ok(SessionExpiryPolicy {
            idle_floor_secs: policy.session_idle_floor_seconds(),
            lifetime_ceiling_secs: policy.session_lifetime_ceiling_seconds(),
        })
    }

    /// Changes after each commit that may have changed an admitted policy
    /// manifest (FIX 11402). Subscribe before the first policy read; every
    /// notification means "re-read the policy", never "a sitting is due".
    pub fn subscribe_policy_manifest_changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.store.policy_manifest_updates.subscribe()
    }
}

impl crate::store::Store {
    /// Only post-commit callers signal; the value carries no policy data.
    pub(crate) fn notify_policy_manifest_changes(&self) {
        self.policy_manifest_updates.send_modify(|generation| {
            *generation = generation.wrapping_add(1);
        });
    }
}
