//! The root's door after the recovery box's own wait
//! (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT = A): on a hosted vault the box's
//! wait is the recovery wait, so the door's hold lands at the box's release
//! second and never waits a second time. Every box call first lands this
//! install's due holds, and a landing that enrolled its successor answers it.

use super::*;

/// When a box recovery's hold lands, on this install's clock.
#[derive(Debug, Clone, Copy)]
pub(super) enum HoldEnd {
    /// `wait` after the hold is written: the engine's own wait, where no box
    /// waited.
    AfterWait(std::time::Duration),
    /// At the box's release second, and never later than `wait` after the
    /// hold is written: the box already waited.
    AtBoxRelease {
        release_at: u64,
        wait: std::time::Duration,
    },
}

impl HoldEnd {
    /// The landing second of a hold written at `now`.
    pub(super) fn lands_at(self, now: u64) -> u64 {
        match self {
            Self::AfterWait(wait) => now.saturating_add(wait.as_secs()),
            Self::AtBoxRelease { release_at, wait } => {
                release_at.min(now.saturating_add(wait.as_secs()))
            }
        }
    }
}

impl Vault {
    /// After the box's own wait, the hold `hold` this call answered lands in
    /// the same call once it is due (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT =
    /// A): its enrolment and revocations answer [`RootRecovery::Vouched`],
    /// and the hold row stays as their receipt. A hold not yet due (the
    /// box's clock ahead of this install's) answers `Held` at `lands_at`. A
    /// landing that fails leaves the committed hold due, so the answer is
    /// `Held` and the next call lands it first.
    pub(super) fn land_held_after_box_wait(
        &self,
        hold: AuthorityEntryHash,
        lands_at: u64,
    ) -> Result<RootRecovery> {
        let held = RootRecovery::Held { hold, lands_at };
        let landed = match self.land_due_recovery_holds() {
            Ok(landed) => landed,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a box recovery's hold is due after the box's wait, but its landing did not go through; the next call lands it"
                );
                return Ok(held);
            }
        };
        Ok(landed
            .into_iter()
            .find(|landing| landing.hold == hold && landing.state == RecoveryHoldState::Landed)
            .and_then(|landing| {
                landing.enrollment.map(|enrollment| RootRecovery::Vouched {
                    enrollment,
                    revoked: landing.revoked,
                })
            })
            .unwrap_or(held))
    }

    /// The landing among `landed` that enrolled `successor`'s key, as the
    /// box call's [`RootRecovery::Vouched`]: this install's own key for
    /// [`RootSuccessor::ThisInstall`], the named key for a device.
    ///
    /// # Errors
    /// Preparing this install's signing keys.
    pub(super) fn landing_for_successor(
        &self,
        landed: &[RecoveryHoldLanding],
        successor: &RootSuccessor,
    ) -> Result<Option<RootRecovery>> {
        if landed.iter().all(|landing| landing.enrollment.is_none()) {
            return Ok(None);
        }
        let machine = match successor {
            RootSuccessor::ThisInstall => Some(self.prepare_install_signing()?),
            RootSuccessor::Device(_) => None,
        };
        Ok(landed.iter().find_map(|landing| {
            let receipt = landing.enrollment.as_ref()?;
            let names = match successor {
                RootSuccessor::Device(input) => receipt.public_key == input.public_key,
                RootSuccessor::ThisInstall => machine == Some(receipt.machine),
            };
            names.then(|| RootRecovery::Vouched {
                enrollment: receipt.clone(),
                revoked: landing.revoked.clone(),
            })
        }))
    }
}
