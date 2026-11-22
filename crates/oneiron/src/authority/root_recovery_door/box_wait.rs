//! The root's door after the recovery box's own wait
//! (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT = A): on a hosted vault the box's
//! wait is the recovery wait, so the door's hold lands at the box's release
//! second and never waits a second time. Every box call is judged first
//! and then lands this install's due holds, and a landing of the acting
//! owner's own hold that enrolled its successor answers it.

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

    /// A box call's due holds, landed once its request passed the door's
    /// own checks (row RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS), and the
    /// landing among them that answers the call
    /// ([`Self::landing_for_successor`]). The checks read one transaction
    /// and write nothing, in the door's order: the fold names its vault,
    /// the preset is not kit-only, the released key is this vault's and
    /// live (else the door's refusal for that roster), the key that proved
    /// the owner is not named lost, the proof is this vault's live owner,
    /// and every lost key is one the root's key may revoke. A refused call
    /// lands nothing; the host's poll lands a due hold all the same.
    ///
    /// # Errors
    /// The door's refusals above; the landing run's.
    pub(super) fn land_due_holds_for_box_call(
        &self,
        owner: &AuthenticatedOwner,
        signer: &RecoveryAuthoritySigner,
        successor: &RootSuccessor,
        lost: &[AuthorityKey],
    ) -> Result<Option<RootRecovery>> {
        let actor = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            if self.recovery_preset_in_txn(&txn)?.is_nobody_but_me() {
                return Err(authority_refused(RELEASED_UNDER_KIT_ONLY));
            }
            if *signer.vault_id() != vault_id {
                return Err(invalid_authority());
            }
            let root_key = signer.authority_key();
            if !live_owner_key(&fold, &root_key) {
                return Err(authority_refused(if rooted(&fold) {
                    ROOT_KEY_NOT_LIVE
                } else {
                    RELEASED_KEY_CANNOT_APPOINT
                }));
            }
            if owner
                .proving_owner_key()
                .is_some_and(|key| lost.contains(key))
            {
                return Err(authority_refused(PROVING_KEY_NAMED_LOST));
            }
            let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
            let named = match successor {
                RootSuccessor::Device(input) => Some(AuthorityKey::Ed25519(input.public_key)),
                RootSuccessor::ThisInstall => None,
            };
            self.lost_keys_in_txn(&txn, &fold, actor, (&root_key, named.as_ref()), lost)?;
            actor
        };
        let landed = self.land_due_recovery_holds()?;
        self.landing_for_successor(&landed, successor, actor)
    }

    /// The landing among `landed` of a hold whose owner is `actor`, the
    /// owner who acts, that enrolled `successor`'s key, as the box call's
    /// [`RootRecovery::Vouched`]: this install's owner signing key for
    /// [`RootSuccessor::ThisInstall`] (a device successor on the same
    /// machine is another attempt's), the named key for a device. Another
    /// owner's landing is never this call's. A slot that holds no seed, or
    /// one a device PIN bars, is no key here, so no landing answers for this
    /// install then.
    ///
    /// # Errors
    /// Reading the holds and this install's owner signing slot.
    pub(super) fn landing_for_successor(
        &self,
        landed: &[RecoveryHoldLanding],
        successor: &RootSuccessor,
        actor: EntityId,
    ) -> Result<Option<RootRecovery>> {
        if landed.iter().all(|landing| landing.enrollment.is_none()) {
            return Ok(None);
        }
        let own: BTreeSet<AuthorityEntryHash> = {
            let txn = self.store.env.read_txn()?;
            self.recovery_holds_in_txn(&txn)?
                .into_iter()
                .filter(|view| view.owner == actor)
                .map(|view| view.hold)
                .collect()
        };
        let own_key = match successor {
            RootSuccessor::ThisInstall => self
                .existing_device_owner_signing_key()?
                .map(|key| key.public_key()),
            RootSuccessor::Device(input) => Some(input.public_key),
        };
        Ok(landed.iter().find_map(|landing| {
            let receipt = landing.enrollment.as_ref()?;
            (own.contains(&landing.hold) && own_key == Some(receipt.public_key)).then(|| {
                RootRecovery::Vouched {
                    enrollment: receipt.clone(),
                    revoked: landing.revoked.clone(),
                }
            })
        }))
    }
}
