//! The recovery root's one door (pass 27 section 4.3, row R4; Engine
//! RULINGs WAYBACK-E2 = A and WAYBACK-BOX-AUTHORITY-SEED = A).
//!
//! The owner brings the same kit whatever was lost, and the door picks the
//! arm from the roster; the person never chooses between them:
//! - While the roster holds the root's authority key live, that key vouches.
//!   It is the predecessor of an `OwnerKeyEnroll` of the new key, carried by
//!   this install as every enrolment is, and it signs a `RevokeDevice` of
//!   each lost key the owner names, all in one write transaction. These are
//!   the two ordinary ops, on every posture. On a hosted fold the custodial
//!   root and every slip the host minted stay live, where a ReRoot would
//!   revoke them (NOTE WAYBACK-REROOT-TRACE, 15 Nov 22:02).
//! - While the roster holds no live root key at all, the root's anchor
//!   appoints a fresh key of this install ([`Vault::appoint_owner_root`]).
//! - Otherwise the door refuses and says why: the root's key was never
//!   enrolled, or was revoked, and the roster still holds a root key.
//!
//! The recovery box brings the authority key alone
//! ([`RecoveryAuthoritySigner::from_released_seed`]): it vouches and never
//! appoints. A lost key is one of the owner signing keys the acting owner
//! enrolled, live on the roster. The root's own key, the new key and the
//! host roots are never a lost key here; a self-hosted vault's lost host
//! root is a ReRoot's ([`Vault::recover_owner_authority_from_kit`]).

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron_keystore::KeystoreSlot;

use super::owner_key_enrollment_door::EntrySigner;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::world_keys::{
    KitConfirmation, OwnerRootSigner, OwnerSigningSlot, RecoveryAuthoritySigner, RecoveryRootSeed,
};
use crate::{EntityId, Result, Vault};

/// The roster still holds a live root key, and the root's authority key is
/// not a live owner key on it. Nothing was written.
const ROOT_KEY_NOT_LIVE: &str = "the recovery root's authority key is not a live owner key on this \
                                 vault's roster, and the roster still holds a live root key; \
                                 nothing was written";
/// The roster holds no live root key, and the box released the authority key
/// alone: only the kit's anchor appoints. Nothing was written.
const RELEASED_KEY_CANNOT_APPOINT: &str = "the roster holds no live root key, and only the kit's \
                                           anchor appoints one; the released authority key is not \
                                           on the roster; nothing was written";
/// The anchor appoints a fresh key of this install and revokes nothing.
/// Nothing was written.
const APPOINTMENT_TAKES_THIS_INSTALL: &str = "the roster holds no live root key: the root's anchor \
                                              appoints a fresh key of this install and revokes \
                                              nothing; nothing was written";
/// A key named as lost is not one the root's key may revoke here. Nothing
/// was written.
const NOT_A_LOST_KEY: &str = "a key named as lost is not a live owner signing key the owner \
                              enrolled, or is the root's own key or the new key; nothing was \
                              written";
/// This install's owner signing key is live: it needs no recovery. Nothing
/// was written.
const THIS_INSTALL_KEY_LIVE: &str = "this install's owner signing key is live on the roster; it \
                                     needs no recovery; nothing was written";
/// While kit-only holds the recovery box holds nothing: only the kit serves.
/// Nothing was written.
const RELEASED_UNDER_KIT_ONLY: &str = "under Nobody but me the recovery box holds nothing; bring \
                                       your recovery kit; nothing was written";

/// What the owner brings to the root's door.
pub enum RootMaterial {
    /// The kit's typed restore result, rebuilt into the root's seed, and the
    /// kit confirmation the kit-restored seed rule reads at the anchor arm.
    Kit {
        seed: RecoveryRootSeed,
        confirm: Option<KitConfirmation>,
    },
    /// The root's authority key alone, as the recovery box releases it
    /// (WAYBACK-BOX-AUTHORITY-SEED = A): it vouches, and never appoints.
    Released(RecoveryAuthoritySigner),
}

/// The new owner key the root's door puts on the roster.
pub enum RootSuccessor {
    /// A fresh owner signing key of this install, made in its keystore slot.
    ThisInstall,
    /// Another device's key, with its proof of possession over its
    /// enrolment challenge for this vault, machine, key and owner. Only the
    /// root's authority key vouches for it.
    Device(OwnerKeyEnrollment),
}

/// What the root's door answers once its write transaction committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootRecovery {
    /// The box recovery waits: the hold's attempt id and the second it
    /// lands at, on this install's clock. Another owner device or the kit
    /// cancels it or ends the wait early, or it lands at the wait's end.
    Held {
        hold: AuthorityEntryHash,
        lands_at: u64,
    },
    /// The root's authority key vouched: each lost key's revocation, in the
    /// order written, and the new key's enrolment, written after them.
    Vouched {
        enrollment: OwnerKeyEnrollmentReceipt,
        revoked: Vec<AuthorityEntryHash>,
    },
    /// The root's anchor appointed this install's fresh key on a roster that
    /// held no root key.
    Appointed(RootAppointmentReceipt),
}

impl Vault {
    /// The owner gets owner control back with the recovery root `material`
    /// names: the root's authority key vouches for `successor` and revokes
    /// `lost` while the roster holds it live, and the root's anchor appoints
    /// this install's fresh key while the roster holds no root key (module
    /// doc). `owner` is the owner's proof on this install, revalidated in the
    /// writer; it names who acts, and the root's key or anchor is the
    /// possession. Each arm checks its own condition again in its writer
    /// transaction, and writes everything or nothing.
    ///
    /// # Errors
    /// [`crate::error::RecordError::AuthorityRefused`] when neither arm
    /// serves, for a lost key the root's key may not revoke, or for an entry
    /// the fold does not count; each arm's own refusals
    /// ([`Vault::enrol_owner_signing_key_as`], [`Vault::appoint_owner_root`]);
    /// the keystore's for [`RootSuccessor::ThisInstall`].
    pub fn recover_owner_root(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        material: RootMaterial,
        successor: RootSuccessor,
        lost: &[AuthorityKey],
    ) -> Result<RootRecovery> {
        let wait = {
            let txn = self.store.env.read_txn()?;
            self.recovery_wait_in_txn(&txn)?
        };
        self.recover_owner_root_with_wait(owner, surface, material, successor, lost, wait)
    }

    /// [`Self::recover_owner_root`] with an explicit wait: the test door's
    /// seam, so tests cover zero and nonzero waits. A box recovery
    /// (`RootMaterial::Released`) with a nonzero wait holds instead of
    /// vouching: [`RootRecovery::Held`]; a zero wait vouches as today. The
    /// kit arm never waits. On a box call this install's due holds land
    /// first, and a landing that enrolled this call's successor answers
    /// [`RootRecovery::Vouched`]: the call completes the attempt it held.
    ///
    /// # Errors
    /// As [`Self::recover_owner_root`].
    pub(crate) fn recover_owner_root_with_wait(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        material: RootMaterial,
        successor: RootSuccessor,
        lost: &[AuthorityKey],
        wait: std::time::Duration,
    ) -> Result<RootRecovery> {
        // A kit recovery lands nothing first: it cancels every live hold in
        // its write, a due one too, so no hold's landing stands in its way.
        if matches!(material, RootMaterial::Released(_)) {
            let landed = self.land_due_recovery_holds()?;
            if let Some(done) = self.landing_for_successor(&landed, &successor)? {
                return Ok(done);
            }
        }
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // The kit's live generation, if any: old kits read as generation 0 by
        // construction, and the same kit vouches with generation 1 after a
        // rotation. A kit with none live falls through to the rooted check,
        // as a never-enrolled key does. The box's released bytes need no
        // finder: they name their generation directly.
        let (signer, kit, released) = match material {
            RootMaterial::Kit { seed, confirm } => {
                let found = self.recovery_authority_generations_in_txn(&txn, &seed, &vault_id)?;
                match found.live {
                    Some((_, signer)) => (Some(signer), Some((seed, confirm)), false),
                    None => (None, Some((seed, confirm)), false),
                }
            }
            RootMaterial::Released(signer) => (Some(signer), None, true),
        };
        // While kit-only holds the box holds nothing: the released key is
        // refused before the liveness check, so a revoked released key under
        // kit-only still says so. The writer checks again in its txn.
        if released && self.recovery_preset_in_txn(&txn)?.is_nobody_but_me() {
            return Err(authority_refused(RELEASED_UNDER_KIT_ONLY));
        }
        drop(txn);
        if let Some(signer) = &signer {
            if *signer.vault_id() != vault_id {
                return Err(invalid_authority());
            }
            if live_owner_key(&fold, &signer.authority_key()) {
                let authority = ActAuthority::Owner(owner.clone(), surface);
                if released && !wait.is_zero() {
                    return self.hold_with_root_key(
                        (owner, &authority),
                        signer,
                        successor,
                        lost,
                        wait,
                    );
                }
                return self.vouch_with_root_key(
                    (owner, &authority),
                    signer,
                    released,
                    successor,
                    lost,
                    kit.as_ref().map(|(seed, _)| seed),
                );
            }
        }
        if rooted(&fold) {
            return Err(authority_refused(ROOT_KEY_NOT_LIVE));
        }
        let Some((seed, confirm)) = kit else {
            return Err(authority_refused(RELEASED_KEY_CANNOT_APPOINT));
        };
        if !matches!(successor, RootSuccessor::ThisInstall) || !lost.is_empty() {
            return Err(authority_refused(APPOINTMENT_TAKES_THIS_INSTALL));
        }
        self.appoint_owner_root(owner, &seed, confirm)
            .map(RootRecovery::Appointed)
    }

    /// The authority arm: one write transaction revokes each lost key under
    /// the root's authority key and then enrols the successor with that key
    /// as predecessor. This install's fresh key is made in that transaction, once
    /// the roster reads its slot's key revoked there, and is held as a
    /// checkpoint root signer once the transaction commits, as at the device
    /// door.
    fn vouch_with_root_key(
        &self,
        (owner, authority): (&AuthenticatedOwner, &ActAuthority),
        signer: &RecoveryAuthoritySigner,
        released: bool,
        successor: RootSuccessor,
        lost: &[AuthorityKey],
        kit_seed: Option<&RecoveryRootSeed>,
    ) -> Result<RootRecovery> {
        // Preparing this install's signing keys writes, so its slot is made
        // ready before the writer opens.
        let install = match successor {
            RootSuccessor::ThisInstall => Some((
                self.prepare_install_signing()?,
                self.device_owner_signing_slot()?,
            )),
            RootSuccessor::Device(_) => None,
        };
        let root_key = signer.authority_key();
        let mut sign_enrolment = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        let sign_revoke = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        let mut txn = self.store.env.write_txn()?;
        // The check that counts: the preset could have flipped between the
        // pre-check's read txn and this writer. Before the liveness check,
        // so a revoked released key under kit-only still says so.
        if released && self.recovery_preset_in_txn(&txn)?.is_nobody_but_me() {
            return Err(authority_refused(RELEASED_UNDER_KIT_ONLY));
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !live_owner_key(&fold, &root_key) {
            return Err(authority_refused(ROOT_KEY_NOT_LIVE));
        }
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let named = match &successor {
            RootSuccessor::Device(input) => Some(AuthorityKey::Ed25519(input.public_key)),
            RootSuccessor::ThisInstall => None,
        };
        let lost = self.lost_keys_in_txn(&txn, &fold, actor, (&root_key, named.as_ref()), lost)?;
        let (input, held) = match (successor, install) {
            (RootSuccessor::Device(input), _) => (input, None),
            (RootSuccessor::ThisInstall, Some((machine, slot))) => {
                let (input, key) = this_install_successor(&fold, actor, machine, &slot)?;
                (input, Some(key))
            }
            (RootSuccessor::ThisInstall, None) => return Err(invalid_authority()),
        };
        if let Some(seed) = kit_seed {
            self.cancel_live_holds_for_kit_in_txn(&mut txn, seed)?;
        }
        // The lost keys go first: a self-hosted vault binds an owner's new
        // key only while no live `human` binding names them, and a lost key
        // that held the owner's binding takes it with it when revoked. So
        // the successor's enrolment binds them when the revocations left
        // them unbound, and an owner whose own key held their binding keeps
        // owner control.
        let mut revoked = Vec::with_capacity(lost.len());
        for key in lost {
            let signer = EntrySigner::Key(&root_key, &sign_revoke);
            revoked.push(self.append_revoke_device_in_txn(&mut txn, signer, key)?);
        }
        let enrollment = self.enrol_owner_signing_key_in_txn(
            &mut txn,
            authority,
            input,
            EnrolledOwnerKeyKind::Device,
            root_key.clone(),
            &mut sign_enrolment,
        )?;
        let rows =
            authority_rows_counted_since(&fold, &self.authority_view_readonly_in_txn(&txn)?)?;
        self.mark_authority_rows_in_txn(&mut txn, &rows)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        if let Some(key) = held {
            self.hold_checkpoint_root_signer(Arc::new(key));
        }
        Ok(RootRecovery::Vouched {
            enrollment,
            revoked,
        })
    }

    /// The box arm with a wait: the vouch writer's checks (R live in the
    /// transaction, the owner revalidated, the lost keys filtered, the
    /// successor input built, the kit-only refusal), then one `RecoveryHold`
    /// entry signed by R with `lands_at` on this install's clock, and no
    /// enrolment and no revocation. R's released seed goes to this
    /// install's keystore slot for the successor before the transaction,
    /// and leaves it again when the transaction fails. A second call while
    /// this install's hold for the same successor waits answers the same
    /// held attempt, and writes no second hold.
    fn hold_with_root_key(
        &self,
        (owner, authority): (&AuthenticatedOwner, &ActAuthority),
        signer: &RecoveryAuthoritySigner,
        successor: RootSuccessor,
        lost: &[AuthorityKey],
        wait: std::time::Duration,
    ) -> Result<RootRecovery> {
        // Preparing this install's signing keys writes, so its slot is made
        // ready before any transaction opens, as at the vouch arm.
        let machine = self.prepare_install_signing()?;
        let install = match successor {
            RootSuccessor::ThisInstall => Some(self.device_owner_signing_slot()?),
            RootSuccessor::Device(_) => None,
        };
        let candidate = match (&successor, &install) {
            (RootSuccessor::Device(input), _) => input.public_key,
            (RootSuccessor::ThisInstall, Some(slot)) => slot.key()?.public_key(),
            (RootSuccessor::ThisInstall, None) => return Err(invalid_authority()),
        };
        let vault_id = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            if let Some((hold, lands_at)) =
                self.waiting_hold_for_successor_in_txn(&txn, machine, &candidate)?
            {
                return Ok(RootRecovery::Held { hold, lands_at });
            }
            vault_id
        };
        let seed = signer.released_seed();
        let expected = signer.public_key();
        let candidate_slot = self.recovery_hold_slot(&vault_id, machine, &candidate);
        let mut created = Vec::new();
        if self.put_recovery_hold_seed(&candidate_slot, &seed, &expected)? {
            created.push(candidate_slot);
        }
        let outcome = self.hold_write_with_root_key(
            (owner, authority),
            signer,
            successor,
            install,
            lost,
            wait,
            machine,
            candidate,
            &seed,
            &expected,
            &mut created,
        );
        if outcome.is_err() {
            for slot in created {
                let _ = self.delete_recovery_hold_seed(&slot);
            }
        }
        outcome
    }

    /// [`Self::hold_with_root_key`]'s writer half: the checks, the hold row
    /// and the commit. `created` names the seed slots this attempt made, so
    /// the caller removes them again when the write fails. When this
    /// install's slot key was revoked, the successor is a fresh key the
    /// writer mints here (as at the vouch arm), and the seed moves from the
    /// candidate's slot to the actual successor's.
    fn hold_write_with_root_key(
        &self,
        (owner, authority): (&AuthenticatedOwner, &ActAuthority),
        signer: &RecoveryAuthoritySigner,
        successor: RootSuccessor,
        install: Option<OwnerSigningSlot>,
        lost: &[AuthorityKey],
        wait: std::time::Duration,
        machine: EntityId,
        candidate: [u8; 32],
        seed: &zeroize::Zeroizing<[u8; 32]>,
        expected: &[u8; 32],
        created: &mut Vec<KeystoreSlot>,
    ) -> Result<RootRecovery> {
        let root_key = signer.authority_key();
        let sign = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        let mut txn = self.store.env.write_txn()?;
        // The checks the vouch writer makes, in its order.
        if self.recovery_preset_in_txn(&txn)?.is_nobody_but_me() {
            return Err(authority_refused(RELEASED_UNDER_KIT_ONLY));
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if !live_owner_key(&fold, &root_key) {
            return Err(authority_refused(ROOT_KEY_NOT_LIVE));
        }
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let named = match &successor {
            RootSuccessor::Device(input) => Some(AuthorityKey::Ed25519(input.public_key)),
            RootSuccessor::ThisInstall => None,
        };
        let lost = self.lost_keys_in_txn(&txn, &fold, actor, (&root_key, named.as_ref()), lost)?;
        let (input, held) = match (successor, install) {
            (RootSuccessor::Device(input), _) => (input, None),
            (RootSuccessor::ThisInstall, Some(slot)) => {
                let (input, key) = this_install_successor(&fold, actor, machine, &slot)?;
                (input, Some(key))
            }
            (RootSuccessor::ThisInstall, None) => return Err(invalid_authority()),
        };
        if input.public_key != candidate {
            let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
            let candidate_slot = self.recovery_hold_slot(&vault_id, machine, &candidate);
            if created.contains(&candidate_slot) {
                self.delete_recovery_hold_seed(&candidate_slot)?;
                created.retain(|slot| *slot != candidate_slot);
            }
            let slot = self.recovery_hold_slot(&vault_id, machine, &input.public_key);
            if self.put_recovery_hold_seed(&slot, seed, expected)? {
                created.push(slot);
            }
        }
        let now = self.instant_in_write_txn(&mut txn)?.secs();
        let lands_at = now.saturating_add(wait.as_secs());
        let hold = self.append_recovery_hold_in_txn(
            &mut txn,
            &root_key,
            &sign,
            RecoveryHold {
                owner: actor,
                enrolment: RecoveryHoldEnrolment {
                    machine: input.machine,
                    public_key: input.public_key,
                    proof: input.proof,
                },
                lost: lost.into_iter().collect(),
                lands_at,
            },
            now,
        )?;
        let rows = self.mark_authority_rows_counted_since_in_txn(&mut txn, &fold)?;
        txn.commit()?;
        self.note_committed_authority_rows(rows);
        if let Some(key) = held {
            self.hold_checkpoint_root_signer(Arc::new(key));
        }
        Ok(RootRecovery::Held { hold, lands_at })
    }

    /// The landing among `landed` that enrolled `successor`'s key, as the
    /// box call's [`RootRecovery::Vouched`]: this install's own key for
    /// [`RootSuccessor::ThisInstall`], the named key for a device.
    ///
    /// # Errors
    /// Preparing this install's signing keys.
    fn landing_for_successor(
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

    /// Marks the rows `txn` counted since `before` for the live mirror, as
    /// the vouch writer does: the caller commits, then announces them with
    /// [`Self::note_committed_authority_rows`], so other owner devices see
    /// a hold, an answer or a landing at the next mirror pass.
    ///
    /// # Errors
    /// The log's and the mirror marks'.
    pub(super) fn mark_authority_rows_counted_since_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: &AuthorityFold,
    ) -> Result<BTreeSet<EntityId>> {
        let rows =
            authority_rows_counted_since(before, &self.authority_view_readonly_in_txn(txn)?)?;
        self.mark_authority_rows_in_txn(txn, &rows)?;
        Ok(rows)
    }

    /// The kit's anchor cancels every live hold in the caller's write
    /// transaction, before its rows (W3): a kit recovery lands over any
    /// hold, so an attacker's hold never lands after the owner's kit. The
    /// anchor arm of this door needs none: with no live root key no hold
    /// is live, since a live hold's signer R is one.
    pub(super) fn cancel_live_holds_for_kit_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        seed: &RecoveryRootSeed,
    ) -> Result<()> {
        let live: Vec<AuthorityEntryHash> = self
            .recovery_holds_in_txn(txn)?
            .into_iter()
            .filter(|view| {
                matches!(
                    view.state,
                    RecoveryHoldState::Waiting | RecoveryHoldState::Due
                )
            })
            .map(|view| view.hold)
            .collect();
        self.append_anchor_cancels_in_txn(txn, &seed.anchor(), &live)?;
        Ok(())
    }

    /// The keys `lost` names, once each: every one a live owner signing key
    /// that `actor`, the owner who acts, enrolled, never the root's own key
    /// or the new one (`root_key`, and `new_key` when the successor is
    /// another device's key; this install's successor is never a live key:
    /// [`this_install_successor`] refuses a live one, and a fresh key is on
    /// no row). Another owner's key on a shared vault is never this owner's
    /// lost key, as the membership move revokes only its person's keys. Host
    /// roots are never enrolled owner keys, so they never pass.
    fn lost_keys_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        actor: EntityId,
        (root_key, new_key): (&AuthorityKey, Option<&AuthorityKey>),
        lost: &[AuthorityKey],
    ) -> Result<BTreeSet<AuthorityKey>> {
        let enrolled = self.enrolled_owner_keys_in_txn(txn)?;
        let named: BTreeSet<AuthorityKey> = lost.iter().cloned().collect();
        for key in &named {
            let enrolled_live = enrolled.iter().any(|listed| {
                listed.live
                    && listed.owner == actor
                    && AuthorityKey::Ed25519(listed.public_key) == *key
            });
            if key == root_key
                || Some(key) == new_key
                || !enrolled_live
                || !live_owner_key(fold, key)
            {
                return Err(authority_refused(NOT_A_LOST_KEY));
            }
        }
        Ok(named)
    }
}

/// This install's successor key and its enrolment input for `actor`, made
/// in the root door's writer from `fold`, that writer's fold: the key in
/// this install's owner signing slot, or a fresh one when the roster names
/// that key revoked. A key the roster names live needs no recovery. A run
/// checked before another run's recovery committed is refused here, before
/// it drops the seed of that run's successor, a live key
/// ([`OwnerSigningSlot::fresh_key`]).
fn this_install_successor(
    fold: &AuthorityFold,
    actor: EntityId,
    machine: EntityId,
    slot: &OwnerSigningSlot,
) -> Result<(OwnerKeyEnrollment, OwnerRootSigner)> {
    let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
    let mut key = slot.key()?;
    match fold.roster.get(&AuthorityKey::Ed25519(key.public_key())) {
        Some(device) if !device.revoked => {
            return Err(authority_refused(THIS_INSTALL_KEY_LIVE));
        }
        Some(_) => key = slot.fresh_key()?,
        None => {}
    }
    let public_key = key.public_key();
    let challenge = owner_key_enrollment_challenge(&vault_id, machine, &public_key, actor)?;
    let input = OwnerKeyEnrollment {
        machine,
        public_key,
        proof: key.sign_possession(&challenge),
    };
    Ok((input, key))
}

/// The authority rows `after` counts and `before` did not, as their entity
/// ids: every row the root door's write staged (frontier joins, the
/// revocations, the enrolment and its binding). The door marks them for the
/// vault's loaded windows in its write and announces them once it committed,
/// as the ReRoot writer does (FIX 11993), so the host and every replica see
/// the lost key revoked without a window reload.
fn authority_rows_counted_since(
    before: &AuthorityFold,
    after: &AuthorityFold,
) -> Result<BTreeSet<EntityId>> {
    after
        .valid_entries
        .difference(&before.valid_entries)
        .map(authority_log_entity_id_from_hash)
        .collect()
}

/// Whether `fold`'s roster holds `key` live with the owner role.
fn live_owner_key(fold: &AuthorityFold, key: &AuthorityKey) -> bool {
    fold.roster
        .get(key)
        .is_some_and(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
}

/// Whether `fold`'s roster holds any live root key (`ROLE_OWNER`), as the
/// anchor's appointment reads it.
fn rooted(fold: &AuthorityFold) -> bool {
    fold.roster
        .values()
        .any(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
}
