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
//! appoints. A lost key is one of the owner keys the acting owner enrolled,
//! a device key or a passkey, live on the roster. The root's own key, the
//! new key and the host roots are never a lost key here; a self-hosted
//! vault's lost host root is a ReRoot's
//! ([`Vault::recover_owner_authority_from_kit`]).

use std::collections::BTreeSet;
use std::sync::{Arc, PoisonError};

use super::owner_key_enrollment_door::EntrySigner;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::world_keys::{
    DevicePin, FreshOwnerKey, KitConfirmation, OwnerActImportance, OwnerRootSigner,
    OwnerSigningSlot, RecoveryAuthoritySigner, RecoveryRootSeed, SlotRenewal,
    owner_presence_reasons,
};
use crate::{EntityId, Result, Vault};

mod box_wait;
mod hold_arm;

use box_wait::HoldEnd;

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
const NOT_A_LOST_KEY: &str = "a key named as lost is not a live owner key the owner enrolled, \
                              or is the root's own key or the new key; nothing was written";
/// A key named as lost is the owner key that proved this owner's act: the
/// owner holds it, so it is not lost, and the act would revoke the proof it
/// stands on. Nothing was written.
const PROVING_KEY_NAMED_LOST: &str = "a key named as lost is the owner key that proved this act, \
                                      a key this install holds, not a lost one; nothing was \
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
    /// The root's authority key as the recovery box releases it at the end
    /// of the box's own wait, with `release_at`, the box's release second.
    /// On a hosted vault the box's wait is the recovery wait
    /// (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT = A), so the door's hold lands
    /// at `release_at`, never later than its own wait from now, and a hold
    /// already due lands in the same call. Otherwise as [`Self::Released`].
    ReleasedAfterBoxWait {
        signer: RecoveryAuthoritySigner,
        release_at: u64,
    },
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
    /// The door asks for the person at this device before its write (an
    /// important act, [`Vault::owner_presence`]), in the chosen arm after its checks
    /// and before taking the PIN step or slot lock.
    ///
    /// # Errors
    /// A refused confirm answers [`crate::error::RecordError::OwnerPresenceRequired`];
    /// on a device with a PIN set, [`crate::error::SecretError::DevicePin`]
    /// answers `Required` outside the PIN's window.
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
    /// kit arm never waits. A box call is judged before it lands anything;
    /// then this install's due holds land, and a landing of the acting
    /// owner's own hold that enrolled this call's successor answers
    /// [`RootRecovery::Vouched`]: the call completes the attempt it held.
    /// After the box's own wait (`RootMaterial::ReleasedAfterBoxWait`) the
    /// hold lands at the box's release second, and one already due lands
    /// in this call, which answers [`RootRecovery::Vouched`]: one wait, and
    /// the hold row stays as its receipt.
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
        // A box call lands due holds only once its request passed (row
        // RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS). A kit recovery lands
        // nothing first: it cancels every live hold in its write, a due one
        // too, so no hold's landing stands in its way.
        if let RootMaterial::Released(signer) | RootMaterial::ReleasedAfterBoxWait { signer, .. } =
            &material
            && let Some(done) = self.land_due_holds_for_box_call(owner, signer, &successor, lost)?
        {
            return Ok(done);
        }
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        // The kit's live generation, if any: old kits read as generation 0 by
        // construction, and the same kit vouches with generation 1 after a
        // rotation. A kit with none live falls through to the rooted check,
        // as a never-enrolled key does. The box's released bytes need no
        // finder: they name their generation directly.
        let mut end = HoldEnd::AfterWait(wait);
        let (signer, kit, released) = match material {
            RootMaterial::Kit { seed, confirm } => {
                let found = self.recovery_authority_generations_in_txn(&txn, &seed, &vault_id)?;
                match found.live {
                    Some((_, signer)) => (Some(signer), Some((seed, confirm)), false),
                    None => (None, Some((seed, confirm)), false),
                }
            }
            RootMaterial::Released(signer) => (Some(signer), None, true),
            RootMaterial::ReleasedAfterBoxWait { signer, release_at } => {
                end = HoldEnd::AtBoxRelease { release_at, wait };
                (Some(signer), None, true)
            }
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
                    let held =
                        self.hold_with_root_key((owner, &authority), signer, successor, lost, end)?;
                    return match (end, held) {
                        (HoldEnd::AtBoxRelease { .. }, RootRecovery::Held { hold, lands_at }) => {
                            self.land_held_after_box_wait(hold, lands_at)
                        }
                        (_, held) => Ok(held),
                    };
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
    ///
    /// The door asks for the person at this device before its write (an
    /// important act, [`Vault::owner_presence`]), after it revalidated the
    /// owner's proof on a read, before it readies this install's signing keys
    /// and before taking the PIN step or slot lock. Readying those keys
    /// writes ([`Vault::prepare_install_signing`]), so a refused confirm
    /// leaves this install's machine as it was, and a proof that is not this
    /// vault's owner raises no prompt.
    ///
    /// # Errors
    /// A refused confirm answers [`crate::error::RecordError::OwnerPresenceRequired`];
    /// on a device with a PIN set, [`crate::error::SecretError::DevicePin`]
    /// answers `Required` outside the PIN's window.
    fn vouch_with_root_key(
        &self,
        (owner, authority): (&AuthenticatedOwner, &ActAuthority),
        signer: &RecoveryAuthoritySigner,
        released: bool,
        successor: RootSuccessor,
        lost: &[AuthorityKey],
        kit_seed: Option<&RecoveryRootSeed>,
    ) -> Result<RootRecovery> {
        // The key that proved the owner is held, never lost: refused before
        // anything is readied (REVIEW-9487 P1 1).
        if owner
            .proving_owner_key()
            .is_some_and(|key| lost.contains(key))
        {
            return Err(authority_refused(PROVING_KEY_NAMED_LOST));
        }
        // The proof is this vault's live owner before the door asks; the
        // writer revalidates it in its transaction (REVIEW-10128 P1 2).
        self.owner_key_act_owner(authority)?;
        // The keystore is read before the door asks, and this install's
        // signing keys are readied after it: readying them writes
        // (REVIEW-10128 P1 1).
        if matches!(successor, RootSuccessor::ThisInstall) {
            self.device_keystore()?;
        }
        let _asked = self.owner_presence(
            OwnerActImportance::Important,
            owner_presence_reasons::RECOVER_OWNER_ROOT,
        )?;
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
        let mut sign_enrolment =
            |_: &AuthorityFold, transcript: &[u8]| signer.sign_authority_transcript(transcript);
        let sign_revoke = |transcript: &[u8]| signer.sign_authority_transcript(transcript);
        // This install's slot is read, renewed and its successor committed
        // under the vault's owner signing slot lock, which every door that
        // renews the slot takes before its transaction (REVIEW-9487 P1 2): a
        // vouch request that read the slot's old key revoked never drops the
        // seed of a successor this door enrolled. One step with a first PIN's
        // set is entered before that lock and held to the commit (row
        // OCS-OWNER-PIN), as the root appointment holds it and in the order
        // every slot door takes them: no PIN of this process is set between
        // this install's successor's making and the commit.
        let device_pin = self.device_pin();
        let _step = device_pin.as_deref().map(DevicePin::step);
        let slot_lock = install.is_some().then(|| {
            self.store
                .owner_signing_slot_lock
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
        });
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
        let (input, install_successor) = match (successor, &install) {
            (RootSuccessor::Device(input), _) => (input, None),
            (RootSuccessor::ThisInstall, Some((machine, slot))) => {
                let (input, key) = this_install_successor(&fold, actor, *machine, slot)?;
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
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let rows = authority_rows_counted_since(&fold, &after)?;
        self.mark_authority_rows_in_txn(&mut txn, &rows)?;
        // This install's fresh key enters its slot only now, the last step
        // before the commit, so a refusal above leaves the slot's seed as it
        // was (row RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS).
        let (held, renewal) = match (install_successor, &install) {
            (Some(key), Some((_, slot))) => {
                let (key, renewal) = key.settle(slot)?;
                (Some(key), renewal.map(|renewal| (slot, renewal)))
            }
            _ => (None, None),
        };
        if let Err(error) = txn.commit() {
            if let Some((slot, renewal)) = renewal {
                self.put_back_unless_on_roster(slot, renewal);
            }
            return Err(error.into());
        }
        self.note_committed_authority_rows(rows);
        // The successor is held once the slot lock is let go: a hold asks
        // every signer held for its root, and a signer's answer may read the
        // slot (REVIEW-9678 P1).
        drop(slot_lock);
        if let Some(key) = held {
            self.hold_checkpoint_root_signer(Arc::new(key));
        }
        Ok(RootRecovery::Vouched {
            enrollment,
            revoked,
        })
    }

    /// The keys `lost` names, once each: every one a live owner key that
    /// `actor`, the owner who acts, enrolled, a device key or a passkey
    /// (REVIEW-9487 P1 3), never the root's own key
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
        let named: BTreeSet<AuthorityKey> = lost.iter().cloned().collect();
        if self.revocable_lost_keys_in_txn(txn, fold, actor, (root_key, new_key), lost)? != named {
            return Err(authority_refused(NOT_A_LOST_KEY));
        }
        Ok(named)
    }

    /// The keys of `lost` that the root's key `root_key` may revoke as
    /// `owner`'s lost keys in `fold`, once each: each a live owner key that
    /// `owner` enrolled, a device key or a passkey, and never `root_key`
    /// itself or `new_key`. The door refuses a request that names any other
    /// key ([`Self::lost_keys_in_txn`]). A hold's landing revokes only these
    /// keys, read again at the landing (row
    /// RECOVERY-HOLD-LOST-KEY-RULE-AT-FOLD), so a hold that R signs by hand,
    /// with R itself or a key outside this rule among its lost keys, never
    /// lands more than the door would have held.
    pub(super) fn revocable_lost_keys_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        owner: EntityId,
        (root_key, new_key): (&AuthorityKey, Option<&AuthorityKey>),
        lost: &[AuthorityKey],
    ) -> Result<BTreeSet<AuthorityKey>> {
        let enrolled: BTreeSet<AuthorityKey> = self
            .live_owner_keys_enrolled_for_in_txn(txn, owner)?
            .into_iter()
            .collect();
        Ok(lost
            .iter()
            .filter(|key| {
                *key != root_key
                    && Some(*key) != new_key
                    && enrolled.contains(*key)
                    && live_owner_key(fold, key)
            })
            .cloned()
            .collect())
    }
}

/// This install's successor key as the root door's writer judges it: the
/// slot's own key, or a fresh key made in memory whose seed the slot takes
/// only once the writer judged the request
/// ([`InstallSuccessor::settle`]; row
/// RECOVERY-HOLD-BOX-PATH-WRITES-BEFORE-CHECKS).
enum InstallSuccessor {
    /// The key in this install's owner signing slot, which no row names.
    Kept(OwnerRootSigner),
    /// A fresh key: the roster names the slot's key revoked.
    Fresh(FreshOwnerKey),
}

impl InstallSuccessor {
    /// The key that signs the successor's proof of possession.
    fn signer(&self) -> &OwnerRootSigner {
        match self {
            Self::Kept(key) => key,
            Self::Fresh(fresh) => fresh.signer(),
        }
    }

    /// The key this install holds once the writer judged the request: the
    /// kept key, or the fresh key read back from `slot` once the slot took
    /// its seed ([`OwnerSigningSlot::renew`], under the slot lock the door
    /// holds), with what the slot held before, for the put-back when the
    /// commit fails.
    fn settle(self, slot: &OwnerSigningSlot) -> Result<(OwnerRootSigner, Option<SlotRenewal>)> {
        match self {
            Self::Kept(key) => Ok((key, None)),
            Self::Fresh(fresh) => slot
                .renew(&fresh)
                .map(|(key, renewal)| (key, Some(renewal))),
        }
    }
}

/// This install's successor key and its enrolment input for `actor`, made
/// in the root door's writer from `fold`, that writer's fold: the key in
/// this install's owner signing slot, or a fresh one when the roster names
/// that key revoked. A key the roster names live needs no recovery. A run
/// checked before another run's recovery committed is refused here, before
/// it drops the seed of that run's successor, a live key
/// ([`OwnerSigningSlot::fresh_key`]). The fresh key is in memory only: the
/// slot keeps its seed until the writer settles the key.
fn this_install_successor(
    fold: &AuthorityFold,
    actor: EntityId,
    machine: EntityId,
    slot: &OwnerSigningSlot,
) -> Result<(OwnerKeyEnrollment, InstallSuccessor)> {
    let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
    let key = this_install_successor_key(fold, slot)?;
    let public_key = key.signer().public_key();
    let challenge = owner_key_enrollment_challenge(&vault_id, machine, &public_key, actor)?;
    let input = OwnerKeyEnrollment {
        machine,
        public_key,
        proof: key.signer().sign_possession(&challenge),
    };
    Ok((input, key))
}

/// [`this_install_successor`]'s key, judged against `fold`, a write
/// transaction's fold: the slot's key when no row names it, a fresh one in
/// memory when the roster names it revoked, and a refusal when the roster
/// names it live. The hold arm settles it in its first write, so its hold
/// write reads the renewed slot's key, which no row names, and gets the
/// same key.
fn this_install_successor_key(
    fold: &AuthorityFold,
    slot: &OwnerSigningSlot,
) -> Result<InstallSuccessor> {
    let key = slot.key()?;
    match fold.roster.get(&AuthorityKey::Ed25519(key.public_key())) {
        Some(device) if !device.revoked => Err(authority_refused(THIS_INSTALL_KEY_LIVE)),
        Some(_) => Ok(InstallSuccessor::Fresh(slot.fresh_key()?)),
        None => Ok(InstallSuccessor::Kept(key)),
    }
}

/// The authority rows `after` counts and `before` did not, as their entity
/// ids: every row the root door's write staged (frontier joins, the
/// revocations, the enrolment and its binding). The door marks them for the
/// vault's loaded windows in its write and announces them once it committed,
/// as the ReRoot writer does (FIX 11993), so the host and every replica see
/// the lost key revoked without a window reload. The owner key removal
/// doors do the same with the rows their writes counted.
pub(super) fn authority_rows_counted_since(
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
