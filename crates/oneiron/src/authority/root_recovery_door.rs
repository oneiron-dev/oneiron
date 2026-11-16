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
        let fold = {
            let txn = self.store.env.read_txn()?;
            self.authority_view_readonly_in_txn(&txn)?
        };
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let (signer, kit) = match material {
            RootMaterial::Kit { seed, confirm } => (
                RecoveryAuthoritySigner::from_seed(&seed, &vault_id)?,
                Some((seed, confirm)),
            ),
            RootMaterial::Released(signer) => (signer, None),
        };
        if *signer.vault_id() != vault_id {
            return Err(invalid_authority());
        }
        if live_owner_key(&fold, &signer.authority_key()) {
            let authority = ActAuthority::Owner(owner.clone(), surface);
            return self.vouch_with_root_key((owner, &authority), &signer, successor, lost);
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
        successor: RootSuccessor,
        lost: &[AuthorityKey],
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
            root_key.clone(),
            &mut sign_enrolment,
        )?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let rows = authority_rows_counted_since(&fold, &after)?;
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
