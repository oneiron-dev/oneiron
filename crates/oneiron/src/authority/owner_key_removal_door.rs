//! The owner removes a device's owner key (the owner's ruling AUTH-5, pass
//! 27 row R1; Engine RULING AUTH-5-PR-B-REMOVE-DEVICE = A).
//!
//! Two acts end an enrolled owner key, and both sign one `RevokeDevice` per
//! key with the owner key this install holds, as the entry's primary signer:
//! - the key door ([`Vault::remove_owner_key`]): the owner removes one key
//!   and keeps its machine;
//! - a machine removal that lands ([`Vault::remove_machine`], and every
//!   other landing of a removal): the same transaction ends every live owner
//!   key whose enrolment names that machine, so a removed device can no
//!   longer approve changes. A revoke the fold does not count fails the
//!   removal.
//!
//! A revoke of an owner key counts only with an owner key's proof (row
//! HOSTED-ROOT-REVOKES-OWNER-KEY), so an install that holds none removes no
//! key: the key door answers [`RecordError::OwnerKeyRequired`], and a machine
//! removal there goes as before and lists the keys the device still holds.
//!
//! The last key held on a device: once no device key would remain, a change
//! of the owner's needs recovery. The vault keeps asking for an owner key
//! after the removal (the ratchet), so both doors ask first
//! ([`OwnerKeyRemoval::LastDeviceKey`], [`MachineRemoval::LastDeviceKey`])
//! and store nothing until the owner confirms
//! ([`LastDeviceKeyConfirmation::Given`]). The recovery root's authority key
//! is no device key: it stays, the root's door changes it, and it does not
//! count toward the keys that remain on a device.

use std::collections::BTreeSet;

use super::machine_answers::AnswerAct;
use super::owner_key_enrollment_door::EntrySigner;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, RecordError, Result};
use crate::{EntityId, Vault};

/// The key is not one an owner key enrolment of this vault names. Nothing
/// was written.
const NOT_ENROLLED: &str =
    "no owner key enrolment of this vault names the key; nothing was written";
/// The key is the recovery root's authority key. Nothing was written.
const RECOVERY_ROOT_KEY: &str = "the key is the recovery root's authority key, which the recovery \
                                 root's door changes; nothing was written";
/// The key no longer proves for the owner: it is revoked, or the roster no
/// longer holds it as the owner's. Nothing was written.
const NOT_LIVE: &str =
    "the key is not a live owner key on this vault's roster; nothing was written";
/// A machine removal would end the last owner key held on a device, and the
/// owner did not confirm that. Nothing was written.
const LAST_DEVICE_KEY_UNCONFIRMED: &str = "removing this machine ends the last owner key held on \
                                           a device, and the owner did not confirm that; remove \
                                           the machine at the machine removal door, which asks \
                                           first; nothing was written";

/// Whether the owner confirmed that an act may end the last owner key held on
/// a device. The doors ask first and store nothing without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LastDeviceKeyConfirmation {
    /// The owner was not asked, or did not confirm.
    NotGiven,
    /// The owner read that a later change of theirs needs recovery, and
    /// confirmed.
    Given,
}

/// The keys that prove for the owner on the roster, apart from the ones an
/// act ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RemainingOwnerKeys {
    /// The live Ed25519 keys held on a device: every enrolled device key,
    /// and a self-hosted vault's owner root.
    pub device_keys: usize,
    /// Whether the recovery root's authority key is live.
    pub recovery_root: bool,
}

impl RemainingOwnerKeys {
    /// Whether a later change of the owner's needs recovery: no key held on
    /// a device remains.
    #[must_use]
    pub fn needs_recovery(&self) -> bool {
        self.device_keys == 0
    }
}

/// One owner key an act ended: its `RevokeDevice` entry, counted by the fold
/// here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndedOwnerKey {
    /// The revocation's authority entry.
    pub entry: AuthorityEntryHash,
    /// The key that ended.
    pub public_key: [u8; 32],
    /// The machine its enrolment names.
    pub machine: EntityId,
    /// The owner key that signed the revocation.
    pub signed_by: AuthorityKey,
}

/// What the key door answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerKeyRemoval {
    /// The key ended, and what remains.
    Removed {
        /// The key and its revocation.
        ended: EndedOwnerKey,
        /// The owner keys that remain.
        remaining: RemainingOwnerKeys,
    },
    /// The key is the last one held on a device, and the owner has not
    /// confirmed. Nothing was written; these keys would remain.
    LastDeviceKey(RemainingOwnerKeys),
}

/// What a machine removal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineRemovalReceipt {
    /// The removal as the fold judged it: it stands, or it is held for the
    /// owner's proof.
    pub landing: MachineAnswerLanding,
    /// The owner keys the removal ended: the machine's device keys, when the
    /// removal stands and this install holds an owner key.
    pub ended_keys: Vec<[u8; 32]>,
    /// The owner keys the machine still holds live: the same keys, when the
    /// removal is held or this install holds no owner key to end them with.
    pub live_keys: Vec<[u8; 32]>,
    /// The owner keys that remain after the act.
    pub remaining: RemainingOwnerKeys,
}

/// What the machine removal door answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineRemoval {
    /// The removal was written: it stands, or it is held for the owner's
    /// proof, as the receipt's landing says.
    Written(MachineRemovalReceipt),
    /// The removal would end the last owner key held on a device, and the
    /// owner has not confirmed. Nothing was written; these keys would remain.
    LastDeviceKey(RemainingOwnerKeys),
}

impl Vault {
    /// The owner removes the enrolled owner key `key` and keeps its machine.
    /// This install's owner key signs one `RevokeDevice` of it, and the door
    /// answers only once the fold counts that entry here. A key removes
    /// itself the same way.
    ///
    /// When no key held on a device would remain, the door asks first: it
    /// answers [`OwnerKeyRemoval::LastDeviceKey`] and writes nothing unless
    /// `confirmation` is given.
    ///
    /// # Errors
    /// [`RecordError::OwnerKeyRequired`] when this install holds no owner
    /// key; an authority refusal when no enrolment names `key`, when it is
    /// the recovery root's authority key, when it is not a live owner key,
    /// or when the fold does not count the revocation; a refusal when the
    /// proof is no longer the vault's live owner.
    pub fn remove_owner_key(
        &self,
        owner: &AuthenticatedOwner,
        key: [u8; 32],
        confirmation: LastDeviceKeyConfirmation,
    ) -> Result<OwnerKeyRemoval> {
        let mut txn = self.store.env.write_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        if self.owner_proof_signer(&fold).is_none() {
            return Err(Error::Record(RecordError::OwnerKeyRequired));
        }
        let enrolled = self
            .enrolled_owner_keys_in_txn(&txn)?
            .into_iter()
            .find(|enrolled| enrolled.public_key == key)
            .ok_or_else(|| authority_refused(NOT_ENROLLED))?;
        if enrolled.kind == EnrolledOwnerKeyKind::RecoveryAuthority {
            return Err(authority_refused(RECOVERY_ROOT_KEY));
        }
        if !enrolled.live || !fold.proves_owner_acts(&AuthorityKey::Ed25519(key), self.is_hosted())
        {
            return Err(authority_refused(NOT_LIVE));
        }
        let ending = vec![enrolled];
        if confirmation == LastDeviceKeyConfirmation::NotGiven {
            let remaining = self.owner_keys_remaining_in_txn(&txn, &fold, &ending)?;
            if remaining.needs_recovery() {
                return Ok(OwnerKeyRemoval::LastDeviceKey(remaining));
            }
        }
        let ended = self
            .end_owner_keys_in_txn(&mut txn, ending)?
            .pop()
            .ok_or_else(invalid_authority)?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let remaining = self.owner_keys_remaining_in_txn(&txn, &after, &[])?;
        txn.commit()?;
        Ok(OwnerKeyRemoval::Removed { ended, remaining })
    }

    /// The owner removes `machine`, from `surface` (audit only), as
    /// [`Self::set_machine_role`] does with `MachineRole::Removed`; `seen` is
    /// as there. A removal that stands on an install that holds an owner key
    /// also ends every live owner key whose enrolment names the machine, in
    /// the same transaction, so the receipt lists them as ended. A held
    /// removal, and one on an install that holds no owner key, ends none:
    /// the receipt lists the keys the machine still holds.
    ///
    /// When the removal would end the last key held on a device, the door
    /// asks first: it answers [`MachineRemoval::LastDeviceKey`] and writes
    /// nothing unless `confirmation` is given.
    ///
    /// # Errors
    /// As [`Self::set_machine_role`]; an authority refusal when the fold does
    /// not count a key's revocation, and then nothing is written.
    pub fn remove_machine(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        machine: EntityId,
        seen: Option<[u8; 32]>,
        confirmation: LastDeviceKeyConfirmation,
    ) -> Result<MachineRemoval> {
        let mut txn = self.store.env.write_txn()?;
        let actor = owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        let ending = self.owner_keys_ending_with_machine_in_txn(&txn, &fold, machine)?;
        if confirmation == LastDeviceKeyConfirmation::NotGiven && !ending.is_empty() {
            let remaining = self.owner_keys_remaining_in_txn(&txn, &fold, &ending)?;
            if remaining.needs_recovery() {
                return Ok(MachineRemoval::LastDeviceKey(remaining));
            }
        }
        let mut answer = AnswerAct::by_owner(actor, surface, MachineRole::Removed, seen);
        answer.last_device_key = confirmation;
        let landing = self.machine_role_answer_in_txn(
            &mut txn,
            &fold,
            answer,
            machine,
            MachineRole::Removed,
        )?;
        let after = self.authority_view_readonly_in_txn(&txn)?;
        let live_keys: Vec<[u8; 32]> = self
            .device_keys_of_machine_in_txn(&txn, &after, machine)?
            .into_iter()
            .map(|enrolled| enrolled.public_key)
            .collect();
        let ended_keys = if landing.held().is_none() {
            ending.into_iter().map(|key| key.public_key).collect()
        } else {
            Vec::new()
        };
        let remaining = self.owner_keys_remaining_in_txn(&txn, &after, &[])?;
        txn.commit()?;
        #[cfg(feature = "sync")]
        if landing.held().is_none() {
            self.reseal_after_machine_admission()?;
        }
        Ok(MachineRemoval::Written(MachineRemovalReceipt {
            landing,
            ended_keys,
            live_keys,
            remaining,
        }))
    }

    /// Whether this vault is a hosted one: there a managed host's custodial
    /// root proves nothing for the owner.
    fn is_hosted(&self) -> bool {
        self.privacy_posture() == crate::HostingPrivacyPosture::Hosted
    }

    /// The live device keys whose enrolment names `machine` and that prove
    /// for the owner on `fold`, ascending by key. The recovery root's
    /// authority key is never among them: no machine holds it.
    fn device_keys_of_machine_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        machine: EntityId,
    ) -> Result<Vec<EnrolledOwnerKey>> {
        let hosted = self.is_hosted();
        Ok(self
            .enrolled_owner_keys_in_txn(txn)?
            .into_iter()
            .filter(|enrolled| {
                enrolled.live
                    && enrolled.machine == machine
                    && enrolled.kind == EnrolledOwnerKeyKind::Device
                    && fold.proves_owner_acts(&AuthorityKey::Ed25519(enrolled.public_key), hosted)
            })
            .collect())
    }

    /// The owner keys a removal of `machine` that stands ends on this
    /// install: the machine's live device keys
    /// ([`Self::device_keys_of_machine_in_txn`]) when this install holds an
    /// owner key to sign their revocations, none when it holds none.
    pub(super) fn owner_keys_ending_with_machine_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        machine: EntityId,
    ) -> Result<Vec<EnrolledOwnerKey>> {
        if self.owner_proof_signer(fold).is_none() {
            return Ok(Vec::new());
        }
        self.device_keys_of_machine_in_txn(txn, fold, machine)
    }

    /// Refuses a removal that would end `ending`, the last owner key held on
    /// a device, without the owner's confirmation: the backstop of every
    /// landing of a removal that cannot ask ([`Self::set_machine_role`], the
    /// confirm of a held removal). [`Self::remove_machine`] asks first.
    ///
    /// # Errors
    /// An authority refusal; the log's read errors.
    pub(super) fn refuse_unconfirmed_last_device_key_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        ending: &[EnrolledOwnerKey],
        confirmation: LastDeviceKeyConfirmation,
    ) -> Result<()> {
        if confirmation == LastDeviceKeyConfirmation::Given || ending.is_empty() {
            return Ok(());
        }
        if self
            .owner_keys_remaining_in_txn(txn, fold, ending)?
            .needs_recovery()
        {
            return Err(authority_refused(LAST_DEVICE_KEY_UNCONFIRMED));
        }
        Ok(())
    }

    /// The keys that prove for the owner on `fold` once `ending` ended: each
    /// live roster key the fold trusts as the owner's
    /// ([`AuthorityFold::proves_owner_acts`]), by what its enrolment says it
    /// is. A key no enrolment names is held on a device: a self-hosted
    /// vault's owner root. Only an Ed25519 key counts as a device key: the
    /// fold takes an owner proof from no other suite (`owner_proof_key`)
    /// and no install holds one to sign with, so while only a P-256 key
    /// remains the doors ask.
    fn owner_keys_remaining_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        fold: &AuthorityFold,
        ending: &[EnrolledOwnerKey],
    ) -> Result<RemainingOwnerKeys> {
        let hosted = self.is_hosted();
        let ending: BTreeSet<AuthorityKey> = ending
            .iter()
            .map(|enrolled| AuthorityKey::Ed25519(enrolled.public_key))
            .collect();
        let recovery_roots: BTreeSet<AuthorityKey> = self
            .enrolled_owner_keys_in_txn(txn)?
            .into_iter()
            .filter(|enrolled| enrolled.kind == EnrolledOwnerKeyKind::RecoveryAuthority)
            .map(|enrolled| AuthorityKey::Ed25519(enrolled.public_key))
            .collect();
        let mut remaining = RemainingOwnerKeys::default();
        for key in fold.roster.keys() {
            if ending.contains(key) || !fold.proves_owner_acts(key, hosted) {
                continue;
            }
            if recovery_roots.contains(key) {
                remaining.recovery_root = true;
            } else if matches!(key, AuthorityKey::Ed25519(_)) {
                remaining.device_keys += 1;
            }
        }
        Ok(remaining)
    }

    /// Ends `keys` in the caller's write transaction: one `RevokeDevice` of
    /// each through the one writer
    /// ([`Self::append_revoke_device_in_txn`]), signed by the owner key this
    /// install holds as the entry's primary signer, with no cosign. The fold
    /// counts it because its signer proves for the owner. The signing key's
    /// own revocation goes last, since a revoked key signs nothing more.
    /// Answers the ended keys in that order.
    ///
    /// # Errors
    /// [`RecordError::OwnerKeyRequired`] when this install holds no owner
    /// key; the writer's, when the fold does not count a revocation.
    pub(super) fn end_owner_keys_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        mut keys: Vec<EnrolledOwnerKey>,
    ) -> Result<Vec<EndedOwnerKey>> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let signer = self
            .owner_proof_signer(&fold)
            .ok_or(Error::Record(RecordError::OwnerKeyRequired))?;
        let signed_by = signer.root();
        let sign = |transcript: &[u8]| signer.sign_owner_proof(transcript);
        keys.sort_by_key(|key| AuthorityKey::Ed25519(key.public_key) == signed_by);
        let mut ended = Vec::with_capacity(keys.len());
        for key in keys {
            let entry = self.append_revoke_device_in_txn(
                txn,
                EntrySigner::Key(&signed_by, &sign),
                AuthorityKey::Ed25519(key.public_key),
            )?;
            ended.push(EndedOwnerKey {
                entry,
                public_key: key.public_key,
                machine: key.machine,
                signed_by: signed_by.clone(),
            });
        }
        Ok(ended)
    }
}
