//! The kit-only switch as a fact every machine of the vault folds
//! (WAYBACK-BOX-HOLD-FROM-DEVICE-SWITCH = A, Engine 17 Nov 01:49).
//!
//! The recovery preset is a row of the install that changed it, and on a
//! managed vault the switch into "Nobody but me" (or "any 2 pieces") and
//! back runs on the owner's device, so the managed node that holds the
//! recovery box never reads it. The switch's own write therefore signs one
//! act of the setting [`PolicySetting::RecoveryBoxKitOnly`], kit-only on or
//! off, carried by this install's key and proved by the owner key it holds.
//! The fold counts the act only with that proof: an agent's act is no valid
//! entry, a carrier's word alone waits for the owner, and a revoked key's
//! cosign proves nothing. [`Vault::recovery_box_kit_only_fact`] answers the
//! act in force, for the node to hold or release the box.
//!
//! A preset door asks before its write when the switch would change the fact
//! or rotate the recovery authority key ([`Vault::recovery_preset_proof_ground`]).
//! It does not check for a proving key before it asks: a key under a device
//! PIN proves only once the PIN step has opened its window. The act's proof
//! is signed on the person's confirm. An install that still holds no key the
//! fold takes as the owner's proof writes no act, as nothing could count it:
//! the preset change stands, and the node reads no new fact.

use crate::Vault;
use crate::authority::{
    ActSurface, AuthorityEntryHash, OwnerAct, OwnerActKind, OwnerProofGround, PolicySetting,
    PolicySettingAct,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::world_keys::{OwnerActImportance, owner_presence_reasons};

/// The act did not land with the owner key's proof in the switch's write.
const FACT_NOT_COUNTED: &str = "the kit-only switch's signed record did not count with the owner \
                                key's proof; nothing was written";

/// The switch's write found a rotation or a fact change that its door's read
/// did not, so the person at this device was not asked about it.
const SWITCH_CHANGED_SINCE_ASKED: &str = "this switch would change more than it did when the \
                                          person at this device was asked; nothing was written";

/// The ground a switch's write rotates the recovery authority key or changes
/// the kit-only fact on: the important confirm its door asked for. A door
/// that asked for none read neither change, so the write found one that came
/// after the read: a conflict, and nothing is written.
pub(super) fn asked_ground(ground: Option<&OwnerProofGround>) -> Result<&OwnerProofGround> {
    let ground = ground.ok_or(Error::ConcurrentWrite(SWITCH_CHANGED_SINCE_ASKED))?;
    ground.refuse_risen_importance(OwnerActImportance::Important)?;
    Ok(ground)
}

/// The recovery box's kit-only switch as the fold holds it: the owner's act
/// in force of [`PolicySetting::RecoveryBoxKitOnly`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryBoxKitOnlyFact {
    /// The recovery preset is kit-only: the box keeps no way back.
    pub kit_only: bool,
    /// The signed act that says so.
    pub entry: AuthorityEntryHash,
}

fn kit_only_target() -> Result<EntityId> {
    PolicySetting::RecoveryBoxKitOnly
        .reserved_target()?
        .ok_or_else(crate::authority::invalid_authority)
}

impl Vault {
    /// The vault's kit-only fact from the fold: the act of
    /// [`PolicySetting::RecoveryBoxKitOnly`] in force, by the rule every
    /// setting's choice follows (the live acts that agree, else their newest
    /// common act). `None` when the vault never switched with an owner key's
    /// proof, or its live acts never agreed.
    ///
    /// # Errors
    /// The authority log's read errors.
    pub fn recovery_box_kit_only_fact(&self) -> Result<Option<RecoveryBoxKitOnlyFact>> {
        let txn = self.store.env.read_txn()?;
        self.recovery_box_kit_only_fact_in_txn(&txn)
    }

    /// [`Vault::recovery_box_kit_only_fact`] in `txn`.
    pub(crate) fn recovery_box_kit_only_fact_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<RecoveryBoxKitOnlyFact>> {
        let target = kit_only_target()?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        Ok(fold
            .policy_settings
            .targets
            .get(&target)
            .and_then(|folded| folded.in_force.as_ref())
            .and_then(|head| {
                let kit_only = crate::authority::recovery_box_kit_only_of(head.choice.as_ref()?)?;
                Some(RecoveryBoxKitOnlyFact {
                    kit_only,
                    entry: head.act,
                })
            }))
    }

    /// The ground a preset door signs its kit-only fact on, checked before
    /// the door's write: the person's confirm of an important act
    /// ([`Vault::owner_presence`]), asked when the fact in force does not
    /// already say `kit_only` or the door reads that it `rotates` the recovery
    /// authority key; `None` otherwise. The read does not look for a proving
    /// key: a key under a device PIN proves only once the PIN step has opened
    /// its window. An install on which no key proves is asked and signs no fact.
    /// The read revalidates `owner` first, so a proof that no longer holds
    /// raises no prompt; the door's write revalidates it again.
    ///
    /// # Errors
    /// An owner proof that no longer holds; the presence check's refusal (a
    /// declined prompt; a device PIN whose window is closed); the authority
    /// log's read errors.
    pub(crate) fn recovery_preset_proof_ground(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        kit_only: bool,
        rotates: bool,
    ) -> Result<Option<OwnerProofGround>> {
        let before = {
            let txn = self.store.env.read_txn()?;
            owner.revalidate_in_txn(self, &txn)?;
            self.recovery_box_kit_only_fact_in_txn(&txn)?
        };
        if !rotates && before.is_some_and(|fact| fact.kit_only == kit_only) {
            return Ok(None);
        }
        let witness = self.owner_presence(
            OwnerActImportance::Important,
            owner_presence_reasons::RECOVERY_PRESET,
        )?;
        Ok(Some(OwnerProofGround::witnessed(&witness)))
    }

    /// Signs the kit-only fact `kit_only` for `owner`, decided from
    /// `surface`, in the preset's write `txn`, on `ground`, the person's
    /// confirm the door asked for, when the fact in force does not already
    /// say so and this install holds a key that proves for the owner
    /// ([`Vault::holds_proving_owner_key`]). A change to the fact requires
    /// an important ground even when no key proves. The act's `prior` is
    /// the fact in force, off when there is none. The entry hash when it
    /// signed one.
    ///
    /// # Errors
    /// The act did not land with the owner key's proof (`FACT_NOT_COUNTED`),
    /// the carried act's own errors, and storage errors: the preset's write
    /// fails whole. A fact change the door did not ask for is a conflict.
    pub(crate) fn append_recovery_box_kit_only_fact_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        ground: Option<&OwnerProofGround>,
        owner: EntityId,
        surface: ActSurface,
        kit_only: bool,
    ) -> Result<Option<AuthorityEntryHash>> {
        let before = self.recovery_box_kit_only_fact_in_txn(txn)?;
        if before.is_some_and(|fact| fact.kit_only == kit_only) {
            return Ok(None);
        }
        let ground = asked_ground(ground)?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if !self.holds_proving_owner_key(&fold) {
            tracing::info!(
                kit_only,
                "no owner key on this install proves the kit-only switch: no fact was signed"
            );
            return Ok(None);
        }
        let target = kit_only_target()?;
        let seen = self.policy_setting_revision_in_txn(txn, target)?;
        let prior = before.is_some_and(|fact| fact.kit_only);
        let entry = self.append_policy_setting_op_in_txn(
            txn,
            Some(ground),
            PolicySettingAct {
                act: OwnerAct::by_owner(owner, OwnerActKind::PolicySetting, target, surface, seen),
                setting: PolicySetting::RecoveryBoxKitOnly.wire().to_owned(),
                prior: crate::authority::recovery_box_kit_only_value(prior),
                value: Some(crate::authority::recovery_box_kit_only_value(kit_only)),
            },
        )?;
        if self.recovery_box_kit_only_fact_in_txn(txn)?
            != Some(RecoveryBoxKitOnlyFact { kit_only, entry })
        {
            return Err(crate::authority::authority_refused(FACT_NOT_COUNTED));
        }
        Ok(Some(entry))
    }
}
