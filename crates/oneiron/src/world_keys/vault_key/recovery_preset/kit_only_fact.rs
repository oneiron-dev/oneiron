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
//! An install that holds no key the fold takes as the owner's proof writes
//! no act, as nothing could count it: the preset change stands, and the node
//! reads no new fact.

use crate::Vault;
use crate::authority::{
    ActSurface, AuthorityEntryHash, OwnerAct, OwnerActKind, PolicySetting, PolicySettingAct,
};
use crate::entity_id::EntityId;
use crate::error::Result;

/// The act did not land with the owner key's proof in the switch's write.
const FACT_NOT_COUNTED: &str = "the kit-only switch's signed record did not count with the owner \
                                key's proof; nothing was written";

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

    /// Signs the kit-only fact `kit_only` for `owner`, decided from
    /// `surface`, in the preset's write `txn`, when the fact in force does not
    /// already say so and this install holds a key that proves for the owner
    /// ([`Vault::owner_proof_signer`]). The act's `prior` is the fact in force,
    /// off when there is none. The entry hash when it signed one.
    ///
    /// # Errors
    /// The act did not land with the owner key's proof (`FACT_NOT_COUNTED`),
    /// the carried act's own errors, and storage errors: the preset's write
    /// fails whole.
    pub(crate) fn append_recovery_box_kit_only_fact_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        surface: ActSurface,
        kit_only: bool,
    ) -> Result<Option<AuthorityEntryHash>> {
        let before = self.recovery_box_kit_only_fact_in_txn(txn)?;
        if before.is_some_and(|fact| fact.kit_only == kit_only) {
            return Ok(None);
        }
        let proves = self
            .owner_proof_signer(&self.authority_view_readonly_in_txn(txn)?)
            .is_some();
        if !proves {
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
            PolicySettingAct {
                act: OwnerAct::by_owner(owner, OwnerActKind::PolicySetting, target, surface, seen),
                setting: PolicySetting::RecoveryBoxKitOnly,
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
