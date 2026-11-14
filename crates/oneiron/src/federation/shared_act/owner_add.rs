//! Add a co-owner while retaining every existing Owner.

use super::*;

/// Payload of an `add_owner` act: `owner` gains the Owner role; nobody loses it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddOwnerPlan {
    pub v: u8,
    pub owner: String,
}

impl Vault {
    /// Start an `add_owner` act for a live person who is not already an Owner.
    /// The starter remains an Owner. Execute the returned act through
    /// [`Vault::execute_completed_shared_act`] under its snapshotted wait policy.
    pub fn propose_add_owner(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        owner: EntityId,
    ) -> Result<PendingAuthorityAct> {
        self.propose_add_owner_with_check_in(starter, vault_id, owner, None)
    }

    /// [`Self::propose_add_owner`], judged by check-in (2k1; P25-SHAPE Q1 and
    /// Q4 = A; the door names the act class `ownership_transfer`): the act
    /// records the Owner's decision, and with `check_in_ref`, an asker's
    /// approved check-in for making `owner` an Owner
    /// ([`crate::check_in::owner_add_effect_digest`]), which the Owner applies
    /// on their own proof: it is spent in the start's writer and the act
    /// names its requester. The add rule, the policy row's wait and the Owner
    /// executors stay.
    ///
    /// # Errors
    /// As [`Self::propose_add_owner`]; a `check_in_ref` that names no
    /// approved, unspent check-in for this add.
    pub fn propose_add_owner_with_check_in(
        &self,
        starter: &AuthenticatedOwner,
        vault_id: u64,
        owner: EntityId,
        check_in_ref: Option<EntityId>,
    ) -> Result<PendingAuthorityAct> {
        {
            let txn = self.store.env.read_txn()?;
            let starter = starter.revalidate_person_in_txn(self, &txn)?;
            check_vault(self, &txn, vault_id)?;
            let holders =
                self.live_act_holders(&txn, vault_id, self.store.clock.now_recorded_at())?;
            self.check_add_owner_in_txn(&txn, &live_owners(&holders, None), starter, owner)?;
        }
        self.start_authority_act_checked(
            starter,
            vault_id,
            SharedActKind::AddOwner.as_str(),
            encode(&AddOwnerPlan {
                v: PLAN_VERSION,
                owner: owner.to_hex(),
            })?,
            crate::federation::pending_act::StartCheckIn {
                verb: "vault.shared.propose_add_owner",
                act: crate::check_in::ActClass::OwnershipTransfer,
                effect_digest: crate::check_in::owner_add_effect_digest(vault_id, &owner),
                applies: check_in_ref,
            },
        )
    }

    pub(super) fn check_add_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owners: &BTreeSet<EntityId>,
        starter: EntityId,
        owner: EntityId,
    ) -> Result<()> {
        if !owners.contains(&starter)
            || owners.contains(&owner)
            || !crate::consent::person_is_live_in_txn(self, txn, &owner)?
        {
            return Err(invalid());
        }
        Ok(())
    }
}
