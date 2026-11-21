//! What a member's removal or leave asks the person at the device.
//!
//! A departure narrows who reaches the vault, and a narrowing is an ordinary
//! act: the door asks nothing. One part of a departure is an identity act:
//! where the member holds owner authority on this vault's log (an owner key,
//! or a `human` binding), the move ends it, and those revocations are what a
//! departure signs on the ground its door asked for. Such a departure is
//! important. A door derives the importance on a read before it asks, after
//! the checks it can make on that read, and the write refuses a revoke the
//! person was not asked for where it is signed
//! ([`crate::Vault::revoke_owner_authority_in_txn`]).
//!
//! An ordinary departure can still carry two signatures, neither made on the
//! door's ground: the host issuer's withdrawals of the member's slips and
//! signed-mint Grants, and, for an Owner's own removal of a member, the proof
//! this install's owner key gives the change's record as an owner-authored
//! write ([`crate::Vault::owner_act_proof_signer`]), which buys log room and
//! nothing in any fold.

use super::super::{check_vault, invalid};
use super::{MemberChange, MemberEffect};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::federation::{FederationGrantRole as Role, OrgAdminPower, SharedVaultWrite};
use crate::world_keys::OwnerActImportance;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

impl Vault {
    /// The importance of `member`'s removal or leave: important when they
    /// hold owner authority on this vault's log, which the move ends, else
    /// ordinary.
    fn member_departure_importance_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
    ) -> Result<OwnerActImportance> {
        let _ = (txn, member);
        Ok(OwnerActImportance::Ordinary)
    }

    /// The role `member` is removed from. The refusals, in the order the
    /// removal's judge gives them: a house mind, a person who holds no
    /// membership role here, an Owner.
    pub(super) fn removable_member_role_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        vault_id: u64,
        member: EntityId,
    ) -> Result<Role> {
        super::refuse_house_mind_move_in_txn(self, txn, &member)?;
        let from = self
            .member_role_in_txn(txn, vault_id, member)?
            .ok_or_else(invalid)?;
        if from == Role::Owner {
            return Err(invalid());
        }
        Ok(from)
    }

    /// The checks [`Vault::remove_shared_member`] makes on a read of the
    /// store, in the order its write makes them, then the importance the door
    /// asks with: the applier's proof, the vault, the remove power, the live
    /// holders (a conflicted root is refused there), a named `ask` (still
    /// open, its Steward still a live Steward), then the refusals the
    /// check-in judge gives before it opens or spends anything: the member's
    /// role, the applier's own membership Grant, a role the act's power is
    /// not given to, and a `check_in_ref` named for a removal that goes at
    /// once (review of #10358). The door runs this before it asks, so a
    /// refusal raises no prompt; the write makes each check again. Opening
    /// and spending a check-in, and the issuer's checks, stay in the write.
    pub(super) fn member_removal_importance_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
        ask: Option<&str>,
        check_in_ref: Option<EntityId>,
    ) -> Result<OwnerActImportance> {
        let actor = self.revalidated_actor_in_txn(txn, admin, vault_id)?;
        self.authorize_shared_vault_write_in_txn(
            txn,
            vault_id,
            &WriteActor::new(actor, EdgeActorClass::Human),
            &SharedVaultWrite::Admin(OrgAdminPower::RemoveMember),
        )?;
        let holders = self.live_act_holders(txn, vault_id, self.store.clock.now_recorded_at())?;
        if let Some(ask) = ask {
            self.member_ask_steward_stands_in_txn(txn, ask, vault_id, &holders)?;
        }
        let effect = MemberEffect {
            change: MemberChange::Remove { member },
            check_in_ref,
        };
        let act = self.member_door_act_in_txn(txn, vault_id, actor, &effect)?;
        crate::check_in::judge_person_door_act(&act, effect.check_in_ref.as_ref())?;
        self.member_departure_importance_in_txn(txn, member)
    }

    /// The checks [`Vault::leave_shared_vault`] makes on a read of the store,
    /// in the order its write makes them, then the importance the door asks
    /// with: the member's proof, the vault, the live holders (a conflicted
    /// root is refused there), the member's role, a house mind. The door runs
    /// this before it asks, so a refusal raises no prompt; the write makes
    /// each check again.
    pub(super) fn member_leave_importance_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<OwnerActImportance> {
        let actor = self.revalidated_actor_in_txn(txn, member, vault_id)?;
        self.live_act_holders(txn, vault_id, self.store.clock.now_recorded_at())?;
        let from = self
            .member_role_in_txn(txn, vault_id, actor)?
            .ok_or_else(invalid)?;
        if from == Role::Owner {
            return Err(invalid());
        }
        super::refuse_house_mind_move_in_txn(self, txn, &actor)?;
        self.member_departure_importance_in_txn(txn, actor)
    }

    /// The actor of `proof`, revalidated as a live person, while `vault_id`
    /// still names a live shared vault.
    fn revalidated_actor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<EntityId> {
        let actor = proof.revalidate_person_in_txn(self, txn)?;
        check_vault(self, txn, vault_id)?;
        Ok(actor)
    }
}
