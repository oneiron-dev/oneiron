//! The importance of a member's move is what it ends. A move that ends owner
//! authority the member holds on this vault's log is important: its write
//! signs that revocation on the ground the door asked for. Every other
//! removal and leave is ordinary: a narrowing that signs nothing with the
//! owner key. A door derives the importance on a read before it asks, and
//! the move's write derives it again.

use super::super::{check_vault, invalid};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::federation::{FederationGrantRole as Role, OrgAdminPower, SharedVaultWrite};
use crate::world_keys::OwnerActImportance;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

impl Vault {
    /// The importance of moving `member` from `from` to `to` (`None` leaves
    /// the vault): important when the move retires owner authority and the
    /// member holds any on this vault's log, else ordinary.
    pub(super) fn member_move_importance_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: EntityId,
        from: Role,
        to: Option<Role>,
    ) -> Result<OwnerActImportance> {
        if super::move_retires_owner_authority(from, to)
            && self.person_holds_owner_authority_in_txn(txn, member)?
        {
            Ok(OwnerActImportance::Important)
        } else {
            Ok(OwnerActImportance::Ordinary)
        }
    }

    /// The checks [`Vault::remove_shared_member`] makes that need only a read
    /// of the store, in the order its write makes them, then the importance
    /// the act asks with. The door runs this on a read before it asks, so a
    /// refusal raises no prompt; the write makes each check again. The checks
    /// that need the write's clock, a key of this install or the check-in
    /// judge's own write stay in the write alone.
    pub(super) fn member_removal_importance_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        admin: &AuthenticatedOwner,
        vault_id: u64,
        member: EntityId,
    ) -> Result<OwnerActImportance> {
        let actor = self.revalidated_actor_in_txn(txn, admin, vault_id)?;
        self.authorize_shared_vault_write_in_txn(
            txn,
            vault_id,
            &WriteActor::new(actor, EdgeActorClass::Human),
            &SharedVaultWrite::Admin(OrgAdminPower::RemoveMember),
        )?;
        super::refuse_house_mind_move_in_txn(self, txn, &member)?;
        let from = self
            .member_role_in_txn(txn, vault_id, member)?
            .ok_or_else(invalid)?;
        if from == Role::Owner {
            return Err(invalid());
        }
        self.member_move_importance_in_txn(txn, member, from, None)
    }

    /// The checks [`Vault::leave_shared_vault`] makes that need only a read
    /// of the store, in the order its write makes them, then the importance
    /// the act asks with. The door runs this on a read before it asks, so a
    /// refusal raises no prompt; the write makes each check again.
    pub(super) fn member_leave_importance_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        member: &AuthenticatedOwner,
        vault_id: u64,
    ) -> Result<OwnerActImportance> {
        let actor = self.revalidated_actor_in_txn(txn, member, vault_id)?;
        let from = self
            .member_role_in_txn(txn, vault_id, actor)?
            .ok_or_else(invalid)?;
        if from == Role::Owner {
            return Err(invalid());
        }
        super::refuse_house_mind_move_in_txn(self, txn, &actor)?;
        self.member_move_importance_in_txn(txn, actor, from, None)
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
