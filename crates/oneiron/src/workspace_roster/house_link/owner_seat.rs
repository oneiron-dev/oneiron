//! A house seated at the Owner role is a co-Owner, so over its workspace's
//! shared vault the seat waits as a person's Owner add waits (Engine RULING
//! HOUSE-UNBIND-AUTHORITY = A: "an Owner-role house link goes through
//! propose_add_owner, so a vault that enabled a veto wait applies it the
//! same as for a human Owner add"; ARCH-0043 #vault-owner-changes; FIX
//! HOUSE-OWNER-ROLE-VIA-ADD-OWNER).
//!
//! [`Vault::propose_house_owner_role`] starts the same `add_owner` act a
//! person's add starts, its plan naming the workspace: the act's policy row,
//! the vault's common owner-change wait, its objection window and its
//! check-in apply as they stand, and every Owner is told. A live Owner runs
//! the matured act through [`Vault::execute_completed_shared_act`], whose
//! executor seats the house by its link ([`seat_house_owner_by_act_in_txn`]).
//!
//! The doors that write a link at once, the bind and
//! [`Vault::set_house_role`], refuse an Owner seat that such an act would
//! hold ([`require_owner_seat_skips_no_wait_in_txn`]). With no wait (the
//! default, D1 = B) and before sharing, they seat the house at once, as
//! before; a house already an Owner there is no new co-Owner.

use super::{
    OWNER_OVER_OWN_DEVICE_REFUSAL, house_grants_in_txn, link_house_in_txn,
    require_role_assigner_in_txn, require_undeleted_in_txn, stored_preset_in_txn,
};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{
    FederationGrantRole, FederationGrantScope, OrgAdminStepUp, PendingAuthorityAct, SharedActKind,
};
use crate::workspace_roster::WorkspaceRosterPreset;

/// The refusal of an Owner house seat, written outside its `add_owner` act,
/// that the act would hold.
const OWNER_SEAT_WAITS_REFUSAL: &str = "seating a house at the owner role waits the vault's owner-change wait and objection window, as a person's Owner add does: start it with propose_house_owner_role";

/// The refusal of an Owner seat act for a workspace whose vault is not
/// shared yet: no act runs there, and the seat is written at once.
const NOT_SHARED_REFUSAL: &str =
    "the workspace's vault is not shared yet: set_house_role seats the house at once";

/// The refusal of an `add_owner` act's house seat whose workspace no longer
/// names that house over that vault.
const HOUSE_SEAT_ACT_STALE_REFUSAL: &str =
    "the add_owner act's workspace no longer names that house over this vault";

/// The refusal of a house Owner seat for a house already an Owner there.
const HOUSE_ALREADY_OWNER_REFUSAL: &str = "the house already holds the owner role in this vault";

/// Whether `vault_id` is this vault's live shared vault: the one its
/// Owners' acts run on. A house may be linked before sharing, with no act;
/// a deleted vault takes no link change, which the link itself refuses.
fn holds_owner_acts_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, vault_id: u64) -> Result<bool> {
    Ok(vault
        .shared_vault_creation_in_txn(txn)?
        .is_some_and(|creation| creation.vault_id == vault_id)
        && vault.shared_vault_deletion_in_txn(txn)?.is_none())
}

/// Whether `house` holds the Owner role over `vault_id`.
fn is_owner_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    house: EntityId,
    vault_id: u64,
) -> Result<bool> {
    Ok(house_grants_in_txn(vault, txn, house, vault_id)?
        .iter()
        .any(|(_, grant)| grant.role == FederationGrantRole::Owner))
}

/// Refuses a link of `preset`'s house at `role` by `binder`, written at
/// once, that would make the house a new co-Owner past a wait the vault
/// set: an `add_owner` act started now would wait (the common owner-change
/// wait, or the row's objection window with two or more Owners). `binder`
/// must first be able to assign the role, so a caller who may not keeps
/// that refusal. Any other role, a vault not shared, and a house already an
/// Owner there pass.
pub(crate) fn require_owner_seat_skips_no_wait_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    preset: &WorkspaceRosterPreset,
    role: FederationGrantRole,
    binder: EntityId,
    now: u64,
) -> Result<()> {
    let vault_id = preset.workspace_vault_id;
    if role != FederationGrantRole::Owner || !holds_owner_acts_in_txn(vault, txn, vault_id)? {
        return Ok(());
    }
    // The Owner role is an org-root assignment, which no Admin step-up
    // gates (L7-17), so this check reads none.
    require_role_assigner_in_txn(vault, txn, vault_id, binder, &OrgAdminStepUp::Absent, role)?;
    if is_owner_in_txn(vault, txn, preset.house_actor_ref, vault_id)? {
        return Ok(());
    }
    if vault.stored_act_wait_secs_in_txn(txn, vault_id, SharedActKind::AddOwner, now)? > 0 {
        return Err(Error::InvalidConfig(OWNER_SEAT_WAITS_REFUSAL.into()));
    }
    Ok(())
}

/// The seat of `house` at the Owner role that an `add_owner` act names, in
/// its executor's transaction: the link a door would write, its bind
/// receipt naming the act's `starter`, who must still be able to assign the
/// role. The act's workspace must still name `house` over `vault_id`, and
/// the house must not be an Owner there already. Answers the role the house
/// held there before, if any, and the grants that seat it now.
pub(crate) fn seat_house_owner_by_act_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    vault_id: u64,
    workspace_ref: &str,
    house: EntityId,
    starter: EntityId,
    now: u64,
) -> Result<(Option<FederationGrantRole>, Vec<EntityId>)> {
    let preset = stored_preset_in_txn(vault, txn, workspace_ref)?;
    if preset.house_actor_ref != house || preset.workspace_vault_id != vault_id {
        return Err(Error::InvalidConfig(HOUSE_SEAT_ACT_STALE_REFUSAL.into()));
    }
    if is_owner_in_txn(vault, txn, house, vault_id)? {
        return Err(Error::InvalidConfig(HOUSE_ALREADY_OWNER_REFUSAL.into()));
    }
    let before = house_grants_in_txn(vault, txn, house, vault_id)?
        .first()
        .map(|(_, grant)| grant.role);
    // The act runs after its request: no step-up of the starter's is shown
    // here, so the starter must still hold the roles by a live Owner grant
    // (L7-17: an Admin's assignment stands on its request's step-up).
    link_house_in_txn(
        vault,
        txn,
        &preset,
        FederationGrantRole::Owner,
        starter,
        &OrgAdminStepUp::Absent,
        now,
    )?;
    let grants = house_grants_in_txn(vault, txn, house, vault_id)?
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    Ok((before, grants))
}

impl Vault {
    /// Starts the `add_owner` act that seats `workspace_ref`'s house mind at
    /// the Owner role in its workspace's shared vault (HOUSE-UNBIND-AUTHORITY
    /// = A; FIX HOUSE-OWNER-ROLE-VIA-ADD-OWNER), as
    /// [`Vault::propose_add_owner`] starts a person's: the same policy row,
    /// owner-change wait, objection window and check-in, and every Owner is
    /// told. The house keeps the role it holds until a live Owner executes
    /// the completed act through [`Vault::execute_completed_shared_act`]: at
    /// once when no wait applies, after the window otherwise, and never once
    /// an Owner objects inside it. `actor` must be able to assign the Owner
    /// role and every role the house holds there, by the role table, and be
    /// a live Owner. Refused for a vault not shared yet (there
    /// [`Vault::set_house_role`] seats it at once), over the own-device
    /// residence vault, and for a house already an Owner there.
    ///
    /// # Errors
    ///
    /// The refusals above; no stored preset is `EntityNotFound`; the act
    /// start's own refusals; storage errors.
    pub fn propose_house_owner_role(
        &self,
        actor: &AuthenticatedOwner,
        workspace_ref: &str,
    ) -> Result<PendingAuthorityAct> {
        let (vault_id, house) = {
            let txn = self.store.env.read_txn()?;
            let step_up = actor.org_admin_step_up();
            let starter = actor.revalidate_person_in_txn(self, &txn)?;
            let preset = stored_preset_in_txn(self, &txn, workspace_ref)?;
            let vault_id = preset.workspace_vault_id;
            let house = preset.house_actor_ref;
            if FederationGrantScope::vault(vault_id)
                == crate::federation::own_device_residence_scope()
            {
                return Err(Error::InvalidConfig(OWNER_OVER_OWN_DEVICE_REFUSAL.into()));
            }
            require_undeleted_in_txn(self, &txn)?;
            if !holds_owner_acts_in_txn(self, &txn, vault_id)? {
                return Err(Error::InvalidConfig(NOT_SHARED_REFUSAL.into()));
            }
            let owner = FederationGrantRole::Owner;
            require_role_assigner_in_txn(self, &txn, vault_id, starter, &step_up, owner)?;
            for (_, grant) in house_grants_in_txn(self, &txn, house, vault_id)? {
                require_role_assigner_in_txn(self, &txn, vault_id, starter, &step_up, grant.role)?;
            }
            if is_owner_in_txn(self, &txn, house, vault_id)? {
                return Err(Error::InvalidConfig(HOUSE_ALREADY_OWNER_REFUSAL.into()));
            }
            (vault_id, house)
        };
        self.propose_house_owner_seat(actor, vault_id, workspace_ref, house)
    }
}
