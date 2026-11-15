//! A person as a holder of a key, and the grant a person's ask stands on (DESIGN 1.2 steps 3
//! and 4; AUTH-1 = A: "a person whose Grant covers the key may widen it").

use super::{SetBy, SettingSpec};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::PolicyRowScope;

/// The grant through which `person` holds `spec` as a person holder: DEC-0005's policy power over
/// a [`SetBy::Policy`] key. Until stage 6d-1 mints that power as a Grant line, it is read from the
/// consent registry: an Admin, Deputy or Delegate whose Owner-minted `policy.change` grant names
/// the vault-scope target of the key's [`SettingSpec::policy_target`]. The answer is the
/// membership grant that power stands on, which the change row names. An Owner holds the key by
/// role, through the owner's door, so this answers `None` for an Owner. 6d-1 swaps this
/// function's source for the minted line, and 6d-2 deletes the field with the consent read.
///
/// # Errors
///
/// A store, census or grant-bound failure; never a refusal.
pub(super) fn person_policy_line_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    person: EntityId,
) -> Result<Option<EntityId>> {
    let (SetBy::Policy, Some(row_ref)) = (spec.set_by, spec.policy_target) else {
        return Ok(None);
    };
    let target = crate::policy_model::policy_row_grant_target(&PolicyRowScope::Vault, row_ref);
    crate::policy_model::vault_policy_holder_grant_in_txn(vault, txn, person, &target)
}

/// The grant a person's ask for a setting change stands on: their membership grant on this
/// shared vault, the grant a person's pending check-in climbs the ladder from (as a membership
/// door's ask does). `None` for an Owner of the vault, whose own door makes the change; on a
/// personal vault; and for a person who is no member.
///
/// # Errors
///
/// A store or census failure.
pub(super) fn person_ask_grant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<Option<EntityId>> {
    if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &person)? {
        return Ok(None);
    }
    let Some(creation) = vault.shared_vault_creation_in_txn(txn)? else {
        return Ok(None);
    };
    Ok(vault
        .member_grant_in_txn(txn, creation.vault_id, person)?
        .map(|(grant, _)| grant))
}
