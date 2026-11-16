//! Doors to the recovery box kit-only fact
//! (WAYBACK-BOX-HOLD-FROM-DEVICE-SWITCH = A): the node-side tests mint the
//! fact the owner's device signs in its preset write without running the
//! switch, and the fold tests sign one a carrier alone carries.

use crate::Vault;
use crate::authority::{
    ActSurface, AuthorityEntryHash, OwnerAct, OwnerActKind, PolicySetting, PolicySettingAct,
};
use crate::consent::AuthenticatedOwner;
use crate::error::Result;

const NOTHING_APPENDED: &str = "no kit-only fact was appended: the fact in force already says so, \
                                or this handle holds no owner key the fold takes as the owner's \
                                proof";
const HOLDS_AN_OWNER_KEY: &str = "this handle holds an owner key that proves the act: release it \
                                  first (owner_key_release)";

/// Appends the kit-only fact `kit_only` as the owner's preset switch signs
/// it, from this install: carried by its key, proved by the owner key this
/// handle holds. The entry hash.
///
/// # Errors
/// Refused when nothing was appended (the fact in force already says so, or
/// this handle holds no key that proves for the owner); the writer's errors.
pub fn append_recovery_box_kit_only_fact(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    kit_only: bool,
) -> Result<AuthorityEntryHash> {
    vault.with_write_txn(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        vault
            .append_recovery_box_kit_only_fact_in_txn(
                txn,
                actor,
                ActSurface::ThisInstall,
                kit_only,
            )?
            .ok_or_else(|| crate::authority::authority_refused(NOTHING_APPENDED))
    })
}

/// Appends an act of the kit-only setting that this install carries with no
/// owner key's proof, as a carrier alone would: the fold keeps it waiting for
/// the owner, and the fact in force does not move. The entry hash.
///
/// # Errors
/// Refused while this handle holds a key that proves for the owner; the
/// carried act's errors.
pub fn append_unproven_recovery_box_kit_only_fact(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    kit_only: bool,
) -> Result<AuthorityEntryHash> {
    vault.with_write_txn(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let proves = vault
            .owner_proof_signer(&vault.authority_view_readonly_in_txn(txn)?)
            .is_some();
        if proves {
            return Err(crate::authority::authority_refused(HOLDS_AN_OWNER_KEY));
        }
        let target = PolicySetting::RecoveryBoxKitOnly
            .reserved_target()?
            .ok_or_else(crate::authority::invalid_authority)?;
        let seen = vault.policy_setting_revision_in_txn(txn, target)?;
        vault.append_policy_setting_op_in_txn(
            txn,
            PolicySettingAct {
                act: OwnerAct::by_owner(
                    actor,
                    OwnerActKind::PolicySetting,
                    target,
                    ActSurface::ThisInstall,
                    seen,
                ),
                setting: PolicySetting::RecoveryBoxKitOnly,
                prior: crate::authority::recovery_box_kit_only_value(!kit_only),
                value: Some(crate::authority::recovery_box_kit_only_value(kit_only)),
            },
        )
    })
}
