//! An owner's change of a setting as a signed act (FIX 4624, FIX 5660; DESIGN 1.2 "The change
//! stream"; stage 7a-1, RULING SETTING-7A-SIGNED-ACT-BASE = A).
//!
//! The signed act stays as the older setting doors sign it, generalised to any catalogue key.
//! Where the owner's change names where the owner said so (its act surface), the same write
//! appends one `PolicySettingSet` on the key's reserved target ([`policy_setting_target`] of the
//! key name). Its `seen` is the key's live acts as this write reads them, and it keeps BLAKE3
//! over the row's value it replaced and the value it left, each as the key's JSON (JSON null for
//! no row, and no value digest for a clear). The change row names the entry (`signed`).
//!
//! It is the change's last step, and best effort. It runs in a savepoint of the change's write,
//! after the row, the change row and the key's hook. So a record that cannot be signed (no
//! carrier, a fold that does not count it, a storage fault) rolls back alone. The change then
//! stands with `signed` none, as it did before the act existed (rubric 1, no new refusal).

use oneiron_authority::authority::{
    ActSurface, AuthorityEntryHash, OwnerAct, OwnerActKind, policy_setting_target,
};

use super::change::record_signed_entry_in_txn;
use super::{EncodedValue, SettingChange, SettingSpec};
use crate::Vault;
use crate::authority::PolicySettingAct;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Signs `recorded`, the owner `owner`'s applied change of a row of `spec`, as one
/// `PolicySettingSet` in `txn`, from `surface`, and names the entry on its change row. Returns
/// the entry's hash, or `None` where nothing was signed: whatever it met is logged and rolled
/// back alone.
pub(super) fn sign_owner_change_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &SettingSpec,
    owner: EntityId,
    surface: ActSurface,
    recorded: &SettingChange,
) -> Option<AuthorityEntryHash> {
    match sign_in_savepoint(vault, txn, spec, (owner, surface), recorded) {
        Ok(signed) => signed,
        Err(error) => {
            tracing::warn!(
                key = %recorded.key,
                %error,
                "the setting change stands on this install alone: no signed record of it was appended"
            );
            None
        }
    }
}

fn sign_in_savepoint(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &SettingSpec,
    (owner, surface): (EntityId, ActSurface),
    recorded: &SettingChange,
) -> Result<Option<AuthorityEntryHash>> {
    let target = policy_setting_target(&recorded.key)?;
    let prior = json_digest(spec, recorded.prior.as_ref())?;
    let value = recorded
        .value
        .as_ref()
        .map(|value| json_digest(spec, Some(value)))
        .transpose()?;
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let seen = vault.policy_setting_revision_in_txn(&savepoint, target)?;
    let act = OwnerAct::by_owner(owner, OwnerActKind::PolicySetting, target, surface, seen);
    // The record logs its own reason and rolls its own savepoint back; this one then holds
    // nothing, and dropping it leaves the change as it is.
    let Some(signed) = vault.record_policy_setting_op_in_txn(
        &mut savepoint,
        PolicySettingAct {
            act,
            setting: recorded.key.clone(),
            prior,
            value,
        },
    ) else {
        return Ok(None);
    };
    record_signed_entry_in_txn(&vault.store, &mut savepoint, recorded, signed)?;
    savepoint.commit()?;
    Ok(Some(signed))
}

/// BLAKE3 over `value` as `spec`'s JSON; over JSON null for no row.
fn json_digest(spec: &SettingSpec, value: Option<&EncodedValue>) -> Result<[u8; 32]> {
    let json = value
        .and_then(|value| spec.kind.to_json(value))
        .unwrap_or(serde_json::Value::Null);
    let bytes =
        serde_json::to_vec(&json).map_err(|_| Error::InvariantViolation("setting act encoding"))?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
