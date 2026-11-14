//! Doors for `tests/payment_credential_withhold.rs` (L8-60): a credential
//! bound to one effector, the scan kind a mask on write would have recorded
//! for it, the owner's payment mark, this host's release fact, and the
//! reveal door's value read under the authority a settled reveal would hold,
//! so the test reaches the second value door without an agent's whole reveal
//! flow.

use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};
use crate::secret_custody::{
    CustodyClass, CustodyTier, RevealAuthority, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding,
    SecretCustodyFloor, SecretCustodyRecord, SecretCustodyStatus, reveal_value_in_txn,
};
use crate::vault::Vault;

/// When the fixture's credential was registered.
const REGISTERED_AT: u64 = 1_700_000_000;

/// Registers an active portable credential holding `value`, bound to
/// `effector` with a read grant at the T0 rung, as the vault's own register
/// door stores one. Its id.
pub fn register_bound_secret(
    vault: &Vault,
    name: &str,
    value: &[u8],
    effector: &str,
) -> Result<EntityId> {
    vault.register_secret(SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: value.to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: REGISTERED_AT,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![SecretBinding {
            effector: effector.to_owned(),
            tier_ceiling: CustodyTier::T0Doored,
            scopes: vec!["read".to_owned()],
        }],
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: vec![".secrets/api.key".to_owned()],
        policy_floor_snapshot: SecretCustodyFloor::default(),
    })
}

/// Records that a scan of kind `kind` (`stripe_key`, `openai_key`, ...)
/// lifted the credential `secret`, as a mask on write does: its label hint.
pub fn record_scan_kind(vault: &Vault, secret: &EntityId, kind: &str) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        crate::batch::secret_scan::put_mask_origin_for_test_door(
            &vault.store,
            wtxn,
            secret,
            secret,
            &format!("gate.secret_scan.{kind}"),
            REGISTERED_AT,
        )
    })
}

/// The owner's payment mark on the credential `secret`: `Some(true)` a
/// payment credential, `Some(false)` not one, `None` back to its label hint.
pub fn mark_payment_credential(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    secret: &EntityId,
    payment: Option<bool>,
) -> Result<()> {
    // Main has no payment mark (L8-60 RED scaffold): nothing is stored.
    let _ = (vault, owner, secret, payment);
    Ok(())
}

/// Seeds this host's release fact, as the server does at serve start.
pub fn seed_release(vault: &Vault, runner_fence_proven: bool, withholding_lifted: bool) {
    // Main has no release fact (L8-60 RED scaffold): nothing is seeded.
    let _ = (vault, runner_fence_proven, withholding_lifted);
}

/// The length of the value the reveal door delivers from the credential
/// `secret` to the model connection `effector`, read in one read
/// transaction; the door's refusal otherwise.
pub fn reveal_value_len(vault: &Vault, secret: &EntityId, effector: &str) -> Result<usize> {
    let meta = vault.get_secret_metadata(secret)?.ok_or_else(|| {
        Error::Secret(SecretError::SecretRefNotFound {
            name: secret.to_hex(),
        })
    })?;
    let authority =
        RevealAuthority::for_test_door(*secret, secret.to_hex(), meta.class, effector.to_owned());
    let rtxn = vault.store.env.read_txn()?;
    let value = reveal_value_in_txn(&vault.store, &rtxn, &authority)?;
    Ok(value.len())
}
