//! Doors for the untangle regression tests (`tests/untangle_regressions.rs`;
//! lead 19:05 9 Nov, TESTS-MUST-RUN): each is a thin door over one
//! crate-private item, or a port of a seed helper of the `#[cfg(test)]`
//! fixtures, so the ruled behaviour tests of X01, X02, CONSENT-RAMP and the
//! repeat revoke (#6874) run from an integration target while the lib test
//! target does not compile. Hidden; never API. Every assertion stays in the
//! test file: these return plain values.

use std::sync::Arc;

use crate::config::VaultConfig;
use crate::consent::AuthenticatedOwner;
use crate::error::GateError;
use crate::vault::Vault;
use crate::{Error, Result};

// ─── vaults ─────────────────────────────────────────────────────────────

/// A temporary vault opened with `cfg` as the crate's legacy test opener
/// (`test_util::open_test_vault_with`) opens it: the seeded default policy
/// manifest cleared and a process-memory device keystore installed.
#[doc(hidden)]
#[must_use]
pub fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    vault
        .with_write_txn(|wtxn| crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id))
        .expect("clear default policy manifest for legacy test fixture");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    (dir, vault)
}

/// The crate's embedding test config (`test_util::embedding_test_config`).
#[doc(hidden)]
#[must_use]
pub fn embedding_test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config
}

// ─── #6874: the owner's revoke of a standing grant ──────────────────────

/// A revoke's answer through the owner door, in plain values.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeAnswer {
    /// The decision id (hex) of the consent revoke receipt the door returned.
    pub receipt: Option<String>,
    /// The grant was already revoked.
    pub already_revoked: bool,
    /// The record that revoked the current issuance without a consent receipt.
    pub revoked_by: Option<String>,
}

/// The owner revokes `grant_ref` (`Vault::consent_revocation`, the owner door
/// that answers a repeat revoke). A refusal is its error kind:
/// `ConsentGrantNotFound`, else the error's debug form.
///
/// # Errors
/// The door's refusal, as above.
#[doc(hidden)]
pub fn owner_revoke(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    grant_ref: &str,
) -> std::result::Result<RevokeAnswer, String> {
    // RED-BASE ADAPTATION: `Vault::consent_revocation` and its
    // `already_revoked` / `revoked_by` land with #6874. On the base the owner
    // door is `Vault::revoke_consent_grant`, which returns the receipt it
    // wrote and has neither field: already_revoked is false, revoked_by None.
    match vault.revoke_consent_grant(owner, grant_ref) {
        Ok(receipt) => Ok(RevokeAnswer {
            receipt: Some(receipt.decision_id().to_hex()),
            already_revoked: false,
            revoked_by: None,
        }),
        Err(error) => Err(error_kind(&error)),
    }
}

fn error_kind(error: &Error) -> String {
    match error {
        Error::Gate(GateError::ConsentGrantNotFound) => "ConsentGrantNotFound".to_owned(),
        other => format!("{other:?}"),
    }
}

/// The decision ids (hex) of every gate decision carrying `grant_ref`,
/// newest first.
///
/// # Errors
/// The ledger's.
#[doc(hidden)]
pub fn gate_decision_ids_for_grant(vault: &Vault, grant_ref: &str) -> Result<Vec<String>> {
    Ok(vault
        .store
        .gate_decisions_for_grant_ref(grant_ref)?
        .into_iter()
        .map(|record| record.decision_id.to_hex())
        .collect())
}

/// Every `Gate` receipt id the public receipt query returns, sorted.
///
/// # Errors
/// The query's.
#[doc(hidden)]
pub fn gate_receipt_ids(vault: &Vault) -> Result<Vec<String>> {
    let mut ids: Vec<String> = vault
        .receipts(
            crate::receipt::ReceiptQuery::default().with_kind(crate::receipt::ReceiptKind::Gate),
        )?
        .into_iter()
        .map(|record| record.receipt_id)
        .collect();
    ids.sort();
    Ok(ids)
}

/// The receipt ids of every graduation demotion, in log order.
///
/// # Errors
/// The query's.
#[doc(hidden)]
pub fn ramp_demotion_receipt_ids(vault: &Vault) -> Result<Vec<String>> {
    Ok(vault
        .receipts(
            crate::receipt::ReceiptQuery::default().with_kind(crate::receipt::ReceiptKind::Gate),
        )?
        .into_iter()
        .filter(crate::consent_graduation::is_ramp_demotion_receipt)
        .map(|record| record.receipt_id)
        .collect())
}
