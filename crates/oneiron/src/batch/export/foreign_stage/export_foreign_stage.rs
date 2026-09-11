//! Sync-gated foreign-import staging operations and test hooks.
#[cfg(test)]
use std::sync::{Arc, Mutex};

use crate::Vault;
use crate::error::{Error, Result};
use crate::sync::selector::{FederationAdmissionRole, admit_federated_window_update};
use crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES;
use crate::sync::types::WindowKey;

use super::super::export_authority::{VaultImportClassification, VaultImportReceipt};
use super::export_foreign_receipt::{
    ForeignVaultImportSource, REMOTE_ENTITY_METADATA_CORRUPT, StagedVaultImport,
    VaultImportFailure, VaultImportStageReceipt, VaultImportStageStatus, content_key,
    encode_vault_import_receipt, receipt_id, receipt_key, source_bytes, vault_import_stage_receipt,
};
use crate::error::{RecordError, RegistryError, SyncError};

/// One-shot hook fired inside the staged-content read window, i.e. AFTER a
/// Pending receipt has been observed and BEFORE its content row is read.
/// Lets a test land a confirmation (and its same-txn GC) in exactly the
/// interleaving a concurrent confirmer would otherwise hit by chance.
#[cfg(test)]
pub(crate) type PreContentHook = Arc<dyn Fn(&Vault) + Send + Sync>;

/// The staged-foreign-import test seams of ONE open vault; a field on that
/// vault's [`crate::store::TestHooks`].
#[cfg(test)]
#[derive(Default)]
pub(crate) struct StagedImportHooks {
    /// The armed pre-content hook and the receipt it waits for. Keyed by
    /// `receipt_id` as well as by vault, because one vault stages many
    /// receipts and only the armed one may fire.
    pre_content_hook: Mutex<Option<([u8; 32], PreContentHook)>>,
}

#[cfg(test)]
impl StagedImportHooks {
    /// Arms the pre-content hook for `receipt_id` on this vault.
    pub(crate) fn install_pre_content_hook(&self, receipt_id: [u8; 32], hook: PreContentHook) {
        *self
            .pre_content_hook
            .lock()
            .expect("staged-import pre-content hook poisoned") = Some((receipt_id, hook));
    }

    fn take_pre_content_hook(&self, receipt_id: &[u8; 32]) -> Option<PreContentHook> {
        let mut slot = self
            .pre_content_hook
            .lock()
            .expect("staged-import pre-content hook poisoned");
        if slot.as_ref().is_some_and(|(armed, _)| armed == receipt_id) {
            return slot.take().map(|(_, hook)| hook);
        }
        None
    }
}

pub(crate) fn vault_import_confirm_if_pending(
    vault: &Vault,
    expected: &VaultImportStageReceipt,
    confirmed: &VaultImportStageReceipt,
) -> Result<bool> {
    let key = receipt_key(&expected.receipt_id);
    let a = encode_vault_import_receipt(expected)?;
    let b = encode_vault_import_receipt(confirmed)?;
    vault.with_write_txn(|w| {
        let Some(current) = vault.store.sync_state.get(w, &key)? else {
            return Ok(false);
        };
        if current != a {
            return Ok(false);
        }
        vault.store.sync_state.put(w, &key, &b)?;
        // The staged payload exists only to recover a Pending receipt. Once this CAS
        // wins the receipt leaves Pending forever, so drop the content in the same
        // write txn: the terminal receipt and the GC commit or roll back together.
        vault
            .store
            .sync_state
            .delete(w, &content_key(&expected.receipt_id))?;
        Ok(true)
    })
}

/// Reads the admitted bytes retained solely to make a Pending receipt recoverable
/// after the caller loses its in-memory `StagedVaultImport`.
///
/// The row exists only while the receipt is Pending: `vault_import_confirm_if_pending`
/// deletes it atomically in the same write txn that moves the receipt out of Pending,
/// so a confirmed (or otherwise terminal) receipt never retains staged content.
pub fn vault_import_staged_content(vault: &Vault, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    vault.sync_state_get(&content_key(id))
}

fn put_stage_if_absent(
    vault: &Vault,
    receipt: &VaultImportStageReceipt,
    admitted: Option<&[u8]>,
) -> Result<bool> {
    let receipt_key = receipt_key(&receipt.receipt_id);
    let encoded = encode_vault_import_receipt(receipt)?;
    let content_key = content_key(&receipt.receipt_id);
    vault.with_write_txn(|w| {
        if vault.store.sync_state.get(w, &receipt_key)?.is_some() {
            return Ok(false);
        }
        if let Some(content) = admitted {
            vault.store.sync_state.put(w, &content_key, content)?;
        }
        vault.store.sync_state.put(w, &receipt_key, &encoded)?;
        Ok(true)
    })
}

fn staged_from_pending(
    vault: &Vault,
    receipt: VaultImportStageReceipt,
) -> Result<StagedVaultImport> {
    #[cfg(test)]
    if let Some(hook) = vault
        .test_hooks()
        .staged_import
        .take_pre_content_hook(&receipt.receipt_id)
    {
        hook(vault);
    }
    // The receipt was read in an EARLIER txn than the content row below, so
    // the two are not observed atomically. `vault_import_confirm_if_pending`
    // moves the receipt out of Pending and deletes the content in ONE write
    // txn, so a confirmation that commits inside this window leaves us
    // holding a Pending receipt whose content is legitimately gone. Treating
    // that as corruption would let a routine confirm race turn an ACCEPTED
    // import into a false "missing admitted content" error, so re-read the
    // receipt before judging and believe the durable state.
    let observed = vault_import_staged_content(vault, &receipt.receipt_id)?;
    let matches_receipt = |admitted: &[u8]| {
        admitted.len() <= MAX_DECODED_PAYLOAD_BYTES
            && receipt.admitted_update_digest == Some(*blake3::hash(admitted).as_bytes())
    };
    let admitted = match observed {
        Some(admitted) if matches_receipt(&admitted) => admitted,
        // Content is missing, oversized, or not the bytes this receipt
        // promises. Revalidate against the durable receipt: if it already
        // left Pending, the content was GC'd by the winning transition and
        // the terminal receipt is the honest answer — the same one a read
        // ordered a moment later would have returned. It carries no staged
        // content, exactly like every other terminal arm in this module.
        observed => {
            if let Some(current) = vault_import_stage_receipt(vault, &receipt.receipt_id)?
                && !matches!(current.status, VaultImportStageStatus::Pending)
            {
                return Ok(StagedVaultImport {
                    receipt: current,
                    admitted_update: Vec::new(),
                });
            }
            // Still Pending (or vanished) with unusable content: this is a
            // real invariant break, not a race. Fail closed.
            return Err(Error::InvariantViolation(if observed.is_none() {
                "pending receipt missing admitted content"
            } else {
                "pending receipt admitted content mismatch"
            }));
        }
    };
    Ok(StagedVaultImport {
        receipt,
        admitted_update: admitted,
    })
}

pub fn stage_foreign_vault_import(
    vault: &Vault,
    classification: &VaultImportReceipt,
    source: ForeignVaultImportSource,
    key: &WindowKey,
    remote: &[u8],
) -> Result<StagedVaultImport> {
    // Admission must be unique before helper effects occur within this vault:
    // the receipt read, the selector admission and the stage-if-absent write
    // are one logical step. The lock lives on the vault's store handle, so two
    // vaults open in one process no longer queue behind each other.
    let _admission_guard = vault
        .store
        .staged_import_admission_lock
        .lock()
        .map_err(|_| Error::InvariantViolation("staged admission lock poisoned"))?;
    if remote.len() > MAX_DECODED_PAYLOAD_BYTES {
        return Err(Error::InvalidConfig("foreign update too large".into()));
    };
    if classification.byte_faithful
        != matches!(
            classification.classification,
            VaultImportClassification::ByteFaithfulOwnerRestore
        )
        || !matches!(
            classification.classification,
            VaultImportClassification::ForeignAuthorityChain
                | VaultImportClassification::ReviewRequired
        )
    {
        return Err(Error::InvalidConfig(
            "invalid foreign classification".into(),
        ));
    };
    let source = match source {
        ForeignVaultImportSource::ForeignPlatform { platform } => {
            ForeignVaultImportSource::ForeignPlatform {
                platform: platform.trim().to_owned(),
            }
        }
        x => x,
    };
    source_bytes(&source)?;
    let remote_digest = *blake3::hash(remote).as_bytes();
    let id = receipt_id(
        &classification.manifest_digest,
        &source,
        key.as_str(),
        &remote_digest,
    )?;
    if let Some(existing) = vault_import_stage_receipt(vault, &id)? {
        return match existing.status {
            VaultImportStageStatus::Pending => staged_from_pending(vault, existing),
            // An already-confirmed matching artifact is idempotently observable, but it
            // cannot be used to import again because it carries no staged content.
            VaultImportStageStatus::Confirmed | VaultImportStageStatus::Failed => {
                Ok(StagedVaultImport {
                    receipt: existing,
                    admitted_update: Vec::new(),
                })
            }
        };
    }
    let admitted = match admit_federated_window_update(
        vault,
        key,
        remote,
        FederationAdmissionRole::Guest,
    ) {
        Ok(a) if a.len() <= MAX_DECODED_PAYLOAD_BYTES => a,
        Ok(_) => {
            let failed = VaultImportStageReceipt {
                receipt_id: id,
                manifest_digest: classification.manifest_digest,
                remote_update_digest: remote_digest,
                admitted_update_digest: None,
                window_key: key.as_str().into(),
                source,
                role: FederationAdmissionRole::Guest,
                status: VaultImportStageStatus::Failed,
                confirmed_by: None,
                confirmed_at_secs: None,
                failure: Some(VaultImportFailure::AdmissionRejected),
            };
            if put_stage_if_absent(vault, &failed, None)? {
                return Ok(StagedVaultImport {
                    receipt: failed,
                    admitted_update: Vec::new(),
                });
            }
            let winner = vault_import_stage_receipt(vault, &id)?
                .ok_or_else(|| Error::InvariantViolation("receipt disappeared during refusal"))?;
            return match winner.status {
                VaultImportStageStatus::Pending => staged_from_pending(vault, winner),
                VaultImportStageStatus::Confirmed | VaultImportStageStatus::Failed => {
                    Ok(StagedVaultImport {
                        receipt: winner,
                        admitted_update: Vec::new(),
                    })
                }
            };
        }
        Err(error) => {
            // Only typed protocol refusal is terminal. Storage, corruption,
            // configuration, and engine errors remain retryable.
            //
            // Gate rejections are NEVER terminal here. A Gate refusal encodes
            // local policy/trust state at decision time, not a defect in the
            // foreign artifact, and `receipt_id` deliberately excludes that
            // state. Writing a Failed receipt for one would make an artifact
            // permanently unimportable under its re-derived id even after the
            // operator installs the missing permit, so pending-outcome Gate
            // rejections fall through to the retryable `Err` path below and
            // leave no receipt behind.
            let terminal = matches!(error,
                Error::Sync(SyncError::SyncProtocolError { .. })
                    | Error::Sync(SyncError::CrdtDecodeError { .. })
                    | Error::InvalidClaimBody(_)
                    | Error::InvalidKey
                    | Error::Registry(RegistryError::MaintenanceKindNotWritable(_))
                    | Error::Registry(RegistryError::ReservedEdgeKind(_))
                    | Error::Record(RecordError::AuthorityLogStoreKeyMismatch { .. }))
                // Only this selector-produced local-root fault is retryable.
                || matches!(&error, Error::Record(RecordError::InvalidAuthorityLogBody(message)) if *message != "missing local authority root")
                // A remote entity blob too short to carry its metadata
                // header is a DEFECT IN THE FOREIGN ARTIFACT, exactly like
                // the invalid key / invalid claim body / unwritable kind
                // refusals already listed above: re-fetching the same bytes
                // re-derives the same `receipt_id` and truncates again, so
                // leaving it retryable spins forever instead of telling the
                // operator the artifact is unusable. Fail closed with a
                // terminal Failed receipt. This is verdict-text scoped (see
                // `REMOTE_ENTITY_METADATA_CORRUPT`) and deliberately does
                // NOT make `CorruptedIndex` as a whole terminal — a local
                // index fault during admission still retries.
                || matches!(&error, Error::CorruptedIndex(verdict) if *verdict == REMOTE_ENTITY_METADATA_CORRUPT);
            if !terminal {
                return Err(error);
            }
            let failed = VaultImportStageReceipt {
                receipt_id: id,
                manifest_digest: classification.manifest_digest,
                remote_update_digest: remote_digest,
                admitted_update_digest: None,
                window_key: key.as_str().into(),
                source,
                role: FederationAdmissionRole::Guest,
                status: VaultImportStageStatus::Failed,
                confirmed_by: None,
                confirmed_at_secs: None,
                failure: Some(VaultImportFailure::AdmissionRejected),
            };
            if put_stage_if_absent(vault, &failed, None)? {
                return Ok(StagedVaultImport {
                    receipt: failed,
                    admitted_update: Vec::new(),
                });
            }
            let winner = vault_import_stage_receipt(vault, &id)?
                .ok_or_else(|| Error::InvariantViolation("receipt disappeared during refusal"))?;
            return match winner.status {
                VaultImportStageStatus::Pending => staged_from_pending(vault, winner),
                VaultImportStageStatus::Confirmed | VaultImportStageStatus::Failed => {
                    Ok(StagedVaultImport {
                        receipt: winner,
                        admitted_update: Vec::new(),
                    })
                }
            };
        }
    };
    let pending = VaultImportStageReceipt {
        receipt_id: id,
        manifest_digest: classification.manifest_digest,
        remote_update_digest: remote_digest,
        admitted_update_digest: Some(*blake3::hash(&admitted).as_bytes()),
        window_key: key.as_str().into(),
        source,
        role: FederationAdmissionRole::Guest,
        status: VaultImportStageStatus::Pending,
        confirmed_by: None,
        confirmed_at_secs: None,
        failure: None,
    };
    if put_stage_if_absent(vault, &pending, Some(&admitted))? {
        return Ok(StagedVaultImport {
            receipt: pending,
            admitted_update: admitted,
        });
    }
    let existing = vault_import_stage_receipt(vault, &id)?
        .ok_or_else(|| Error::InvariantViolation("receipt disappeared during stage"))?;
    match existing.status {
        VaultImportStageStatus::Pending => staged_from_pending(vault, existing),
        VaultImportStageStatus::Confirmed | VaultImportStageStatus::Failed => {
            Ok(StagedVaultImport {
                receipt: existing,
                admitted_update: Vec::new(),
            })
        }
    }
}
