//! Sync-gated foreign-import staging operations and test hooks.
use std::collections::BTreeSet;
#[cfg(test)]
use std::sync::{Arc, Mutex};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::window_protocol::FederationAdmissionRole;
use crate::store::window_protocol::MAX_DECODED_PAYLOAD_BYTES;
use crate::sync::selector::admit_staged_window_update;
use crate::window_key::WindowKey;

use super::super::export_authority::{VaultImportClassification, VaultImportReceipt};
use super::body_work::StagedImportBodyWork;
use super::content::{StagedWindowPart, decode_staged_import_parts, encode_staged_import_parts};
use super::export_foreign_receipt::{
    CONTENT, ForeignVaultImportSource, Hex64, RECEIPT, REMOTE_ENTITY_METADATA_CORRUPT, STAMPS,
    StagedVaultImport, VaultImportFailure, VaultImportStageReceipt, VaultImportStageStatus,
    content_key, encode_vault_import_receipt, receipt_id, source_bytes, vault_import_stage_receipt,
};
use super::payload::encode_staged_window_parts;
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

/// Moves the receipt from `expected` (Pending) to `confirmed` in one write,
/// or returns false when another writer moved it first. With bodies still
/// owed (`work`, FIX 12408), the write keeps the admitted content and staged
/// stamps beside the work for their later delivery; with none, it drops them.
pub(crate) fn vault_import_confirm_if_pending(
    vault: &Vault,
    expected: &VaultImportStageReceipt,
    confirmed: &VaultImportStageReceipt,
    work: Option<&StagedImportBodyWork>,
) -> Result<bool> {
    let key = Hex64(expected.receipt_id);
    let a = encode_vault_import_receipt(expected)?;
    let b = encode_vault_import_receipt(confirmed)?;
    vault.with_write_txn_grouped(|w| {
        let Some(current) = RECEIPT.get(&vault.store, w, &key)? else {
            return Ok(false);
        };
        if current != a {
            return Ok(false);
        }
        RECEIPT.put(&vault.store, w, &key, &b)?;
        // The staged payload recovers a Pending receipt, and after this CAS
        // delivers the bodies it still owes. With none owed, drop it in the
        // same write txn: the terminal receipt and the GC commit or roll back
        // together.
        match work {
            Some(work) if !work.owed.is_empty() => {
                super::body_work::keep_body_work_in_txn(
                    &vault.store,
                    w,
                    &expected.receipt_id,
                    work,
                )?;
            }
            _ => {
                CONTENT.delete(&vault.store, w, &key)?;
                STAMPS.delete(&vault.store, w, &key)?;
            }
        }
        Ok(true)
    })
}

/// Reads the admitted bytes retained to make a Pending receipt recoverable
/// after the caller loses its in-memory `StagedVaultImport`, and to deliver
/// the bodies a confirmed one still owes (FIX 12408).
///
/// The row exists while the receipt is Pending, and after its confirmation
/// only while its body work names an owed body: `vault_import_confirm_if_pending`
/// deletes it in the same write txn that confirms a receipt owing none, and
/// the body work drops it with the last owed body, a cancellation or an erase
/// of a row it carries.
pub fn vault_import_staged_content(vault: &Vault, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    vault.sync_state_get(&content_key(id))
}

/// The record of the facet stamps the artifact staged under `id` holds ahead
/// of their rows, kept exactly as long as its content: while the receipt is
/// Pending, and after its confirmation while it owes bodies.
pub(crate) fn vault_import_staged_stamps(vault: &Vault, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let txn = vault.store.env.read_txn()?;
    STAMPS.get(&vault.store, &txn, &Hex64(*id))
}

/// Whether the receipt `id` still keeps a record of staged stamps, that is,
/// whether it is Pending, or confirmed and owing bodies, with stamps of its
/// own, judged in `txn`.
pub(crate) fn vault_import_keeps_stamps_in(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &heed::RoTxn<'_>,
    id: &[u8; 32],
) -> Result<bool> {
    STAMPS.contains(dbs, txn, &Hex64(*id))
}

/// Writes `record` as the receipt `id`'s record of its staged stamps, as an
/// edit on disk would, and binds the receipt's digest to it when `bind`.
#[cfg(test)]
pub(crate) fn rewrite_staged_stamps_for_test(
    vault: &Vault,
    id: &[u8; 32],
    record: &[u8],
    bind: bool,
) -> Result<()> {
    let key = Hex64(*id);
    let mut receipt = vault_import_stage_receipt(vault, id)?
        .ok_or(Error::InvariantViolation("no receipt to rewrite"))?;
    receipt.staged_stamps_digest = Some(*blake3::hash(record).as_bytes());
    let encoded = encode_vault_import_receipt(&receipt)?;
    vault.with_write_txn_grouped(|w| {
        STAMPS.put(&vault.store, w, &key, &record.to_vec())?;
        if bind {
            RECEIPT.put(&vault.store, w, &key, &encoded)?;
        }
        Ok(())
    })
}

/// Writes `receipt` unless one is stored under its id, with the admitted
/// `content` and the record of its staged `stamps` when it is Pending.
fn put_stage_if_absent(
    vault: &Vault,
    receipt: &VaultImportStageReceipt,
    admitted: Option<(&[u8], &[u8], &BTreeSet<EntityId>)>,
) -> Result<bool> {
    let key = Hex64(receipt.receipt_id);
    let encoded = encode_vault_import_receipt(receipt)?;
    vault.with_write_txn_grouped(|w| {
        if RECEIPT.contains(&vault.store, w, &key)? {
            return Ok(false);
        }
        if let Some((content, stamps, discarded)) = admitted {
            // The content was projected for these marks; a discard since
            // owes it a projection of its own (FIX 14534 part E, E4 = A).
            if crate::sync::residence::discarded_rows_in(&vault.store, w)? != *discarded {
                return Err(Error::InvalidConfig(
                    "the owner's discard marked rows while this import staged; stage it again"
                        .into(),
                ));
            }
            CONTENT.put(&vault.store, w, &key, &content.to_vec())?;
            if !stamps.is_empty() {
                STAMPS.put(&vault.store, w, &key, &stamps.to_vec())?;
            }
        }
        RECEIPT.put(&vault.store, w, &key, &encoded)?;
        Ok(true)
    })
}

/// Deletes, in the owner's discard's write, every Pending staged import
/// whose admitted parts hold a row in `discarded`, with its content and its
/// record of stamps (FIX 14534 part E, E4 = A); its held stamps retire with
/// the receipt. The artifact can be staged again, and that staging projects
/// it for the marks. Content exists only while its receipt is Pending.
/// Returns how many went.
///
/// # Errors
///
/// Store errors.
pub(crate) fn cancel_staged_imports_holding_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    discarded: &BTreeSet<EntityId>,
) -> Result<usize> {
    if discarded.is_empty() {
        return Ok(0);
    }
    let mut cancelled = 0;
    for (key, content) in CONTENT.scan(store, txn)? {
        // A carrier that does not decode stays: its confirmation fails closed.
        let holds = decode_staged_import_parts(&content).is_ok_and(|parts| {
            parts.iter().any(|part| {
                part.born_with
                    .iter()
                    .any(|(id, _, _)| discarded.contains(id))
                    || crate::sync::window::update_holds_discarded(
                        &part.key,
                        &part.update,
                        discarded,
                    )
            })
        });
        if holds {
            CONTENT.delete(store, txn, &key)?;
            STAMPS.delete(store, txn, &key)?;
            RECEIPT.delete(store, txn, &key)?;
            cancelled += 1;
        }
    }
    Ok(cancelled)
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
        receipt.admitted_update_digest == Some(*blake3::hash(admitted).as_bytes())
            && decode_staged_import_parts(admitted).is_ok_and(|parts| {
                parts
                    .iter()
                    .all(|part| part.update.len() <= MAX_DECODED_PAYLOAD_BYTES)
            })
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
    // What the owner's discard of a world copy marks never persists here: the
    // admitted parts are projected for the marks before any content does,
    // and the write checks the marks again (FIX 14534 part E, E4 = A).
    let discarded = {
        let txn = vault.store.env.read_txn()?;
        crate::sync::residence::discarded_rows_in(&vault.store, &txn)?
    };
    let admission = admit_staged_window_update(
        vault,
        key,
        remote,
        FederationAdmissionRole::Guest,
        &id,
        classification.exported_vault_id.as_ref(),
    )
    .and_then(|mut admitted| {
        // A projection that fails is no defect of the artifact: retryable.
        admitted
            .project_for_discard(&discarded)
            .map_err(|error| Error::InvalidConfig(format!("discard projection: {error}")))?;
        Ok(admitted)
    });
    let (admitted, stamps) = match admission {
        Ok(a)
            if a.parts()
                .all(|part| part.bytes().len() <= MAX_DECODED_PAYLOAD_BYTES) =>
        {
            let mut parts = Vec::new();
            let mut records = Vec::new();
            for part in a.parts() {
                part.hold_staged(vault, part.key())?;
                parts.push(StagedWindowPart {
                    key: part.key().clone(),
                    update: part.bytes().to_vec(),
                    born_with: part.born_with().to_vec(),
                });
                records.push((part.key().clone(), part.staged_stamps()));
            }
            (
                encode_staged_import_parts(&parts)?,
                encode_staged_window_parts(&records)?,
            )
        }
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
                staged_stamps_digest: None,
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
                staged_stamps_digest: None,
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
        staged_stamps_digest: Some(*blake3::hash(&stamps).as_bytes()),
    };
    if put_stage_if_absent(vault, &pending, Some((&admitted, &stamps, &discarded)))? {
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
