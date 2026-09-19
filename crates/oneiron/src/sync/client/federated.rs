//! Federated admission and staged vault-import confirmation.

use super::base::SyncClient;
use crate::batch::export::{
    StagedVaultImport, VaultImportConfirmation, VaultImportStageReceipt, VaultImportStageStatus,
};
use crate::error::SyncProtocolValidation;
use crate::sync::federation_burst::{
    FederationBurstDecision, WorkKind, admit_work, record_outcome,
};
use crate::sync::selector::{
    FederationAdmissionRole, SyncSelector, admit_federated_window_update,
    encode_selector_vv_request, revalidate_admitted_federated_claims,
};
use crate::sync::transport;
use crate::sync::transport::{MAX_DECODED_PAYLOAD_BYTES, TransportError, window_sub_tags};
use crate::sync::types::WindowKey;

/// Trust is selected by the authenticated import context, never by claim bytes.
#[derive(Debug, Clone, Copy)]
pub enum ImportTier {
    OwnDevice,
    Federated(FederationAdmissionRole),
}

impl SyncClient {
    /// Replays raw window bytes by their caller-bound tier. Federation is admitted
    /// once before `put_replicated`; shared crash replay only sees locally admitted
    /// bytes and must not re-run policy or compound the confidence scale.
    pub fn import_window_update(
        &mut self,
        window_key: &str,
        update: &[u8],
        tier: ImportTier,
    ) -> std::result::Result<(), TransportError> {
        if let ImportTier::Federated(role) = tier {
            return self.import_federated_window_update(window_key, update, role);
        }
        if update.len() > MAX_DECODED_PAYLOAD_BYTES {
            return Err(TransportError::FrameTooLarge {
                size: update.len(),
                max: MAX_DECODED_PAYLOAD_BYTES,
            });
        }
        let window = self.ensure_window(window_key)?;
        self.import_accepted_window_update(window_key, &window, update)
    }

    /// Builds a selector request frame for a selector-capable caller.
    ///
    /// This builder is pure. Bind the authenticated remote peer in the client
    /// config (or `bind_federation_peer`) before receiving selector `UPDATE`
    /// frames. Bound lanes automatically route those frames through federation
    /// admission and reject full-window vector/bulk fallback.
    pub fn federated_selector_vv_request(
        &self,
        window_key: &str,
        selector: &SyncSelector,
        remote_vv: &[u8],
    ) -> std::result::Result<Vec<u8>, TransportError> {
        let key = WindowKey::try_new(window_key).ok_or(TransportError::InvalidWindowKey)?;
        let payload = encode_selector_vv_request(selector, remote_vv)
            .map_err(|_| TransportError::InvalidPayload("sync selector request encode failed"))?;
        let frame = transport::encode_window_sync(
            key.as_str(),
            window_sub_tags::SELECTOR_VV_REQUEST,
            &payload,
        )
        .into_result()?;
        Ok(frame)
    }

    /// Imports a selector response whose caller already bound the request to
    /// an explicit member/guest admission role.
    ///
    /// The role is explicit and is not inferred from grant role names. The
    /// client must also have a transport-authenticated peer/grant binding;
    /// the request's claimed member is never used as authentication.
    pub fn import_federated_selector_window_update(
        &mut self,
        window_key: &str,
        update: &[u8],
        role: FederationAdmissionRole,
    ) -> std::result::Result<(), TransportError> {
        self.import_federated_window_update(window_key, update, role)
    }

    /// Imports a member/guest federation update after applying the local
    /// federation admission gate.
    ///
    /// Full-window sync continues to call the ordinary `UPDATE` arm directly.
    /// Selector/federation callers that can identify member/guest bytes should
    /// enter through this seam so claim entities are re-stamped and admitted
    /// exactly once before the shared observed-doc import/materialization path.
    pub fn import_federated_window_update(
        &mut self,
        window_key: &str,
        update: &[u8],
        role: FederationAdmissionRole,
    ) -> std::result::Result<(), TransportError> {
        if update.len() > MAX_DECODED_PAYLOAD_BYTES {
            return Err(TransportError::FrameTooLarge {
                size: update.len(),
                max: MAX_DECODED_PAYLOAD_BYTES,
            });
        }
        let key = WindowKey::try_new(window_key).ok_or(TransportError::InvalidWindowKey)?;
        let peer = self.config.federation_peer.clone().ok_or_else(|| {
            map_federated_admission_err(crate::Error::sync_protocol(
                SyncProtocolValidation::FederationPeerUnbound,
            ))
        })?;
        peer.revalidate(&self.vault)
            .map_err(map_federated_admission_err)?;
        // Validate before retaining bytes. Malformed rows never become durable
        // deferred work, and they cannot reach an observed Loro document.
        let admitted = match admit_federated_window_update(&self.vault, &key, update, role) {
            Ok(admitted) => admitted,
            Err(error) => {
                let error = map_federated_admission_err(error);
                if matches!(error, TransportError::InvalidPayload(_)) {
                    record_outcome(&self.vault, &peer, true)
                        .map_err(map_federated_admission_err)?;
                }
                return Err(error);
            }
        };
        let kind = match role {
            FederationAdmissionRole::Member => WorkKind::MemberUpdate,
            FederationAdmissionRole::Guest => WorkKind::GuestUpdate,
        };
        let admitted_doc = loro::LoroDoc::new();
        admitted_doc
            .import(&admitted)
            .map_err(|_| TransportError::InvalidPayload("admitted update decode failed"))?;
        let writes = (admitted_doc.get_map("entities").len() as u64)
            .saturating_add(admitted_doc.get_map("edges").len() as u64)
            .max(1);
        let (decision, work) = admit_work(&self.vault, &peer, &key, kind, update, writes)
            .map_err(map_federated_admission_err)?;
        if let FederationBurstDecision::Defer { request_id, inputs } = decision {
            let _ = self
                .event_tx
                .send(crate::sync::SyncEvent::FederationDeferred {
                    window_key: window_key.to_owned(),
                    request_id,
                    inputs,
                });
            return Ok(());
        }
        let window = self.ensure_window(window_key)?;
        self.import_accepted_window_update(window_key, &window, &admitted)?;
        match work {
            Some(work) => work.complete(&self.vault, &peer),
            None => record_outcome(&self.vault, &peer, false),
        }
        .map_err(map_federated_admission_err)
    }

    pub fn confirm_staged_vault_import(
        &mut self,
        staged: StagedVaultImport,
        confirmation: VaultImportConfirmation,
    ) -> std::result::Result<VaultImportStageReceipt, TransportError> {
        // Serializes the staged-import admission and the terminal receipt
        // transition for THIS vault; the durable reread remains the
        // cross-process guard when a true CAS is unavailable. The lock lives on
        // the vault's store handle, so a second vault in the same process is
        // not held behind this one. The guard borrows a cloned handle rather
        // than `self.vault`, because the body below needs `&mut self`.
        let vault = std::sync::Arc::clone(&self.vault);
        let _admission_guard = vault
            .store
            .staged_import_confirm_lock
            .lock()
            .map_err(|_| TransportError::Storage("staged import lock poisoned".into()))?;
        if confirmation.receipt_id != staged.receipt.receipt_id
            || confirmation.confirmed_at_secs == 0
        {
            return Err(TransportError::InvalidPayload("confirmation mismatch"));
        }
        let durable =
            crate::batch::export::vault_import_stage_receipt(&self.vault, &confirmation.receipt_id)
                .map_err(|_| TransportError::Storage("receipt unreadable".into()))?
                .ok_or(TransportError::InvalidPayload(
                    "missing durable pending receipt",
                ))?;
        {
            if durable.status == VaultImportStageStatus::Confirmed {
                if durable.confirmed_by == Some(confirmation.actor)
                    && durable.confirmed_at_secs == Some(confirmation.confirmed_at_secs)
                {
                    return Ok(durable);
                }
                return Err(TransportError::InvalidPayload("conflicting confirmation"));
            }
            if durable.status == VaultImportStageStatus::Failed {
                return Err(TransportError::InvalidPayload("failed staged import"));
            }
            if durable.status != VaultImportStageStatus::Pending {
                return Err(TransportError::InvalidPayload("receipt not pending"));
            }
            if durable.receipt_id != staged.receipt.receipt_id
                || durable.manifest_digest != staged.receipt.manifest_digest
                || durable.remote_update_digest != staged.receipt.remote_update_digest
                || durable.admitted_update_digest != staged.receipt.admitted_update_digest
                || durable.window_key != staged.receipt.window_key
                || durable.source != staged.receipt.source
                || durable.role != staged.receipt.role
            {
                return Err(TransportError::InvalidPayload("receipt identity mismatch"));
            }
        }
        // A durable Pending may only be advanced by the matching Pending stage.
        // In particular, never turn an in-crate fabricated Confirmed stage into
        // phantom success while the durable ledger is still Pending.
        if staged.receipt.status != VaultImportStageStatus::Pending {
            return Err(TransportError::InvalidPayload(
                "staged receipt status mismatch",
            ));
        }
        if staged.admitted_update.len() > MAX_DECODED_PAYLOAD_BYTES {
            return Err(TransportError::FrameTooLarge {
                size: staged.admitted_update.len(),
                max: MAX_DECODED_PAYLOAD_BYTES,
            });
        }
        let expected = durable
            .admitted_update_digest
            .ok_or(TransportError::InvalidPayload(
                "missing durable admitted update digest",
            ))?;
        let actual = *blake3::hash(&staged.admitted_update).as_bytes();
        if actual != expected {
            return Err(TransportError::InvalidPayload(
                "admitted update digest mismatch",
            ));
        }
        // The bytes were admitted under the policy resolved at STAGE time, and a
        // durable Pending receipt may sit unconfirmed indefinitely. Re-resolve
        // policy now and re-run federated claim admission over the digest-pinned
        // admitted bytes, so a policy that TIGHTENED between stage and confirm is
        // honored before anything is imported. The receipt's own `role` is the
        // admission role to judge under; nothing here is inferred from the caller.
        //
        // A refusal is deliberately NON-TERMINAL and writes no receipt. The stage
        // leg already treats gate rejections as retryable rather than writing a
        // Failed receipt, because a gate refusal encodes local policy state at
        // decision time — not a defect in the foreign artifact — and `receipt_id`
        // excludes that state. Making the confirm leg terminal would make an
        // artifact permanently unimportable under its re-derived id even after the
        // operator installs the missing permit. Leaving the receipt Pending lets a
        // re-stage under the same receipt id re-evaluate once policy relaxes.
        let admission_key = WindowKey::try_new(durable.window_key.as_str())
            .ok_or(TransportError::InvalidWindowKey)?;
        revalidate_admitted_federated_claims(
            &self.vault,
            &admission_key,
            &staged.admitted_update,
            durable.role,
        )
        .map_err(map_federated_admission_err)?;
        let window = self.ensure_window(&durable.window_key)?;
        self.import_accepted_window_update(&durable.window_key, &window, &staged.admitted_update)?;
        let expected_receipt = durable;
        let mut receipt = expected_receipt.clone();
        receipt.status = VaultImportStageStatus::Confirmed;
        receipt.confirmed_by = Some(confirmation.actor);
        receipt.confirmed_at_secs = Some(confirmation.confirmed_at_secs);
        if crate::batch::export::vault_import_confirm_if_pending(
            &self.vault,
            &expected_receipt,
            &receipt,
        )
        .map_err(|e| TransportError::Storage(e.to_string()))?
        {
            return Ok(receipt);
        }
        // A different writer won the durable CAS. Return the idempotent result
        // only when it chose the same actor/time; otherwise fail closed.
        let current =
            crate::batch::export::vault_import_stage_receipt(&self.vault, &confirmation.receipt_id)
                .map_err(|_| TransportError::Storage("receipt reread failed".into()))?
                .ok_or(TransportError::InvalidPayload("receipt disappeared"))?;
        if current.status == VaultImportStageStatus::Confirmed
            && current.confirmed_by == Some(confirmation.actor)
            && current.confirmed_at_secs == Some(confirmation.confirmed_at_secs)
        {
            Ok(current)
        } else {
            Err(TransportError::InvalidPayload(
                "receipt terminal transition raced",
            ))
        }
    }
}

pub(super) fn map_federated_admission_err(e: crate::error::Error) -> TransportError {
    // A door's policy denial is its own class: it needs owner approval, never a
    // retry. Carry the door's typed taxonomy across the boundary rather than
    // flattening it into the storage bucket a caller retries.
    if let Some(denial) = e.gate_denial() {
        return TransportError::AdmissionDenied(denial);
    }
    match e {
        crate::error::Error::Sync(crate::error::SyncError::CrdtDecodeError { .. }) => {
            TransportError::InvalidPayload("federated update import failed")
        }
        // Reached only when a code is outside the typed taxonomy above, so the
        // raw codes stay auditable instead of being dropped.
        crate::error::Error::Gate(crate::error::GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => TransportError::Storage(format!(
            "federated admission rejected: outcome={outcome}, reasons={reason_codes:?}"
        )),
        crate::error::Error::Sync(crate::error::SyncError::SyncProtocolError {
            context: SyncProtocolValidation::FederatedTombstoneAdmission,
        }) => TransportError::InvalidPayload("federated tombstone update rejected"),
        e if is_local_federated_admission_failure(&e) => {
            TransportError::Storage(format!("federated admission failed: {e}"))
        }
        _ => TransportError::InvalidPayload("federated update admission failed"),
    }
}

fn is_local_federated_admission_failure(e: &crate::error::Error) -> bool {
    matches!(
        e,
        crate::error::Error::Storage(_)
            | crate::error::Error::Io(_)
            | crate::error::Error::MapFull
            | crate::error::Error::InvalidConfig(_)
            | crate::error::Error::Store(crate::error::StoreError::EmbeddingModelChanged { .. })
            | crate::error::Error::Store(crate::error::StoreError::HnswConfigChanged { .. })
            | crate::error::Error::Store(crate::error::StoreError::StorageAbiVersionChanged { .. })
            | crate::error::Error::Store(
                crate::error::StoreError::StorageSchemaVersionChanged { .. }
            )
            | crate::error::Error::Store(crate::error::StoreError::DbManifestMismatch { .. })
            | crate::error::Error::Store(crate::error::StoreError::VaultRootPreflight { .. })
            | crate::error::Error::Sync(crate::error::SyncError::WindowNotFound { .. })
            | crate::error::Error::Sync(crate::error::SyncError::WindowBusy { .. })
    )
}
