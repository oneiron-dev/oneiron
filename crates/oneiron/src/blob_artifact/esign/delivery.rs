//! Lease-fenced cloud-edge handoff; provider and capability secrets stay in the host.
use super::{
    ledger::state_in,
    lifecycle::{ESIGN_DELIVERY_ATTEMPT_KIND, EsignDeliveryPayload, EsignMailTransition},
    model::*,
};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt,
};
use crate::{EntityId, Result, Vault};
use sha2::{Digest, Sha256};

const RECEIPT: &[u8] = b"esign.delivery_receipt.v1/";

/// Content-free, typed mail request for the host's local/cloud mail pack.
/// The adapter owns templates, branding, DKIM and raw capability custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsignMailDelivery {
    pub payload: EsignDeliveryPayload,
    pub email: String,
    pub title: String,
    /// Required on Completed, and read only from the sealed, pinned versions.
    pub sealed_pdfs: Vec<Vec<u8>>,
    /// MUST be passed as the provider idempotency key on every retry.
    pub idempotency_key: String,
}

/// The host must use a provider that deduplicates `idempotency_key` (or can
/// reconcile it before retry). LMDB cannot atomically commit a network send.
pub trait EsignMailTransport {
    fn send(&self, mail: &EsignMailDelivery) -> Result<String>;
}

fn admission(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: &AttemptRecord,
    now: u64,
) -> Result<Option<EsignMailDelivery>> {
    if attempt.kind != ESIGN_DELIVERY_ATTEMPT_KIND {
        return Err(invalid("delivery kind"));
    }
    let payload: EsignDeliveryPayload =
        serde_json::from_slice(&attempt.payload).map_err(|_| invalid("delivery payload"))?;
    let document = EntityId::from_hex(&payload.document)?;
    if vault.get_blob_artifact_in_txn(txn, &document)?.is_none() {
        return Ok(None);
    }
    let state = state_in(vault, txn, document)?;
    let recipient = state
        .document
        .recipients
        .iter()
        .find(|r| r.id == payload.recipient)
        .ok_or_else(|| invalid("delivery recipient"))?;
    let progress = &state.recipients[&recipient.id];
    let policy = &state.document.lifecycle;
    let enabled = match payload.transition {
        EsignMailTransition::Invite => policy.invite,
        EsignMailTransition::Pending => policy.pending,
        EsignMailTransition::Completed => policy.completed,
        EsignMailTransition::Rejection => policy.rejection,
        EsignMailTransition::Void => policy.voided,
        EsignMailTransition::Expiry => policy.expired,
        EsignMailTransition::Reminder => policy.reminder,
    };
    if !enabled {
        return Ok(None);
    }
    let valid = match payload.transition {
        EsignMailTransition::Invite
        | EsignMailTransition::Pending
        | EsignMailTransition::Reminder => {
            state.status == DocumentStatus::Pending
                && state.rejection.is_none()
                && progress.signing == SigningStatus::Ready
                && now < progress.expires_at
                && now < state.document.expires_at
        }
        EsignMailTransition::Completed => state.status == DocumentStatus::Completed,
        EsignMailTransition::Rejection => state.status == DocumentStatus::Rejected,
        EsignMailTransition::Void => state.status == DocumentStatus::Voided,
        EsignMailTransition::Expiry => state.status == DocumentStatus::Expired,
    };
    if !valid {
        return Ok(None);
    }
    // The queued item must be backed by the committed event or dispatch
    // marker, not a caller-inserted mail payload.
    if let Some(sequence) = payload.trigger.strip_prefix("event:") {
        let sequence: usize = sequence.parse().map_err(|_| invalid("delivery trigger"))?;
        let events = super::ledger::events_in(vault, txn, document)?;
        let event = &events
            .get(sequence)
            .ok_or_else(|| invalid("delivery event"))?
            .event;
        let matched = match (&payload.transition, event) {
            (EsignMailTransition::Pending, EsignEvent::Signed { .. }) => true,
            (
                EsignMailTransition::Completed,
                EsignEvent::Sealed {
                    rejected: false, ..
                },
            ) => true,
            (EsignMailTransition::Rejection, EsignEvent::Sealed { rejected: true, .. }) => true,
            (EsignMailTransition::Void, EsignEvent::Voided { .. }) => true,
            (
                EsignMailTransition::Expiry,
                EsignEvent::Expired | EsignEvent::RecipientExpired { .. },
            ) => true,
            (EsignMailTransition::Reminder, EsignEvent::ReminderClaimed { recipient, .. }) => {
                recipient == &payload.recipient
            }
            _ => false,
        };
        if !matched {
            return Err(invalid("delivery event mismatch"));
        }
    } else {
        let digest = blake3::hash(payload.trigger.as_bytes());
        let marker = [b"esign.dispatch.v1/".as_slice(), digest.as_bytes()].concat();
        if vault.store.vault_meta.get(txn, &marker)?.is_none()
            || !matches!(
                payload.transition,
                EsignMailTransition::Invite | EsignMailTransition::Reminder
            )
        {
            return Err(invalid("delivery dispatch mismatch"));
        }
    }
    let mut sealed_pdfs = Vec::new();
    if payload.transition == EsignMailTransition::Completed {
        let manifest = vault
            .store
            .vault_meta
            .get(
                txn,
                &[b"esign.sealed.v1/".as_slice(), document.as_bytes()].concat(),
            )?
            .ok_or_else(|| invalid("sealed manifest missing"))?;
        let manifest: super::SealedDocument =
            serde_json::from_slice(&manifest).map_err(|_| invalid("sealed manifest"))?;
        if manifest.rejected || manifest.items.len() != state.document.items.len() {
            return Err(invalid("sealed manifest status"));
        }
        for item in &manifest.items {
            let bytes = vault
                .read_blob_artifact_version_in_txn(
                    txn,
                    &EntityId::from_hex(&item.sealed_artifact)?,
                    item.sealed_version,
                )?
                .ok_or_else(|| invalid("sealed PDF missing"))?;
            if <[u8; 32]>::from(Sha256::digest(&bytes)) != item.sha256 {
                return Err(invalid("sealed PDF hash"));
            }
            sealed_pdfs.push(bytes);
        }
    }
    Ok(Some(EsignMailDelivery {
        idempotency_key: format!("esign:{}", blake3::hash(&attempt.payload).to_hex()),
        email: recipient.email.clone(),
        title: state.document.title.clone(),
        payload,
        sealed_pdfs,
    }))
}

impl Vault {
    /// Provider acceptance is distinct from the earlier outbound enqueue receipt.
    pub fn esign_delivery_receipt(
        &self,
        attempt: crate::attempt_queue::AttemptId,
    ) -> Result<Option<String>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &[RECEIPT, attempt.as_bytes()].concat())?
            .map(|bytes| String::from_utf8(bytes.to_vec()).map_err(|_| invalid("delivery receipt")))
            .transpose()
    }

    /// Consume one queued mail. A competing worker cannot take the same lease;
    /// a crash after provider acceptance repeats the SAME idempotency key.
    /// No provider call happens while the vault writer lock is held.
    pub fn deliver_one_esign<T: EsignMailTransport>(
        &self,
        owner: &str,
        now: u64,
        transport: &T,
    ) -> Result<bool> {
        let claimed = self.with_write_txn(|txn| {
            let queue = AttemptQueue::new(self);
            let claim = queue.claim_kind_in_txn(
                txn,
                ESIGN_DELIVERY_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: owner.into(),
                    now,
                },
            )?;
            let ClaimOutcome::Claimed(attempt) = claim else {
                return Ok(None);
            };
            let request = admission(self, txn, &attempt, now)?;
            if request.is_none() {
                queue.complete_in_txn(
                    txn,
                    CompleteAttempt {
                        id: attempt.id,
                        lease_owner: owner.into(),
                        attempt_count: attempt.attempt_count,
                        now,
                    },
                )?;
            }
            Ok(Some((attempt, request)))
        })?;
        let Some((attempt, request)) = claimed else {
            return Ok(false);
        };
        let Some(request) = request else {
            return Ok(true);
        };
        let provider_receipt = transport.send(&request)?;
        if provider_receipt.is_empty()
            || provider_receipt.len() > 512
            || provider_receipt.contains(['\r', '\n'])
        {
            return Err(invalid("provider receipt"));
        }
        self.with_write_txn(|txn| {
            let queue = AttemptQueue::new(self);
            let current = queue
                .get_in_write_txn(txn, attempt.id)?
                .ok_or_else(|| invalid("delivery attempt missing"))?;
            if current.state != crate::attempt_queue::AttemptState::Leased
                || current.lease_owner != attempt.lease_owner
                || current.attempt_count != attempt.attempt_count
            {
                return Err(invalid("delivery lease changed"));
            }
            let key = [RECEIPT, attempt.id.as_bytes()].concat();
            self.store
                .vault_meta
                .put(txn, &key, provider_receipt.as_bytes())?;
            queue.complete_in_txn(
                txn,
                CompleteAttempt {
                    id: attempt.id,
                    lease_owner: owner.into(),
                    attempt_count: attempt.attempt_count,
                    now,
                },
            )?;
            Ok(())
        })?;
        Ok(true)
    }
}
