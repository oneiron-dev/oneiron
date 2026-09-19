//! Publication receipts co-commit with the pointer, not with a later response write.
use super::*;
use crate::outbound::OutboundIntent;
use crate::outbound_intent_ledger::IntentLedgerRecord;
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use std::collections::BTreeMap;

const PREFIX: &[u8] = b"artifact:publish:receipt:v1:";
const OUTBOUND_INTENT_ID: &str = "outbound_intent_id";
fn key(intent: &str) -> Vec<u8> {
    let mut key = PREFIX.to_vec();
    key.extend_from_slice(blake3::hash(intent.as_bytes()).as_bytes());
    key
}
fn decode(bytes: &[u8]) -> Result<ReceiptRecord> {
    let record: ReceiptRecord = rmp_serde::from_slice(bytes)
        .map_err(|_| Error::CorruptedIndex("artifact publish receipt"))?;
    if record.receipt_kind != ReceiptKind::Share || record.outcome != "published" {
        return Err(Error::CorruptedIndex("artifact publish receipt kind"));
    }
    Ok(record)
}
fn matches(receipt: &ReceiptRecord, request: &ArtifactPublishVerbRequest) -> bool {
    receipt.trigger_ref.as_deref() == Some(request.intent_ref.as_str())
        && receipt.actor == request.actor.actor_ref
        && receipt.fields.get("artifact").map(String::as_str) == Some(request.artifact.as_str())
        && receipt.fields.get("artifact_channel").map(String::as_str)
            == Some(request.channel.as_str())
        && receipt.fields.get("artifact_version")
            == Some(&artifact_hex(&request.version.encode(false)))
        && receipt.fields.get("actor_class").map(String::as_str)
            == Some(request.actor.actor_class.as_str())
        && receipt.fields.get("actor_entity_ref")
            == Some(
                &request
                    .actor
                    .actor_entity_ref
                    .map(|id| id.to_hex())
                    .unwrap_or_default(),
            )
}
impl Vault {
    pub(super) fn committed_artifact_publication(
        &self,
        request: &ArtifactPublishVerbRequest,
    ) -> Result<Option<ReceiptRecord>> {
        let txn = self.store.env.read_txn()?;
        let Some(bytes) = self.store.vault_meta.get(&txn, &key(&request.intent_ref))? else {
            return Ok(None);
        };
        let receipt = decode(&bytes)?;
        if !matches(&receipt, request) {
            return Err(Error::InvalidConfig(
                "artifact publication replay binding mismatch".into(),
            ));
        }
        Ok(Some(receipt))
    }

    /// A committed local effect is a completion fact, not permission to send.
    /// The sink stores the ledger's frozen id with the pointer and share receipt.
    /// Matching that id binds every frozen payload/actor/attempt axis without
    /// trusting the caller's request or reusing its spent approval.
    pub(crate) fn committed_artifact_publication_for_outbound(
        &self,
        record: &IntentLedgerRecord,
    ) -> Result<Option<ReceiptRecord>> {
        if record.server != "artifact"
            || record.tool != "publish"
            || !record.idempotency_supported
            || !record.budget_accounting.budget_class.is_send()
            || record.resolved_endpoint.is_some()
            || record.authorization_binding.is_some()
            || record.capability_provenance().is_some()
        {
            return Ok(None);
        }
        let Ok(intent) = serde_json::from_slice::<OutboundIntent>(record.payload()) else {
            return Ok(None);
        };
        if intent.channel != "artifact" || intent.verb != "publish" {
            return Ok(None);
        }
        let txn = self.store.env.read_txn()?;
        let Some(bytes) = self.store.vault_meta.get(&txn, &key(&intent.trigger_ref))? else {
            return Ok(None);
        };
        let receipt = decode(&bytes)?;
        if receipt.trigger_ref.as_deref() != Some(intent.trigger_ref.as_str())
            || receipt.fields.get(OUTBOUND_INTENT_ID) != Some(&record.idempotency_key)
        {
            return Err(Error::InvalidConfig(
                "artifact publication outbound binding mismatch".into(),
            ));
        }
        Ok(Some(receipt))
    }

    // Called only by the OF-327 execution sink, after its gate. Re-entry after a
    // crash before the outbound acknowledgement returns the committed receipt
    // without restoring an old pointer over a newer publication/unpublish.
    pub(super) fn publish_with_receipt(
        &self,
        request: &ArtifactPublishVerbRequest,
        outbound_intent_id: &str,
    ) -> Result<ReceiptRecord> {
        let artifact_id = self
            .resolve_pinned_artifact(&request.artifact, request.version)?
            .ok_or(Error::EntityNotFound)?;
        self.with_write_txn(|txn| {
            if let Some(bytes) = self.store.vault_meta.get(txn, &key(&request.intent_ref))? {
                let receipt = decode(&bytes)?;
                if !matches(&receipt, request)
                    || receipt.fields.get(OUTBOUND_INTENT_ID).map(String::as_str)
                        != Some(outbound_intent_id)
                {
                    return Err(Error::InvalidConfig(
                        "artifact publication replay binding mismatch".into(),
                    ));
                }
                return Ok(receipt);
            }
            let pointer = self.publish_pointer_in_txn(
                txn,
                &request.artifact,
                request.channel,
                request.version,
                artifact_id,
            )?;
            let receipt = ReceiptRecord {
                receipt_id: format!("share:publish:{}", request.intent_ref),
                receipt_kind: ReceiptKind::Share,
                occurred_at: request.occurred_at,
                actor: request.actor.actor_ref.clone(),
                on_behalf_of: None,
                outcome: "published".into(),
                job_ref: None,
                trigger_ref: Some(request.intent_ref.clone()),
                policy_trace: vec!["outbound_dispatch.allowed".into()],
                fields: BTreeMap::from([
                    ("artifact_publish".into(), "true".into()),
                    ("artifact".into(), request.artifact.clone()),
                    ("artifact_id".into(), artifact_id.to_hex()),
                    ("actor_class".into(), request.actor.actor_class.clone()),
                    (
                        "actor_entity_ref".into(),
                        request
                            .actor
                            .actor_entity_ref
                            .map(|id| id.to_hex())
                            .unwrap_or_default(),
                    ),
                    (OUTBOUND_INTENT_ID.into(), outbound_intent_id.to_owned()),
                    ("artifact_channel".into(), request.channel.as_str().into()),
                    (
                        "artifact_version".into(),
                        artifact_hex(&request.version.encode(false)),
                    ),
                    (
                        "stale_taint_override".into(),
                        pointer.stale_taint_override.to_string(),
                    ),
                ]),
            };
            let bytes = rmp_serde::to_vec_named(&receipt)
                .map_err(|_| Error::InvariantViolation("artifact publish receipt encode"))?;
            self.store
                .vault_meta
                .put(txn, &key(&request.intent_ref), &bytes)?;
            Ok(receipt)
        })
    }
}

pub(crate) fn artifact_publish_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let txn = vault.store.env.read_txn()?;
    let mut records = Vec::new();
    for (index, item) in vault
        .store
        .vault_meta
        .prefix_iter(&txn, PREFIX)?
        .enumerate()
    {
        if index >= 100_000 {
            return Err(Error::InvalidConfig(
                "artifact publication receipt scan limit".into(),
            ));
        }
        let (_, bytes) = item?;
        let receipt = decode(&bytes)?;
        if query.matches(&receipt) {
            records.push(receipt);
        }
    }
    Ok(records)
}
