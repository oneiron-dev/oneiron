//! Receipt projection for the family.

use std::collections::BTreeMap;

use super::codec::{corrupt, decode_settlement_record, settlement_key_artifact_id};
use super::keys::{
    BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX, FIELD_ANCHOR_DRIFTS, FIELD_ANCHOR_MOVES,
    FIELD_ARTIFACT_REF, FIELD_BEFORE_VERSION, FIELD_BRIEF_REF, FIELD_CONTENT_HASH,
    FIELD_MANIFEST_OPS, FIELD_MANIFEST_REF, FIELD_PROPOSAL_REF, FIELD_REASON, FIELD_RUN_REF,
    FIELD_VERSION,
};
use super::records::{SettleOutcomeKind, SettledAnchor, SettlementRecord};
use crate::Vault;
use crate::anchored_annotation::ReanchorSummary;
use crate::edit_roundtrip::EditManifest;
use crate::entity_id::EntityId;
use crate::error::ArtifactError;
use crate::error::{Error, Result};
use crate::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};

/// Projects the settlement ledger into OF-367 family receipts matching `query`.
///
/// The query filter is applied DURING the scan — the settlement key is ordered
/// by artifact id then proposal-ref hash, NOT by time, so filtering before the
/// caller's newest-first sort + `limit` truncation keeps a narrow query from
/// being starved by unrelated rows. The scan is capped at the family DoS guard.
pub(crate) fn settle_receipts(vault: &Vault, query: &ReceiptQuery) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for (scanned, entry) in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX)?
        .enumerate()
    {
        if scanned >= crate::receipt::MAX_RECEIPT_QUERY_SCAN {
            break;
        }
        let (key, raw) = entry?;
        let artifact_id = settlement_key_artifact_id(&key)?;
        let record = decode_settlement_record(&raw)?;
        let receipt = settlement_receipt_record(artifact_id, &record)?;
        if query.matches(&receipt) {
            out.push(receipt);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Receipt projection
// ---------------------------------------------------------------------------

pub(super) fn settlement_receipt_record(
    artifact_id: EntityId,
    record: &SettlementRecord,
) -> Result<ReceiptRecord> {
    let artifact_hex = artifact_id.to_hex();
    let mut fields = BTreeMap::new();
    fields.insert(FIELD_ARTIFACT_REF.to_owned(), artifact_hex.clone());
    fields.insert(FIELD_PROPOSAL_REF.to_owned(), record.proposal_ref.clone());
    // Surface the proposal ref as run_ref too, so the settle joins run-rooted
    // receipt projections like any other agent-run effect.
    fields.insert(FIELD_RUN_REF.to_owned(), record.proposal_ref.clone());
    if let Some(brief_ref) = record.brief_ref.as_ref() {
        fields.insert(FIELD_BRIEF_REF.to_owned(), brief_ref.clone());
    }

    let trigger_ref = match record.outcome {
        SettleOutcomeKind::Selected => {
            // Fail closed: a Selected ledger row MUST carry its version and the
            // content/manifest hashes. A missing one is a corrupt record, never
            // an artifact@0 receipt.
            let version = record.version.ok_or_else(corrupt)?;
            let content_hash = record.content_hash.ok_or_else(corrupt)?;
            let manifest_ref = record.manifest_ref.ok_or_else(corrupt)?;
            if let Some(before_version) = record.before_version {
                fields.insert(FIELD_BEFORE_VERSION.to_owned(), before_version.to_string());
            }
            fields.insert(FIELD_VERSION.to_owned(), version.to_string());
            fields.insert(
                FIELD_CONTENT_HASH.to_owned(),
                crate::receipt::hex_lower(&content_hash),
            );
            fields.insert(
                FIELD_MANIFEST_REF.to_owned(),
                crate::receipt::hex_lower(&manifest_ref),
            );
            fields.insert(
                FIELD_MANIFEST_OPS.to_owned(),
                record.manifest_ops.to_string(),
            );
            let drifts = record.anchors.iter().filter(|a| a.drifted).count();
            let moves = record.anchors.len() - drifts;
            fields.insert(FIELD_ANCHOR_MOVES.to_owned(), moves.to_string());
            fields.insert(FIELD_ANCHOR_DRIFTS.to_owned(), drifts.to_string());
            // The door opens the lens at artifact@version.
            format!("artifact:{artifact_hex}@{version}")
        }
        SettleOutcomeKind::Discarded => {
            if let Some(reason) = record.reason.as_ref() {
                fields.insert(FIELD_REASON.to_owned(), reason.clone());
            }
            format!("proposal:{}", record.proposal_ref)
        }
    };

    Ok(ReceiptRecord {
        receipt_id: format!("artifact_settle:{artifact_hex}:{}", record.proposal_ref),
        receipt_kind: ReceiptKind::ArtifactSettle,
        occurred_at: record.settled_at,
        actor: record.actor_ref.clone(),
        on_behalf_of: None,
        outcome: record.outcome.as_str().to_owned(),
        // Join the assigning brief's project view (B2 RS4), like other
        // brief-rooted receipts.
        job_ref: record.brief_ref.clone(),
        trigger_ref: Some(trigger_ref),
        policy_trace: Vec::new(),
        fields,
    })
}

pub(super) fn settled_anchors_from_summary(summary: &ReanchorSummary) -> Vec<SettledAnchor> {
    let mut anchors = Vec::with_capacity(summary.remapped.len() + summary.drifted.len());
    for thread in &summary.remapped {
        anchors.push(SettledAnchor {
            thread_id: thread.thread_id,
            locator: thread.anchor.locator.clone(),
            drifted: false,
        });
    }
    for thread in &summary.drifted {
        anchors.push(SettledAnchor {
            thread_id: thread.thread_id,
            locator: thread.anchor.locator.clone(),
            drifted: true,
        });
    }
    anchors
}

pub(super) fn manifest_ref(manifest: &EditManifest) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&manifest.to_msgpack()?).as_bytes())
}

pub(super) fn already_settled(existing: &SettlementRecord) -> Error {
    Error::Artifact(ArtifactError::EditProposalAlreadySettled {
        outcome: existing.outcome.as_str(),
    })
}
