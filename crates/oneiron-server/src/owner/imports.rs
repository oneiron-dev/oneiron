//! Bulk import consent: preview the exact batch, then approve or decline it
//! whole (OF-202).
//!
//! The batch travels with every call, so there is no staged import to drift:
//! preview fills any missing ids and returns the exact batch plus its digest,
//! and approve or decline must present that same batch and digest. Approve is
//! one engine transaction (the approve-once receipt and the admission of every
//! claim); decline writes a refusal receipt and admits nothing. Either one is
//! the batch's only decision: a second approve or decline is refused.

use oneiron::consent::{AuthenticatedOwner, EffectDigest};
use oneiron::ingest::{ImportedClaimBatch, ImportedClaimBatchEntry};
use oneiron::{EntityId, TimeRange, Vault};
use serde::{Deserialize, Serialize};

use super::{OwnerError, OwnerResult, entity_id};

/// One imported claim on the wire. `claim_id` may be left out of a preview.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportClaim {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) claim_id: Option<String>,
    /// The entity the claim is about.
    pub(crate) subject: String,
    /// The record in the source this claim came from.
    pub(crate) source_record_id: String,
    pub(crate) predicate: String,
    pub(crate) value: serde_json::Value,
    pub(crate) occurred: Span,
    pub(crate) learned_at: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Span {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

/// A batch on the wire. `request_id` may be left out of a preview.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportBatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) request_id: Option<String>,
    /// A registered import source whose claims enter as imported.
    pub(crate) source_id: String,
    pub(crate) claims: Vec<ImportClaim>,
}

/// What the owner is asked to approve.
#[derive(Debug, Serialize)]
pub(crate) struct ImportPreview {
    /// Send this back with the batch to approve or decline it.
    pub(crate) digest: String,
    pub(crate) source_id: String,
    pub(crate) claims: usize,
    /// The exact batch the digest names, ids filled in.
    pub(crate) batch: ImportBatch,
}

/// An approved batch.
#[derive(Debug, Serialize)]
pub(crate) struct ImportApproved {
    pub(crate) digest: String,
    pub(crate) approval: &'static str,
    pub(crate) claim_ids: Vec<String>,
}

/// A declined batch: one receipt, nothing admitted.
#[derive(Debug, Serialize)]
pub(crate) struct ImportDeclined {
    pub(crate) digest: String,
    pub(crate) decision_id: String,
    pub(crate) admitted: usize,
}

/// Fills missing ids and returns the exact batch with its digest.
pub(crate) fn preview(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    mut batch: ImportBatch,
) -> OwnerResult<ImportPreview> {
    if batch.request_id.is_none() {
        batch.request_id = Some(EntityId::now().to_hex());
    }
    for claim in &mut batch.claims {
        if claim.claim_id.is_none() {
            claim.claim_id = Some(EntityId::now().to_hex());
        }
    }
    let exact = engine_batch(&batch)?;
    let digest = vault
        .imported_claim_batch_effect(owner, &exact)?
        .digest()
        .to_hex();
    Ok(ImportPreview {
        digest,
        source_id: batch.source_id.clone(),
        claims: batch.claims.len(),
        batch,
    })
}

/// Admits the whole previewed batch as approved, in one transaction.
pub(crate) fn approve(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    batch: &ImportBatch,
    digest: &str,
) -> OwnerResult<ImportApproved> {
    let (exact, _) = previewed(vault, owner, batch, digest)?;
    let receipt = vault.approve_imported_claim_batch(owner, &exact)?;
    Ok(ImportApproved {
        digest: receipt.approval_digest,
        approval: receipt.approval.as_str(),
        claim_ids: receipt.claim_ids.iter().map(EntityId::to_hex).collect(),
    })
}

/// Refuses the whole previewed batch with one receipt; admits nothing. A
/// batch already approved or declined is refused and its decision stands.
pub(crate) fn decline(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    batch: &ImportBatch,
    digest: &str,
) -> OwnerResult<ImportDeclined> {
    let (exact, effect) = previewed(vault, owner, batch, digest)?;
    let receipt = vault.decline_imported_claim_batch(owner, &exact)?;
    Ok(ImportDeclined {
        digest: effect.to_hex(),
        decision_id: receipt.decision_id().to_hex(),
        admitted: 0,
    })
}

/// The engine batch, refused unless it is exactly the one the owner previewed.
fn previewed(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    batch: &ImportBatch,
    digest: &str,
) -> OwnerResult<(ImportedClaimBatch, EffectDigest)> {
    if batch.request_id.is_none() || batch.claims.iter().any(|c| c.claim_id.is_none()) {
        return Err(OwnerError::Invalid(
            "approve or decline the exact batch preview returned, ids included".into(),
        ));
    }
    let exact = engine_batch(batch)?;
    let effect = vault.imported_claim_batch_effect(owner, &exact)?.digest();
    if effect.to_hex() != digest {
        return Err(OwnerError::Changed(
            "this batch is not the one that was previewed; preview it again".into(),
        ));
    }
    Ok((exact, effect))
}

fn engine_batch(batch: &ImportBatch) -> OwnerResult<ImportedClaimBatch> {
    let request_id = entity_id(
        "request_id",
        batch.request_id.as_deref().unwrap_or_default(),
    )?;
    let entries = batch
        .claims
        .iter()
        .map(|claim| {
            if claim.occurred.start > claim.occurred.end {
                return Err(OwnerError::Invalid(
                    "occurred.start must not be after occurred.end".into(),
                ));
            }
            Ok(ImportedClaimBatchEntry {
                claim_id: entity_id("claim_id", claim.claim_id.as_deref().unwrap_or_default())?,
                subject: entity_id("subject", &claim.subject)?,
                source_record_id: claim.source_record_id.clone(),
                predicate: claim.predicate.clone(),
                value: claim.value.clone(),
                occurred: TimeRange {
                    start: claim.occurred.start,
                    end: claim.occurred.end,
                },
                learned_at: claim.learned_at,
            })
        })
        .collect::<OwnerResult<Vec<_>>>()?;
    Ok(ImportedClaimBatch {
        request_id,
        source_id: batch.source_id.clone(),
        entries,
    })
}
