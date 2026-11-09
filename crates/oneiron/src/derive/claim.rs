//! The claim item (kind 1): a `Generated` claim through the shared claim gate
//! as the committing actor, held to the derivation floors.

use rmpv::Value;

use super::batch::DerivedClaim;
use super::commit::{ItemContext, ItemOutcome, refusal_receipt_in_txn};
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
use crate::dreamer_consolidation::{ConsolidationEvidenceEnvelope, encode_consolidation_evidence};
use crate::error::{Error, GateError, Result};
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, EntityId, TimeRange, Vault};

/// Stages `claim` in a savepoint of `txn`: first at Auto, then, when the
/// gate holds it, as a proposal (as the Dreamer's writers do). A refusal
/// rolls the savepoint back and keeps a refusal receipt in `txn`.
///
/// # Errors
///
/// A value that does not encode, and any error other than the gate's
/// refusal: each aborts the whole commit.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    claim: &DerivedClaim,
) -> Result<ItemOutcome> {
    let id = EntityId::now();
    let subject = context.resolve(&claim.subject)?;
    let evidence = claim
        .evidence
        .iter()
        .map(|named| context.resolve(named))
        .collect::<Result<Vec<_>>>()?;
    let value = rmpv::ext::to_value(&claim.value)
        .map_err(|_| Error::InvalidClaimBody("a derived claim's value does not encode"))?;
    let candidate = ClaimCandidate::new(
        claim.predicate.clone(),
        ClaimSubject::Entity(subject),
        value,
        claim.confidence,
    )
    .with_evidence(encode_consolidation_evidence(
        &ConsolidationEvidenceEnvelope {
            refs: evidence,
            chain: Vec::new(),
            source_meet: ClaimSource::Generated,
        },
    ));
    for approval in [ClaimApprovalStatus::Auto, ClaimApprovalStatus::Proposed] {
        let mut envelope = envelope(context, claim, approval)?;
        let mut savepoint = vault.store.env.nested_write_txn(txn)?;
        vault.sign_retained_machine_claim_in_txn(&savepoint, &id, &candidate, &mut envelope)?;
        let staged = vault
            .batch_in()
            .claim_candidate(
                &id,
                candidate.clone(),
                &envelope,
                TimeRange {
                    start: context.now,
                    end: context.now,
                },
                context.now,
            )
            .apply_recording_gate_decisions(&mut savepoint);
        match staged {
            Ok(()) => {
                savepoint.commit()?;
                return Ok(ItemOutcome::Landed {
                    rows: vec![id],
                    approval: Some(approval),
                });
            }
            Err(Error::Gate(GateError::GateWriteRejected {
                outcome: "pending", ..
            })) if approval == ClaimApprovalStatus::Auto => savepoint.abort(),
            Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
                savepoint.abort();
                let reasons: Vec<String> =
                    reason_codes.iter().map(|code| (*code).to_owned()).collect();
                let receipt = refusal_receipt_in_txn(vault, txn, context, Some(id), &reasons)?;
                return Ok(ItemOutcome::Refused { reasons, receipt });
            }
            Err(error) => return Err(error),
        }
    }
    Err(Error::InvariantViolation(
        "a derived claim's proposal was neither landed nor refused",
    ))
}

/// The envelope the engine stamps on a derived claim: the committing actor,
/// the `Generated` source, the run's recorded lineage, and provenance naming
/// the derivation surface, the batch, the item and the run.
fn envelope(
    context: &ItemContext<'_>,
    claim: &DerivedClaim,
    approval: ClaimApprovalStatus,
) -> Result<WriteEnvelope> {
    let mut provenance = vec![
        (Value::from("surface"), Value::from(super::DERIVE_SURFACE)),
        (
            Value::from(super::DERIVE_BATCH_KEY),
            Value::from(context.batch.to_hex()),
        ),
        (Value::from("item"), Value::from(claim.local.as_str())),
    ];
    if let Some(run) = &context.stamp.run {
        provenance.push((Value::from("run"), Value::from(run.as_str())));
    }
    Ok(WriteEnvelope::with_lineage(
        context.stamp.actor,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(provenance))?,
        approval,
        context.stamp.lineage.clone().with(ClaimSource::Generated),
    ))
}
