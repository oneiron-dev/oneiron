//! The evidence item (kind 2): rows an agent reads support a stored claim it
//! reads. The assertion goes through the shared claim gate as the caller,
//! over the head's own scope, as the Dreamer's sealed attachment does: the
//! head's bytes stay as they are, and each source lands one `supports` edge
//! with its provenance row.

use std::collections::BTreeSet;

use rmpv::Value;

use super::batch::{DerivedEvidence, DerivedEvidenceSpans};
use super::commit::{ItemContext, ItemOutcome, refusal_receipt_in_txn};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::dreamer_consolidation::evidence::{RangedSource, VerifiedEvidenceSet};
use crate::dreamer_promotion::{AssertedEvidence, EvidenceAssertion, assert_evidence_in_txn};
use crate::error::{Error, GateError, Result};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, EntityId, Vault};

/// The refusal of evidence for a head that is no claim the actor reads.
pub const EVIDENCE_HEAD_NOT_A_CLAIM: &str = "gate.deny.derive.evidence_head_not_a_claim";

/// The refusal of evidence one of whose sources is no TURN or admissible
/// claim the actor reads.
pub const EVIDENCE_UNVERIFIED: &str = "gate.deny.derive.evidence_unverified";

/// The refusal of an item whose spans entry does not bind: its source is no
/// TURN the actor reads, or a range is not one `vault.evidence.spans` would
/// serve this actor.
pub const EVIDENCE_SPAN_UNBOUND: &str = "gate.deny.derive.evidence_span_unbound";

/// Stages `item`: the head and every source read by the actor, then the
/// evidence assertion through the claim gate and its supports, in a
/// savepoint of `txn`. A gate refusal rolls the savepoint back and keeps a
/// refusal receipt.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedEvidence,
) -> Result<ItemOutcome> {
    let head = context.resolve(&item.head)?;
    let sources = item
        .sources
        .iter()
        .map(|named| context.resolve(named))
        .collect::<Result<BTreeSet<_>>>()?;
    let actor = context.stamp.actor;
    let read = super::actor_read(vault, actor)?;
    let Some((ENTITY_TYPE_CLAIM, _, body)) = read
        .get_entities_parts_in_txn(txn, &[head])?
        .pop()
        .flatten()
    else {
        return refuse(vault, txn, context, head, EVIDENCE_HEAD_NOT_A_CLAIM);
    };
    let Ok(claim) = crate::claim::decode_claim_body(&body, true) else {
        return refuse(vault, txn, context, head, EVIDENCE_HEAD_NOT_A_CLAIM);
    };
    let cited: Vec<EntityId> = sources.iter().copied().collect();
    // The set's floor is `Generated`, as the Dreamer's extraction sets it:
    // a derived support never claims more trust than a derivation has, and
    // the provenance writer refuses one that does (a user's TURN read as
    // `UserStated` evidence would be "source trust widened").
    let evidence = match verified_in_txn(vault, &read, txn, &cited, &item.spans)? {
        Ok(evidence) => evidence,
        Err(token) => return refuse(vault, txn, context, head, token),
    };
    let envelope = envelope(context, item, evidence.meet())?;
    // The assertion restates the head: the gate judges the head's words as
    // the actor asserts them from this evidence.
    let candidate = ClaimCandidate::new(
        claim.predicate.clone(),
        claim.subject.clone(),
        claim.value.clone(),
        claim.confidence,
    );
    let assertion = EvidenceAssertion {
        actor,
        envelope: &envelope,
        head,
        candidate: &candidate,
        sources: &sources,
        evidence: &evidence,
        answers: &[],
        now_ms: context.now.saturating_mul(1_000),
    };
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let asserted = assert_evidence_in_txn(
        vault,
        &mut savepoint,
        &assertion,
        None,
        &read,
        crate::own_rate::auto_write_rate(),
        &mut None,
    );
    match asserted {
        Ok(AssertedEvidence {
            original, records, ..
        }) => {
            if vault.get_claim_in_txn(&savepoint, &head)?.as_ref() != Some(&original) {
                return Err(Error::InvalidClaimBody(
                    "evidence attachment altered its head",
                ));
            }
            savepoint.commit()?;
            Ok(ItemOutcome::Landed {
                rows: records,
                approval: Some(ClaimApprovalStatus::Auto),
                receipt: None,
            })
        }
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
            savepoint.abort();
            let reasons: Vec<String> = reason_codes.iter().map(|code| (*code).to_owned()).collect();
            let receipt = refusal_receipt_in_txn(vault, txn, context, Some(head), &reasons)?;
            Ok(ItemOutcome::Refused { reasons, receipt })
        }
        Err(Error::InvalidClaimBody(_)) => {
            savepoint.abort();
            refuse(vault, txn, context, head, EVIDENCE_UNVERIFIED)
        }
        Err(error) => Err(error),
    }
}

/// Verifies `cited` for one evidence item: whole when `spans` is empty,
/// ranged where an entry names the source and whole otherwise. Returns the
/// refusal token for a source that does not verify, and storage errors
/// directly. The claim stager shares it for an item with span locators.
pub(super) fn verified_in_txn(
    vault: &Vault,
    read: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    cited: &[EntityId],
    spans: &[DerivedEvidenceSpans],
) -> Result<std::result::Result<VerifiedEvidenceSet, &'static str>> {
    if spans.is_empty() {
        return Ok(
            match VerifiedEvidenceSet::verify_whole_in_txn(
                vault,
                read,
                txn,
                cited,
                ClaimSource::Generated,
            ) {
                Ok(evidence) => Ok(evidence),
                Err(Error::InvalidClaimBody(_)) => Err(EVIDENCE_UNVERIFIED),
                Err(error) => return Err(error),
            },
        );
    }
    let bound = match super::spans::bind_in_txn(vault, read, txn, spans) {
        Ok(bound) => bound,
        Err(Error::InvalidClaimBody(_)) => return Ok(Err(EVIDENCE_SPAN_UNBOUND)),
        Err(error) => return Err(error),
    };
    let ranged: Vec<RangedSource> = cited
        .iter()
        .map(|source| RangedSource {
            source: *source,
            ranges: bound
                .iter()
                .find(|entry| entry.source == *source)
                .map(|entry| entry.ranges.clone())
                .unwrap_or_default(),
        })
        .collect();
    Ok(
        match VerifiedEvidenceSet::verify_ranged_in_txn(
            vault,
            read,
            txn,
            &ranged,
            ClaimSource::Generated,
        ) {
            Ok(evidence) => Ok(evidence),
            Err(Error::InvalidClaimBody(_)) => Err(EVIDENCE_UNVERIFIED),
            Err(error) => return Err(error),
        },
    )
}

/// The envelope the engine stamps on an evidence assertion: the committing
/// actor, the evidence's own source meet, the run's recorded lineage, and
/// provenance naming the derivation surface, the batch, the item and the
/// run.
fn envelope(
    context: &ItemContext<'_>,
    item: &DerivedEvidence,
    meet: ClaimSource,
) -> Result<WriteEnvelope> {
    let mut provenance = vec![
        (Value::from("surface"), Value::from(super::DERIVE_SURFACE)),
        (
            Value::from(super::DERIVE_BATCH_KEY),
            Value::from(context.batch.to_hex()),
        ),
        (Value::from("item"), Value::from(item.local.as_str())),
    ];
    if let Some(run) = &context.stamp.run {
        provenance.push((Value::from("run"), Value::from(run.as_str())));
    }
    Ok(WriteEnvelope::with_lineage(
        context.stamp.actor,
        meet,
        WriteProvenance::new(Value::Map(provenance))?,
        ClaimApprovalStatus::Auto,
        context
            .stamp
            .lineage
            .clone()
            .with(ClaimSource::Generated)
            .with(meet),
    ))
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    head: EntityId,
    reason: &str,
) -> Result<ItemOutcome> {
    let reasons = vec![reason.to_owned()];
    let receipt = refusal_receipt_in_txn(vault, txn, context, Some(head), &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
