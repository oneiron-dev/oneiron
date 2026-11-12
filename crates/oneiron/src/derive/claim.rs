//! The claim item (kind 1): a derived claim through the shared claim gate as
//! the committing actor, held to the derivation floors and to that actor's
//! own read. Its source is the trust of the rows it cites, folded from the
//! `Generated` floor, or Observed for a preference supported by three user
//! TURNs across two sessions. Its caller never chooses the source.

use rmpv::Value;

use super::batch::DerivedClaim;
use super::commit::{ItemContext, ItemOutcome, refusal_receipt_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimSource, ClaimSubject, is_preference_predicate,
    observed_preference_support_in_txn, stated_preference_peers_in_txn, write_coaching,
};
use crate::dreamer_consolidation::{
    ConsolidationEvidenceEnvelope, encode_consolidation_evidence, evidence_source_from_row_in_txn,
    source_meet,
};
use crate::error::{Error, GateError, Result};
use crate::write_envelope::{WriteEnvelope, WriteProvenance};
use crate::{ClaimCandidate, EntityId, TimeRange, Vault};

/// Stages `claim` in a savepoint of `txn`: first at Auto, then, when the
/// gate holds it, as a proposal (as the Dreamer's writers do). A refusal
/// rolls the savepoint back and keeps a refusal receipt in `txn`.
///
/// The write goes in the committing actor's read lane, so the gate's
/// reference check judges the subject and every cited row under that read:
/// a claim about, or citing, a row its actor does not read is refused.
///
/// The engine computes the source, never taking one from its caller. It
/// stamps Observed on a `preference.*` claim with a Generated evidence meet
/// and three live, nonimported user TURNs across two live sessions. Otherwise
/// the source stays the cited rows' meet ([`evidence_meet_in_txn`]): imported
/// words remain Imported, held for review whatever the Generated permit grants.
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
    let subject = context.resolve(&claim.subject)?;
    let evidence = claim
        .evidence
        .iter()
        .map(|named| context.resolve(named))
        .collect::<Result<Vec<_>>>()?;
    let meet = evidence_meet_in_txn(vault, txn, &evidence)?;
    let beside_stated = meet == ClaimSource::Generated
        && is_preference_predicate(&claim.predicate)
        && observed_preference_support_in_txn(vault, txn, &evidence)?;
    let source = if beside_stated {
        ClaimSource::Observed
    } else {
        meet
    };
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
            source_meet: source,
        },
    ));
    // The lane an ordinary core write is held to (`Memory::core_write_lane`):
    // every recorded claim the actor's read reaches, so a proposal an
    // earlier item of this batch landed still reads to the item citing it.
    let read = super::actor_read(vault, context.stamp.actor)?
        .with_claim_status(crate::ports::ClaimReadStatus::Recorded);
    stage_candidate_in_txn(
        vault,
        txn,
        context,
        &StagedClaim {
            local: &claim.local,
            id: EntityId::now(),
            candidate: &candidate,
            source,
            beside_stated,
        },
        crate::core_write::CoreWriteLaneRef::Read(&read),
    )
}

/// One claim an item stages through the shared claim gate.
pub(super) struct StagedClaim<'a> {
    /// The item's local name.
    pub(super) local: &'a str,
    /// The id the claim is minted as.
    pub(super) id: EntityId,
    /// The claim's words and evidence.
    pub(super) candidate: &'a ClaimCandidate,
    /// The engine-computed source, never caller-supplied: for a claim item,
    /// the cited rows' meet, or Observed when user TURNs meet the preference bar.
    pub(super) source: ClaimSource,
    /// Whether this claim item was stamped Observed beside stated preferences.
    pub(super) beside_stated: bool,
}

/// Stages `claim` in a savepoint of `txn`: first at Auto, then,
/// when the gate holds it, as a proposal (as the Dreamer's writers do). A
/// refusal rolls the savepoint back and keeps a refusal receipt in `txn`.
///
/// The write goes in `lane`: under a read lane the gate's reference check
/// refuses a subject or cited row outside that read.
///
/// # Errors
///
/// Any error other than the gate's refusal: each aborts the whole commit.
pub(super) fn stage_candidate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    claim: &StagedClaim<'_>,
    lane: crate::core_write::CoreWriteLaneRef<'_>,
) -> Result<ItemOutcome> {
    let StagedClaim {
        local,
        id,
        candidate,
        source,
        beside_stated,
    } = *claim;
    for approval in [ClaimApprovalStatus::Auto, ClaimApprovalStatus::Proposed] {
        let mut envelope = envelope(context, local, approval, source)?;
        let mut savepoint = vault.store.env.nested_write_txn(txn)?;
        vault.sign_retained_machine_claim_in_txn(&savepoint, &id, candidate, &mut envelope)?;
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
            .apply_recording_gate_decisions_in_lane(&mut savepoint, lane);
        if approval == ClaimApprovalStatus::Auto
            && matches!(
                &staged,
                Err(Error::Gate(GateError::GateWriteRejected {
                    outcome: "pending",
                    ..
                }))
            )
        {
            savepoint.abort();
            continue;
        }
        let staged = match staged {
            Ok(()) if beside_stated => {
                open_stated_conflicts_in_txn(vault, &mut savepoint, &id, &envelope, context.now)
            }
            staged => staged,
        };
        match staged {
            Ok(()) => {
                savepoint.commit()?;
                return Ok(ItemOutcome::Landed {
                    rows: vec![id],
                    approval: Some(approval),
                    receipt: None,
                });
            }
            Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
                savepoint.abort();
                let reasons: Vec<String> =
                    reason_codes.iter().map(|code| (*code).to_owned()).collect();
                let receipt = refusal_receipt_in_txn(vault, txn, context, Some(id), &reasons)?;
                return Ok(ItemOutcome::Refused { reasons, receipt });
            }
            Err(error) => {
                savepoint.abort();
                return Err(error);
            }
        }
    }
    Err(Error::InvariantViolation(
        "a derived claim's proposal was neither landed nor refused",
    ))
}

/// OF-023: one `core.conflict.open` marker for each standing stated
/// preference whose answer differs from the Observed claim `id` staged in
/// `txn`, written with that claim's `envelope`, as the Memory door opens them.
///
/// # Errors
///
/// A read failure, or the gate's refusal of a marker.
fn open_stated_conflicts_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    envelope: &WriteEnvelope,
    now: u64,
) -> Result<()> {
    let body = vault
        .get_claim_in_txn(txn, id)?
        .ok_or(Error::EntityNotFound)?;
    for peer in stated_preference_peers_in_txn(vault, txn, &body)? {
        write_coaching(vault, txn, id, &peer, &body, envelope, now)?;
    }
    Ok(())
}

/// The trust the rows `evidence` carry, folded from the `Generated` floor a
/// derivation starts at, most restrictive first, as each row stands in
/// `txn`: an imported TURN or NOTE is `Imported`, a claim brings its own
/// source and evidence taint, and any other row, or one that does not
/// resolve, counts as `Imported`, the bottom of the order (as
/// [`crate::dreamer_consolidation::evidence_chain_source`] folds the refs an
/// agent supplies). A user's own words never lift the meet above the floor.
///
/// # Errors
///
/// Storage errors.
fn evidence_meet_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    evidence: &[EntityId],
) -> Result<ClaimSource> {
    let mut meet = ClaimSource::Generated;
    for id in evidence {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store.read(), txn, id)?;
        let trust = match raw
            .as_deref()
            .map(|raw| (EntityMetadataHeader::parse(raw), raw))
        {
            Some((Some(header), raw)) if raw.len() > ENTITY_METADATA_HEADER_LEN => {
                match evidence_source_from_row_in_txn(
                    vault,
                    txn,
                    header.entity_type,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                ) {
                    Ok(trust) => trust,
                    Err(Error::InvalidClaimBody(_)) => ClaimSource::Imported,
                    Err(error) => return Err(error),
                }
            }
            _ => ClaimSource::Imported,
        };
        meet = source_meet(meet, trust);
    }
    Ok(meet)
}

/// The envelope the engine stamps on a derived claim: the committing actor,
/// the engine-computed `source`, the run's recorded
/// lineage with that source, and provenance naming the derivation surface,
/// the batch, the item and the run.
fn envelope(
    context: &ItemContext<'_>,
    local: &str,
    approval: ClaimApprovalStatus,
    source: ClaimSource,
) -> Result<WriteEnvelope> {
    let mut provenance = vec![
        (Value::from("surface"), Value::from(super::DERIVE_SURFACE)),
        (
            Value::from(super::DERIVE_BATCH_KEY),
            Value::from(context.batch.to_hex()),
        ),
        (Value::from("item"), Value::from(local)),
    ];
    if let Some(run) = &context.stamp.run {
        provenance.push((Value::from("run"), Value::from(run.as_str())));
    }
    Ok(WriteEnvelope::with_lineage(
        context.stamp.actor,
        source,
        WriteProvenance::new(Value::Map(provenance))?,
        approval,
        context
            .stamp
            .lineage
            .clone()
            .with(ClaimSource::Generated)
            .with(source),
    ))
}
