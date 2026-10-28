//! A bound writer's read through the committing terminal (OF-063, FIX 1223,
//! 6068). The rows its puts would take are judged against their originals
//! before any op stages; the typed record refs its CLAIMs name are judged by
//! the claim gate's reference check under that read once the batch's own rows
//! are staged (FIX 10785), so a CLAIM about a row the same batch writes still
//! lands.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::BatchOp;
use crate::Vault;
use crate::claim::{ClaimBody, ScopedRead};
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result};
use crate::gate::{GateReasonCode, GateRetentionContext, RecordedClaimGateDecision};
use crate::store::Store;

/// One CLAIM body the batch's preflight gates, as it gates it.
pub(super) struct GatedClaim {
    id: EntityId,
    body: ClaimBody,
    envelope: Option<crate::WriteEnvelope>,
}

/// What `reader` admits of `ops` in `txn`, before any op stages: `None` when
/// a put would take a row it does not read (FIX 6068); else the CLAIMs whose
/// record refs it judges once the batch is staged.
pub(super) fn admit_before_staging(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    txn: &RoTxn<'_>,
    ops: &[BatchOp],
) -> Result<Option<Vec<GatedClaim>>> {
    if !put_targets_admitted(vault, reader, txn, ops)? {
        return Ok(None);
    }
    gated_claims(&vault.store, txn, ops).map(Some)
}

/// Whether `reader` may take every row this batch's puts name. Each id is
/// judged once, against its original row, so a batch cannot first put a row
/// into its reader's sight and so admit its own later put. The TURN doors'
/// owner ([`Vault::turn_doors_owner`]) puts as before.
fn put_targets_admitted(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    txn: &RoTxn<'_>,
    ops: &[BatchOp],
) -> Result<bool> {
    if vault.turn_doors_owner_in(reader, txn)? {
        return Ok(true);
    }
    let mut judged = BTreeSet::new();
    for op in ops {
        let (BatchOp::Put { id, .. } | BatchOp::ClaimCandidate { id, .. }) = op else {
            continue;
        };
        if judged.insert(*id) && !crate::batch::put_target_admitted_in(reader, txn, id)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Every CLAIM body the preflight gates, in op order, derived in `txn` as the
/// preflight derives it.
fn gated_claims(store: &Store, txn: &RoTxn<'_>, ops: &[BatchOp]) -> Result<Vec<GatedClaim>> {
    let mut claims = Vec::new();
    let mut default_facet = None;
    for op in ops {
        match op {
            BatchOp::Put {
                id,
                entity_type,
                data,
                allow_reserved_predicate,
                ..
            } if *entity_type == crate::registry::ENTITY_TYPE_CLAIM
                && !*allow_reserved_predicate =>
            {
                claims.push(GatedClaim {
                    id: *id,
                    body: crate::claim::validate_claim_body_and_decode_in_txn(
                        store, txn, data, false,
                    )?,
                    envelope: None,
                });
            }
            BatchOp::ClaimCandidate {
                id,
                candidate,
                envelope,
                internal_lexical_query_hint,
                ..
            } if !*internal_lexical_query_hint => {
                let facet = facet_in(store, txn, &mut default_facet)?;
                claims.push(GatedClaim {
                    id: *id,
                    body: (**candidate).clone().into_claim_body(envelope, facet)?,
                    envelope: Some(envelope.clone()),
                });
            }
            BatchOp::CommitmentGapDecay { ids, envelope, .. } => {
                let facet = facet_in(store, txn, &mut default_facet)?;
                for lapse in crate::commitment::pending_commitment_lapses_in_txn(store, txn, ids)? {
                    claims.push(GatedClaim {
                        id: lapse.id,
                        body: lapse.candidate.into_claim_body(envelope, facet)?,
                        envelope: Some(envelope.clone()),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(claims)
}

/// The vault's default facet, read once.
fn facet_in(store: &Store, txn: &RoTxn<'_>, cached: &mut Option<EntityId>) -> Result<EntityId> {
    if let Some(facet) = cached {
        return Ok(*facet);
    }
    let facet = crate::claim::default_facet_in(store, txn)?;
    *cached = Some(facet);
    Ok(facet)
}

/// The claim gate's refusal of a CLAIM whose typed record refs its writer's
/// read does not resolve over the staged batch, with its one receipt.
pub(super) struct StagedDenial {
    err: Error,
    decision: Option<RecordedClaimGateDecision>,
    claim: EntityId,
    retention: GateRetentionContext,
}

/// The first gated CLAIM whose record refs `reader` does not resolve in
/// `txn`, the batch's own rows staged there (FIX 1218). The claim gate's
/// reference check alone judges it (FIX 10785), so no other verdict the
/// staged snapshot gives, a Dreamer precommit refusal seen only there
/// included, decides or shadows it; every other verdict is the preflight's,
/// which already gave it. For the CLAIM it finds, the claim gate's reader-bound
/// door is asked in a savepoint that is always rolled back, only for the
/// receipt the gate records with that denial; a door that answers with
/// another verdict there leaves the denial standing without one.
pub(super) fn staged_reference_denial(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    reader: &ScopedRead<'_>,
    claims: &[GatedClaim],
) -> Result<Option<StagedDenial>> {
    let mut found = None;
    for claim in claims {
        if let Some(field) = crate::gate::unresolved_claim_reference(reader, &*txn, &claim.body)? {
            found = Some((claim, field));
            break;
        }
    }
    let Some((claim, field)) = found else {
        return Ok(None);
    };
    tracing::info!(%field, "a batch claim names a record its writer cannot read; denied");
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &*txn)?;
    let mut probe = vault.store.env.nested_write_txn(txn)?;
    let mut recorded = None;
    let verdict = crate::gate::check_claim_policy_for_write_with_record_with_reader(
        &vault.store,
        &mut probe,
        &claim.id,
        crate::gate::ClaimGateWrite {
            body: &claim.body,
            envelope: claim.envelope.as_ref(),
            // The preflight consulted any checker; only the receipt is asked.
            auto_checker: None,
            defer_metrics_until_commit: true,
            transition: None,
            owner_authored: None,
        },
        &policy,
        crate::gate::GateWriteMode {
            record_decision: true,
            persist_pending_consent: false,
            resolve_pending: false,
            can_resolve_pending_consent: true,
            include_source_in_gate_input: false,
        },
        &mut recorded,
        reader,
    );
    drop(probe);
    let (err, decision) = match verdict {
        Err(err) if unresolved_reference(&err) => (err, recorded),
        Ok(()) | Err(Error::Gate(_)) => (reference_rejection(), None),
        Err(err) => return Err(err),
    };
    Ok(Some(StagedDenial {
        err,
        decision,
        claim: claim.id,
        retention: GateRetentionContext {
            world: Some(claim.body.world.unwrap_or_else(crate::claim::base_world_id)),
            project: Some(claim.body.scope_project),
            sub_project: None,
            thread: None,
        },
    }))
}

/// The claim gate's unresolved-record-reference refusal, as its door
/// returns it.
fn reference_rejection() -> Error {
    Error::Gate(GateError::GateWriteRejected {
        outcome: "deny",
        reason_codes: vec![GateReasonCode::DenyUnresolvedRecordReference.as_str()],
    })
}

/// Whether `err` is the claim gate's unresolved-record-reference denial.
fn unresolved_reference(err: &Error) -> bool {
    let Error::Gate(GateError::GateWriteRejected { reason_codes, .. }) = err else {
        return false;
    };
    reason_codes.contains(&GateReasonCode::DenyUnresolvedRecordReference.as_str())
}

/// Settles `denial` in `wtxn`, the transaction its rolled-back savepoint was
/// opened in, as a preflight refusal settles: every receipt the preflight
/// staged (`staged`) goes, and the denial's own record is appended again
/// under its one id (FIX 1223). Returns the refusal, and the receipt it
/// keeps when the gate recorded one.
pub(super) fn settle_denial_in(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    staged: &[RecordedClaimGateDecision],
    denial: StagedDenial,
) -> Result<(Error, Option<RecordedClaimGateDecision>)> {
    for decision in staged {
        store.delete_gate_decision_in_txn(wtxn, decision.decision_id())?;
    }
    let Some(decision) = denial.decision else {
        return Ok((denial.err, None));
    };
    decision.append_in_txn(store, wtxn)?;
    store.stamp_claim_gate_retention_context_in_txn(
        wtxn,
        decision.decision_id(),
        &denial.claim,
        denial.retention,
    )?;
    Ok((denial.err, Some(decision)))
}
