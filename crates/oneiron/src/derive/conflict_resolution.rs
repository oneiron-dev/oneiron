//! The conflict_resolution item: the Conflict item's set shape with the job's
//! decision for that set.
//!
//! The engine rebuilds the set exactly as the Conflict item does and then does
//! what native's conflict loop does for that decision, inside the batch's write
//! transaction. `skip` replaces the set's prior head with the set's one member
//! and no verdict, `merge` lands one merged claim from the whole set, and
//! `accumulate` lands every member beside the heads.
//!
//! The job never names the head a claim replaces, and the engine computes every
//! field it can. Of the landed rows only the choice of outcome and kept member,
//! the merged value's bytes, and each member's confidence and hints are the
//! job's. A replacement lands Proposed with its staged supersession, then takes
//! native's Auto grant in the same transaction when the policy allows it; a
//! granted replacement closes the open conflicts that named its prior, as
//! native's sink does. Every row carries derive provenance and no decision memo.
//!
//! For `skip` by the bound-correction rule, the engine checks both native rules
//! on what it reads. Native also requires that no other candidate of the pass
//! stands on the corrected head; the item does not carry the pass, and that
//! scan stays in the job's routing (RULING S69E2G3-BOUND-CORRECTION-SKIP = B).
//!
//! Only a queued extraction attempt stages one, as the attempt's Dreamer. Each
//! refusal lands nothing, writes the item's refusal receipt and the batch goes
//! on; a storage error aborts the commit. A receipt carries tokens only.
use super::batch::{DerivedConflictResolution, DerivedResolutionOutcome};
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn};
use super::conflict::inputs::derive_provenance;
use super::extraction_opening::{ExtractionOpening, open_attempt, open_verdict_read};
use super::extraction_set::{RebuildInput, SetRebuildError, rebuild_conflict_set};
use super::verified_landing::{
    LandingError, LandingRefusal, VerifiedLandingOptions, attempt_dreamer_matches,
    land_verified_candidate, promotion_run_id, refuse, refuse_or_abort,
};
use crate::dreamer_consolidation::evidence::{VerifiedCandidate, VerifiedEvidenceSet};
use crate::dreamer_consolidation::extraction_pack::{
    ExtractionRebuildContext, kept_matches_for_one_proposal,
};
use crate::dreamer_consolidation::{
    PromotionCandidate, bound_correction, bound_matching_priors, candidate_probe_body,
    cross_predicate_merge_unnamed, fast_path, json_to_rmpv, merged_candidate,
    recompute_kept_selection,
};
use crate::error::{Error, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::{EntityId, Vault};
use std::collections::BTreeMap;

mod completion;

/// One landed output.
struct LandedOutput {
    /// The landed claim.
    claim: EntityId,
    /// Its approval, which becomes Auto when its grant lands.
    approval: crate::claim::ClaimApprovalStatus,
    /// The head it replaces, for a replacement.
    prior: Option<EntityId>,
    /// The evidence it cites, which a close of an open conflict cites too.
    evidence: Vec<EntityId>,
}

/// The refusal of a resolution item whose commit runs outside a queued
/// extraction attempt.
pub const CONFLICT_RESOLUTION_NEEDS_EXTRACTION_ATTEMPT: &str =
    "gate.deny.derive.conflict_resolution_needs_extraction_attempt";
/// The refusal of a resolution item whose stamp's actor is not the attempt's
/// Dreamer.
pub const CONFLICT_RESOLUTION_NOT_ATTEMPT_DREAMER: &str =
    "gate.deny.derive.conflict_resolution_not_attempt_dreamer";
/// The refusal of a resolution item whose operands are not one servable native
/// conflict.
pub const CONFLICT_RESOLUTION_OPERANDS_REFUSED: &str =
    "gate.deny.derive.conflict_resolution_operands_refused";
/// The refusal of a resolution item whose heads differ from the rebuilt set's
/// prior heads.
pub const CONFLICT_RESOLUTION_HEADS_DIFFER: &str =
    "gate.deny.derive.conflict_resolution_heads_differ";
/// The refusal of a skip native's own no-verdict rule does not allow.
pub const CONFLICT_RESOLUTION_SKIP_NOT_ALLOWED: &str =
    "gate.deny.derive.conflict_resolution_skip_not_allowed";
/// The refusal of a merge the engine cannot build.
pub const CONFLICT_RESOLUTION_MERGE_REFUSED: &str =
    "gate.deny.derive.conflict_resolution_merge_refused";
/// The refusal of an output native's seal refuses.
pub const CONFLICT_RESOLUTION_OUTPUT_REFUSED: &str =
    "gate.deny.derive.conflict_resolution_output_refused";
/// The refusal of an output that restates a head.
pub const CONFLICT_RESOLUTION_RESTATES_HEAD: &str =
    "gate.deny.derive.conflict_resolution_restates_head";
/// The refusal of an output whose words the owner declined.
pub const CONFLICT_RESOLUTION_OWNER_DECLINED: &str =
    "gate.deny.derive.conflict_resolution_owner_declined";
/// The refusal of a resolution whose claim is already stored.
pub const CONFLICT_RESOLUTION_DUPLICATE: &str = "gate.deny.derive.conflict_resolution_duplicate";
/// The refusal of an accumulate with no member left to write.
pub const CONFLICT_RESOLUTION_NOTHING_TO_LAND: &str =
    "gate.deny.derive.conflict_resolution_nothing_to_land";
/// The refusal of an output from imported evidence.
pub const CONFLICT_RESOLUTION_IMPORTED_EVIDENCE: &str =
    "gate.deny.derive.conflict_resolution_imported_evidence";
/// The refusal of an output native's promotion refused to land.
pub const CONFLICT_RESOLUTION_LANDING_REFUSED: &str =
    "gate.deny.derive.conflict_resolution_landing_refused";
/// The reason a landed resolution item's receipt names.
const CONFLICT_RESOLUTION_ALLOWED: &str = "gate.allow.derive.conflict_resolution";

/// One output the stager may write: the proposal with its verified evidence.
struct OutputCandidate {
    proposal: PromotionCandidate,
    evidence: VerifiedEvidenceSet,
}

/// Which seal refusal one output met.
enum SealRefusal {
    /// Native's seal refuses it.
    OutputRefused,
    /// It restates a head.
    RestatesHead,
}

/// What the seal met instead of a pass: which refusal, or the store's error.
enum SealError {
    Refusal(SealRefusal),
    Abort(Error),
}

/// Native's seal for one output (`prepare_write_verified`), restated for the
/// bound read in the caller's read `txn`, in native's order: the evidence
/// match, the two supersession refusals, the attachment and restatement
/// skips, and the provisional and self-evidence rules.
///
/// Of native's `validate_candidates` conditions it checks the provenance
/// chain, the unverified evidence, the evidence rows and their project. It
/// does not check the world, facet and relationship against the branch or
/// recompute the claim id: `check_pack_candidates` builds each member from
/// the queued branch plan and `merged_candidate` builds the merged output
/// from those members, and the job supplies neither. The branch output's
/// write check has no bound form; the derive verdict and the landing's gate
/// judge the write.
///
/// Answers `Ok` when native would write it, `RestatesHead` when native would
/// attach to a head or skip it as a restatement, and `OutputRefused` when
/// native would refuse it.
fn seal_one(
    vault: &Vault,
    bound: &crate::dreamer_consolidation::extraction_pack::BoundBranchRead,
    read: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    proposal: &PromotionCandidate,
    evidence: &VerifiedEvidenceSet,
) -> std::result::Result<(), SealError> {
    use SealError::{Abort, Refusal};
    use SealRefusal::{OutputRefused, RestatesHead};
    if proposal.evidence_turn_refs != evidence.refs() || proposal.evidence_meet != evidence.meet() {
        return Err(Refusal(OutputRefused));
    }
    let prior = proposal.supersedes;
    let mut stripped = proposal.clone();
    stripped.supersedes = None;
    if !stripped.provenance_chain.is_empty() {
        return Err(Refusal(OutputRefused));
    }
    if stripped.candidate.evidence().is_some() {
        return Err(Refusal(OutputRefused));
    }
    for id in &stripped.evidence_turn_refs {
        if bound.turn_conversation(*id).is_none() && bound.prior(*id).is_none() {
            return Err(Refusal(OutputRefused));
        }
    }
    let probe = match candidate_probe_body(&stripped.candidate) {
        Ok(body) => body,
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return Err(Refusal(OutputRefused));
        }
        Err(error) => return Err(Abort(error)),
    };
    match bound.evidence_project(&stripped.evidence_turn_refs) {
        Ok(project) if project == Some(probe.scope_project) => {}
        Ok(_) => return Err(Refusal(OutputRefused)),
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return Err(Refusal(OutputRefused));
        }
        Err(error) => return Err(Abort(error)),
    }
    if let Some(id) = prior
        && bound.require_prior_write(id).is_err()
    {
        return Err(Refusal(OutputRefused));
    }
    let matches = match bound_matching_priors(
        &stripped,
        &bound.priors().values().cloned().collect::<Vec<_>>(),
        bound.key_rules(),
    ) {
        Ok(matches) => matches,
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return Err(Refusal(OutputRefused));
        }
        Err(error) => return Err(Abort(error)),
    };
    if prior.is_some_and(|id| !matches.iter().any(|(matched, _)| *matched == id)) {
        return Err(Refusal(OutputRefused));
    }
    if matches.len() > 1 && prior.is_some() {
        return Err(Refusal(OutputRefused));
    }
    let meet = evidence.meet();
    let mut attachment: Option<EntityId> = None;
    if let [(id, true)] = matches.as_slice() {
        attachment = Some(*id);
    } else if matches.len() > 1 && meet != crate::claim::ClaimSource::Imported {
        let mut all_equal = true;
        for (id, equal) in &matches {
            if !equal {
                all_equal = false;
                break;
            }
            let Some(head) = bound.prior(*id) else {
                return Err(Refusal(OutputRefused));
            };
            match bound.observation_prior_provisional(head) {
                Ok(false) => {}
                Ok(true) => {
                    all_equal = false;
                    break;
                }
                Err(_) => return Err(Refusal(OutputRefused)),
            }
        }
        if all_equal {
            let (id, _) = matches[0];
            let Some(head) = bound.prior(id) else {
                return Err(Refusal(OutputRefused));
            };
            // A scope whose facet does not read names none, as native reads it.
            let named =
                crate::dreamer_consolidation::resources::BoundBranchRead::observation_named_facet(
                    probe.scope.as_ref(),
                )
                .ok()
                .flatten();
            let same_scope = named == Some(probe.scope_facet)
                && probe.scope_facet == head.body.scope_facet
                && probe.scope_project == head.body.scope_project
                && crate::dreamer_promotion::scope_with_taint(probe.scope.clone(), meet)
                    == crate::dreamer_promotion::scope_with_taint(head.body.scope.clone(), meet);
            if same_scope {
                attachment = Some(id);
            }
        }
    }
    if attachment.is_none() && matches.is_empty() && prior.is_none() {
        match bound.restates_unlisted_candidate_in_txn(vault, read, txn, &stripped, meet) {
            Ok(true) => return Err(Refusal(RestatesHead)),
            Ok(false) => {}
            Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                return Err(Refusal(OutputRefused));
            }
            Err(error) => return Err(Abort(error)),
        }
    }
    if let Some(id) = attachment {
        let Some(head) = bound.prior(id) else {
            return Err(Refusal(OutputRefused));
        };
        match bound.observation_prior_provisional(head) {
            Ok(true) if id != stripped.claim_id => return Err(Refusal(RestatesHead)),
            Ok(_) => {}
            Err(_) => return Err(Refusal(OutputRefused)),
        }
        if stripped.evidence_turn_refs.contains(&id) {
            return Err(Refusal(OutputRefused));
        }
        if bound.require_prior_write(id).is_err() {
            return Err(Refusal(OutputRefused));
        }
        return Err(Refusal(RestatesHead));
    }
    Ok(())
}

/// Stages a resolution item: the rebuilt set decided as the job asked, in the
/// batch's write transaction (`txn` reborrowed as a read for every read).
/// Each refusal writes the item's receipt and lands nothing, and the batch
/// goes on.
///
/// # Errors
///
/// Storage errors: each aborts the whole commit, never a refusal.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedConflictResolution,
) -> Result<ItemOutcome> {
    let Some(attempt_id) = open_attempt(vault, txn, context.stamp)? else {
        return refuse(
            vault,
            txn,
            context,
            &[CONFLICT_RESOLUTION_NEEDS_EXTRACTION_ATTEMPT.to_owned()],
        );
    };
    if !attempt_dreamer_matches(vault, txn, attempt_id, context.stamp.actor)? {
        return refuse(
            vault,
            txn,
            context,
            &[CONFLICT_RESOLUTION_NOT_ATTEMPT_DREAMER.to_owned()],
        );
    }
    let opening = match open_verdict_read(vault, txn, context.stamp) {
        Ok(Some(opening)) => opening,
        Ok(None) => {
            return refuse(
                vault,
                txn,
                context,
                &[CONFLICT_RESOLUTION_OPERANDS_REFUSED.to_owned()],
            );
        }
        Err(error) => {
            return refuse_or_abort(
                vault,
                txn,
                context,
                error,
                CONFLICT_RESOLUTION_OPERANDS_REFUSED,
            );
        }
    };
    let ExtractionOpening {
        actor,
        read,
        turn_owned,
        memory,
        reader_scope,
    } = opening;
    let now_ms = context.now.saturating_mul(1_000);
    let rebuilt = {
        let read_txn: &heed::RoTxn<'_> = txn;
        let turn_read = turn_owned.as_ref().unwrap_or(&read);
        match rebuild_conflict_set(RebuildInput {
            memory: &memory,
            read: &read,
            turn_read,
            txn: read_txn,
            reader_scope: reader_scope.as_ref(),
            attempt: attempt_id,
            members: &item.members,
            heads: &item.heads,
            set_members: item.set_members.as_deref(),
            now_ms,
        }) {
            Ok(rebuilt) => rebuilt,
            Err(SetRebuildError::Operands(error)) => {
                return refuse_or_abort(
                    vault,
                    txn,
                    context,
                    error,
                    CONFLICT_RESOLUTION_OPERANDS_REFUSED,
                );
            }
            Err(SetRebuildError::HeadsDiffer(error)) => {
                return refuse_or_abort(
                    vault,
                    txn,
                    context,
                    error,
                    CONFLICT_RESOLUTION_HEADS_DIFFER,
                );
            }
            Err(SetRebuildError::Abort(error)) => return Err(error),
        }
    };
    let mut members = rebuilt.members;
    for verified in &mut members {
        verified.proposal.evidence_meet = verified.evidence.meet();
    }
    let bound = rebuilt.bound;
    let selected = rebuilt.selected;
    let checked = rebuilt.checked;
    let mut outputs: Vec<OutputCandidate> = Vec::new();
    match &item.outcome {
        DerivedResolutionOutcome::Skip => {
            if members.len() != 1 || selected.set.candidate_indexes.len() != 1 {
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_SKIP_NOT_ALLOWED.to_owned()],
                );
            }
            let Some(prior_head) = selected.set.prior_head else {
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_SKIP_NOT_ALLOWED.to_owned()],
                );
            };
            let policy = {
                let read_txn: &heed::RoTxn<'_> = txn;
                crate::gate::resolve_policy_manifest(&vault.store, read_txn)?
            };
            let prior = bound.prior(prior_head);
            let member_data = [&members[0].proposal];
            let mut corrections = BTreeMap::new();
            if let Some(index) = selected.set.candidate_indexes.first()
                && let Some(row) = checked.rows.get(*index)
                && let Some(head) = row.corrects_head
            {
                corrections.insert(members[0].proposal.claim_id, head);
            }
            let allowed = fast_path(&policy, &selected.set, &member_data, prior)
                || bound_correction(&corrections, &selected.set, &member_data, prior);
            if !allowed {
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_SKIP_NOT_ALLOWED.to_owned()],
                );
            }
            let mut verified = members
                .pop()
                .ok_or(Error::InvariantViolation("a selected set names its member"))?;
            verified.proposal.supersedes = Some(prior_head);
            outputs.push(OutputCandidate {
                proposal: verified.proposal,
                evidence: verified.evidence,
            });
        }
        DerivedResolutionOutcome::Merge { kept, value } => {
            let merged_value = json_to_rmpv(value);
            let member_refs: Vec<&VerifiedCandidate> = members.iter().collect();
            // The kept member with its own operand: a member of the selected
            // set, named by its index into the item's members.
            let kept_member = match kept {
                Some(index) if selected.set.candidate_indexes.contains(index) => {
                    let (Some(member), Some(proposal)) =
                        (item.members.get(*index), selected.proposals.get(*index))
                    else {
                        return refuse(
                            vault,
                            txn,
                            context,
                            &[CONFLICT_RESOLUTION_MERGE_REFUSED.to_owned()],
                        );
                    };
                    Some((&member.operand, proposal.claim_id))
                }
                Some(_) => {
                    return refuse(
                        vault,
                        txn,
                        context,
                        &[CONFLICT_RESOLUTION_MERGE_REFUSED.to_owned()],
                    );
                }
                None => None,
            };
            let recomputed = match kept_member {
                Some((operand, id)) => {
                    let read_txn: &heed::RoTxn<'_> = txn;
                    let turn_read = turn_owned.as_ref().unwrap_or(&read);
                    // The kept member's matches are the one-candidate route's,
                    // which reads the qualification of one operand: its own.
                    let rebuild = ExtractionRebuildContext {
                        memory: &memory,
                        read: &read,
                        turn_read,
                        txn: read_txn,
                        operands: std::slice::from_ref(operand),
                    };
                    match recompute_kept_selection(
                        &selected.set,
                        &member_refs,
                        id,
                        bound.key_rules(),
                        |member| {
                            kept_matches_for_one_proposal(&bound, &rebuild, &member.proposal)
                                .map_err(|error| {
                                    if error.code == crate::memory::MEMORY_CODE_BAD_REQUEST
                                        || error.code == crate::memory::MEMORY_CODE_FORBIDDEN
                                    {
                                        Error::InvalidClaimBody("kept matches refused")
                                    } else {
                                        Error::Io(std::io::Error::other(error.to_string()))
                                    }
                                })
                        },
                    ) {
                        Ok(selected) => selected,
                        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                            return refuse(
                                vault,
                                txn,
                                context,
                                &[CONFLICT_RESOLUTION_MERGE_REFUSED.to_owned()],
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
                None => {
                    if cross_predicate_merge_unnamed(&selected.set, &member_refs) {
                        return refuse(
                            vault,
                            txn,
                            context,
                            &[CONFLICT_RESOLUTION_MERGE_REFUSED.to_owned()],
                        );
                    }
                    selected.set.clone()
                }
            };
            let mut priors = Vec::with_capacity(recomputed.prior_heads.len());
            for id in &recomputed.prior_heads {
                let Some(prior) = bound.prior(*id) else {
                    return refuse(
                        vault,
                        txn,
                        context,
                        &[CONFLICT_RESOLUTION_MERGE_REFUSED.to_owned()],
                    );
                };
                priors.push(prior.clone());
            }
            let merged = match merged_candidate(
                &recomputed,
                &member_refs,
                &priors,
                merged_value,
                Vec::new(),
                attempt_id,
                now_ms,
            ) {
                Ok(merged) => merged,
                Err(_) => {
                    return refuse(
                        vault,
                        txn,
                        context,
                        &[CONFLICT_RESOLUTION_MERGE_REFUSED.to_owned()],
                    );
                }
            };
            outputs.push(OutputCandidate {
                proposal: merged.proposal,
                evidence: merged.evidence,
            });
        }
        DerivedResolutionOutcome::Accumulate => {
            for mut verified in members {
                verified.proposal.supersedes = None;
                outputs.push(OutputCandidate {
                    proposal: verified.proposal,
                    evidence: verified.evidence,
                });
            }
        }
    }
    let is_accumulate = matches!(item.outcome, DerivedResolutionOutcome::Accumulate);
    let mut writable: Vec<OutputCandidate> = Vec::with_capacity(outputs.len());
    for output in outputs {
        let read_txn: &heed::RoTxn<'_> = txn;
        match seal_one(
            vault,
            &bound,
            &read,
            read_txn,
            &output.proposal,
            &output.evidence,
        ) {
            Ok(()) => writable.push(output),
            Err(SealError::Refusal(SealRefusal::RestatesHead)) if is_accumulate => {}
            Err(SealError::Refusal(SealRefusal::RestatesHead)) => {
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_RESTATES_HEAD.to_owned()],
                );
            }
            Err(SealError::Refusal(SealRefusal::OutputRefused)) => {
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_OUTPUT_REFUSED.to_owned()],
                );
            }
            Err(SealError::Abort(error)) => return Err(error),
        }
    }
    let mut passing: Vec<OutputCandidate> = Vec::with_capacity(writable.len());
    for output in writable {
        let read_txn: &heed::RoTxn<'_> = txn;
        let cited = output.evidence.cited_messages();
        match crate::dreamer_consolidation::reviewed::declined_from_same_words_in_txn(
            vault,
            read_txn,
            &output.proposal,
            &cited,
        ) {
            Ok(Some(_)) if is_accumulate => {}
            Ok(Some(_)) => {
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_OWNER_DECLINED.to_owned()],
                );
            }
            Ok(None) => passing.push(output),
            Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_OUTPUT_REFUSED.to_owned()],
                );
            }
            Err(error) => return Err(error),
        }
    }
    if passing.is_empty() {
        return refuse(
            vault,
            txn,
            context,
            &[CONFLICT_RESOLUTION_NOTHING_TO_LAND.to_owned()],
        );
    }
    {
        let read_txn: &heed::RoTxn<'_> = txn;
        for output in &passing {
            if vault
                .get_claim_in_txn(read_txn, &output.proposal.claim_id)?
                .is_some()
            {
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_DUPLICATE.to_owned()],
                );
            }
        }
    }
    let allowance = match derive_verdict_in_txn(
        &vault.store,
        txn,
        actor,
        DeriveCapability::Derive,
        Some(selected.set.identity.subject),
    )? {
        Ok(allowance) => allowance,
        Err(refusal) => return refuse(vault, txn, context, &[refusal.token().to_owned()]),
    };
    let fence =
        crate::dreamer_consolidation::resources::ConsolidationFence::for_bound_read(actor, &bound);
    let run = crate::dreamer_promotion::DreamerRunContext {
        run_id: promotion_run_id(context.stamp, attempt_id),
        attempt_id,
        agent_actor: actor,
        now_ms,
    };
    let provenance = rmpv::Value::Map(derive_provenance(context, &item.local));
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let mut landed: Vec<LandedOutput> = Vec::with_capacity(passing.len());
    for output in passing {
        let claim_id = output.proposal.claim_id;
        let prior = output.proposal.supersedes;
        let evidence_refs = output.proposal.evidence_turn_refs.clone();
        let OutputCandidate { proposal, evidence } = output;
        match land_verified_candidate(
            vault,
            &run,
            proposal,
            Some(&evidence),
            Some(&fence),
            VerifiedLandingOptions {
                provenance: Some(provenance.clone()),
                record_output: context.record_outputs,
            },
            &mut savepoint,
        ) {
            Ok(approval) => landed.push(LandedOutput {
                claim: claim_id,
                approval,
                prior,
                evidence: evidence_refs,
            }),
            Err(LandingError::Refusal(LandingRefusal::Gate(reasons))) => {
                savepoint.abort();
                return refuse(vault, txn, context, &reasons);
            }
            Err(LandingError::Refusal(LandingRefusal::Imported)) => {
                savepoint.abort();
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_IMPORTED_EVIDENCE.to_owned()],
                );
            }
            Err(LandingError::Refusal(LandingRefusal::LandingRefused)) => {
                savepoint.abort();
                return refuse(
                    vault,
                    txn,
                    context,
                    &[CONFLICT_RESOLUTION_LANDING_REFUSED.to_owned()],
                );
            }
            Err(LandingError::Abort(error)) => {
                savepoint.abort();
                return Err(error);
            }
        }
    }
    let (savepoint, landed) = completion::grant_and_close_in_txn(
        vault, savepoint, context, run, fence, provenance, landed,
    )?;
    savepoint.commit()?;
    // The replacement alone (skip, merge) or the members written, in set
    // order (accumulate). The item's approval is Auto unless a row waits.
    let rows: Vec<EntityId> = landed.iter().map(|output| output.claim).collect();
    let approval = landed
        .iter()
        .map(|output| output.approval)
        .find(|approval| *approval != crate::claim::ClaimApprovalStatus::Auto)
        .unwrap_or(crate::claim::ClaimApprovalStatus::Auto);
    let about = rows.first().copied();
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        about,
        &[CONFLICT_RESOLUTION_ALLOWED.to_owned()],
        &allowance,
    )?;
    Ok(ItemOutcome::Landed {
        rows,
        approval: Some(approval),
        receipt: Some(receipt),
    })
}
