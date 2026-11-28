//! `vault.arms.review` (design pass 32 r2, sections 4.5 and 4.6; verb 9 of
//! section 5.2): the independent review of a rung's promote.
//!
//! - `confirmed` scores the rung (`success = true`, anchor
//!   `Audit { rate: 1.0 }`), writes its receipt projection, and opens the
//!   next rung with the engine's promotion record, or closes the arm
//!   `Succeeded` at its last rung.
//! - `changed { to: kill }` scores the rung as an audited loss and closes
//!   the arm; `changed { to: invalid }` closes it with no outcome.
//! - `unresolved` is not a decision: the rung keeps waiting.
//!
//! An agent reviews under a Grant in the line's `reviewers`; the owner's
//! own proof passes too (section 5.1 point 4), and the review records it as
//! the owner's. The reviewing actor, the owner included, is not the arm's admitter, not the verdict's author, not the
//! reserver of any claim at the rung, not the declared runner actor, and
//! holds no lead role on the line under any of its Grants: the check is on
//! the actor, so a second credential does not help. The declared model is a
//! claim; a review that declares the runner's model is refused all the
//! same. The review names the arm revision it read and the verdict's result
//! digest. It is one write, as the verdict is.
//!
//! A confirm publishes nothing (owner rule): its writes are the arm row (the
//! outcome, the promotion and the next rung), the receipt projection and the
//! intent row. It makes no outbound call and touches no registry, release
//! queue or publisher credential, on the first call or on a replay.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::{IntentAsk, IntentStand, LineRole, doors_caller, line_in_txn};
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

use super::outcome::{
    RungClaims, audited_outcome, invalid_state, result_scored_in_txn, rung_won_before_in_txn,
    score_rung_in_txn,
};
use super::verdict::{
    EVIDENCE_NAME_MAX_BYTES, bad_request, check_digests, check_ledger_row, not_found,
};
use super::{
    ArmChangedTo, ArmDecision, ArmEvidenceDigest, ArmInvalidReason, ArmPromotion, ArmReview,
    ArmReviewVerdict, ArmRung, ArmState, ArmView, EXPERIMENT_ARMS, ExperimentArm, LedgerRowRef,
    RungEnd, RungState,
};

/// The verb that writes a rung's review.
pub const ARMS_REVIEW_VERB: &str = "vault.arms.review";

/// `vault.arms.review`: the reviewer's finding on one rung's promote, at the
/// arm revision the reviewer read, under the caller's intent key.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArmReviewRequest {
    /// Names this write: a repeat of the same ask under it answers the arm,
    /// marked `replayed`.
    pub intent_key: String,
    /// The arm.
    pub arm: EntityId,
    /// The rung whose promote is reviewed.
    pub rung: u8,
    /// The arm's revision as the reviewer read it, after the promote: the
    /// review's compare-and-set.
    pub of_arm_revision: u64,
    pub verdict: ArmReviewVerdict,
    /// The promote's result digest, read again: it must be the stored one.
    pub result: ArmEvidenceDigest,
    /// At most 32 digests, by hash: never a body.
    #[serde(default)]
    pub evidence: Vec<ArmEvidenceDigest>,
    /// The review text (REVIEW.md), by hash.
    pub review_ref: ArmEvidenceDigest,
    #[serde(default)]
    pub ledger_row: Option<LedgerRowRef>,
    /// The reviewer's model, with its revision: a claim, shown as declared.
    pub model: String,
}

impl ArmReviewRequest {
    /// The ask its intent key digests: everything but the key itself.
    fn ask(&self) -> Self {
        Self {
            intent_key: String::new(),
            ..self.clone()
        }
    }

    /// The checks that read nothing.
    fn check_shape(&self) -> MemoryResult<()> {
        if self.rung == 0 {
            return Err(bad_request("rungs count from 1"));
        }
        if self.model.trim().is_empty()
            || self.model.len() > EVIDENCE_NAME_MAX_BYTES
            || self.model.contains('\0')
        {
            return Err(bad_request("a reviewer's model is 1 to 256 bytes"));
        }
        if let ArmReviewVerdict::Changed {
            to: ArmChangedTo::Invalid { reason },
        } = &self.verdict
        {
            match reason {
                ArmInvalidReason::Withdrawn => {
                    return Err(bad_request(
                        "a review does not withdraw an arm: a withdrawn rung has no charged seconds, and a promote rests on some",
                    ));
                }
                ArmInvalidReason::Other(why)
                    if why.trim().is_empty() || why.len() > EVIDENCE_NAME_MAX_BYTES =>
                {
                    return Err(bad_request(
                        "an invalid reason of kind other is 1 to 256 bytes",
                    ));
                }
                _ => {}
            }
        }
        check_digests(
            [&self.result, &self.review_ref]
                .into_iter()
                .chain(&self.evidence),
            self.evidence.len(),
        )?;
        check_ledger_row(self.ledger_row.as_ref())
    }

    /// The review this ask writes, by `by` under `grant` (`None`: the
    /// owner's own proof) at `at_ms`.
    fn review(&self, by: EntityId, grant: Option<EntityId>, at_ms: u64) -> ArmReview {
        ArmReview {
            verdict: self.verdict.clone(),
            of_arm_revision: self.of_arm_revision,
            result: self.result.clone(),
            evidence: self.evidence.clone(),
            review_ref: self.review_ref.clone(),
            ledger_row: self.ledger_row.clone(),
            model: self.model.clone(),
            by: Some(by),
            grant,
            at_ms,
        }
    }

    /// Whether the stored review `stored` is what this ask wrote.
    fn written_as(&self, stored: &ArmReview) -> bool {
        stored.of_arm_revision == self.of_arm_revision
            && stored.verdict == self.verdict
            && stored.result == self.result
            && stored.evidence == self.evidence
            && stored.review_ref == self.review_ref
            && stored.ledger_row == self.ledger_row
            && stored.model == self.model
    }
}

/// `vault.arms.review` as `memory`'s caller: the independent review of the
/// promote on the arm's rung, in one write at `now_ms` on the host's clock.
/// An agent reviews under a Grant in the line's reviewers; the owner's own
/// proof passes as well, and the stored review then names no Grant (Engine
/// ANSWER 11:18 to NOTE PLAN-M2-E2). The caller is judged again in the
/// write: the line cover, an agent's reviewer role, and the independence of
/// section 4.6, which holds for the owner too.
///
/// # Errors
///
/// `bad_request` for a malformed ask or a blank intent key; `forbidden` for
/// a caller whose Grant does not reach the arm's line or
/// holds no reviewer role on it (`not_this_line`), or a reviewer who is not
/// independent of the arm (`reviewer_not_independent`); `not_found` for an
/// unknown arm, a rung the arm has not opened, or a line that is gone;
/// `invalid_state` for an arm revision that is not the stored one
/// (`stale_revision`), a rung that already holds another review at that
/// revision (`review_set`), a rung not awaiting review (`rung_closed`,
/// `rung_not_awaiting_review`), a result digest that is not the promote's
/// (`result_changed`), a result that backs another scored rung on the line
/// (`result_scored`), a rung the arm's experiment already won (`rung_won`),
/// or an intent key that names another ask; a store failure.
pub fn arm_review_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmReviewRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    request.check_shape()?;
    let vault = memory.vault();
    vault.try_with_write_txn_grouped(|wtxn| {
        review_in_txn(vault, wtxn, memory, owner, request, now_ms)
    })
}

fn review_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &ArmReviewRequest,
    now_ms: u64,
) -> MemoryResult<ArmView> {
    let Some(mut arm) = vault.experiment_arm_in_txn(wtxn, &request.arm)? else {
        return Err(not_found("no experiment arm has this id"));
    };
    let caller = doors_caller::admit_in_txn(memory, wtxn, owner, ARMS_REVIEW_VERB, arm.line)?;
    let line = line_in_txn(vault, wtxn, &arm.line)?
        .ok_or_else(|| not_found("the arm's GPU line is gone"))?;
    // `None`: the owner's own proof, which passes every door.
    let grant = match caller {
        doors_caller::LineCaller::Owner(_) => None,
        doors_caller::LineCaller::Agent { grant } => Some(grant),
    };
    caller.require_role(&line, &[LineRole::Reviewer], ARMS_REVIEW_VERB)?;
    let reviewer = memory.actor();
    let intent = IntentAsk::new(
        reviewer,
        ARMS_REVIEW_VERB,
        &request.intent_key,
        &request.ask(),
    )?;
    if let IntentStand::Replayed(_) = intent.stand_in_txn(vault, wtxn)?? {
        // The ask names the arm, so the row this key wrote is this arm's.
        return Ok(ArmView::of(arm, true));
    }
    let Some(index) = arm.rungs.iter().position(|rung| rung.rung == request.rung) else {
        return Err(not_found("the arm has not opened this rung"));
    };
    // The logical key (section 5.2): one review on (arm, rung) at an arm
    // revision. Two reviewers who race produce one outcome: the second reads
    // the first as a replay, or is refused below.
    if let Some(stored) = &arm.rungs[index].review
        && stored.of_arm_revision == request.of_arm_revision
        && stored.by == Some(reviewer)
    {
        if !request.written_as(stored) {
            return Err(invalid_state(
                "review_set: the rung already holds another review given at this arm revision",
            ));
        }
        intent.keep_in_txn(vault, wtxn, arm.id.as_bytes().to_vec(), now_ms)?;
        return Ok(ArmView::of(arm, true));
    }
    match &arm.rungs[index].state {
        RungState::AwaitingReview => {}
        RungState::Closed { .. } => {
            return Err(invalid_state(
                "rung_closed: the rung's outcome is written; a settled rung keeps its first outcome",
            ));
        }
        RungState::Open => {
            return Err(invalid_state(
                "rung_not_awaiting_review: the rung has no promote waiting for review",
            ));
        }
    }
    if request.of_arm_revision != arm.revision {
        return Err(invalid_state(&format!(
            "stale_revision: the arm is at revision {}, not {}; read it again with vault.arms.get",
            arm.revision, request.of_arm_revision
        )));
    }
    let Some(verdict) = arm.rungs[index].verdict.clone() else {
        return Err(invalid_state(
            "rung_not_awaiting_review: the rung holds no promote",
        ));
    };
    if verdict.decision != ArmDecision::Promote
        || verdict.result.as_ref().map(|result| &result.sha256) != Some(&request.result.sha256)
    {
        return Err(invalid_state(
            "result_changed: the result digest is not the one the promote rests on",
        ));
    }
    let claims = RungClaims::read_in_txn(vault, wtxn, &arm, request.rung)?;
    let leads_the_line = vault.agent_grants_in_txn(wtxn)?.iter().any(|standing| {
        standing.grant.member_ref == reviewer && line.holds_role(&standing.id, LineRole::Lead)
    });
    check_independent(
        &arm,
        verdict.by,
        &claims,
        leads_the_line,
        reviewer,
        &request.model,
    )?;
    let scores = matches!(
        request.verdict,
        ArmReviewVerdict::Confirmed
            | ArmReviewVerdict::Changed {
                to: ArmChangedTo::Kill
            }
    );
    if scores && result_scored_in_txn(vault, wtxn, &arm, request.rung, &request.result)? {
        return Err(invalid_state(
            "result_scored: this result digest already backs a scored rung on the line; a result backs one outcome",
        ));
    }
    let policy = claims.policy_in_txn(vault, wtxn, &line, &arm)?;
    let cap = policy
        .rung_caps_secs
        .get(usize::from(request.rung) - 1)
        .copied();
    match &request.verdict {
        ArmReviewVerdict::Confirmed => {
            if rung_won_before_in_txn(vault, wtxn, &arm, request.rung)? {
                return Err(invalid_state(
                    "rung_won: an arm this one supersedes already won this rung; an experiment wins a rung once",
                ));
            }
            arm.rungs[index].state = RungState::Closed {
                end: RungEnd::Promoted,
            };
            score_rung_in_txn(
                vault,
                wtxn,
                &mut arm,
                index,
                audited_outcome(true, now_ms),
                &claims,
                cap,
            )?;
            if usize::from(request.rung) < policy.rung_caps_secs.len() {
                arm.rungs.push(ArmRung::open(
                    request.rung + 1,
                    Some(ArmPromotion {
                        review_at_ms: now_ms,
                        reviewer: Some(reviewer),
                    }),
                ));
            } else {
                arm.state = ArmState::Succeeded;
            }
        }
        ArmReviewVerdict::Changed {
            to: ArmChangedTo::Kill,
        } => {
            arm.rungs[index].state = RungState::Closed {
                end: RungEnd::Killed,
            };
            arm.state = ArmState::Killed;
            score_rung_in_txn(
                vault,
                wtxn,
                &mut arm,
                index,
                audited_outcome(false, now_ms),
                &claims,
                cap,
            )?;
        }
        ArmReviewVerdict::Changed {
            to: ArmChangedTo::Invalid { reason },
        } => {
            arm.rungs[index].state = RungState::Closed {
                end: RungEnd::Invalid {
                    reason: reason.clone(),
                },
            };
            arm.state = ArmState::Invalid;
        }
        ArmReviewVerdict::Unresolved => {}
    }
    arm.rungs[index].review = Some(request.review(reviewer, grant, now_ms));
    arm.revision += 1;
    EXPERIMENT_ARMS.put(&vault.store, wtxn, &arm.id, &arm)?;
    intent.keep_in_txn(vault, wtxn, arm.id.as_bytes().to_vec(), now_ms)?;
    Ok(ArmView::of(arm, false))
}

/// The independence of section 4.6, on the reviewing actor: not the arm's
/// admitter, not the promote's author (`promoted_by`), no reserver of a claim
/// at the rung, not the declared runner, no lead of the line under any of its
/// Grants (`leads_the_line`), and not declaring the runner's model.
///
/// # Errors
///
/// `forbidden` (`reviewer_not_independent`) naming the first tie found.
fn check_independent(
    arm: &ExperimentArm,
    promoted_by: Option<EntityId>,
    claims: &RungClaims,
    leads_the_line: bool,
    reviewer: EntityId,
    model: &str,
) -> MemoryResult<()> {
    let tie = if arm.admitted_by == Some(reviewer) {
        Some("the reviewer admitted the arm")
    } else if promoted_by == Some(reviewer) {
        Some("the reviewer gave the promote")
    } else if claims.reservers().contains(&reviewer) {
        Some("the reviewer reserved a claim at this rung")
    } else if arm.runner.actor == Some(reviewer) {
        Some("the reviewer is the arm's declared runner")
    } else if leads_the_line {
        Some("the reviewer holds a lead role on the line under one of its Grants")
    } else if model.trim().eq_ignore_ascii_case(arm.runner.model.trim()) {
        Some("the review declares the runner's own model")
    } else {
        None
    };
    match tie {
        Some(tie) => Err(forbidden(&format!(
            "reviewer_not_independent: {tie}; the review goes to another reviewer"
        ))),
        None => Ok(()),
    }
}

fn forbidden(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        why,
        &["Ask another reviewer of the line to review the rung."],
    )
}
