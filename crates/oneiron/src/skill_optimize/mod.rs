//! SKILL-OPT-1 (ONE-1448, ARCH-0026 dreamer-v2 "Optimize skills"): the Coach's
//! job on the Dreamer's runner that keeps skill instructions honest over time.
//! It keeps its `dreamer.skill_optimize` kind token; its stamp names the Coach.
//!
//! ```text
//! Dreamer wake ─▶ skill_optimize attempt
//!        │
//!        ├─ candidates: ACTIVE skills, tier-filtered (fail-closed),
//!        │              ≥N attributed outcomes, posterior BELOW its own prior
//!        │              └─ worst posterior mean first ─▶ ONE skill
//!        │
//!        ├─ evidence: skill.reliability posterior + its cited receipts
//!        │            + SK-04 defect judgments
//!        │            + OPEN gated skill-edit proposals (ED-04, SK-04 discovery)
//!        │
//!        └─ author (LLM tier) ─▶ ONE gated proposal  ·  or nothing
//! ```
//!
//! # What this job may and may not do
//!
//! **It drafts. It never mutates.** The proposal is a NEW SKILL entity — a
//! revision of the target's `skillId`, born `candidate` and stamped
//! `approval = proposed`. The Active record is not touched, not re-versioned
//! and not re-stamped, exactly as `skill_convert`'s merge proposal leaves its
//! target alone. Admission of the successor (`candidate → active`) is the
//! GATE's act (ONE-1449, ARCH-0005b: AI is never the sole approver), and the
//! prior revision is frozen by [`Vault::supersede_skill_record`](crate::Vault::supersede_skill_record) — the door
//! that writes the `Supersedes` edge. [`Vault::update_skill_record`](crate::Vault::update_skill_record) is NOT
//! the archive path and rejects a bare flip into `superseded`.
//!
//! **One skill and at most one proposal per attempt**, by construction: the
//! selector returns a ranking, this job reads its head. Per-cycle caps and the
//! held-out strictly-improving accept gate live in the `gate` submodule
//! (ONE-1449); this job invokes neither, and cannot admit what it drafts.
//!
//! **This job is a DEV-VIEW-ONLY consumer, receipts and aggregates alike.**
//! Every receipt list [`optimize_brief`] hands the author passes through
//! [`dev_receipts`], every PROPOSAL payload it forwards must rest only on that
//! same dev evidence (their ids, and a substitution's correction text, are
//! held-out content wearing another shape), and every NUMBER — the ranking, the
//! N-dial check, the posterior in the brief — is folded from the dev partition
//! of the outcome ledger ([`SkillOptimizeCandidate::posterior`]). Filtering the
//! flat receipt lists alone left the leak intact on both sides: one level up, a
//! posterior computed over both halves is a held-out aggregate deciding WHICH
//! skill is rewritten; one level down, a forwarded proposal is a held-out
//! outcome quoted verbatim.
//!
//! That import direction is half of ONE-1449's leakage rule (the other half is
//! that the gate recomputes its own held-out view at accept time, so a leaky
//! author still cannot choose which receipts score it) — see the `gate`
//! module header. It is a correctness convention, not a security boundary: a
//! same-process reader can reach any receipt, and the threat being managed is
//! overfitting drift, not an adversary.
//!
//! **It consumes evidence; it owns no buffer.** The "rejected-edit buffer" of
//! the canon has no store of its own — its concrete form is the gated
//! skill-edit proposals ED-04's miner and SK-04's discovery arm already mint.
//! This job LISTS the open ones for its skill and hands them to the author, so
//! a question already asked is visible to whoever drafts the next one. It also
//! joins prior rejected optimizer edits for that skill to their proposals,
//! showing the proposed text and categorical rejection reason without showing
//! the held-out scores or receipts.
//!
//! # Exclusion is structural, and it fails closed
//!
//! Identity- and alignment-tier skills are never optimization targets — not
//! "rejected at the end", but absent from the candidate list
//! ([`optimize_candidates`]). [`SkillGovernanceTier`](crate::SkillGovernanceTier) is minted for this by
//! ONE-1448 as a SKILL body key; what makes the rule hold on data older than
//! the key is [`skill_governance_tier`]:
//!
//! | record | verdict |
//! |---|---|
//! | marked `identity` / `alignment` | protected — never a candidate |
//! | marked `standard` | eligible |
//! | unmarked, born conversation-convert or hub-import | `standard` by provenance |
//! | unmarked, provenance cannot say | AMBIGUOUS — never a candidate |
//!
//! The last row is the whole point. A blanket `standard` default would admit
//! every pre-existing record — including any identity pack seeded before the
//! mark existed — into an automated edit loop on the strength of a missing
//! field. So the legacy default is POSITIVE-EVIDENCE: a record is eligible
//! only if it can show it was born on one of the roads this wave's ordinary
//! skills come from. Everything else waits for its owner, who marks tiers
//! through the ordinary update door (a tier mark is a state flip, not a
//! content revision — see `skill::skill_content_changed`).
//!
//! This is deliberately not a pack-NAME allowlist. No identity/alignment pack
//! naming symbol exists in the engine to match against, and a hardcoded name
//! list would fail open for every pack not on it — while the provenance rule
//! already excludes exactly the records a name list would have caught.
//!
//! # Which skill, and when it is worth touching
//!
//! Three gates, all read off machinery that already exists:
//!
//! 1. **Enough evidence** — at least [`skill_optimize_min_outcomes`]
//!    attributed outcomes (the N dial; a `vault_meta` key in this module, the
//!    `INBOX_REVIEW_DIAL_KEY` house pattern — `settings.rs` is UI
//!    customization and owns nothing here). A posterior computed on a pure
//!    prior measures IGNORANCE, and rewriting a skill nobody has used yet is
//!    churn with a rationale.
//! 2. **Evidence of LOSS** — the posterior mean sits below the mean of the
//!    skill's own provenance prior
//!    ([`SkillReliabilityPosterior::seeded_from_provenance`](crate::skill_reliability::SkillReliabilityPosterior::seeded_from_provenance)): attributed
//!    outcomes have moved this skill DOWN from where its birth path started
//!    it. No second dial is minted for this, and the reliability FLOOR is
//!    deliberately not reused — crossing the floor is the QUARANTINE question
//!    ("retire this"), which a repair job must be able to fire long before.
//! 3. **Something to be scored ON** — the skill's held-out reserve
//!    ([`held_out_receipts`]) is non-empty. The N dial counts DEV outcomes and
//!    the split reserves about one receipt in five INDEPENDENTLY, so a skill
//!    can clear N with an empty reserve; drafting one of those spent an LLM
//!    author on a proposal the gate had nothing to score it against. No dial
//!    for this either: "can this be judged at all" is a fact about the ledger.
//!
//! A skill whose evidence is winning is not a candidate, so a healthy library
//! produces no proposals at all.
//!
//! # Not asking the same question twice
//!
//! A skill with an OPEN proposed revision of its `skillId` is skipped: an
//! unanswered proposal is a question already put to a human, and drafting a
//! second one is nagging. That is derived from the records themselves on each
//! pass — never a stored count (doc-13 r1, the `skill.reliability` posture) —
//! so there is no third ledger to keep honest.
//!
//! The honest bound: admission is per-device (private queue rows), so two
//! devices that wake before syncing can each draft one proposal for the same
//! skill. They converge to two open questions a decider answers, never to a
//! silent double edit — nothing here writes canon.

mod ask_band;
pub(crate) mod audit_rate;
mod brief;
mod decisions;
mod dials;
mod eval_set;
mod gate;
mod goal_axes;
mod goal_binding;
mod job;
mod judge_swap;
mod labels;
mod offer;
mod offer_switch;
pub(crate) mod policy;
mod response_pair;
mod selection;
mod tier;
mod tradeoff_route;

pub use self::ask_band::{AskBandLabel, AskBandPolicy};
#[cfg(test)]
pub(crate) use self::brief::optimize_brief_bound_at;
pub use self::brief::{
    RejectedSkillEdit, RejectedSkillEditReason, SKILL_OPTIMIZE_CALL_PURPOSE_NAME,
    SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE, SKILL_OPTIMIZE_RATIONALE_MAX_BYTES, SkillEditDraft,
    SkillOptimizeAuthor, SkillOptimizeBrief, optimize_brief, optimize_brief_for_principal_at,
    skill_optimize_call_purpose,
};
pub use self::decisions::{SkillOptimizeDecisions, SkillReplayPair, judgment_kind};
pub use self::dials::{
    DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES, SKILL_OPTIMIZE_MIN_OUTCOMES_KEY,
    set_skill_optimize_min_outcomes, skill_optimize_min_outcomes,
};
pub use self::eval_set::{
    DerivationKind, EvalCase, EvalCaseDraft, EvalCohort, EvalExposure, EvalExposureCounts,
    EvalExposureKind, EvalLabel, EvalLabelAsk, EvalLabelKind, EvalRelease, EvalSeat, FamilyPurpose,
    SourceFamily, SufficiencyCard, SufficiencyInput, SufficiencyVerdict, UnknownReason,
    WaitingDecision, sufficiency_card,
};
pub use self::goal_axes::{
    AxisArm, AxisScores, ConfidenceInterval, GoalAxisBandit, GoalAxisBandits, GoalAxisPlan,
    GoalAxisReport, OnlineAxisMeasurement, OnlineAxisOutcome, OnlineAxisSample, measure_goal_axes,
};
pub use self::job::{
    PROVENANCE_OPTIMIZE_ATTEMPT_KEY, PROVENANCE_OPTIMIZE_CYCLE_KEY,
    PROVENANCE_OPTIMIZE_OF_ENTITY_KEY, PROVENANCE_OPTIMIZE_OF_KEY,
    PROVENANCE_OPTIMIZE_OF_VERSION_KEY, PROVENANCE_OPTIMIZE_RATIONALE_KEY,
    PROVENANCE_OPTIMIZE_RECEIPTS_KEY, SKILL_OPTIMIZE_BIRTH_PATH, SkillOptimizeOutcome,
    run_skill_optimize, run_skill_optimize_as, run_skill_optimize_for_resident,
};
pub use self::judge_swap::{
    JUDGE_SWAP_NOTIFICATION_PRODUCER, JudgeIncumbent, JudgeOutcomeLink, JudgeShadowAnswer,
    JudgeShadowCase, JudgeShadowHost, JudgeSwapDisagreement, JudgeSwapPick, JudgeSwapPolicy,
    JudgeSwapReceipt, JudgeSwapReport, JudgeSwapSettledBy, JudgeTieBreaker, judge_incumbent,
    judge_swap_policy, judge_swap_receipts, pick_judge_swap_case, set_judge_swap_policy,
};
pub(crate) use self::judge_swap::{
    judge_retest_flips, retest_flip_ask, run_judge_swap, swap_case_ask, swap_case_retest_picked,
};
pub use self::labels::{
    JudgeAsk, JudgeAskReason, JudgeLabel, ask_judge_disagreement, ask_judge_uncertainty,
    judge_digest_minutes, judge_label_anchor, record_judge_pick, set_judge_digest_minutes,
};
pub(crate) use self::labels::{
    judge_ask_room, take_digest_asks_in_txn, take_digest_eval_asks_in_txn,
};
pub use self::offer::{
    ComputeDestination, OFFER_SKILL_AXIS, OfferAnswer, OfferAnswerRecord, OfferCandidate,
    OfferCheck, OfferCheckInput, OfferCost, OfferEvidence, OfferIntent, OfferModelPin, OfferOption,
    SeatWorkload, TrainingOffer, TrainingOfferDraft, offer_skill_cell, pending_training_offers,
    record_offer_check, record_training_offer, settle_training_offer, training_offer,
    training_offer_checks, training_offer_skill_id, training_offers,
};
pub use self::offer_switch::{
    OfferSwitchReceipt, OfferSwitchUndo, model_role_seat, seat_model_role, training_offer_switch,
    undo_training_offer_switch,
};
pub use self::response_pair::{ResponsePairPick, pick_response_pair, response_pair_picks};
pub use self::selection::{
    SkillOptimizeCandidate, optimize_candidates, optimize_candidates_for_resident,
};
pub use self::tier::{SkillTierVerdict, skill_governance_tier};
pub(crate) use self::tradeoff_route::run_tradeoff_route;
pub use self::tradeoff_route::{
    TRADEOFF_ROUTE_NOTIFICATION_PRODUCER, TradeoffRouteChannel, TradeoffRouteIssue,
    TradeoffRouteReport,
};
pub use gate::{
    AnchorLabelScore, AuditPair, BlindPreference, DEFAULT_SKILL_EDIT_CYCLE_CAP, GoalAxisKind,
    GoalAxisScore, GoalAxisSpec, HELD_OUT_REPLAY_SCORER, HELD_OUT_RESERVE_DIVISOR,
    HeldOutReplayCase, HeldOutReplayNotes, HeldOutVerdict, HonestyReplay, HonestyReplayObservation,
    JevTradeoffVerdict, JudgeMeasurements, PreferredResponse, ProjectGoalRevisionProposal,
    SKILL_EDIT_CYCLE_CAP_KEY, SKILL_EDIT_CYCLE_MAX_BYTES, SKILL_EDIT_SCORE_CALL_PURPOSE_NAME,
    SkillEditCycle, SkillEditDisposition, SkillEditGoal, SkillEditPreflight, SkillTradeoffAsk,
    SkillTradeoffPreferences, SkillTradeoffQuestion, TradeoffChoice, TradeoffResolution,
    TradeoffRole, TradeoffRule, TradeoffRung, WorldAxisScore, admit_optimized_skill_revision,
    dev_receipts, dismiss_project_goal_revision_proposal, escalate_skill_tradeoff_ask,
    held_out_receipt_set_digest, held_out_receipts, is_skill_edit_verdict_receipt,
    measure_skill_edit_goal_axes, pending_skill_tradeoff_asks, preflight_skill_edit_offline_floors,
    project_goal_revision_proposals, receipt_is_held_out, register_held_out_replay_scorer,
    resolve_skill_edit_tradeoff, resolve_skill_edit_tradeoff_in_cycle, score_gate_skill_edit,
    score_gate_skill_edit_in_cycle, score_gate_skill_edit_with_scorer, set_skill_edit_cycle_cap,
    set_skill_edit_goal_axes, set_skill_goal_project, set_skill_tradeoff_preferences,
    settle_skill_tradeoff_ask, settle_skill_tradeoff_ask_as, settle_skill_tradeoff_ask_as_agent,
    skill_body_binding_digest, skill_edit_cycle_cap, skill_edit_goal, skill_edit_goal_axis_report,
    skill_edit_needs_goal_axis_report, skill_edit_score_call_purpose, skill_edit_verdict,
    skill_edit_verdicts, skill_edit_verdicts_for_proposal, skill_goal_axis_plan,
    skill_goal_project, skill_tradeoff_ask, skill_tradeoff_asks_for, skill_tradeoff_preferences,
    supersede_skill_edit_judge,
};
pub(crate) use gate::{
    SkillEditTrialBasis, check_optimizer_admission_in_txn, displaced_judge_revision_in_txn,
    ensure_current_judge_in_txn, optimizer_birth_marker_for_create_in_txn,
    project_goal_revision_proposals_in_txn, settle_skill_tradeoff_ask_as_in_txn,
    settle_skill_tradeoff_ask_in_txn, skill_edit_preflight_passed_in_txn,
    skill_edit_trial_basis_in_txn, skill_edit_verdict_receipts, skill_tradeoff_ask_in_txn,
    validate_judge_revision, with_optimized_skill_admission,
};

pub(crate) use self::goal_binding::validate_goal_birth_in_txn;
use self::goal_binding::{GOAL_ID_KEY, SkillGoalId};
pub(crate) use self::job::{
    SKILL_EDIT_CYCLE_RUN_PREFIX, SkillRepairStamp, propose_skill_package_revision,
    propose_skill_repair_in_txn, proven_cycle, skill_repair_brief, validate_skill_draft,
};

use self::dials::invalid;
use self::tier::tier_verdict_in_txn;

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::brief::rests_only_on_dev;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::AttemptId;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimSource};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_SKILL;
#[cfg(test)]
use crate::skill::{SkillDependency, SkillGovernanceTier, SkillLifecycle, SkillRecord};
#[cfg(test)]
use crate::skill_attribution::pending_edit_proposals;
#[cfg(test)]
use crate::skill_convert::PROVENANCE_BIRTH_KEY;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use rmpv::Value;
