//! SKILL-OPT-1 (ONE-1448, ARCH-0026 dreamer-v2 "Optimize skills"): the Dreamer
//! maintenance job that keeps skill instructions honest over time.
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
//! prior revision is frozen by [`Vault::supersede_skill_record`] — the door
//! that writes the `Supersedes` edge. [`Vault::update_skill_record`] is NOT
//! the archive path and rejects a bare flip into `superseded`.
//!
//! **One skill and at most one proposal per attempt**, by construction: the
//! selector returns a ranking, this job reads its head. Per-cycle caps and the
//! held-out strictly-improving accept gate live in the [`gate`] submodule
//! (ONE-1449); this job invokes neither, and cannot admit what it drafts.
//!
//! **This job is a DEV-VIEW-ONLY consumer, receipts and aggregates alike.**
//! Every receipt list [`optimize_brief`] hands the author passes through
//! [`dev_receipts`], and every NUMBER — the ranking, the N-dial check, the
//! posterior in the brief — is folded from the dev partition of the outcome
//! ledger ([`SkillOptimizeCandidate::posterior`]). Filtering the receipt lists
//! alone would have left the leak intact one level up: a posterior computed
//! over both sides is a held-out aggregate, and one that decides WHICH skill is
//! rewritten is a held-out outcome choosing the exam question.
//!
//! That import direction is half of ONE-1449's leakage rule (the other half is
//! that the gate recomputes its own held-out view at accept time, so a leaky
//! author still cannot choose which receipts score it) — see the [`gate`]
//! module header. It is a correctness convention, not a security boundary: a
//! same-process reader can reach any receipt, and the threat being managed is
//! overfitting drift, not an adversary.
//!
//! **It consumes evidence; it owns no buffer.** The "rejected-edit buffer" of
//! the canon has no store of its own — its concrete form is the gated
//! skill-edit proposals ED-04's miner and SK-04's discovery arm already mint.
//! This job LISTS the open ones for its skill and hands them to the author, so
//! a question already asked is visible to whoever drafts the next one.
//!
//! # Exclusion is structural, and it fails closed
//!
//! Identity- and alignment-tier skills are never optimization targets — not
//! "rejected at the end", but absent from the candidate list
//! ([`optimize_candidates`]). [`SkillGovernanceTier`] is minted for this by
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
//! Two gates, both read off machinery that already exists:
//!
//! 1. **Enough evidence** — at least [`skill_optimize_min_outcomes`]
//!    attributed outcomes (the N dial; a `vault_meta` key in this module, the
//!    `INBOX_REVIEW_DIAL_KEY` house pattern — `settings.rs` is UI
//!    customization and owns nothing here). A posterior computed on a pure
//!    prior measures IGNORANCE, and rewriting a skill nobody has used yet is
//!    churn with a rationale.
//! 2. **Evidence of LOSS** — the posterior mean sits below the mean of the
//!    skill's own provenance prior
//!    ([`SkillReliabilityPosterior::seeded_from_provenance`]): attributed
//!    outcomes have moved this skill DOWN from where its birth path started
//!    it. No second dial is minted for this, and the reliability FLOOR is
//!    deliberately not reused — crossing the floor is the QUARANTINE question
//!    ("retire this"), which a repair job must be able to fire long before.
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

use std::collections::HashSet;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::edit_distance::miner::{MinedSkillEditProposal, pending_substitution_skill_edits};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::llm::CallPurpose;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{
    SKILL_DESC_MAX_BYTES, SkillDependency, SkillGovernanceTier, SkillLifecycle, SkillRecord,
};
use crate::skill_attribution::{
    AttributionVerdict, SkillEditProposal, attribution_judgments, pending_edit_proposals,
};
use crate::skill_convert::PROVENANCE_BIRTH_KEY;
use crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE;
use crate::skill_reliability::{SkillReliabilityPosterior, skill_reliability_prior};
use crate::temporal::TimeRange;

mod gate;

pub use gate::{
    DEFAULT_SKILL_EDIT_CYCLE_CAP, HELD_OUT_REPLAY_SCORER, HELD_OUT_RESERVE_DIVISOR,
    HeldOutReplayCase, HeldOutReplayScorer, HeldOutVerdict, SKILL_EDIT_CYCLE_CAP_KEY,
    SKILL_EDIT_CYCLE_MAX_BYTES, SKILL_EDIT_SCORE_CALL_PURPOSE_NAME, SkillEditCycle,
    SkillEditDisposition, admit_optimized_skill_revision, dev_receipts,
    held_out_receipt_set_digest, held_out_receipts, is_skill_edit_verdict_receipt,
    receipt_is_held_out, register_held_out_replay_scorer, score_gate_skill_edit,
    score_gate_skill_edit_in_cycle, score_gate_skill_edit_with_scorer, set_skill_edit_cycle_cap,
    skill_body_binding_digest, skill_edit_cycle_cap, skill_edit_score_call_purpose,
    skill_edit_verdict, skill_edit_verdicts, skill_edit_verdicts_for_proposal,
};
pub(crate) use gate::{
    check_optimizer_admission_in_txn, optimizer_birth_marker_for_create_in_txn,
    skill_edit_verdict_receipts,
};

// ---------------------------------------------------------------------------
// Dials + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` key holding N, the attributed outcomes a skill must carry
/// before it can be optimized.
///
/// A per-feature engine dial over `vault_meta` — the `INBOX_REVIEW_DIAL_KEY`
/// house pattern, the same one `SKILL_RELIABILITY_FLOOR_KEY` and
/// `MINER_K_SETTINGS_KEY` follow. `settings.rs` is UI customization and owns
/// nothing here.
pub const SKILL_OPTIMIZE_MIN_OUTCOMES_KEY: &[u8] = b"settings:skill_optimize:v1:min_outcomes";

/// N when the dial has never been set.
///
/// Five, matching `SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES`: the two gates ask
/// the same underlying question ("is there evidence, or only a prior?") of the
/// same posterior, and answering it with two different numbers would mean a
/// skill could be evidenced enough to retire but not enough to repair.
pub const DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES: u32 = 5;

/// The [`PROVENANCE_BIRTH_KEY`] value stamped on a drafted proposal.
pub const SKILL_OPTIMIZE_BIRTH_PATH: &str = "skill_optimize";

/// The [`CallPurpose`] an author's LLM tier must stamp, so optimization calls
/// are budgeted and audited as their own class.
pub const SKILL_OPTIMIZE_CALL_PURPOSE_NAME: &str = "skill_optimize_draft";

/// Upper bound on any one evidence list handed to the author.
///
/// Mirrors `SKILL_RELIABILITY_MAX_CITED_RECEIPTS`, which already caps the
/// citation trace this brief is mostly built from: a brief is a summary, and a
/// summary that grows without bound is a ledger.
pub const SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE: usize = 64;

/// Upper bound on an author's rationale, matching `skill_convert`'s.
pub const SKILL_OPTIMIZE_RATIONALE_MAX_BYTES: usize = 1024;

/// Provenance key naming the optimized parent's `skillId`.
pub const PROVENANCE_OPTIMIZE_OF_KEY: &str = "optimizeOf";
/// Provenance key naming the optimized parent ENTITY, hex.
pub const PROVENANCE_OPTIMIZE_OF_ENTITY_KEY: &str = "optimizeOfEntity";
/// Provenance key naming the optimized parent's version.
pub const PROVENANCE_OPTIMIZE_OF_VERSION_KEY: &str = "optimizeOfVersion";
/// Provenance key carrying the author's rationale.
pub const PROVENANCE_OPTIMIZE_RATIONALE_KEY: &str = "rationale";
/// Provenance key carrying the receipt ids the draft rests on.
pub const PROVENANCE_OPTIMIZE_RECEIPTS_KEY: &str = "evidenceReceipts";
/// Provenance key naming the Dreamer attempt that drafted the proposal.
pub const PROVENANCE_OPTIMIZE_ATTEMPT_KEY: &str = "attempt";
/// Provenance key carrying the Dreamer CYCLE the proposal was drafted in.
///
/// Stamped at BIRTH and immutable thereafter
/// ([`gate::check_optimizer_admission_in_txn`]), because the per-cycle accept
/// cap is counted against this label: a cycle identity recovered later from a
/// prunable queue row would hand every proposal a private budget the moment the
/// queue was trimmed, and a mutable one would let a relabelled proposal buy a
/// second slot.
pub const PROVENANCE_OPTIMIZE_CYCLE_KEY: &str = "cycle";

/// Page size of the SKILL type-index sweep.
const SKILL_SCAN_PAGE: usize = 1024;

/// Version prefix of a drafted revision.
const OPTIMIZE_VERSION_PREFIX: &str = "opt-";

/// Hex characters of the desc digest a drafted version carries.
const OPTIMIZE_VERSION_HASH_HEX: usize = 16;

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidSkillBody(reason)
}

/// Reads the N dial (default [`DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES`]).
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn skill_optimize_min_outcomes(vault: &Vault) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, SKILL_OPTIMIZE_MIN_OUTCOMES_KEY)?
    else {
        return Ok(DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES);
    };
    let bytes: [u8; 4] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("skill optimize min outcomes"))?;
    Ok(u32::from_be_bytes(bytes))
}

/// Sets the N dial.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] when `min_outcomes` is zero — a job that may
/// rewrite a skill on no evidence at all is the thing N exists to prevent.
pub fn set_skill_optimize_min_outcomes(vault: &Vault, min_outcomes: u32) -> Result<()> {
    if min_outcomes == 0 {
        return Err(invalid(
            "skill optimize min_outcomes must be > 0: evidence is the point",
        ));
    }
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(
            wtxn,
            SKILL_OPTIMIZE_MIN_OUTCOMES_KEY,
            &min_outcomes.to_be_bytes(),
        )?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Governance tier
// ---------------------------------------------------------------------------

/// What the tier axis says about one stored skill.
///
/// Three answers, not two: "marked standard" and "unmarked but born on an
/// ordinary road" are both eligible, while "unmarked and unexplainable" is a
/// third thing that must not collapse into either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillTierVerdict {
    /// The record carries an explicit mark.
    Marked(SkillGovernanceTier),
    /// No mark, and provenance says the record was born on one of the roads
    /// ordinary skills come from (conversation convert, hub import), so the
    /// legacy default is `standard`.
    LegacyStandard,
    /// No mark and provenance cannot say. Never a candidate.
    Ambiguous,
}

impl SkillTierVerdict {
    /// The tier this verdict resolves to, or `None` when it resolves to no
    /// tier at all.
    #[must_use]
    pub const fn tier(self) -> Option<SkillGovernanceTier> {
        match self {
            Self::Marked(tier) => Some(tier),
            Self::LegacyStandard => Some(SkillGovernanceTier::Standard),
            Self::Ambiguous => None,
        }
    }

    /// Whether the automated edit loop may consider this record.
    ///
    /// Fail-closed by shape: only a resolved, unprotected tier passes, so a
    /// future verdict arm is excluded until someone rules on it.
    #[must_use]
    pub const fn optimizable(self) -> bool {
        match self.tier() {
            Some(tier) => !tier.is_protected(),
            None => false,
        }
    }
}

/// Resolves the governance tier of a stored skill, fail-closed.
///
/// See the module header for the table this implements. The provenance halves
/// are POSITIVE evidence, both of them:
/// - conversation convert stamps its birth path on the record itself;
/// - a hub import is vouched for by an active `skill.hub_provenance` alias,
///   which the import door writes — an `Imported` stamp with no such alias is
///   an assertion about a road nobody travelled, so it stays ambiguous.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when `skill` is not a stored SKILL; storage
/// errors.
pub fn skill_governance_tier(vault: &Vault, skill: &EntityId) -> Result<SkillTierVerdict> {
    let record = vault
        .get_skill_record(skill)?
        .ok_or(Error::EntityNotFound)?;
    tier_verdict(vault, skill, &record)
}

fn tier_verdict(vault: &Vault, skill: &EntityId, record: &SkillRecord) -> Result<SkillTierVerdict> {
    let rtxn = vault.store.env.read_txn()?;
    tier_verdict_in_txn(vault, &rtxn, skill, record)
}

/// The tier rule itself, over a caller's snapshot.
///
/// The write path resolves the tier against its OWN transaction rather than
/// opening a second one: the tier is the last thing checked before a proposal
/// lands, and reading it from a different snapshot than the one the write
/// commits into is exactly the gap an owner's identity-mark could fall through.
fn tier_verdict_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
    record: &SkillRecord,
) -> Result<SkillTierVerdict> {
    if let Some(tier) = record.governance_tier {
        return Ok(SkillTierVerdict::Marked(tier));
    }
    if born_on_convert_road(record) {
        return Ok(SkillTierVerdict::LegacyStandard);
    }
    if record.source == ClaimSource::Imported && hub_vouches_in_txn(vault, rtxn, skill)? {
        return Ok(SkillTierVerdict::LegacyStandard);
    }
    Ok(SkillTierVerdict::Ambiguous)
}

/// True when an active `skill.hub_provenance` alias says a hub carried this
/// record here — the positive half of the hub-import road.
fn hub_vouches_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>, skill: &EntityId) -> Result<bool> {
    for id in vault.claims_for_subject_in_txn(rtxn, skill)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate == PREDICATE_SKILL_HUB_PROVENANCE
            && body.lifecycle == ClaimLifecycleStatus::Active
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn born_on_convert_road(record: &SkillRecord) -> bool {
    let Value::Map(entries) = &record.provenance else {
        return false;
    };
    entries.iter().any(|(key, value)| {
        key.as_str() == Some(PROVENANCE_BIRTH_KEY)
            && value.as_str() == Some(crate::skill_convert::CONVERT_BIRTH_PATH)
    })
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// One skill the job may work on, with the reading that ranked it.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub struct SkillOptimizeCandidate {
    pub skill: EntityId,
    /// The DEV-PARTITION posterior: the provenance prior folded with the
    /// attributed outcomes ONE-1449's split did NOT reserve.
    ///
    /// Deliberately not the projected `skill.reliability` claim (and never the
    /// record's `confidence` cache). That claim is a fold over BOTH sides of
    /// the split, so selecting on it would let held-out outcomes decide which
    /// skill gets rewritten and hand the drafting author a held-out aggregate —
    /// the leak the split exists to prevent, one level up from the receipt
    /// lists. The cost is honest and stated: only outcomes whose LOCAL ledger
    /// rows are present can be partitioned, so a posterior that arrived by sync
    /// is not counted here at all. Under-reading evidence delays an edit;
    /// over-reading it fits the edit to its own exam.
    pub posterior: SkillReliabilityPosterior,
    /// The provenance prior the posterior is judged against.
    pub prior: SkillReliabilityPosterior,
    /// Dev-partition attributed outcomes: the weight `posterior` holds above
    /// `prior`, and the quantity the N dial is compared against.
    pub attributed_outcomes: u32,
}

/// Every ACTIVE skill the automated loop may target, worst posterior mean
/// first.
///
/// The sweep is COMPLETE rather than paged-and-truncated: "the worst skill in
/// the library" is not a question a prefix of the type index can answer, and
/// silently ranking a prefix would make the job's choice depend on entity-id
/// order.
///
/// Ties break on entity id so two devices reading the same vault choose the
/// same skill.
///
/// # Errors
///
/// Storage errors; body errors from an undecodable SKILL record.
pub fn optimize_candidates(vault: &Vault) -> Result<Vec<SkillOptimizeCandidate>> {
    let min_outcomes = skill_optimize_min_outcomes(vault)?;
    let skills = all_skill_ids(vault)?;

    // One pass to learn which `skillId`s already have an unanswered proposed
    // revision, so the second pass can skip asking again.
    let mut open_questions: HashSet<String> = HashSet::new();
    let mut records = Vec::with_capacity(skills.len());
    for id in skills {
        let Some(record) = vault.get_skill_record(&id)? else {
            continue;
        };
        if record.lifecycle_status == SkillLifecycle::Candidate
            && record.approval_status == ClaimApprovalStatus::Proposed
        {
            open_questions.insert(record.skill_id.clone());
        }
        records.push((id, record));
    }

    let mut candidates = Vec::new();
    for (id, record) in records {
        if record.lifecycle_status != SkillLifecycle::Active {
            continue;
        }
        if open_questions.contains(&record.skill_id) {
            continue;
        }
        if !tier_verdict(vault, &id, &record)?.optimizable() {
            continue;
        }
        let prior = skill_reliability_prior(vault, &id)?;
        // ONE-1449: the DEV half, folded here. Both numbers this ranking rests
        // on are partitioned, so no held-out outcome votes on which skill the
        // author is asked to rewrite.
        let (posterior, attributed) = dev_partition_reading(vault, &id, prior)?;
        if attributed < min_outcomes {
            continue;
        }
        // Evidence of LOSS, not merely of use: the outcomes have to have moved
        // this skill below where its own birth path started it.
        if posterior.mean() >= prior.mean() {
            continue;
        }
        candidates.push(SkillOptimizeCandidate {
            skill: id,
            posterior,
            prior,
            attributed_outcomes: attributed,
        });
    }
    candidates.sort_by(|left, right| {
        left.posterior
            .mean()
            .total_cmp(&right.posterior.mean())
            .then_with(|| left.skill.as_bytes().cmp(right.skill.as_bytes()))
    });
    Ok(candidates)
}

fn all_skill_ids(vault: &Vault) -> Result<Vec<EntityId>> {
    let mut out: Vec<EntityId> = Vec::new();
    loop {
        let page = vault.entities_by_type_page(ENTITY_TYPE_SKILL, out.last(), SKILL_SCAN_PAGE)?;
        let exhausted = page.len() < SKILL_SCAN_PAGE;
        out.extend(page);
        if exhausted {
            return Ok(out);
        }
    }
}

/// One skill's DEV-side evidence, folded into a posterior of its own.
///
/// The whole aggregate half of ONE-1449's leakage rule, in one function: the
/// job's ranking, its N-dial check and the brief it hands the author all read
/// this and nothing else, so a held-out outcome has no vote anywhere on the
/// authoring road — not as a receipt id, and not as a number derived from one.
///
/// Counted from the LOCAL outcome ledger rather than derived from the projected
/// claim, because the claim is the fold over both sides and cannot be
/// un-mixed. The consequence is stated where it is felt
/// ([`SkillOptimizeCandidate::posterior`]): evidence that arrived as a synced
/// posterior, with no local rows, is invisible to this job.
fn dev_partition_reading(
    vault: &Vault,
    skill: &EntityId,
    prior: SkillReliabilityPosterior,
) -> Result<(SkillReliabilityPosterior, u32)> {
    let rtxn = vault.store.env.read_txn()?;
    let outcomes = crate::skill_reliability::attributed_outcome_results(vault, &rtxn, skill)?;
    let mut posterior = prior;
    let mut attributed = 0u32;
    for (receipt, win) in outcomes {
        if receipt_is_held_out(skill, &receipt) {
            continue;
        }
        posterior.apply(win);
        attributed = attributed.saturating_add(1);
    }
    Ok((posterior, attributed))
}

// ---------------------------------------------------------------------------
// The author seam
// ---------------------------------------------------------------------------

/// Everything the author is allowed to reason from: the instructions as they
/// stand, and what real usage did with them.
///
/// Everything here is the DEV split (ONE-1449) — the receipt lists AND the
/// aggregates. The outcomes the gate reserved are filtered out of the lists and
/// were never folded into the numbers, so the text this author writes was
/// neither fitted to the evidence that will score it nor prompted by a summary
/// of it.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SkillOptimizeBrief {
    pub skill: EntityId,
    /// The target's `skillId` — the proposal continues it, so a drafted
    /// revision is something the gate can supersede WITH.
    pub skill_id: String,
    /// The instructions as they stand. The edit is against this text.
    pub desc: String,
    pub version: String,
    /// The DEV-PARTITION posterior ([`SkillOptimizeCandidate::posterior`]).
    /// Never the projected `skill.reliability` claim: that one is a fold over
    /// both sides of the split, so showing it here would hand the author a
    /// held-out aggregate.
    pub posterior: SkillReliabilityPosterior,
    pub prior: SkillReliabilityPosterior,
    /// Dev-partition attributed outcomes — the count behind `posterior`.
    pub attributed_outcomes: u32,
    /// Receipts the reliability claim rests on (wins and losses both — the
    /// claim's own citation trace).
    pub cited_receipts: Vec<String>,
    /// Receipts of SK-04 `SkillDefect` judgments against this skill: the
    /// occasions its CONTENT was found wrong.
    pub defect_receipts: Vec<String>,
    /// Open SK-04 discovery proposals for this skill (content found MISSING).
    pub discovery_proposals: Vec<SkillEditProposal>,
    /// Open ED-04 mined substitution proposals for this skill (the same
    /// correction, made repeatedly).
    pub substitution_proposals: Vec<MinedSkillEditProposal>,
}

/// The author's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkillEditDraft {
    /// Replacement instructions the evidence supports, and why.
    Edit { desc: String, rationale: String },
    /// The evidence does not support an edit. Declining is a first-class
    /// answer: a job that must always produce something produces churn.
    Decline { rationale: String },
}

/// Drafts an instruction edit from real usage outcomes, or declines.
///
/// The host implements this against the engine's existing LLM surface under
/// [`skill_optimize_call_purpose`]; this module constructs no client (the
/// `SkillRefiner` / `AttributionJudge` posture). What the author returns is a
/// PROPOSAL either way — nothing it can say reaches canon without a human.
pub trait SkillOptimizeAuthor {
    /// Drafts the edit `brief` supports.
    ///
    /// # Errors
    ///
    /// Implementation-defined: an author that cannot answer must error rather
    /// than invent, and the attempt drafts nothing.
    fn draft(&self, brief: &SkillOptimizeBrief) -> Result<SkillEditDraft>;
}

/// The [`CallPurpose`] an author's LLM tier must stamp.
#[must_use]
pub fn skill_optimize_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: SKILL_OPTIMIZE_CALL_PURPOSE_NAME.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// The job
// ---------------------------------------------------------------------------

/// What one `skill_optimize` attempt did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkillOptimizeOutcome {
    /// The one skill this attempt considered. `None` when the tier-filtered
    /// candidate list was empty — a healthy library is not an error.
    pub skill: Option<EntityId>,
    /// The gated proposal entity, when one was drafted.
    pub proposal: Option<EntityId>,
    /// Why this attempt did what it did, in the words of whoever decided:
    /// the selector's, or the author's own.
    pub rationale: String,
}

/// Runs ONE `skill_optimize` attempt.
///
/// The order of the steps IS the contract:
/// 1. rank the tier-filtered candidates and take the head — one skill, chosen
///    fail-closed;
/// 2. read the evidence: the reliability posterior, its cited receipts, the
///    SK-04 defect receipts, and the OPEN edit proposals for that skill;
/// 3. ask the author, which may decline;
/// 4. re-read the target INSIDE the write transaction and refuse if it moved
///    while the author was thinking (the `skill_convert` merge-target rule):
///    a proposal against a superseded or already-re-proposed revision is one
///    the gate could never admit;
/// 5. land ONE proposal: a new entity, `candidate` + `proposed`, continuing
///    the target's `skillId` and dependency contract, carrying the target's
///    resolved tier forward as an explicit mark.
///
/// # Errors
///
/// Storage and body errors; whatever the author returns; and
/// [`Error::InvalidSkillBody`] when a draft is unusable (empty or oversized
/// text, or a "replacement" identical to the instructions it replaces), or when
/// `attempt` names no stored queue row and so proves no drafting cycle.
pub fn run_skill_optimize(
    vault: &Vault,
    attempt: AttemptId,
    author: &dyn SkillOptimizeAuthor,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<SkillOptimizeOutcome> {
    let Some(candidate) = optimize_candidates(vault)?.into_iter().next() else {
        return Ok(SkillOptimizeOutcome {
            skill: None,
            proposal: None,
            rationale: "no active skill is both optimizable and losing".to_owned(),
        });
    };
    let brief = optimize_brief(vault, &candidate)?;
    let (desc, rationale) = match author.draft(&brief)? {
        SkillEditDraft::Decline { rationale } => {
            validate_text(
                &rationale,
                SKILL_OPTIMIZE_RATIONALE_MAX_BYTES,
                "author rationale must be a non-empty string at most 1024 bytes",
            )?;
            return Ok(SkillOptimizeOutcome {
                skill: Some(candidate.skill),
                proposal: None,
                rationale,
            });
        }
        SkillEditDraft::Edit { desc, rationale } => (desc, rationale),
    };
    validate_text(
        &desc,
        SKILL_DESC_MAX_BYTES,
        "drafted desc must be a non-empty UTF-8 string at most 4096 bytes",
    )?;
    validate_text(
        &rationale,
        SKILL_OPTIMIZE_RATIONALE_MAX_BYTES,
        "author rationale must be a non-empty string at most 1024 bytes",
    )?;
    let SkillOptimizeBrief {
        desc: target_desc,
        version: target_version,
        cited_receipts: cited,
        defect_receipts: defects,
        ..
    } = brief;
    // An "edit" that changes nothing would mint a revision whose version
    // (derived from the text) collides with the one it proposes to replace —
    // and the supersede door would refuse it. Refuse earlier and say why.
    if desc == target_desc {
        return Err(invalid(
            "a drafted edit that restates the current instructions is not an edit",
        ));
    }

    // Resolved BEFORE the write door and persisted with the proposal: the cap
    // this draft will be counted against is a birth fact, not something a later
    // reader reconstructs from a queue row that may have been pruned by then.
    // A proposal whose cycle cannot be PROVEN at this moment is not born at
    // all — a private label is exactly the free budget the cap exists to deny.
    let drafted_in = proven_cycle(vault, attempt)?;
    let proposal_id = EntityId::now();
    vault.with_write_txn(|wtxn| {
        // Resolved at the WRITE door, not carried from the ranking: the
        // author ran outside this transaction, so the target may have been
        // superseded, quarantined or re-proposed in that window. A proposal
        // against a revision the gate can no longer supersede is dead on
        // arrival.
        let target = vault.read_skill_record_in_txn(&*wtxn, &candidate.skill)?;
        if target.lifecycle_status != SkillLifecycle::Active || target.version != target_version {
            return Err(invalid(
                "optimization target moved while the author was drafting",
            ));
        }
        let record = proposal_record(
            &target,
            &desc,
            &rationale,
            &cited,
            &defects,
            &candidate.skill,
            attempt,
            &drafted_in,
            tier_verdict_in_txn(vault, &*wtxn, &candidate.skill, &target)?,
        )?;
        vault.put_skill_record_in_txn(wtxn, &proposal_id, &record, occurred, learned_at)?;
        Ok(())
    })?;

    Ok(SkillOptimizeOutcome {
        skill: Some(candidate.skill),
        proposal: Some(proposal_id),
        rationale,
    })
}

/// The Dreamer cycle `attempt` PROVES — the one resolver, shared by the
/// drafting door (which stamps the label at birth) and the gate (which rules
/// under it).
///
/// Three answers, and the third is the repair:
///
/// | queue row | label |
/// |---|---|
/// | present, names a run | `run:<id>` |
/// | present, no run | `attempt:<hex>` |
/// | ABSENT (pruned, or never enqueued) | typed error, no label |
///
/// The RUN, not the attempt, whenever the attempt names one: a wake that drafts
/// several proposals must count them against one cap, and per-attempt labelling
/// would hand every proposal a private cap that never binds. A genuinely
/// run-less attempt is its own cycle, which is the honest label rather than a
/// fallback — that attempt id is durable and unique either way.
///
/// A MISSING row is not that case, and conflating the two was the defect: a
/// retention sweep that trimmed the queue silently promoted every later
/// proposal to a private budget. Absence proves nothing, so it names nothing,
/// and the caller is refused. Queue read failures PROPAGATE for the same
/// reason: a cap that quietly degrades when the queue cannot be read is a cap
/// that stops binding exactly when it is most needed.
///
/// # Errors
///
/// Storage/decode errors from the queue; [`Error::InvalidSkillBody`] when no
/// row for `attempt` is stored.
pub(crate) fn proven_cycle(vault: &Vault, attempt: AttemptId) -> Result<SkillEditCycle> {
    let Some(record) = AttemptQueue::new(vault).get(attempt)? else {
        return Err(invalid(
            "no stored attempt row proves this cycle; a cap counted against an unprovable label is not a cap",
        ));
    };
    match record.run_id {
        Some(run_id) => SkillEditCycle::new(format!("run:{run_id}")),
        None => SkillEditCycle::new(format!(
            "attempt:{}",
            bytes_to_hex_lower(attempt.as_bytes())
        )),
    }
}

/// Reads everything [`run_skill_optimize`] hands the author for one candidate.
///
/// # Errors
///
/// Storage errors; [`Error::EntityNotFound`] when the candidate is gone.
pub fn optimize_brief(
    vault: &Vault,
    candidate: &SkillOptimizeCandidate,
) -> Result<SkillOptimizeBrief> {
    let record = vault
        .get_skill_record(&candidate.skill)?
        .ok_or(Error::EntityNotFound)?;
    // ONE-1449, the import-direction half of the leakage rule: this loader
    // resolves the DEV split once and every receipt list below is intersected
    // with it, so no held-out outcome can reach the author through any of the
    // three ledgers this brief draws on. One membership set rather than three
    // filters — a second spelling of the rule is a second thing to get wrong.
    let dev: HashSet<String> = dev_receipts(vault, &candidate.skill)?.into_iter().collect();
    let mut defect_receipts = Vec::new();
    for judgment in attribution_judgments(vault)? {
        if judgment.verdict != AttributionVerdict::SkillDefect
            || judgment.subject != candidate.skill
        {
            continue;
        }
        defect_receipts.extend(
            judgment
                .evidence_receipts
                .into_iter()
                .filter(|receipt| dev.contains(receipt)),
        );
    }
    truncate_oldest(&mut defect_receipts);

    let mut discovery_proposals: Vec<SkillEditProposal> = pending_edit_proposals(vault)?
        .into_iter()
        .filter(|proposal| proposal.skill == candidate.skill)
        .collect();
    truncate_oldest(&mut discovery_proposals);
    let mut substitution_proposals: Vec<MinedSkillEditProposal> =
        pending_substitution_skill_edits(vault)?
            .into_iter()
            .filter(|proposal| proposal.skill == candidate.skill)
            .collect();
    truncate_oldest(&mut substitution_proposals);

    Ok(SkillOptimizeBrief {
        skill: candidate.skill,
        skill_id: record.skill_id,
        desc: record.desc,
        version: record.version,
        posterior: candidate.posterior,
        prior: candidate.prior,
        attributed_outcomes: candidate.attributed_outcomes,
        cited_receipts: reliability_citations(vault, &candidate.skill)?
            .into_iter()
            .filter(|receipt| dev.contains(receipt))
            .collect(),
        defect_receipts,
        discovery_proposals,
        substitution_proposals,
    })
}

/// Keeps the most recent [`SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE`] entries.
///
/// Both ledgers this reads are mint-ordered (UUIDv7-derived keys), so dropping
/// from the FRONT drops the oldest — the same choice the reliability claim's
/// citation cap makes.
fn truncate_oldest<T>(evidence: &mut Vec<T>) {
    if evidence.len() > SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE {
        evidence.drain(..evidence.len() - SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE);
    }
}

/// The receipts the active `skill.reliability` claim cites, or none when the
/// skill has never been projected.
fn reliability_citations(vault: &Vault, skill: &EntityId) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut best: Option<(usize, Vec<String>)> = None;
    for id in vault.claims_for_subject_in_txn(&rtxn, skill)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &id)? else {
            continue;
        };
        if body.predicate != crate::skill_reliability::PREDICATE_SKILL_RELIABILITY
            || body.lifecycle != crate::claim::ClaimLifecycleStatus::Active
        {
            continue;
        }
        let Some(Value::Array(cited)) = body.evidence.as_ref() else {
            continue;
        };
        let receipts: Vec<String> = cited
            .iter()
            .filter_map(|entry| entry.as_str().map(str::to_owned))
            .collect();
        // A read landing mid-fork must not answer with whichever head the
        // edge index yielded first; the richest trace is the one to reason
        // from, exactly as the posterior read resolves on weight.
        if best.as_ref().is_none_or(|(len, _)| receipts.len() > *len) {
            best = Some((receipts.len(), receipts));
        }
    }
    Ok(best.map(|(_, receipts)| receipts).unwrap_or_default())
}

/// Builds the gated proposal record.
///
/// Every field is either the target's or the author's, and the two are kept
/// apart deliberately:
/// - `skill_id` and `dependencies` are the TARGET's, so the draft is a
///   REVISION the gate can supersede with rather than a rival skill that
///   declares no requirements;
/// - `desc` is the author's, and is the only content it may move;
/// - `generated` / [`ClaimSource::Generated`] is the honest stamp: an LLM
///   wrote these bytes, so the successor's own posterior starts from the
///   weak `Generated` prior and has to earn its place;
/// - `governance_tier` is the target's resolved tier, stamped EXPLICITLY.
///   The successor is machine-born and would otherwise resolve `Ambiguous`
///   forever, which would quietly retire it from the loop it was born in.
#[expect(
    clippy::too_many_arguments,
    reason = "the proposal's provenance names every input it rests on"
)]
fn proposal_record(
    target: &SkillRecord,
    desc: &str,
    rationale: &str,
    cited_receipts: &[String],
    defect_receipts: &[String],
    parent: &EntityId,
    attempt: AttemptId,
    cycle: &SkillEditCycle,
    tier: SkillTierVerdict,
) -> Result<SkillRecord> {
    let tier = tier.tier().ok_or(invalid(
        "an ambiguous-tier skill is never an optimization target",
    ))?;
    if tier.is_protected() {
        return Err(invalid(
            "identity/alignment-tier skills are never optimization targets",
        ));
    }
    let mut receipts: Vec<Value> = Vec::new();
    let mut seen = HashSet::new();
    for receipt in defect_receipts.iter().chain(cited_receipts) {
        if seen.insert(receipt.as_str()) {
            receipts.push(Value::from(receipt.as_str()));
        }
    }
    let provenance = Value::Map(vec![
        (
            Value::from(PROVENANCE_BIRTH_KEY),
            Value::from(SKILL_OPTIMIZE_BIRTH_PATH),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_KEY),
            Value::from(target.skill_id.as_str()),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_ENTITY_KEY),
            Value::from(parent.to_hex()),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_OF_VERSION_KEY),
            Value::from(target.version.as_str()),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_RATIONALE_KEY),
            Value::from(rationale),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_RECEIPTS_KEY),
            Value::Array(receipts),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_ATTEMPT_KEY),
            Value::from(bytes_to_hex_lower(attempt.as_bytes())),
        ),
        (
            Value::from(PROVENANCE_OPTIMIZE_CYCLE_KEY),
            Value::from(cycle.as_str()),
        ),
    ]);
    let dependencies: Vec<SkillDependency> = target.dependencies.clone();
    Ok(SkillRecord::new(
        target.skill_id.as_str(),
        desc,
        optimize_version(desc),
        // The gate, in one field: a proposal is PROPOSED. Nothing in this
        // module can write `approved`, so nothing in this module can admit.
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        SkillReliabilityPosterior::seeded_from_provenance(
            crate::skill_reliability::ProvenanceTrustClass::Generated,
        )
        .mean(),
        true,
        false,
        dependencies,
        provenance,
    )
    .with_governance_tier(tier))
}

/// The drafted revision's version string.
///
/// Names the content instead of counting behind it (ARCH-0053 §7, the
/// `skill_convert` revision rule): the drafted text decides the version, so a
/// draft can never collide with the revision it proposes to replace unless it
/// IS that revision — which the caller has already refused.
fn optimize_version(desc: &str) -> String {
    let digest = Sha256::digest(desc.as_bytes());
    let hex = bytes_to_hex_lower(&digest);
    format!(
        "{OPTIMIZE_VERSION_PREFIX}{}",
        &hex[..OPTIMIZE_VERSION_HASH_HEX]
    )
}

fn validate_text(value: &str, max_bytes: usize, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid(reason));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
