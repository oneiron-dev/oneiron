//! SKILL-OPT-2 (ONE-1449, ARCH-0026 dreamer-v2 / ARCH-0053 §6): the held-out
//! score gate that arms `candidate → active` for an optimizer-born proposal.
//!
//! ```text
//! ONE-1448 drafts ─▶ proposal (candidate + proposed, cycle stamped at birth)
//!        │
//!        ├─ score gate ─┬─ held-out receipts, recomputed HERE
//!        │              ├─ a standing acceptance over the same basis is
//!        │              │  RETURNED, not re-scored (retries are free)
//!        │              ├─ judged replay: score(current) vs score(proposed)
//!        │              ├─ strict  after > before  (ties reject)
//!        │              ├─ commit-time: held-out set recomputed and compared
//!        │              ├─ accept-time governance_tier recheck
//!        │              └─ per-cycle ACCEPT cap, counted in PROPOSALS
//!        │                     ├─▶ typed verdict row ─▶ Gate receipt
//!        │                     └─▶ any ANSWER closes the proposal
//!        │
//!        └─ admission ──┬─ requires an ACCEPTED verdict
//!                       ├─ requires that verdict to bind THIS body, THIS
//!                       │  predecessor and THIS reserved evidence, all
//!                       │  recomputed in the committing snapshot
//!                       ├─ requires every cited source message still live
//!                       └─▶ candidate → active  (then the caller supersedes)
//! ```
//!
//! # A verdict is about a body, not about an id
//!
//! Every acceptance records the canonical content digest of the candidate it
//! scored, of the predecessor it scored against, and the count and digest of
//! the exact reserved evidence it was judged over. Admission recomputes all
//! three in the transaction the flip commits into and refuses on any
//! difference. Without that, "proposal X passed" was a permission attached to
//! an ID: edit the body under it, or re-point it at another target, and
//! unscored content reaches canon through a gate that did pass — once, for
//! something else.
//!
//! # An answer closes the question, and a race is not an answer
//!
//! ONE-1448 skips any skill with an open `candidate + proposed` revision,
//! because an unanswered proposal is a question already put to a human. So a
//! ruling that ANSWERS a proposal — a rejection, a tie, any refusal — moves it
//! to `approval: rejected` in the same transaction as the verdict row. Exactly
//! ONE durable disposition leaves the record open, and it is the cap deferral
//! ([`SkillEditDisposition::DeferredCycleCap`]): the budget was spent, which
//! says nothing about the proposal, so a later cycle picks it up. A terminal
//! answer that left the record open would wedge that skill out of the
//! optimization loop permanently on one tie.
//!
//! When the WORLD moves under an in-flight call instead — the reserved
//! evidence changes while the scorer is thinking, or a terminal reason read
//! before the write door no longer holds inside it — there is no ruling at all.
//! The transaction returns [`Error::SkillEditGateRetry`] and rolls back, so no
//! verdict row, no closure, no cap spend and no marker change commits: the
//! proposal is left byte-identical to a call that never ran. That is a
//! RETRYABLE outcome, typed apart from every refusal, and a rerun over a
//! settled ledger rules on it deterministically. A durable "the snapshot moved"
//! row would have been a second open class the contract does not have, and one
//! that grew a duplicate row on every raced retry.
//!
//! # The gate refines the approval flow, it does not replace it
//!
//! A passing score makes a proposal ELIGIBLE. Admission
//! ([`admit_optimized_skill_revision`]) is still an explicit act, and freezing
//! the predecessor is still [`crate::Vault::supersede_skill_record`]'s — the
//! landed chain is untouched. What ONE-1449 adds is a floor UNDER the automated
//! loop: an optimizer-born candidate cannot reach canon through a bare state
//! flip at all ([`check_optimizer_admission_in_txn`], wired at the batch
//! materialization chokepoint every SKILL body converges on). The owner's
//! ordinary update door over a HUMAN-authored record is untouched, protected
//! tier included: this is a dial on the robot, not a wall on the owner.
//!
//! # The split is a correctness convention, not a security boundary
//!
//! In-crate, a same-process reader can reach any receipt; the threat here is
//! overfitting drift, not an adversary, so no capability machinery is built for
//! it. Two honest layers are enforced instead:
//!
//! 1. **Import direction.** The optimizer's evidence loader
//!    ([`super::optimize_brief`]) calls [`dev_receipts`] and nothing else, so
//!    the author never sees a held-out outcome. Stated in both modules, and
//!    checkable by reading one function.
//! 2. **Independent recomputation.** The gate derives its held-out view from
//!    the DURABLE outcome ledger at accept time — never from a list the
//!    proposal carries. A leaky proposer therefore cannot influence WHICH
//!    receipts score it, only what it says.
//!
//! The partition itself is a per-skill hash of receipt identity with about one
//! fifth reserved, so the same `(skill, receipt)` always lands on the same side
//! however often it is asked, and the two sides are complements by
//! construction — disjoint without a second ledger to keep honest.
//!
//! # The score is a judged replay, and the judge is not the author
//!
//! A posterior recomputed over held-out receipts cannot be measured offline for
//! instructions that were never run, so the honest v1 score is a REPLAY:
//! [`HeldOutReplayScorer`] is asked to judge the same held-out evidence against
//! each instruction version in turn. The seam is the [`crate::skill_attribution::AttributionJudge`]
//! posture — a host-supplied LLM tier under [`skill_edit_score_call_purpose`],
//! injectable in tests, and structurally not the optimizer grading its own
//! homework. No epsilon: strict `>` is the anti-Goodhart floor, and a tie is a
//! rejection.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use rmpv::Value;
use sha2::{Digest, Sha256};

use super::{
    PROVENANCE_OPTIMIZE_CYCLE_KEY, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY, PROVENANCE_OPTIMIZE_OF_KEY,
    PROVENANCE_OPTIMIZE_OF_VERSION_KEY, SKILL_OPTIMIZE_BIRTH_PATH,
    SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE, invalid, proven_cycle, tier_verdict_in_txn,
};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower, parse_entity_id};
use crate::error::{Error, ErrorKind, Result};
use crate::llm::CallPurpose;
use crate::receipt::{
    FIELD_SKILL_EDIT_ACCEPTED_VERDICT, FIELD_SKILL_EDIT_CYCLE, FIELD_SKILL_EDIT_DISPOSITION,
    FIELD_SKILL_EDIT_HELD_OUT_COUNT, FIELD_SKILL_EDIT_HELD_OUT_DIGEST,
    FIELD_SKILL_EDIT_HELD_OUT_RECEIPTS, FIELD_SKILL_EDIT_HELD_OUT_TRUNCATED,
    FIELD_SKILL_EDIT_MISSING_SOURCES, FIELD_SKILL_EDIT_PROPOSAL, FIELD_SKILL_EDIT_PROPOSAL_DIGEST,
    FIELD_SKILL_EDIT_SCORE_AFTER, FIELD_SKILL_EDIT_SCORE_BEFORE, FIELD_SKILL_EDIT_SKILL,
    FIELD_SKILL_EDIT_TARGET_DIGEST, ReceiptKind, ReceiptQuery, ReceiptRecord,
    retain_newest_receipt,
};
use crate::skill::{
    SkillGovernanceTier, SkillLifecycle, SkillRecord, encode_skill_record, validate_skill_update,
};
use crate::skill_convert::{PROVENANCE_BIRTH_KEY, source_message_refs};
use crate::store::Store;
use crate::temporal::TimeRange;

// ---------------------------------------------------------------------------
// Dials + pinned strings
// ---------------------------------------------------------------------------

/// `vault_meta` key holding K, the accepted edits one Dreamer cycle may admit.
///
/// The `SKILL_OPTIMIZE_MIN_OUTCOMES_KEY` house pattern — a per-feature engine
/// dial over `vault_meta`, not a `settings.rs` UI preference.
pub const SKILL_EDIT_CYCLE_CAP_KEY: &[u8] = b"settings:skill_optimize:v1:cycle_cap";

/// K when the dial has never been set.
///
/// Two. The cap is a blast-radius bound on an automated editor, not a
/// throughput target: a wake that rewrites two skills leaves a reviewer a diff
/// they can hold in their head, and the overflow is DEFERRED rather than lost.
pub const DEFAULT_SKILL_EDIT_CYCLE_CAP: u32 = 2;

/// One receipt in this many is reserved for the gate.
///
/// Five ≈ the canon's 20%. Stated as a divisor because that is what the split
/// actually computes: bucket 0 of five is held out, buckets 1..5 are dev.
pub const HELD_OUT_RESERVE_DIVISOR: u32 = 5;

/// The [`CallPurpose`] a replay scorer's LLM tier must stamp, so gate scoring
/// is budgeted and audited as its own class rather than hiding inside the
/// drafting author's totals.
pub const SKILL_EDIT_SCORE_CALL_PURPOSE_NAME: &str = "skill_edit_score_replay";

/// Upper bound on a cycle label.
pub const SKILL_EDIT_CYCLE_MAX_BYTES: usize = 128;

/// Domain separator of the split hash. Pinned: changing it repartitions every
/// skill's evidence, which is a migration, not a refactor.
const SPLIT_DOMAIN: &[u8] = b"skill_optimize:heldout:v1\0";

/// `vault_meta` key prefix of the verdict ledger. Full key is this prefix ‖ a
/// UUIDv7 row id, so key order is WRITE order and a caller-supplied `at` stays
/// data rather than ordering (the `edit_distance::escalation` posture).
pub(super) const VERDICT_PREFIX: &[u8] = b"skill_optimize/verdict/v1\0";

/// `vault_meta` key prefix of the durable optimizer-BIRTH marker: this prefix ‖
/// the entity id, exactly the [`admission_ticket_key`] key pattern.
///
/// Written beside a LOCAL create whose record is optimizer-born, and never
/// again for the life of that id. It is what makes optimizer origin survive
/// DELETION: without it, `delete` + same-id `put` re-presented the id as a
/// virgin create, the create door saw an ordinary candidate, and the record
/// walked to `active` through the owner's door carrying an id whose gate
/// history said "accepted". The row itself is inert to every other reader.
const OPTIMIZER_ORIGIN_MARKER_PREFIX: &[u8] = b"skill_optimize/origin/v1\0";

/// Schema version of one origin-marker row. Fail-closed like the verdict row:
/// an unreadable marker refuses the create rather than admitting it.
const ORIGIN_MARKER_SCHEMA_VERSION: u64 = 1;

const ORIGIN_MARKER_LABEL: &str = "skill optimizer origin marker";

/// `vault_meta` key prefix of the same-transaction admission precheck.
///
/// NOT a capability token: the ticket is written, consumed and deleted inside
/// ONE write transaction by [`admit_optimized_skill_revision`], so it cannot
/// outlive the admission it authorizes — a rollback takes it with the body.
/// It exists because the chokepoint that must refuse a bare flip
/// ([`check_optimizer_admission_in_txn`]) sees a `Store` and a transaction, not
/// a `Vault`, and re-deriving the whole gate verdict there would be a second
/// implementation of this module's decision.
const ADMISSION_TICKET_PREFIX: &[u8] = b"skill_optimize/admission_ticket/v1\0";

/// Bumped by the MATERIAL-10 repair (v1 → v2: a v1 row carries no binding
/// digests, so a reader that accepted one would be trusting an acceptance
/// nobody can check the body of) and again by the MATERIAL-6 repair (v2 → v3: a
/// v2 row binds no PROPOSAL tier, so an owner's identity mark on the proposal
/// rode an older acceptance into canon, and v2 could still spell the retired
/// `deferred_evidence_changed` disposition).
///
/// Prerelease, and the honest answer to an unbindable row is to refuse it
/// rather than to grow a second code path for it: every v1/v2 row decodes as
/// [`Error::CorruptedIndex`]. There is no shim and no migration.
const VERDICT_SCHEMA_VERSION: u64 = 3;
const KEY_SCHEMA_VERSION: &str = "v";
const KEY_PROPOSAL: &str = "proposal";
const KEY_SKILL: &str = "skill";
const KEY_BEFORE: &str = "before";
const KEY_AFTER: &str = "after";
const KEY_DISPOSITION: &str = "disposition";
const KEY_CYCLE: &str = "cycle";
const KEY_HELD_OUT: &str = "held_out";
const KEY_HELD_OUT_COUNT: &str = "held_out_count";
const KEY_HELD_OUT_DIGEST: &str = "held_out_digest";
const KEY_HELD_OUT_TRUNCATED: &str = "held_out_truncated";
const KEY_PROPOSAL_DIGEST: &str = "proposal_digest";
const KEY_TARGET_DIGEST: &str = "target_digest";
const KEY_PROPOSAL_TIER: &str = "proposal_tier";
const KEY_ACCEPTED_VERDICT: &str = "accepted_verdict";
const KEY_MISSING_SOURCES: &str = "missing_sources";
const KEY_AT: &str = "at";

/// Domain separator of the canonical SKILL-body content digest.
const BODY_DIGEST_DOMAIN: &[u8] = b"skill_optimize:body:v1\0";

/// Domain separator of the canonical evidence-set digest.
const EVIDENCE_DIGEST_DOMAIN: &[u8] = b"skill_optimize:evidence:v1\0";

const VERDICT_ROW_LABEL: &str = "skill edit verdict row";
const SKILL_EDIT_RECEIPT_PREFIX: &str = "skill_edit:";

// ---------------------------------------------------------------------------
// The split
// ---------------------------------------------------------------------------

/// Which fifth of the split `(skill, receipt)` falls in.
///
/// Per-SKILL keying is the point: a receipt held out for one skill is ordinary
/// dev evidence for another, so one global partition would correlate every
/// skill's reserve and let a single unlucky draw starve many gates at once.
fn split_bucket(skill: &EntityId, receipt: &str) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(SPLIT_DOMAIN);
    hasher.update(skill.as_bytes());
    hasher.update([0u8]);
    hasher.update(receipt.as_bytes());
    let digest = hasher.finalize();
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % HELD_OUT_RESERVE_DIVISOR
}

/// Whether this receipt is reserved for the gate on this skill.
///
/// Pure and total: same inputs, same answer, forever and on every replica.
#[must_use]
pub fn receipt_is_held_out(skill: &EntityId, receipt: &str) -> bool {
    split_bucket(skill, receipt) == 0
}

/// The gate's view: the receipts reserved from the optimizer.
///
/// Recomputed from the durable outcome ledger on every call — never cached, and
/// never read from a proposal.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable outcome key.
pub fn held_out_receipts(vault: &Vault, skill: &EntityId) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    held_out_receipts_in_txn(vault, &rtxn, skill)
}

fn held_out_receipts_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<String>> {
    Ok(
        crate::skill_reliability::attributed_outcome_receipts(vault, rtxn, skill)?
            .into_iter()
            .filter(|receipt| receipt_is_held_out(skill, receipt))
            .collect(),
    )
}

/// The optimize job's view: everything the gate did NOT reserve.
///
/// The exact complement of [`held_out_receipts`] over the same ledger, so the
/// two are disjoint and their union is the attributed set — by construction,
/// with no second ledger that could drift out of agreement with the first.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable outcome key.
pub fn dev_receipts(vault: &Vault, skill: &EntityId) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    dev_receipts_in_txn(vault, &rtxn, skill)
}

fn dev_receipts_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    skill: &EntityId,
) -> Result<Vec<String>> {
    Ok(
        crate::skill_reliability::attributed_outcome_receipts(vault, rtxn, skill)?
            .into_iter()
            .filter(|receipt| !receipt_is_held_out(skill, receipt))
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Binding: what a verdict is a verdict ABOUT
// ---------------------------------------------------------------------------

/// Canonical digest of one SKILL record's CONTENT.
///
/// Public because a binding nobody outside this module can recompute is not an
/// audit trail: given a stored record and a verdict, a reader answers "is this
/// the body that was scored?" with this function and an `==`.
///
/// This is the identity an acceptance is bound to, so what it normalizes away
/// is the whole design:
///
/// - `approval_status` and `lifecycle_status` are the two STATE axes the
///   admission this binds is *for* — binding them would make every acceptance
///   refuse itself at the door it authorizes;
/// - `confidence` is a demoted cache the reliability projector refreshes
///   whenever an outcome lands (`skill::skill_content_changed` normalizes it
///   for the same reason), so binding it would let an unrelated attribution
///   kill a passing proposal;
/// - `governance_tier` is the third state axis, and it is bound by something
///   STRICTER than a digest: the verdict carries the tier it resolved for BOTH
///   records ([`HeldOutVerdict::proposal_tier`]), and every door re-resolves
///   them against its own snapshot and refuses a protected, ambiguous or moved
///   one outright, before this comparison is reached.
///
/// Everything else — `desc`, `version`, `skill_id`, `dependencies`,
/// `provenance` (target linkage, birth, rationale and cited receipts included),
/// `source`, the authorship flags, `forked_from`, `content_hash` — is content,
/// and moving any of it after a score means the score was about a different
/// record.
///
/// # Errors
///
/// Body errors from re-encoding the record.
pub fn skill_body_binding_digest(record: &SkillRecord) -> Result<String> {
    let mut normalized = record.clone();
    normalized.approval_status = ClaimApprovalStatus::Proposed;
    normalized.lifecycle_status = SkillLifecycle::Candidate;
    normalized.confidence = 0.0;
    normalized.governance_tier = None;
    let encoded = encode_skill_record(&normalized)?;
    let mut hasher = Sha256::new();
    hasher.update(BODY_DIGEST_DOMAIN);
    hasher.update(&encoded);
    Ok(bytes_to_hex_lower(&hasher.finalize()))
}

/// Canonical identity of an exact evidence set: how many, and which.
///
/// Length-prefixed per entry so no two different sets can collide by
/// re-splitting the same bytes, and ORDER-sensitive because the ledger order is
/// stable (mint order) and a set that arrived in a different order is a
/// different read of the ledger.
fn evidence_identity(receipts: &[String]) -> (u64, String) {
    let count = wide(receipts.len());
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_DIGEST_DOMAIN);
    hasher.update(count.to_be_bytes());
    for receipt in receipts {
        hasher.update(wide(receipt.len()).to_be_bytes());
        hasher.update(receipt.as_bytes());
    }
    (count, bytes_to_hex_lower(&hasher.finalize()))
}

/// A length as the width the digest and the row both speak.
///
/// `try_from` rather than `as`: the saturation is unreachable on every platform
/// this runs on, and writing it out keeps the cast from being the kind that
/// silently wraps somewhere else.
fn wide(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The canonical digest of a held-out evidence set, for callers auditing a
/// verdict against a set they recomputed themselves.
#[must_use]
pub fn held_out_receipt_set_digest(receipts: &[String]) -> String {
    evidence_identity(receipts).1
}

/// Everything a verdict binds itself to: the two bodies, and the evidence.
///
/// Carried as ONE value from the moment the scorer is called to the moment the
/// row commits, so the committing transaction compares what was SCORED rather
/// than re-deriving something that merely ought to match it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ScoredBasis {
    proposal_digest: String,
    target_digest: String,
    evidence_count: u64,
    evidence_digest: String,
    /// The PROPOSAL's own effective governance tier, resolved in the snapshot
    /// this basis was taken in ([`super::tier_verdict_in_txn`] over the
    /// proposal id and record).
    ///
    /// Carried explicitly rather than folded into `proposal_digest`, because
    /// the tier is a state axis the digest deliberately normalizes away: it
    /// moves through the owner's ordinary door with no version bump, and
    /// binding it as content would make every acceptance refuse itself at the
    /// door it authorizes. `None` is AMBIGUOUS — an unmarked record whose
    /// provenance cannot vouch for it — and never rides into canon.
    proposal_tier: Option<SkillGovernanceTier>,
}

impl ScoredBasis {
    /// # Errors
    ///
    /// Body errors from re-encoding either record.
    fn of(
        proposal: &SkillRecord,
        target: &SkillRecord,
        held_out: &[String],
        proposal_tier: Option<SkillGovernanceTier>,
    ) -> Result<Self> {
        let (evidence_count, evidence_digest) = evidence_identity(held_out);
        Ok(Self {
            proposal_digest: skill_body_binding_digest(proposal)?,
            target_digest: skill_body_binding_digest(target)?,
            evidence_count,
            evidence_digest,
            proposal_tier,
        })
    }

    /// Whether a stored verdict rules on exactly this pair, this evidence and
    /// this proposal tier.
    fn matches(&self, verdict: &HeldOutVerdict) -> bool {
        verdict.proposal_digest == self.proposal_digest
            && verdict.target_digest == self.target_digest
            && verdict.held_out_count == self.evidence_count
            && verdict.held_out_digest == self.evidence_digest
            && verdict.proposal_tier == self.proposal_tier
    }
}

// ---------------------------------------------------------------------------
// The scorer seam
// ---------------------------------------------------------------------------

/// One instruction version, put to the replay judge against reserved evidence.
///
/// The gate builds two of these per verdict — current and proposed — over the
/// SAME held-out list, so the pair the comparison rests on differs in exactly
/// one thing: the instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct HeldOutReplayCase<'a> {
    /// The ACTIVE skill entity the evidence was attributed to.
    pub skill: EntityId,
    pub skill_id: &'a str,
    /// The version label of the instructions under test.
    pub version: &'a str,
    /// The instructions themselves — the only field that moves between the two
    /// cases of one verdict.
    pub instructions: &'a str,
    /// The reserved receipts to replay against, gate-recomputed.
    pub held_out_receipts: &'a [String],
}

/// Judges one instruction version against held-out evidence.
///
/// The production tier is a host-supplied implementation over the engine's LLM
/// surface under [`skill_edit_score_call_purpose`]; this module constructs no
/// client (the [`crate::skill_attribution::AttributionJudge`] /
/// [`super::SkillOptimizeAuthor`] posture). There is deliberately no in-engine
/// default: any scalar this crate could compute without a replay would be the
/// optimizer grading its own edit, which is the one thing the gate exists to
/// prevent — so the seam is a required argument rather than a defaulted one.
pub trait HeldOutReplayScorer {
    /// Scores `case` on `0.0..=1.0`, higher is better.
    ///
    /// # Errors
    ///
    /// Implementation-defined. A scorer that cannot judge must error rather
    /// than guess: an invented scalar is a silent accept.
    fn score(&self, case: &HeldOutReplayCase<'_>) -> Result<f32>;
}

/// The [`CallPurpose`] a replay scorer's LLM tier must stamp.
#[must_use]
pub fn skill_edit_score_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: SKILL_EDIT_SCORE_CALL_PURPOSE_NAME.to_owned(),
    }
}

/// The host's replay judge, registered once per process.
///
/// The `ingest::image::RECOGNIZER` posture: a once-set injection door rather
/// than a scorer threaded through every call site, because the two-argument
/// [`score_gate_skill_edit`] is the entry point a Dreamer runner actually has —
/// it holds a proposal id and a vault, not a policy object.
///
/// Unset is FAIL-CLOSED and stays that way. There is deliberately no in-engine
/// default (see [`HeldOutReplayScorer`]): a vault with no registered judge
/// cannot gate an edit, which is the correct answer, not an outage to paper
/// over with a computed scalar.
pub static HELD_OUT_REPLAY_SCORER: OnceLock<&'static (dyn HeldOutReplayScorer + Send + Sync)> =
    OnceLock::new();

/// Registers the host's replay judge.
///
/// `Send + Sync` is required of the REGISTERED judge only, not of the trait: a
/// test double handed straight to [`score_gate_skill_edit_with_scorer`] is
/// borrowed for one call on one thread and needs neither.
///
/// # Errors
///
/// The `&'static str` reason when a judge is already registered. Once-set, so
/// a second registration cannot silently retire the judge earlier verdicts were
/// ruled by.
pub fn register_held_out_replay_scorer(
    scorer: &'static (dyn HeldOutReplayScorer + Send + Sync),
) -> std::result::Result<(), &'static str> {
    HELD_OUT_REPLAY_SCORER
        .set(scorer)
        .map_err(|_| "a held-out replay scorer is already registered")
}

fn host_replay_scorer() -> Result<&'static (dyn HeldOutReplayScorer + Send + Sync)> {
    HELD_OUT_REPLAY_SCORER.get().copied().ok_or(invalid(
        "no held-out replay scorer is registered; the gate has no in-engine default",
    ))
}

/// Refuses a scalar the strict comparison could not mean anything over.
///
/// NaN is the case that matters: `NaN > x` is false, so an unvalidated NaN
/// would read as a quiet rejection rather than the broken scorer it is.
fn validate_score(score: f32) -> Result<f32> {
    if !score.is_finite() || !(0.0..=1.0).contains(&score) {
        return Err(invalid(
            "a held-out replay score must be a finite value in 0.0..=1.0",
        ));
    }
    Ok(score)
}

// ---------------------------------------------------------------------------
// The cycle
// ---------------------------------------------------------------------------

/// The Dreamer cycle a verdict is counted against.
///
/// A LABEL, not a stored object: the cap is derived by counting accepted
/// verdicts that carry this label, so there is no cycle ledger to open, close
/// or leak. But a label nobody can PROVE is not a cap either, so this type is
/// no longer constructible from an arbitrary string. Every value comes from one
/// of exactly two roads, both of which trace to durable scheduler state:
///
/// - [`super::proven_cycle`] derives it from an [`AttemptId`] whose queue row
///   is read at the moment of use — the one resolver, shared by the drafting
///   door and the gate, so `run:<id>` and `attempt:<hex>` have one spelling;
/// - [`SkillEditCycle::of_proposal`] reads the label a proposal was STAMPED
///   with at birth, which that same resolver produced.
///
/// A free-form label with no durable record behind it is therefore
/// unrepresentable rather than rejected at runtime: K bounds one real wake.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SkillEditCycle(String);

impl SkillEditCycle {
    /// The label, from the ONE resolver that is allowed to mint one.
    ///
    /// Deliberately not public: see the type's own note. `pub(super)` reaches
    /// exactly [`super::proven_cycle`], which reads the durable attempt row
    /// this label names.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSkillBody`] on an empty or oversized label.
    pub(super) fn new(label: impl Into<String>) -> Result<Self> {
        let label = label.into();
        if label.trim().is_empty() || label.len() > SKILL_EDIT_CYCLE_MAX_BYTES {
            return Err(invalid(
                "a skill edit cycle label must be a non-empty string at most 128 bytes",
            ));
        }
        Ok(Self(label))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The cycle a proposal was drafted in, READ from the proposal.
    ///
    /// The Dreamer RUN, not the attempt, whenever the drafting attempt named
    /// one: a wake that drafts several proposals must count them against one
    /// cap, and per-attempt labelling would hand every proposal a private cap
    /// of its own — a cap that never binds.
    ///
    /// The label is resolved ONCE, at draft time, and persisted on the record
    /// (`skill_optimize::drafting_cycle`). This function only reads it back.
    /// Recovering it here instead — from the drafting attempt's queue row —
    /// was the ONE-1449 defect: those rows are prunable, so two proposals from
    /// one real wake silently became two private budgets as soon as the queue
    /// was trimmed, and a decode or storage error read as "no run" rather than
    /// as the failure it was.
    ///
    /// A record that carries no cycle is refused here, and — since the
    /// MATERIAL-6 repair — at every gate door as well
    /// ([`require_open_optimizer_proposal`]): an unstamped proposal has no
    /// provable birth cycle, and no caller-named label rescues it. Prerelease,
    /// so no legacy unstamped corpus is accommodated.
    ///
    /// # Errors
    ///
    /// Storage errors; [`Error::EntityNotFound`] when `proposal` is not stored;
    /// [`Error::InvalidSkillBody`] when it carries no drafting cycle.
    pub fn of_proposal(vault: &Vault, proposal: &EntityId) -> Result<Self> {
        let record = vault
            .get_skill_record(proposal)?
            .ok_or(Error::EntityNotFound)?;
        Self::of_record(&record)
    }

    fn of_record(record: &SkillRecord) -> Result<Self> {
        let label = provenance_str(record, PROVENANCE_OPTIMIZE_CYCLE_KEY).ok_or(invalid(
            "this proposal carries no drafting cycle; name the cycle explicitly",
        ))?;
        Self::new(label)
    }
}

/// Reads K (default [`DEFAULT_SKILL_EDIT_CYCLE_CAP`]).
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn skill_edit_cycle_cap(vault: &Vault) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    cycle_cap_in_txn(vault, &rtxn)
}

fn cycle_cap_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<u32> {
    let Some(raw) = vault.store.vault_meta.get(rtxn, SKILL_EDIT_CYCLE_CAP_KEY)? else {
        return Ok(DEFAULT_SKILL_EDIT_CYCLE_CAP);
    };
    let bytes: [u8; 4] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("skill edit cycle cap"))?;
    Ok(u32::from_be_bytes(bytes))
}

/// Sets K.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] when `cap` is zero: a cap of nothing is a
/// disabled loop expressed as a dial, and the honest way to stop the loop is to
/// stop scheduling it.
pub fn set_skill_edit_cycle_cap(vault: &Vault, cap: u32) -> Result<()> {
    if cap == 0 {
        return Err(invalid(
            "skill edit cycle cap must be > 0: a zero cap disables the loop by accident",
        ));
    }
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, SKILL_EDIT_CYCLE_CAP_KEY, &cap.to_be_bytes())?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// What the gate ruled, and why.
///
/// Every arm is durable and queryable — an automated editor whose rejections
/// are invisible is an editor nobody can audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SkillEditDisposition {
    /// Strict improvement, unprotected tier, within cap.
    Accepted,
    /// `after <= before`. Ties live here: there is no epsilon.
    Rejected,
    /// Improving, but this cycle already spent its accepts. The proposal stays
    /// OPEN — a later cycle may admit it. The ONLY durable open disposition.
    DeferredCycleCap,
    /// Identity- or alignment-tier at accept time, on the TARGET or on the
    /// PROPOSAL itself — protected, ambiguous, or moved since the basis was
    /// taken. One arm carries every tier answer, and as a refusal it closes the
    /// proposal atomically.
    RefusedProtectedTier,
    /// The target moved (superseded, re-versioned, no longer active) between
    /// drafting and the verdict.
    RefusedStaleTarget,
    /// A cited `source_messages` id no longer resolves in the active store.
    RefusedSourceLoss,
    /// A `source_messages` linkage is present but not an array of entity ids.
    RefusedSourceMalformed,
    /// The skill has no reserved evidence, so there is nothing to score on.
    RefusedNoHeldOutEvidence,
    /// At admission, the candidate body, the predecessor body or the reserved
    /// evidence was no longer the one the standing acceptance was ruled over.
    ///
    /// The binding arm: an acceptance is about a specific pair of bodies judged
    /// over a specific set of receipts, and admitting anything else would
    /// activate content the gate never scored.
    RefusedBindingMismatch,
}

impl SkillEditDisposition {
    /// The pinned on-disk / on-receipt string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::DeferredCycleCap => "deferred_cycle_cap",
            Self::RefusedProtectedTier => "refused_protected_tier",
            Self::RefusedStaleTarget => "refused_stale_target",
            Self::RefusedSourceLoss => "refused_source_loss",
            Self::RefusedSourceMalformed => "refused_source_malformed",
            Self::RefusedNoHeldOutEvidence => "refused_no_held_out_evidence",
            Self::RefusedBindingMismatch => "refused_binding_mismatch",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "accepted" => Some(Self::Accepted),
            "rejected" => Some(Self::Rejected),
            "deferred_cycle_cap" => Some(Self::DeferredCycleCap),
            // "deferred_evidence_changed" is deliberately ABSENT: the evidence
            // race is a retryable abort that commits nothing, so a row
            // spelling it is a row from a build whose contract no longer
            // holds. It decodes as `CorruptedIndex`, like every other v1/v2
            // row — prerelease, no shim.
            "refused_protected_tier" => Some(Self::RefusedProtectedTier),
            "refused_stale_target" => Some(Self::RefusedStaleTarget),
            "refused_source_loss" => Some(Self::RefusedSourceLoss),
            "refused_source_malformed" => Some(Self::RefusedSourceMalformed),
            "refused_no_held_out_evidence" => Some(Self::RefusedNoHeldOutEvidence),
            "refused_binding_mismatch" => Some(Self::RefusedBindingMismatch),
            _ => None,
        }
    }

    /// Whether this verdict makes the proposal eligible for admission.
    #[must_use]
    pub const fn admits(self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// Whether the proposal remains an open question a later cycle may answer.
    ///
    /// Exactly ONE ruling leaves it open, and it is the cap deferral: a ruling
    /// that says nothing about the proposal except that this wake's budget was
    /// already spent. A rejection and a refusal are both ANSWERS — the evidence
    /// said no — and re-asking them next wake would be the nagging ONE-1448's
    /// open-question rule already refuses.
    ///
    /// A raced snapshot is NOT on this list, because it is not a ruling at all:
    /// it commits nothing and returns [`Error::SkillEditGateRetry`], leaving
    /// the proposal in its pre-call state. A second durable open class would
    /// have grown one more row on every raced retry and made "open" mean two
    /// different things.
    ///
    /// The complement is [`Self::closes_proposal`], and every answer that is
    /// not this deferral closes: a terminal ruling that left the record
    /// `candidate + proposed` would wedge the skill forever, because the
    /// drafting job skips a skill with an open proposed revision.
    #[must_use]
    pub const fn leaves_proposal_open(self) -> bool {
        matches!(self, Self::DeferredCycleCap)
    }

    /// Whether this ruling ANSWERS the proposal, and so must close it.
    ///
    /// An acceptance is not an answer of this kind: it arms the admission door,
    /// and the proposal stays open until that door (or a later refusal at it)
    /// moves the record.
    #[must_use]
    pub const fn closes_proposal(self) -> bool {
        !self.leaves_proposal_open() && !self.admits()
    }

    /// Whether the caller is told by an `Err` as well as by the ledger.
    ///
    /// Reject and defer are ordinary answers a loop keeps running after, so
    /// they return `Ok`. A refusal says the proposal should never have reached
    /// the gate in this shape, so it is also a typed error.
    const fn is_refusal(self) -> bool {
        matches!(
            self,
            Self::RefusedProtectedTier
                | Self::RefusedStaleTarget
                | Self::RefusedSourceLoss
                | Self::RefusedSourceMalformed
                | Self::RefusedNoHeldOutEvidence
                | Self::RefusedBindingMismatch
        )
    }

    const fn refusal_error(self) -> Error {
        match self {
            Self::RefusedBindingMismatch => invalid(
                "the candidate, its target or the reserved evidence moved after the accepted verdict",
            ),
            Self::RefusedProtectedTier => invalid(
                "identity/alignment-tier skills are never admitted by the automated edit loop",
            ),
            Self::RefusedStaleTarget => {
                invalid("optimization target moved before the gate could rule")
            }
            Self::RefusedSourceLoss => {
                invalid("a cited source message no longer resolves; the candidate is ungrounded")
            }
            Self::RefusedSourceMalformed => {
                invalid("source_messages must be an array of 32-char entity id hex strings")
            }
            Self::RefusedNoHeldOutEvidence => invalid(
                "no held-out evidence is reserved for this skill; there is nothing to score",
            ),
            _ => invalid("skill edit gate refusal"),
        }
    }
}

/// One durable gate ruling.
///
/// The three blueprint fields (`before`, `after`, `accepted`) are the headline;
/// the rest is what makes the ruling auditable without a second lookup — which
/// proposal, against which skill, on which reserved evidence, in which cycle.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct HeldOutVerdict {
    /// Score of the CURRENT instructions over the reserved evidence.
    pub before: f32,
    /// Score of the PROPOSED instructions over the same reserved evidence.
    pub after: f32,
    /// `after > before`, and nothing refused or deferred it.
    pub accepted: bool,
    /// Ledger row id; the receipt's id is derived from it.
    pub id: EntityId,
    /// The gated proposal this ruling is about.
    pub proposal: EntityId,
    /// The ACTIVE skill the proposal revises.
    pub skill: EntityId,
    pub disposition: SkillEditDisposition,
    pub cycle: String,
    /// The reserved receipts the scores were computed over — a bounded DISPLAY
    /// list, newest [`SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE`] first-dropped-last.
    ///
    /// [`Self::held_out_truncated`] says when it is a window rather than the
    /// whole basis; [`Self::held_out_count`] and [`Self::held_out_digest`] are
    /// the basis itself and are what every comparison in this module actually
    /// uses. A row that showed 64 of 300 receipts with no count and no digest
    /// was claiming an evidence basis it did not have.
    pub held_out_receipts: Vec<String>,
    /// How many reserved receipts the scores were ACTUALLY computed over.
    pub held_out_count: u64,
    /// Canonical digest of the exact scored evidence set, in scored order
    /// ([`held_out_receipt_set_digest`]).
    pub held_out_digest: String,
    /// Whether [`Self::held_out_receipts`] is a bounded window on the basis.
    pub held_out_truncated: bool,
    /// Canonical content digest of the candidate body that was scored.
    pub proposal_digest: String,
    /// Canonical content digest of the predecessor body it was scored against.
    pub target_digest: String,
    /// The PROPOSAL's effective governance tier at the moment this ruling was
    /// based ([`ScoredBasis::proposal_tier`]).
    ///
    /// `None` on a pre-score refusal, which has no basis at all, and on a
    /// ruling whose proposal resolved AMBIGUOUS — neither can be admitted.
    /// The admission door re-resolves the tier in its own snapshot and refuses
    /// when it is protected, ambiguous, or simply no longer this one: an
    /// owner's identity mark landed on the PROPOSAL after acceptance is the
    /// newer fact, and it must not ride the old acceptance into canon.
    pub proposal_tier: Option<SkillGovernanceTier>,
    /// The accepted verdict this row answers, on a post-score refusal.
    ///
    /// `None` on every ruling the gate itself made. `Some` exactly when
    /// admission was reached THROUGH a standing acceptance and then refused, so
    /// a reader can follow the refusal back to the scores it supersedes rather
    /// than reading a zero pair as an unscored tie.
    pub accepted_verdict: Option<EntityId>,
    /// Cited source ids that failed to resolve, on a source refusal.
    pub missing_sources: Vec<EntityId>,
    pub at: u64,
}

impl HeldOutVerdict {
    /// The improvement the pair records. Negative on a regression.
    #[must_use]
    pub fn improvement(&self) -> f32 {
        self.after - self.before
    }

    /// This ruling, restated as a post-score refusal at the admission door.
    ///
    /// A NEW row (its own id, its own timestamp, its own disposition) that
    /// keeps everything the acceptance established: the real score pair, the
    /// evidence basis, both body digests, the pair of entities and the cycle.
    /// Only the answer changes, and the row names the acceptance it answers.
    fn refused_at_admission(&self, disposition: SkillEditDisposition, at: u64) -> Self {
        Self {
            id: EntityId::now(),
            disposition,
            accepted: disposition.admits(),
            accepted_verdict: Some(self.id),
            missing_sources: Vec::new(),
            at,
            ..self.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// Rules on one optimizer-born proposal. THE entry point.
///
/// Two arguments, because that is what a caller holding a drafted proposal
/// actually has. Everything else is resolved from the record and the vault: the
/// judge is the host's registered one ([`register_held_out_replay_scorer`]),
/// the cycle is the one the proposal was DRAFTED into
/// ([`SkillEditCycle::of_proposal`]), and the clock is the wall clock.
///
/// The two explicit variants exist for the two callers that genuinely know
/// better: [`score_gate_skill_edit_with_scorer`] injects a judge (tests, and a
/// host running more than one), and [`score_gate_skill_edit_in_cycle`] names
/// the wake by its ATTEMPT (a runner batching several proposals under one cap,
/// and any runner picking a cap-deferred proposal up in a later cycle).
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] when no judge is registered or the proposal
/// names no drafting cycle; then everything
/// [`score_gate_skill_edit_in_cycle`] errors on.
pub fn score_gate_skill_edit(vault: &Vault, proposal: &EntityId) -> Result<HeldOutVerdict> {
    score_gate_skill_edit_with_scorer(vault, proposal, host_replay_scorer()?)
}

/// [`score_gate_skill_edit`] with the judge supplied by the caller.
///
/// The scorer is a required argument here, not a defaulted one: see
/// [`HeldOutReplayScorer`]. The cycle is still resolved by
/// [`SkillEditCycle::of_proposal`].
///
/// # Errors
///
/// Everything [`score_gate_skill_edit_in_cycle`] errors on, plus
/// [`Error::InvalidSkillBody`] when the proposal names no drafting cycle.
pub fn score_gate_skill_edit_with_scorer(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayScorer,
) -> Result<HeldOutVerdict> {
    let cycle = SkillEditCycle::of_proposal(vault, proposal)?;
    rule_on_proposal(vault, proposal, scorer, &cycle, crate::unix_seconds_now())
}

/// [`score_gate_skill_edit`] under the cycle a Dreamer ATTEMPT proves.
///
/// The wake is named by its scheduler identity, not by a string: the label is
/// derived from `attempt`'s durable queue row through the one resolver the
/// drafting door also uses ([`super::proven_cycle`]). A caller that cannot show
/// a real attempt cannot name a cycle at all, which is what makes K a bound on
/// one REAL wake rather than on whoever spells a fresh label. Presenting an
/// attempt whose cycle differs from the proposal's birth stamp is the lawful
/// later-cycle pickup: the row records the cycle actually used, and the cap
/// counts it there.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] when `attempt` names no stored queue row; then
/// everything the gate itself errors on (see the entry point's list).
pub fn score_gate_skill_edit_in_cycle(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayScorer,
    attempt: AttemptId,
    at: u64,
) -> Result<HeldOutVerdict> {
    let cycle = proven_cycle(vault, attempt)?;
    rule_on_proposal(vault, proposal, scorer, &cycle, at)
}

/// The gate itself, over a cycle that is already proven.
///
/// The order of the steps IS the contract:
/// 1. read the proposal and the ACTIVE predecessor it names, lock-free, and
///    form the terminal reason (if any) that read implies;
/// 2. open ONE write transaction and re-read all of it there. A terminal reason
///    that still holds is written AS a verdict row and CLOSES the proposal in
///    that same transaction; a reason that no longer holds — or one that only
///    appeared at the write door — commits nothing and returns the retryable
///    outcome, because a refusal the world has already outrun is a false
///    terminal answer, and those must be unrepresentable;
/// 3. take the BASIS in that same snapshot (both body digests, the evidence
///    count and digest, and the PROPOSAL's resolved tier) and answer a repeat
///    delivery from the ledger: a standing ruling over exactly this basis — an
///    acceptance, or a cap deferral from this same cycle — is returned as it
///    stands, unscored and unrecounted, so a retried delivery pays no second
///    replay, spends no second slot and appends no duplicate row;
/// 4. score both instruction versions over that one set, outside any
///    transaction: the LLM tier never runs inside the storage write door;
/// 5. re-read everything inside the VERDICT transaction and decide there — the
///    held-out set is RECOMPUTED and compared with the scored basis, both tiers
///    are rechecked, the cap is counted and the row commits, all in one
///    snapshot. An owner's identity mark landing mid-flight cannot be missed,
///    an outcome arriving mid-flight cannot be scored around, and two
///    concurrent gates cannot both see the last accept slot free;
/// 6. a terminal answer CLOSES the proposal in that same transaction, so a
///    denial cannot wedge the skill it was denying.
///
/// Scoring deliberately precedes the tier refusal rather than short-circuiting
/// on it: "refused even though it improved" is the exact sentence a protected
/// tier's receipt has to be able to say, and it cannot say it without the pair.
/// The cost is one replay on a path ONE-1448 structurally never produces —
/// protected skills are absent from its candidate list, so only a hand-crafted
/// proposal arrives here.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the proposal is gone; whatever the scorer
/// returns; [`Error::InvalidSkillBody`] for a proposal that is not an open,
/// cycle-stamped optimizer-born candidate, an unusable score, and every refusal
/// arm of [`SkillEditDisposition`]; [`Error::SkillEditGateRetry`] when the
/// snapshot moved under the call. Rejections and cap deferrals are `Ok`.
fn rule_on_proposal(
    vault: &Vault,
    proposal: &EntityId,
    scorer: &dyn HeldOutReplayScorer,
    cycle: &SkillEditCycle,
    at: u64,
) -> Result<HeldOutVerdict> {
    // The lock-free pre-read. Sequential, never nested: LMDB allows one read
    // transaction per thread, so a snapshot opened around a call that opens its
    // own is a `BadRslot`, not a consistency win. Nothing here decides
    // anything — every conclusion is re-taken at the write door below.
    let proposal_record = vault
        .get_skill_record(proposal)?
        .ok_or(Error::EntityNotFound)?;
    require_open_optimizer_proposal(&proposal_record)?;
    let target = target_of(&proposal_record)?;
    let target_record = readable_target(vault.get_skill_record(&target))?;
    let held_out = match target_record {
        Some(_) => held_out_receipts(vault, &target)?,
        None => Vec::new(),
    };
    let presented = terminal_reason(&proposal_record, target_record.as_ref(), &held_out);
    race_hook();

    let prepared = vault.with_write_txn(|wtxn| {
        let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
        require_open_optimizer_proposal(&staged)?;
        let target = target_of(&staged)?;
        let current = readable_target(vault.read_skill_record_in_txn(&*wtxn, &target).map(Some))?;
        let held_out = match current {
            Some(_) => held_out_receipts_in_txn(vault, &*wtxn, &target)?,
            None => Vec::new(),
        };
        // The reason is re-verified in the transaction that would WRITE it.
        // Ruling only when both reads agree is what makes a false terminal
        // refusal — one the world had already outrun — impossible to commit.
        match (presented, terminal_reason(&staged, current.as_ref(), &held_out)) {
            (Some(presented), Some(committed)) if presented == committed => {
                let verdict = refusal(proposal, &target, cycle, committed, at);
                record_verdict_in_txn(vault, wtxn, &verdict)?;
                if committed.closes_proposal() {
                    close_answered_proposal_in_txn(vault, wtxn, proposal, at)?;
                }
                Ok(Prepared::Ruled(Box::new(verdict)))
            }
            (None, None) => {
                let current = current.ok_or(Error::InvariantViolation(
                    "a non-terminal pre-score snapshot has a readable target",
                ))?;
                let basis = ScoredBasis::of(
                    &staged,
                    &current,
                    &held_out,
                    tier_verdict_in_txn(vault, &*wtxn, proposal, &staged)?.tier(),
                )?;
                // Idempotence, before the LLM tier rather than after it. A gate
                // call is a DELIVERY, and deliveries are retried; asking the
                // judge the same question twice would not only pay twice, it
                // would answer differently, because the first ruling has by
                // then moved the cap the second call is measured against.
                let standing =
                    standing_ruling_in_txn(vault, &*wtxn, proposal, &basis, cycle)?;
                if let Some(standing) = standing {
                    return Ok(Prepared::Ruled(Box::new(standing)));
                }
                Ok(Prepared::Score(Box::new(ScoreInputs {
                    proposal: staged,
                    target,
                    target_record: current,
                    held_out,
                    basis,
                })))
            }
            _ => Err(retry(
                "the reason the gate was about to rule on no longer holds in the committing snapshot",
            )),
        }
    })?;
    let inputs = match prepared {
        Prepared::Ruled(verdict) => return answer(*verdict),
        Prepared::Score(inputs) => *inputs,
    };

    let before = validate_score(scorer.score(&HeldOutReplayCase {
        skill: inputs.target,
        skill_id: &inputs.target_record.skill_id,
        version: &inputs.target_record.version,
        instructions: &inputs.target_record.desc,
        held_out_receipts: &inputs.held_out,
    })?)?;
    let after = validate_score(scorer.score(&HeldOutReplayCase {
        skill: inputs.target,
        skill_id: &inputs.target_record.skill_id,
        version: &inputs.proposal.version,
        instructions: &inputs.proposal.desc,
        held_out_receipts: &inputs.held_out,
    })?)?;

    // The scored set has done its work; what the row keeps of it is the bounded
    // display list, and the basis keeps the rest.
    let truncated = inputs.held_out.len() > SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE;
    let display = bounded_receipts(inputs.held_out);
    let basis = inputs.basis;
    let target = inputs.target;

    let verdict = vault.with_write_txn(|wtxn| {
        // Re-read at the write door, exactly as ONE-1448's draft path does: the
        // scorer ran outside this transaction, so the target may have been
        // superseded and either tier may have been re-marked while it thought.
        let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
        let current = readable_target(vault.read_skill_record_in_txn(&*wtxn, &target).map(Some))?;
        // The concurrent duplicate: two deliveries that both got past the read
        // above serialize HERE, and the second one finds the first's row.
        if let Some(standing) = standing_ruling_in_txn(vault, &*wtxn, proposal, &basis, cycle)? {
            return Ok(standing);
        }
        let mut verdict = HeldOutVerdict {
            before,
            after,
            accepted: false,
            id: EntityId::now(),
            proposal: *proposal,
            skill: target,
            disposition: SkillEditDisposition::Rejected,
            cycle: cycle.as_str().to_owned(),
            held_out_receipts: display,
            held_out_count: basis.evidence_count,
            held_out_digest: basis.evidence_digest.clone(),
            held_out_truncated: truncated,
            proposal_digest: basis.proposal_digest.clone(),
            target_digest: basis.target_digest.clone(),
            proposal_tier: basis.proposal_tier,
            accepted_verdict: None,
            missing_sources: Vec::new(),
            at,
        };
        verdict.disposition = decide_in_txn(
            vault,
            wtxn,
            proposal,
            &staged,
            current.as_ref(),
            cycle,
            &basis,
            before,
            after,
        )?;
        verdict.accepted = verdict.disposition.admits();
        record_verdict_in_txn(vault, wtxn, &verdict)?;
        if verdict.disposition.closes_proposal() {
            close_answered_proposal_in_txn(vault, wtxn, proposal, at)?;
        }
        Ok(verdict)
    })?;
    answer(verdict)
}

/// What the pre-score transaction settled: a ruling already written (or already
/// standing), or the snapshot the scorer is about to be shown.
enum Prepared {
    Ruled(Box<HeldOutVerdict>),
    Score(Box<ScoreInputs>),
}

/// The snapshot a verdict is scored over, taken inside the pre-score
/// transaction and carried unchanged to the committing one.
struct ScoreInputs {
    proposal: SkillRecord,
    target: EntityId,
    target_record: SkillRecord,
    held_out: Vec<String>,
    basis: ScoredBasis,
}

/// The one place a durable ruling becomes the caller's answer.
///
/// A refusal is reported by `Err` as well as by the ledger; everything else is
/// an ordinary answer a loop keeps running after.
fn answer(verdict: HeldOutVerdict) -> Result<HeldOutVerdict> {
    if verdict.disposition.is_refusal() {
        return Err(verdict.disposition.refusal_error());
    }
    Ok(verdict)
}

/// The terminal pre-score rule, in ONE spelling.
///
/// Both the lock-free pre-read and the transaction that would write the row
/// call this with values they gathered their own way, so "is this terminal"
/// cannot be answered two different ways by two different snapshots.
///
/// `target` is `None` for every unreadable predecessor — missing, purged, an
/// entity of another kind, an undecodable shell. All of them are the SAME fact
/// about the proposal: the revision it was drafted against is not there to be
/// superseded.
fn terminal_reason(
    proposal: &SkillRecord,
    target: Option<&SkillRecord>,
    held_out: &[String],
) -> Option<SkillEditDisposition> {
    let Some(target) = target else {
        return Some(SkillEditDisposition::RefusedStaleTarget);
    };
    if !target_is_current(proposal, target) {
        return Some(SkillEditDisposition::RefusedStaleTarget);
    }
    if held_out.is_empty() {
        return Some(SkillEditDisposition::RefusedNoHeldOutEvidence);
    }
    None
}

/// A target read, classified: absent-or-unreadable is a FACT about the target,
/// and a storage fault is not.
///
/// `EntityNotFound` and `InvalidSkillBody` (a non-SKILL row at that id, an
/// undecodable body) both mean "there is no predecessor here to score against",
/// which is a verdict the gate can write. Everything else — storage errors,
/// index corruption — propagates untouched: those are not answers about a
/// proposal.
fn readable_target(read: Result<Option<SkillRecord>>) -> Result<Option<SkillRecord>> {
    match read {
        Ok(record) => Ok(record),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::EntityNotFound | ErrorKind::InvalidSkillBody
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

/// The typed, retryable "nothing was learned, and nothing was written".
const fn retry(reason: &'static str) -> Error {
    Error::SkillEditGateRetry(reason)
}

/// Test-only rendezvous between the lock-free pre-read and the transaction that
/// re-verifies it.
///
/// The window it opens is REAL — the pre-read holds no lock, so an outcome can
/// land in it — but a test cannot stand in a window it has no hook into, and a
/// sleeping thread is not a regression. Thread-local, so one test's hook cannot
/// reach another's vault, and compiled out entirely otherwise.
#[cfg(test)]
type PreScoreRaceHook = std::cell::RefCell<Option<Box<dyn Fn()>>>;

#[cfg(test)]
thread_local! {
    static PRE_SCORE_RACE_HOOK: PreScoreRaceHook = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_pre_score_race_hook(hook: Box<dyn Fn()>) {
    PRE_SCORE_RACE_HOOK.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(test)]
pub(super) fn clear_pre_score_race_hook() {
    PRE_SCORE_RACE_HOOK.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn race_hook() {
    let hook = PRE_SCORE_RACE_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(not(test))]
const fn race_hook() {}

/// The decision itself, over the committing snapshot.
#[expect(
    clippy::too_many_arguments,
    reason = "the decision names every input it rests on, and hiding them in a struct would only move the list"
)]
fn decide_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    proposal: &EntityId,
    staged: &SkillRecord,
    current: Option<&SkillRecord>,
    cycle: &SkillEditCycle,
    basis: &ScoredBasis,
    before: f32,
    after: f32,
) -> Result<SkillEditDisposition> {
    require_open_optimizer_proposal(staged)?;
    // The predecessor was readable when the basis was taken; if it is not
    // readable now it was purged or overwritten mid-flight, which is the same
    // stale-target answer — carried, this time, with the real score pair.
    let Some(current) = current else {
        return Ok(SkillEditDisposition::RefusedStaleTarget);
    };
    if !target_is_current(staged, current) {
        return Ok(SkillEditDisposition::RefusedStaleTarget);
    }
    // The two bodies, as they stand in the snapshot this row commits into,
    // against the two that were scored. A version bump would already have been
    // caught, but a body can move in ways a version does not have to name, and
    // the question here is not "did the version change" — it is "is this the
    // record the judge was shown".
    if skill_body_binding_digest(staged)? != basis.proposal_digest
        || skill_body_binding_digest(current)? != basis.target_digest
    {
        return Ok(SkillEditDisposition::RefusedStaleTarget);
    }
    // The evidence, RECOMPUTED here rather than trusted from the read that fed
    // the scorer. An outcome attributed while the judge was thinking reserves
    // new held-out evidence, and accepting on a stale reserve would be exactly
    // the accept-time recomputation rule stated and then not kept.
    let committed = held_out_receipts_in_txn(vault, wtxn, &target_of(staged)?)?;
    let (count, digest) = evidence_identity(&committed);
    if count != basis.evidence_count || digest != basis.evidence_digest {
        // Not a ruling: the scores in hand are about a set this transaction can
        // no longer see, and nothing was learned about the proposal. Returning
        // `Err` from the closure ROLLS THE TRANSACTION BACK, so no row, no
        // closure and no cap spend commits, and the proposal is left exactly as
        // a call that never ran would have left it.
        return Err(retry(
            "the reserved evidence moved while the scorer was thinking",
        ));
    }
    // Strict improvement, and evaluated BEFORE the tier and cap arms so a
    // regression is reported as the regression it is rather than as whatever
    // else was also wrong. No epsilon (blueprint note: the anti-Goodhart
    // floor), and a TIE lives on this branch. Written as `<=` rather than a
    // negated `>` because both scalars are already validated finite, so the
    // two are equivalent and this one reads as the rule it is.
    if after <= before {
        return Ok(SkillEditDisposition::Rejected);
    }
    // Accept-time recheck. ONE-1448 already excluded protected tiers at
    // SELECTION; this is the second door, and the one that binds a proposal
    // nobody's selector drafted.
    let target_tier = tier_verdict_in_txn(vault, wtxn, &target_of(staged)?, current)?.tier();
    match target_tier {
        Some(tier) if tier.is_protected() => {
            return Ok(SkillEditDisposition::RefusedProtectedTier);
        }
        // An ambiguous tier is not optimizable either: the fail-closed rule is
        // the same one the candidate list applies.
        None => return Ok(SkillEditDisposition::RefusedProtectedTier),
        Some(_) => {}
    }
    // And the PROPOSAL's own tier, resolved independently in this same
    // snapshot. The body digest normalizes the tier away by design (it is a
    // state axis), so without this arm an owner's `identity` mark on the
    // candidate itself changed nothing the gate could see: the proposal would
    // be accepted and then activated as a protected record the loop was never
    // allowed to author. Protected, ambiguous, or simply not the tier the basis
    // was taken over are all the same answer.
    let proposal_tier = tier_verdict_in_txn(vault, wtxn, proposal, staged)?.tier();
    let bound = proposal_tier.is_some_and(|tier| !tier.is_protected())
        && proposal_tier == basis.proposal_tier
        && proposal_tier == target_tier;
    if !bound {
        return Ok(SkillEditDisposition::RefusedProtectedTier);
    }
    let cap = cycle_cap_in_txn(vault, wtxn)?;
    if accepted_in_cycle_in_txn(vault, wtxn, cycle, proposal)? >= cap {
        return Ok(SkillEditDisposition::DeferredCycleCap);
    }
    Ok(SkillEditDisposition::Accepted)
}

/// Accept slots already spent by `cycle`, DERIVED from the verdict ledger.
///
/// Not a stored counter (doc-13 r1, the posture this module's open-question
/// rule already takes): a counter is a third thing to keep true, and one that
/// disagrees with the receipts would make the cap unauditable.
///
/// The unit is a PROPOSAL, not a row. The cap bounds how many edits one wake
/// may admit, and one edit ruled on twice is still one edit — counting rows
/// would let a retried delivery eat the budget of the next real proposal.
/// `spending` is excluded for the same reason from the other side: a proposal
/// re-ruled over moved evidence must not be deferred by its own earlier
/// acceptance.
fn accepted_in_cycle_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    cycle: &SkillEditCycle,
    spending: &EntityId,
) -> Result<u32> {
    let mut accepted: BTreeSet<EntityId> = BTreeSet::new();
    for verdict in verdict_rows_in_txn(vault, rtxn)? {
        if verdict.disposition.admits()
            && verdict.cycle == cycle.as_str()
            && verdict.proposal != *spending
        {
            accepted.insert(verdict.proposal);
        }
    }
    Ok(u32::try_from(accepted.len()).unwrap_or(u32::MAX))
}

/// The standing ruling this delivery would only be repeating, if there is one.
///
/// "Standing" is the LATEST ruling, not any ruling: a proposal accepted and
/// then refused at the admission door has been answered, and the superseded
/// acceptance is history rather than a live permission.
///
/// Two rulings qualify, and both are answers a REDELIVERY must return rather
/// than re-earn:
///
/// - a standing ACCEPTANCE over exactly this basis, whatever cycle it was ruled
///   in — an acceptance keeps the cycle it was ruled in, and a duplicate
///   arriving under another label must not revoke it;
/// - a standing CAP DEFERRAL over exactly this basis AND this same cycle. The
///   cycle equality is load-bearing in the other direction: a deferral from
///   wake X says nothing about wake Y, so a genuine later-cycle pickup still
///   re-scores and is counted against the cycle that picked it up.
///
/// Returning the standing row is what makes delivery idempotent on BOTH arms:
/// no second replay is paid, no second row is appended, and the cap is neither
/// re-spent nor re-measured.
fn standing_ruling_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    proposal: &EntityId,
    basis: &ScoredBasis,
    cycle: &SkillEditCycle,
) -> Result<Option<HeldOutVerdict>> {
    Ok(
        standing_verdict_in_txn(vault, rtxn, proposal)?.filter(|verdict| {
            basis.matches(verdict)
                && (verdict.disposition.admits()
                    || (verdict.disposition == SkillEditDisposition::DeferredCycleCap
                        && verdict.cycle == cycle.as_str()))
        }),
    )
}

/// The most recent ruling on one proposal, whatever it said.
fn standing_verdict_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    proposal: &EntityId,
) -> Result<Option<HeldOutVerdict>> {
    Ok(verdict_rows_in_txn(vault, rtxn)?
        .into_iter()
        .rfind(|verdict| verdict.proposal == *proposal))
}

/// A refusal ruled BEFORE any score exists.
///
/// The zero pair is honest here and only here: nothing was replayed, so there
/// is no pair to report, no basis, and therefore no bound tier. A refusal
/// reached after an acceptance carries that acceptance's real numbers instead
/// ([`HeldOutVerdict::refused_at_admission`]).
///
/// The row is always written by the transaction that RE-VERIFIED the reason,
/// together with the closure it implies — never by a transaction of its own,
/// which is how a reason that stopped holding used to become a durable answer.
fn refusal(
    proposal: &EntityId,
    skill: &EntityId,
    cycle: &SkillEditCycle,
    disposition: SkillEditDisposition,
    at: u64,
) -> HeldOutVerdict {
    let (held_out_count, held_out_digest) = evidence_identity(&[]);
    HeldOutVerdict {
        before: 0.0,
        after: 0.0,
        accepted: false,
        id: EntityId::now(),
        proposal: *proposal,
        skill: *skill,
        disposition,
        cycle: cycle.as_str().to_owned(),
        held_out_receipts: Vec::new(),
        held_out_count,
        held_out_digest,
        held_out_truncated: false,
        proposal_digest: String::new(),
        target_digest: String::new(),
        proposal_tier: None,
        accepted_verdict: None,
        missing_sources: Vec::new(),
        at,
    }
}

/// Moves an ANSWERED proposal out of the open question set.
///
/// `approval: proposed → rejected`, and the lifecycle deliberately does not
/// move: ARCH-0053 §6 gives `Candidate` exactly one outgoing edge (to `Active`),
/// so the approval axis is the one that can carry "this was answered" without
/// inventing a transition. The record, its provenance and its text survive
/// intact — a closed proposal is readable history, not a deletion.
///
/// Why it must happen at all: `optimize_candidates` treats every
/// `candidate + proposed` revision as an unanswered question and skips the
/// skill. A rejection that left the record open would therefore stop the
/// optimizer from ever proposing for that skill again — one tie, and the skill
/// is frozen out of the loop forever.
///
/// Idempotent, and silent when the record has already moved: the caller is
/// inside a transaction that has just written the ruling, and racing to close a
/// record someone else closed is not a reason to roll that ruling back.
fn close_answered_proposal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
    at: u64,
) -> Result<()> {
    let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
    if staged.lifecycle_status != SkillLifecycle::Candidate
        || staged.approval_status != ClaimApprovalStatus::Proposed
    {
        return Ok(());
    }
    let mut closed = staged.clone();
    closed.approval_status = ClaimApprovalStatus::Rejected;
    validate_skill_update(&staged, &closed)?;
    let data = encode_skill_record(&closed)?;
    vault.apply_skill_record_body(
        wtxn,
        proposal,
        TimeRange { start: at, end: at },
        at,
        data,
        false,
    )
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// Arms `candidate → active` for a gate-passed optimizer-born proposal.
///
/// The one door an optimizer-born candidate can reach canon through; a bare
/// state flip is refused at the batch chokepoint
/// ([`check_optimizer_admission_in_txn`]). It does NOT supersede the
/// predecessor: freezing the old revision stays
/// [`crate::Vault::supersede_skill_record`]'s act, so the landed archive chain
/// is unchanged and callers admit, then supersede — the order that door already
/// requires.
///
/// Every check runs inside ONE write transaction against the snapshot the flip
/// commits into, and a refusal writes its verdict row and rolls back nothing
/// else: the active record is never touched on any path but success.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the proposal is gone;
/// [`Error::InvalidSkillBody`] when the proposal is not an open optimizer-born
/// candidate, when no [`SkillEditDisposition::Accepted`] verdict stands for it,
/// and for every refusal arm (protected or moved tier on either record, moved
/// or purged target, lost or malformed cited source).
pub fn admit_optimized_skill_revision(
    vault: &Vault,
    proposal: &EntityId,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let refused = vault.with_write_txn(|wtxn| {
        let staged = vault.read_skill_record_in_txn(&*wtxn, proposal)?;
        require_open_optimizer_proposal(&staged)?;
        let target = target_of(&staged)?;

        // The gate's standing answer, read from the ledger rather than
        // recomputed: re-scoring here would ask the LLM tier a second time and
        // could answer differently, which would make "passed the gate" a claim
        // no receipt backs. The WHOLE verdict is read, not just its
        // disposition — the scores, the evidence identity, the bound tier and
        // the two body digests are what the checks below are against, and what
        // a refusal from here carries forward.
        //
        // Read BEFORE the target, deliberately: a target that has been purged
        // since the acceptance is a refusal this door must be able to WRITE,
        // and it can only write one derived from the acceptance it supersedes.
        // Exiting on a bare `EntityNotFound` instead left the acceptance
        // standing, the proposal open, and the real score pair unrecorded.
        let Some(accepted) = standing_verdict_in_txn(vault, &*wtxn, proposal)?
            .filter(|verdict| verdict.disposition.admits())
        else {
            return Err(invalid(
                "an optimizer-born candidate is admitted only on a standing accepted gate verdict",
            ));
        };
        let current = readable_target(vault.read_skill_record_in_txn(&*wtxn, &target).map(Some))?;
        let refusal = admission_refusal_in_txn(
            vault,
            &*wtxn,
            proposal,
            &staged,
            current.as_ref(),
            &target,
            &accepted,
            learned_at,
        )?;
        if let Some(verdict) = refusal {
            return record_refusal_in_txn(vault, wtxn, verdict);
        }

        let mut admitted = staged.clone();
        admitted.approval_status = ClaimApprovalStatus::Approved;
        admitted.lifecycle_status = SkillLifecycle::Active;
        validate_skill_update(&staged, &admitted)?;
        let data = crate::skill::encode_skill_record(&admitted)?;
        // Written, consumed and deleted inside this transaction: the ticket is
        // how the chokepoint below knows this flip came through this door, and
        // it cannot outlive the flip it authorizes.
        vault.store.vault_meta.put(
            wtxn,
            &admission_ticket_key(proposal),
            admitted.version.as_bytes(),
        )?;
        let landed =
            vault.apply_skill_record_body(wtxn, proposal, occurred, learned_at, data, false);
        vault
            .store
            .vault_meta
            .delete(wtxn, &admission_ticket_key(proposal))?;
        landed?;
        Ok(None)
    })?;
    match refused {
        Some(disposition) => Err(disposition.refusal_error()),
        None => Ok(()),
    }
}

/// Every reason a standing acceptance is still refused at the door.
///
/// Ordered by which fact is the newer ruling, and the order is load-bearing: a
/// target that moved and an owner's fresh identity mark are answers about the
/// WORLD, so they are reported as themselves rather than collapsed into the
/// binding arm they would also trip.
///
/// Every refusal is derived from `accepted`
/// ([`HeldOutVerdict::refused_at_admission`]), so it carries the real score
/// pair, the evidence basis and both body digests of the ruling it supersedes,
/// and names that ruling. A refusal that reported `0.0 → 0.0` over no evidence
/// would read as an unscored tie, which is not what happened.
#[expect(
    clippy::too_many_arguments,
    reason = "every refusal arm names the exact snapshot value it rests on; a struct would only move the list"
)]
fn admission_refusal_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    proposal: &EntityId,
    staged: &SkillRecord,
    current: Option<&SkillRecord>,
    target: &EntityId,
    accepted: &HeldOutVerdict,
    at: u64,
) -> Result<Option<HeldOutVerdict>> {
    // Every arm answers with the SAME acceptance, restated: the pair, the
    // basis and the bindings travel; only the disposition changes.
    let refused = |disposition| Some(accepted.refused_at_admission(disposition, at));
    // Purged, replaced by another kind, or simply unreadable: the revision this
    // acceptance was scored against is not there to be superseded, and that is
    // a durable answer carrying the acceptance's real numbers — not a bare exit
    // that leaves the permission standing.
    let Some(current) = current else {
        return Ok(refused(SkillEditDisposition::RefusedStaleTarget));
    };
    if !target_is_current(staged, current) {
        return Ok(refused(SkillEditDisposition::RefusedStaleTarget));
    }
    // Re-marked between the verdict and the admission: the owner's ruling
    // is the newer fact, and it wins.
    if tier_verdict_in_txn(vault, wtxn, target, current)?
        .tier()
        .is_none_or(SkillGovernanceTier::is_protected)
    {
        return Ok(refused(SkillEditDisposition::RefusedProtectedTier));
    }
    // The same question asked of the PROPOSAL, independently and in this same
    // snapshot: an owner who marks the candidate itself `identity` after the
    // gate passed has ruled on the body that is one write from becoming canon.
    // Protected, ambiguous, or no longer the tier the acceptance bound are one
    // answer — and it is checked BEFORE the binding arm so the receipt names
    // the owner's mark rather than the digest mismatch it would also trip.
    let proposal_tier = tier_verdict_in_txn(vault, wtxn, proposal, staged)?.tier();
    if proposal_tier.is_none_or(SkillGovernanceTier::is_protected)
        || proposal_tier != accepted.proposal_tier
    {
        return Ok(refused(SkillEditDisposition::RefusedProtectedTier));
    }
    // THE binding check, in the snapshot the flip commits into: is the body
    // about to become canon the body that was scored, is the predecessor it
    // improves on still the one it was compared against, and is the reserved
    // evidence still the set that judged them? A verdict that recorded only
    // "proposal X was accepted" would let any of the three be swapped after the
    // fact, which makes the strict gate a formality.
    let committed = held_out_receipts_in_txn(vault, wtxn, target)?;
    if !ScoredBasis::of(staged, current, &committed, proposal_tier)?.matches(accepted) {
        return Ok(refused(SkillEditDisposition::RefusedBindingMismatch));
    }
    // ONE-1447's gap, closed at the door that owns it: the stale sweep
    // deliberately steps past CANDIDATES (ARCH-0053 §6 has no
    // `Candidate → Stale` edge), so a candidate whose cited source was
    // erased carries no mark to read. Resolve every cited id DIRECTLY in
    // the active store — the reverse index is source→skills, the wrong
    // direction for this question, and it is a cache besides.
    let Ok(cited) = source_message_refs(staged) else {
        return Ok(refused(SkillEditDisposition::RefusedSourceMalformed));
    };
    let mut missing = Vec::new();
    for source in cited {
        if vault.store.entities.get(wtxn, source.as_bytes())?.is_none() {
            missing.push(source);
        }
    }
    if missing.is_empty() {
        return Ok(None);
    }
    let mut verdict = accepted.refused_at_admission(SkillEditDisposition::RefusedSourceLoss, at);
    verdict.missing_sources = missing;
    Ok(Some(verdict))
}

/// Writes a refusal row, closes the proposal it answers, and reports the
/// disposition the caller errors with.
fn record_refusal_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    verdict: HeldOutVerdict,
) -> Result<Option<SkillEditDisposition>> {
    let disposition = verdict.disposition;
    record_verdict_in_txn(vault, wtxn, &verdict)?;
    if disposition.closes_proposal() {
        close_answered_proposal_in_txn(vault, wtxn, &verdict.proposal, verdict.at)?;
    }
    Ok(Some(disposition))
}

/// Provenance keys that say WHERE a record came from and what it revises.
///
/// Immutable together, because they are load-bearing together: the birth path
/// is what makes the admission floor apply at all, the target entity and
/// version are what "this revises that revision" means, and the cycle is what
/// the accept cap is counted against.
const OPTIMIZER_ORIGIN_KEYS: [&str; 5] = [
    PROVENANCE_BIRTH_KEY,
    PROVENANCE_OPTIMIZE_OF_KEY,
    PROVENANCE_OPTIMIZE_OF_ENTITY_KEY,
    PROVENANCE_OPTIMIZE_OF_VERSION_KEY,
    PROVENANCE_OPTIMIZE_CYCLE_KEY,
];

/// The `vault_meta` key the optimizer-birth marker for one entity lives at.
pub(super) fn optimizer_origin_marker_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(OPTIMIZER_ORIGIN_MARKER_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(OPTIMIZER_ORIGIN_MARKER_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

/// The five origin values a record carries, in the pinned key order.
fn optimizer_origin_values(record: &SkillRecord) -> Vec<Option<String>> {
    OPTIMIZER_ORIGIN_KEYS
        .iter()
        .map(|key| provenance_str(record, key))
        .collect()
}

fn encode_origin_marker(values: &[Option<String>]) -> Result<Vec<u8>> {
    let row = Value::Array(
        std::iter::once(Value::from(ORIGIN_MARKER_SCHEMA_VERSION))
            .chain(values.iter().map(|value| match value {
                Some(value) => Value::from(value.as_str()),
                None => Value::Nil,
            }))
            .collect(),
    );
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &row)
        .map_err(|_| invalid("skill optimizer origin marker MessagePack encode failed"))?;
    Ok(encoded)
}

fn decode_origin_marker(raw: &[u8]) -> Result<Vec<Option<String>>> {
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(ORIGIN_MARKER_LABEL))?;
    let Value::Array(entries) = &value else {
        return Err(Error::CorruptedIndex(ORIGIN_MARKER_LABEL));
    };
    let Some((version, rest)) = entries.split_first() else {
        return Err(Error::CorruptedIndex(ORIGIN_MARKER_LABEL));
    };
    if version.as_u64() != Some(ORIGIN_MARKER_SCHEMA_VERSION)
        || rest.len() != OPTIMIZER_ORIGIN_KEYS.len()
    {
        return Err(Error::CorruptedIndex(ORIGIN_MARKER_LABEL));
    }
    rest.iter()
        .map(|entry| match entry {
            Value::Nil => Ok(None),
            other => other
                .as_str()
                .map(|value| Some(value.to_owned()))
                .ok_or(Error::CorruptedIndex(ORIGIN_MARKER_LABEL)),
        })
        .collect()
}

/// The optimizer-birth half of the origin law, at the LOCAL create door.
///
/// [`check_optimizer_admission_in_txn`] freezes origin provenance for the life
/// of an entity by comparing a create-against-prior pair — but DELETION ends
/// that life while the id survives, and the id is what the verdict ledger, the
/// admission ticket and every "this proposal was accepted" row are keyed by. So
/// `delete` + same-id `put` used to launder an optimizer-born id into an
/// ordinary candidate, which the owner's own door then walked to `active` with
/// no ticket and no verdict: two writes, no gate, and a gate history that still
/// said yes.
///
/// The marker closes that road by outliving the body. It is written beside the
/// first LOCAL optimizer-born create and never rewritten (the birth stamp is
/// immutable, cycle included), no delete road clears it, and thereafter any
/// create at that id must present byte-identical origin provenance. The answer
/// is one of four:
///
/// - marked, and the create carries the same five values → allowed, and the
///   record is optimizer-born again, so every update-door rule applies to it
///   unchanged;
/// - marked, and the create carries different or absent origin → refused: that
///   is the laundering this exists to stop;
/// - unmarked, and the create is optimizer-born → the marker is born with it
///   (returned for the caller to stage in the SAME transaction);
/// - unmarked, ordinary create → untouched. The owner's skills are not
///   optimizer-born, so this rule costs them nothing.
///
/// Read-only, and it returns the row to write rather than writing it, so the
/// create arm can run the check while the transaction is still borrowed for
/// reads and stage the marker at its one pre-write site (the ONE-1604-D1
/// posture in the same file). Replicated / sync-remat rows never reach here:
/// settled remote state is not re-decided locally.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] on an origin-laundering create;
/// [`Error::CorruptedIndex`] on an unreadable marker — fail closed, because a
/// marker nobody can read is exactly the case the bypass would hide behind.
pub(crate) fn optimizer_birth_marker_for_create_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    created: &SkillRecord,
) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let key = optimizer_origin_marker_key(id);
    let origin = optimizer_origin_values(created);
    let Some(marked) = store
        .vault_meta
        .get(txn, &key)?
        .as_deref()
        .map(decode_origin_marker)
        .transpose()?
    else {
        return if born_on_optimize_road(created) {
            Ok(Some((key, encode_origin_marker(&origin)?)))
        } else {
            Ok(None)
        };
    };
    if marked != origin {
        return Err(invalid(
            "this entity id was born on the optimize road; a create that does not carry its origin provenance is refused",
        ));
    }
    Ok(None)
}

/// The chokepoint rule, in two halves: an optimizer-born candidate never
/// becomes canon by a bare state flip, and it never stops being optimizer-born.
///
/// Called from `batch::put_apply` — the one arm every local SKILL body update
/// converges on — so `put_entity`, a raw `batch().put` and the typed update
/// door are all governed by it. Replicated rows are exempt: a hub-sync or sync
/// replay row carries settled remote state, and locally re-deciding it would
/// diverge the replicas.
///
/// # Origin is a birth fact, not a field
///
/// The admission floor asks the PRIOR record whether it was optimizer-born, so
/// an origin that could be edited away would be an origin worth editing away:
/// one lawful candidate→candidate content update to drop the birth key, and a
/// second update flips the record active as an ordinary candidate, with no
/// ticket and no verdict. Two writes, no gate. So the origin keys are frozen
/// for the entity's lifetime, in both directions — a record cannot shed the
/// road it was born on, and a record born on another road cannot claim this
/// one.
///
/// This is a rule ABOUT machine-born records and it costs the owner nothing:
/// their own skills are not optimizer-born, and on a record that IS, every
/// other field — the text, the version, the tier, the states — still moves
/// through the ordinary door exactly as before.
///
/// The rule holds over a record's LIFE; deletion ends that life while the id
/// outlives it, so the CREATE half of the same law
/// ([`optimizer_birth_marker_for_create_in_txn`]) closes the delete/recreate
/// road with a durable marker no delete clears.
///
/// Read-only by construction: it runs while the prior body is still borrowed
/// from the transaction, and the ticket it verifies is deleted by the door that
/// wrote it.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] when an optimizer-born record's origin
/// provenance is edited, and when an optimizer-born candidate is flipped active
/// without [`admit_optimized_skill_revision`] having authorized exactly this
/// revision in this transaction.
pub(crate) fn check_optimizer_admission_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    prior: &SkillRecord,
    updated: &SkillRecord,
) -> Result<()> {
    if !born_on_optimize_road(prior) {
        return if born_on_optimize_road(updated) {
            Err(invalid(
                "optimizer birth provenance is a birth fact; an existing record cannot adopt it",
            ))
        } else {
            Ok(())
        };
    }
    for key in OPTIMIZER_ORIGIN_KEYS {
        if provenance_str(prior, key) != provenance_str(updated, key) {
            return Err(invalid(
                "an optimizer-born skill's origin provenance is immutable for the life of the entity",
            ));
        }
    }
    if prior.lifecycle_status != SkillLifecycle::Candidate
        || updated.lifecycle_status != SkillLifecycle::Active
    {
        return Ok(());
    }
    let Some(ticket) = store.vault_meta.get(txn, &admission_ticket_key(id))? else {
        return Err(invalid(
            "an optimizer-born candidate is admitted by the ONE-1449 score gate, not by a bare state flip",
        ));
    };
    if ticket.as_ref() != updated.version.as_bytes() {
        return Err(invalid(
            "the optimizer admission ticket does not name this revision",
        ));
    }
    Ok(())
}

fn admission_ticket_key(proposal: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(ADMISSION_TICKET_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(ADMISSION_TICKET_PREFIX);
    key.extend_from_slice(proposal.as_bytes());
    key
}

// ---------------------------------------------------------------------------
// Record shape helpers
// ---------------------------------------------------------------------------

/// True when this record's provenance says ONE-1448's job drafted it.
fn born_on_optimize_road(record: &SkillRecord) -> bool {
    provenance_str(record, PROVENANCE_BIRTH_KEY).as_deref() == Some(SKILL_OPTIMIZE_BIRTH_PATH)
}

/// Every shape question the gate and the admission door ask of a proposal
/// BEFORE they will rule on it — including the birth cycle.
///
/// The cycle stamp is required here, at both doors, rather than only where the
/// label is read from the record: the cap is counted against a cycle, and a
/// proposal that can show no birth cycle has no provable place in any wake's
/// budget. Naming a cycle explicitly does not rescue it — a caller-named label
/// on an unstamped proposal was exactly the free cap the stamp exists to
/// prevent. Prerelease, so no unstamped corpus is accommodated.
fn require_open_optimizer_proposal(record: &SkillRecord) -> Result<()> {
    if !born_on_optimize_road(record) {
        return Err(invalid("this gate rules on optimizer-born proposals only"));
    }
    if record.lifecycle_status != SkillLifecycle::Candidate
        || record.approval_status != ClaimApprovalStatus::Proposed
    {
        return Err(invalid(
            "an optimizer-born proposal is gated while it is an open candidate",
        ));
    }
    SkillEditCycle::of_record(record)?;
    Ok(())
}

fn target_of(proposal: &SkillRecord) -> Result<EntityId> {
    provenance_str(proposal, PROVENANCE_OPTIMIZE_OF_ENTITY_KEY)
        .and_then(|hex| EntityId::from_hex(&hex).ok())
        .ok_or(invalid(
            "an optimizer-born proposal names the entity it revises",
        ))
}

/// Whether the predecessor is still the revision this proposal was drafted
/// against — active, same `skillId`, same version.
fn target_is_current(proposal: &SkillRecord, target: &SkillRecord) -> bool {
    target.lifecycle_status == SkillLifecycle::Active
        && target.skill_id == proposal.skill_id
        && provenance_str(proposal, PROVENANCE_OPTIMIZE_OF_VERSION_KEY).as_deref()
            == Some(target.version.as_str())
}

fn provenance_str(record: &SkillRecord, key: &str) -> Option<String> {
    let Value::Map(entries) = &record.provenance else {
        return None;
    };
    entries
        .iter()
        .find(|(entry, _)| entry.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

/// Keeps the most recent [`SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE`] receipts, for
/// DISPLAY.
///
/// The ledger is mint-ordered, so dropping from the front drops the oldest —
/// the citation-cap choice the reliability claim and the optimize brief both
/// already make. A verdict cites the evidence it rested on; it is not a copy of
/// the evidence ledger.
///
/// What makes the cap honest rather than a quiet lie is that it is no longer
/// the only record of the basis: the row also carries the exact COUNT, the
/// canonical DIGEST of the whole scored set and a truncation marker
/// ([`HeldOutVerdict::held_out_digest`]), and every comparison this module
/// makes — accept-time, commit-time and admission-time — runs against those,
/// never against this list.
fn bounded_receipts(mut receipts: Vec<String>) -> Vec<String> {
    if receipts.len() > SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE {
        receipts.drain(..receipts.len() - SKILL_OPTIMIZE_MAX_BRIEF_EVIDENCE);
    }
    receipts
}

// ---------------------------------------------------------------------------
// The verdict ledger
// ---------------------------------------------------------------------------

fn verdict_key(id: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(VERDICT_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(VERDICT_PREFIX);
    key.extend_from_slice(id.as_bytes());
    key
}

fn record_verdict_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    verdict: &HeldOutVerdict,
) -> Result<()> {
    let row = Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(VERDICT_SCHEMA_VERSION),
        ),
        (
            Value::from(KEY_PROPOSAL),
            Value::from(verdict.proposal.to_hex()),
        ),
        (Value::from(KEY_SKILL), Value::from(verdict.skill.to_hex())),
        (Value::from(KEY_BEFORE), Value::F32(verdict.before)),
        (Value::from(KEY_AFTER), Value::F32(verdict.after)),
        (
            Value::from(KEY_DISPOSITION),
            Value::from(verdict.disposition.as_str()),
        ),
        (Value::from(KEY_CYCLE), Value::from(verdict.cycle.as_str())),
        (
            Value::from(KEY_HELD_OUT),
            Value::Array(
                verdict
                    .held_out_receipts
                    .iter()
                    .map(|receipt| Value::from(receipt.as_str()))
                    .collect(),
            ),
        ),
        (
            Value::from(KEY_HELD_OUT_COUNT),
            Value::from(verdict.held_out_count),
        ),
        (
            Value::from(KEY_HELD_OUT_DIGEST),
            Value::from(verdict.held_out_digest.as_str()),
        ),
        (
            Value::from(KEY_HELD_OUT_TRUNCATED),
            Value::Boolean(verdict.held_out_truncated),
        ),
        (
            Value::from(KEY_PROPOSAL_DIGEST),
            Value::from(verdict.proposal_digest.as_str()),
        ),
        (
            Value::from(KEY_TARGET_DIGEST),
            Value::from(verdict.target_digest.as_str()),
        ),
        (
            Value::from(KEY_PROPOSAL_TIER),
            verdict
                .proposal_tier
                .map_or(Value::Nil, |tier| Value::from(tier.as_str())),
        ),
        (
            Value::from(KEY_ACCEPTED_VERDICT),
            verdict
                .accepted_verdict
                .map_or(Value::Nil, |id| Value::from(id.to_hex())),
        ),
        (
            Value::from(KEY_MISSING_SOURCES),
            Value::Array(
                verdict
                    .missing_sources
                    .iter()
                    .map(|source| Value::from(source.to_hex()))
                    .collect(),
            ),
        ),
        (Value::from(KEY_AT), Value::from(verdict.at)),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &row)
        .map_err(|_| invalid("skill edit verdict MessagePack encode failed"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &verdict_key(&verdict.id), &encoded)?;
    Ok(())
}

fn decode_verdict(key: &[u8], raw: &[u8]) -> Result<HeldOutVerdict> {
    let id = key
        .get(VERDICT_PREFIX.len()..)
        .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
        .and_then(|tail| parse_entity_id(tail, VERDICT_ROW_LABEL))?;
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(raw))
        .map_err(|_| Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    let Value::Map(entries) = &value else {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    if field(KEY_SCHEMA_VERSION).and_then(Value::as_u64) != Some(VERDICT_SCHEMA_VERSION) {
        return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL));
    }
    let entity = |name: &str| {
        field(name)
            .and_then(Value::as_str)
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
    };
    let score = |name: &str| match field(name) {
        Some(&Value::F32(score)) => Ok(score),
        _ => Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
    };
    let strings = |name: &str| {
        field(name)
            .and_then(|value| match value {
                Value::Array(entries) => Some(entries),
                _ => None,
            })
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.as_str().map(str::to_owned))
                    .collect::<Vec<String>>()
            })
    };
    let disposition = field(KEY_DISPOSITION)
        .and_then(Value::as_str)
        .and_then(SkillEditDisposition::parse)
        .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?;
    let text = |name: &str| {
        field(name)
            .and_then(Value::as_str)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))
            .map(str::to_owned)
    };
    Ok(HeldOutVerdict {
        before: score(KEY_BEFORE)?,
        after: score(KEY_AFTER)?,
        accepted: disposition.admits(),
        id,
        proposal: entity(KEY_PROPOSAL)?,
        skill: entity(KEY_SKILL)?,
        disposition,
        cycle: text(KEY_CYCLE)?,
        held_out_receipts: strings(KEY_HELD_OUT)?,
        held_out_count: field(KEY_HELD_OUT_COUNT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
        held_out_digest: text(KEY_HELD_OUT_DIGEST)?,
        held_out_truncated: field(KEY_HELD_OUT_TRUNCATED)
            .and_then(Value::as_bool)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
        proposal_digest: text(KEY_PROPOSAL_DIGEST)?,
        target_digest: text(KEY_TARGET_DIGEST)?,
        // Nil is AMBIGUOUS or basis-less, and both are unadmittable; an absent
        // key is a row from another schema, and an unparseable tier is
        // corruption. Only the explicit spellings decode.
        proposal_tier: match field(KEY_PROPOSAL_TIER) {
            None => return Err(Error::CorruptedIndex(VERDICT_ROW_LABEL)),
            Some(Value::Nil) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(SkillGovernanceTier::parse)
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            ),
        },
        // Nil is the ordinary shape: only a post-score refusal names the
        // acceptance it answers. A present-but-unreadable id is corruption,
        // not absence — reading it as "no reference" would quietly turn a
        // derived refusal back into the orphan row this field exists to end.
        accepted_verdict: match field(KEY_ACCEPTED_VERDICT) {
            Some(Value::Nil) | None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
            ),
        },
        missing_sources: strings(KEY_MISSING_SOURCES)?
            .iter()
            .filter_map(|hex| EntityId::from_hex(hex).ok())
            .collect(),
        at: field(KEY_AT)
            .and_then(Value::as_u64)
            .ok_or(Error::CorruptedIndex(VERDICT_ROW_LABEL))?,
    })
}

fn verdict_rows_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<Vec<HeldOutVerdict>> {
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(rtxn, VERDICT_PREFIX)? {
        let (key, raw) = row?;
        out.push(decode_verdict(&key, &raw)?);
    }
    Ok(out)
}

/// Every gate verdict this vault has ruled, in ruling order.
///
/// The typed read model: `before` and `after` are `f32` here, not prose and not
/// a hash, so a reader can compare the pair the gate compared.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn skill_edit_verdicts(vault: &Vault) -> Result<Vec<HeldOutVerdict>> {
    let rtxn = vault.store.env.read_txn()?;
    verdict_rows_in_txn(vault, &rtxn)
}

/// Every verdict ruled on one proposal, oldest first.
///
/// More than one is ordinary: a cap-deferred proposal is ruled again in a later
/// cycle, and both rulings are history.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn skill_edit_verdicts_for_proposal(
    vault: &Vault,
    proposal: &EntityId,
) -> Result<Vec<HeldOutVerdict>> {
    Ok(skill_edit_verdicts(vault)?
        .into_iter()
        .filter(|verdict| verdict.proposal == *proposal)
        .collect())
}

/// The gate's standing answer for one proposal: its most recent verdict.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub fn skill_edit_verdict(vault: &Vault, proposal: &EntityId) -> Result<Option<HeldOutVerdict>> {
    Ok(skill_edit_verdicts_for_proposal(vault, proposal)?.pop())
}

// ---------------------------------------------------------------------------
// Receipts (a projector in the `Gate` family)
// ---------------------------------------------------------------------------

/// Whether a receipt is a skill-edit gate verdict.
#[must_use]
pub fn is_skill_edit_verdict_receipt(record: &ReceiptRecord) -> bool {
    record.receipt_kind == ReceiptKind::Gate
        && record.receipt_id.starts_with(SKILL_EDIT_RECEIPT_PREFIX)
}

/// Projects the verdict ledger as `Gate` receipts.
///
/// A gate verdict IS a gate decision, so it mints no kind of its own — the
/// `edit_distance::escalation` precedent, whose field class it copies down to
/// the discriminating key prefix. Opens its own read txn, as that projector
/// does, and bounds the RESULT rather than the walk: these keys are ruling-
/// ordered, so the newest `query.limit` is exactly what cannot be dropped
/// without changing the caller's answer.
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an unreadable row.
pub(crate) fn skill_edit_verdict_receipts(
    vault: &Vault,
    query: &ReceiptQuery,
) -> Result<Vec<ReceiptRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for verdict in verdict_rows_in_txn(vault, &rtxn)? {
        let record = skill_edit_verdict_receipt(&verdict);
        if !query.matches(&record) {
            continue;
        }
        if query.job_ref.is_some() {
            out.push(record);
        } else {
            retain_newest_receipt(&mut out, record, query.limit);
        }
    }
    Ok(out)
}

fn skill_edit_verdict_receipt(verdict: &HeldOutVerdict) -> ReceiptRecord {
    let mut fields = BTreeMap::from([
        (
            FIELD_SKILL_EDIT_PROPOSAL.to_owned(),
            verdict.proposal.to_hex(),
        ),
        (FIELD_SKILL_EDIT_SKILL.to_owned(), verdict.skill.to_hex()),
        // Decimal numerals, not prose: the pair a reader has to be able to
        // compare survives the receipt family's string field ABI intact, and
        // `skill_edit_verdicts` serves the same two numbers already typed.
        (
            FIELD_SKILL_EDIT_SCORE_BEFORE.to_owned(),
            format!("{:.6}", verdict.before),
        ),
        (
            FIELD_SKILL_EDIT_SCORE_AFTER.to_owned(),
            format!("{:.6}", verdict.after),
        ),
        (FIELD_SKILL_EDIT_CYCLE.to_owned(), verdict.cycle.clone()),
        (
            FIELD_SKILL_EDIT_DISPOSITION.to_owned(),
            verdict.disposition.as_str().to_owned(),
        ),
        // The complete basis travels with every ruling, truncated display list
        // or not: a receipt that showed a window and said nothing about the
        // rest was claiming an evidence set it did not have.
        (
            FIELD_SKILL_EDIT_HELD_OUT_COUNT.to_owned(),
            verdict.held_out_count.to_string(),
        ),
        (
            FIELD_SKILL_EDIT_HELD_OUT_DIGEST.to_owned(),
            verdict.held_out_digest.clone(),
        ),
    ]);
    if !verdict.proposal_digest.is_empty() {
        fields.insert(
            FIELD_SKILL_EDIT_PROPOSAL_DIGEST.to_owned(),
            verdict.proposal_digest.clone(),
        );
    }
    if !verdict.target_digest.is_empty() {
        fields.insert(
            FIELD_SKILL_EDIT_TARGET_DIGEST.to_owned(),
            verdict.target_digest.clone(),
        );
    }
    if let Some(accepted) = verdict.accepted_verdict {
        fields.insert(
            FIELD_SKILL_EDIT_ACCEPTED_VERDICT.to_owned(),
            accepted.to_hex(),
        );
    }
    if verdict.held_out_truncated {
        fields.insert(
            FIELD_SKILL_EDIT_HELD_OUT_TRUNCATED.to_owned(),
            "true".to_owned(),
        );
    }
    if !verdict.held_out_receipts.is_empty() {
        fields.insert(
            FIELD_SKILL_EDIT_HELD_OUT_RECEIPTS.to_owned(),
            verdict.held_out_receipts.join(","),
        );
    }
    if !verdict.missing_sources.is_empty() {
        fields.insert(
            FIELD_SKILL_EDIT_MISSING_SOURCES.to_owned(),
            verdict
                .missing_sources
                .iter()
                .map(EntityId::to_hex)
                .collect::<Vec<String>>()
                .join(","),
        );
    }
    ReceiptRecord {
        receipt_id: format!("{SKILL_EDIT_RECEIPT_PREFIX}{}", verdict.id.to_hex()),
        receipt_kind: ReceiptKind::Gate,
        occurred_at: verdict.at,
        actor: None,
        on_behalf_of: None,
        outcome: verdict.disposition.as_str().to_owned(),
        job_ref: None,
        trigger_ref: Some(format!("skill_proposal:{}", verdict.proposal.to_hex())),
        policy_trace: vec![format!(
            "skill_optimize.gate.{}",
            verdict.disposition.as_str()
        )],
        fields,
    }
}
