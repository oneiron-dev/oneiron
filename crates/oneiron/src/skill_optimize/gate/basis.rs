//! What a ruling rests on before the gate decides: the held-out split, the
//! identity a verdict binds itself to, the scorer seam, and the cycle.

use super::*;

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

pub(super) fn held_out_receipts_in_txn(
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
pub(super) fn evidence_identity(receipts: &[String]) -> (u64, String) {
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
pub(super) struct ScoredBasis {
    pub(super) proposal_digest: String,
    pub(super) target_digest: String,
    pub(super) evidence_count: u64,
    pub(super) evidence_digest: String,
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
    pub(super) proposal_tier: Option<SkillGovernanceTier>,
}

impl ScoredBasis {
    /// # Errors
    ///
    /// Body errors from re-encoding either record.
    pub(super) fn of(
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
    pub(super) fn matches(&self, verdict: &HeldOutVerdict) -> bool {
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
/// [`crate::skill_optimize::SkillOptimizeAuthor`] posture). There is deliberately no in-engine
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

pub(super) fn host_replay_scorer() -> Result<&'static (dyn HeldOutReplayScorer + Send + Sync)> {
    HELD_OUT_REPLAY_SCORER.get().copied().ok_or(invalid(
        "no held-out replay scorer is registered; the gate has no in-engine default",
    ))
}

/// Refuses a scalar the strict comparison could not mean anything over.
///
/// NaN is the case that matters: `NaN > x` is false, so an unvalidated NaN
/// would read as a quiet rejection rather than the broken scorer it is.
pub(super) fn validate_score(score: f32) -> Result<f32> {
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
    pub(in crate::skill_optimize) fn new(label: impl Into<String>) -> Result<Self> {
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

    pub(super) fn of_record(record: &SkillRecord) -> Result<Self> {
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

pub(super) fn cycle_cap_in_txn(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<u32> {
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
