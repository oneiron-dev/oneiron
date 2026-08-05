//! ARCH-0035 attribution projector for the ARCH-0053 §4 skills loop.
//!
//! The bottom half of the loop: an attempt's outcome plus its edit-feedback is
//! CLASSIFIED before anything lands, so a good skill is not churned because the
//! executor fumbled, and an agent is not blamed for a skill that lied.
//!
//! ```text
//! RECEIPT (outcome + pack manifest)
//!   └─ projector ──> routed verdict
//!        ├─ skill_defect    → judgment against the SKILL entity
//!        ├─ execution_lapse → judgment against the ACTOR entity
//!        └─ discovery       → a skill EDIT PROPOSAL, never a claim
//! ```
//!
//! **Layer scope (SK stack 1737 → 1738 → 1739).** This module ROUTES and
//! PERSISTS judgments; it writes no claims. `skill.reliability` materializes in
//! ONE-1738 and the `actor.*` write doors open in ONE-1739 — both consume the
//! judgment rows this projector persists. The absence of claim writes here is
//! the stack's shape, not an omission: routing is the decision, claiming is the
//! consequence, and they land in different tickets so the routing can be
//! reviewed on its own.
//!
//! House shape is [`crate::comm::run_comm_projector`]: callers RECORD evidence
//! through a door, the projector converts unprojected evidence into durable
//! output in sequence order, and a cursor makes the pass idempotent and
//! resumable. The cursor is a local u64 following the
//! [`crate::dreamer_consolidation`] `read_watermark`/`advance_watermark` shape
//! (no generic engine watermark type exists — `ConsolidationWatermark` is
//! consolidation-scoped).

use std::io::Cursor;

use rmpv::Value;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::CallPurpose;

/// Schema version for every row this module persists.
pub const SKILL_ATTRIBUTION_SCHEMA_VERSION: u64 = 1;

/// [`CallPurpose::Other`] name for the LLM classification tier. Ambiguous
/// evidence rides the EXISTING engine LLM call surface under this purpose —
/// this module mints no client stack of its own (see [`AttributionJudge`]).
pub const ATTRIBUTION_CALL_PURPOSE_NAME: &str = "skill_attribution";

const EVIDENCE_PREFIX: &[u8] = b"skill_attribution:evidence:v1:"; // + sequence(8 BE)
const JUDGMENT_PREFIX: &[u8] = b"skill_attribution:judgment:v1:"; // + sequence(8 BE)
const AUDIT_PREFIX: &[u8] = b"skill_attribution:audit:v1:"; // + at(8 BE) + seq(8 BE)
const EVIDENCE_SEQUENCE_KEY: &[u8] = b"skill_attribution:evidence_sequence:v1";
const CURSOR_KEY: &[u8] = b"skill_attribution:cursor:v1";

const SEQUENCE_LEN: usize = 8;

const KEY_SCHEMA_VERSION: &str = "schema_version";
const KEY_SEQUENCE: &str = "sequence";
const KEY_RECEIPT_REF: &str = "receipt_ref";
const KEY_ACTOR: &str = "actor";
const KEY_SKILL: &str = "skill";
const KEY_OUTCOME: &str = "outcome";
const KEY_FOLLOWED_SKILL: &str = "followed_skill";
const KEY_SKILL_COVERED_STEP: &str = "skill_covered_step";
const KEY_AT: &str = "at";
const KEY_VERDICT: &str = "verdict";
const KEY_SUBJECT: &str = "subject";
const KEY_EVIDENCE_RECEIPTS: &str = "evidence_receipts";
const KEY_TOTAL: &str = "total";
const KEY_PASSED: &str = "passed";
const KEY_ABSTAINED: &str = "abstained";

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

// ---------------------------------------------------------------------------
// Verdict taxonomy (ARCH-0053 §4 — EmbodiSkill's)
// ---------------------------------------------------------------------------

/// How an attempt's outcome is attributed.
///
/// The taxonomy lives in ARCH-0053/0056 prose; this is its first code home.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributionVerdict {
    /// The skill's content was wrong. Routes against the SKILL entity; the
    /// reliability CLAIM is ONE-1738's projection over these judgments.
    SkillDefect,
    /// The executor fumbled a skill that was correct. Routes against the ACTOR
    /// entity; `actor.lesson` / `actor.failure_mode` writes are ONE-1739's.
    ExecutionLapse,
    /// The skill was missing content the attempt needed. Deliberately NOT a
    /// claim on anything (§4): it becomes a skill EDIT PROPOSAL.
    Discovery,
}

impl AttributionVerdict {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillDefect => "skill_defect",
            Self::ExecutionLapse => "execution_lapse",
            Self::Discovery => "discovery",
        }
    }

    /// Parses a stable wire string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "skill_defect" => Some(Self::SkillDefect),
            "execution_lapse" => Some(Self::ExecutionLapse),
            "discovery" => Some(Self::Discovery),
            _ => None,
        }
    }

    /// True when this verdict routes to a gated skill EDIT PROPOSAL rather
    /// than to a claim on any entity (§4: discovery is not a claim).
    #[must_use]
    pub const fn mints_edit_proposal(self) -> bool {
        matches!(self, Self::Discovery)
    }
}

/// Terminal outcome of the attempt the evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttemptOutcome {
    Succeeded,
    Failed,
}

impl AttemptOutcome {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    /// Parses a stable wire string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// One attributable outcome, as recorded by the caller that observed it.
///
/// The `receipt_ref` is the RS1 receipt id (a string on the landed spine, not
/// an entity id) whose pack manifest names `skill`; every judgment cites it, so
/// a verdict is always traceable back to the record that produced it.
///
/// The two `Option<bool>` facts are the routing inputs. `None` means the
/// evidence did not settle that fact — the rule tier then ABSTAINS rather than
/// guessing, and the ambiguous case is what the LLM tier exists for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeEvidence {
    /// RS1 receipt id of the attempt's terminal receipt.
    pub receipt_ref: String,
    /// The executing actor (agent, human, peer, connector — §4 r1).
    pub actor: EntityId,
    /// The SKILL entity implicated by the attempt's pack manifest, when one is.
    pub skill: Option<EntityId>,
    pub outcome: AttemptOutcome,
    /// Did the actor actually follow what the skill said?
    pub followed_skill: Option<bool>,
    /// Did the skill contain content covering the step that failed?
    pub skill_covered_step: Option<bool>,
    /// Unix seconds the outcome was observed.
    pub at: u64,
}

impl OutcomeEvidence {
    /// Builds evidence for one observed outcome. The routing facts default to
    /// unsettled; set them with [`Self::with_routing_facts`].
    #[must_use]
    pub fn new(
        receipt_ref: impl Into<String>,
        actor: EntityId,
        outcome: AttemptOutcome,
        at: u64,
    ) -> Self {
        Self {
            receipt_ref: receipt_ref.into(),
            actor,
            skill: None,
            outcome,
            followed_skill: None,
            skill_covered_step: None,
            at,
        }
    }

    /// Names the SKILL entity the attempt's pack manifest implicated.
    #[must_use]
    pub fn with_skill(mut self, skill: EntityId) -> Self {
        self.skill = Some(skill);
        self
    }

    /// Settles the two routing facts the rule tier reasons over.
    #[must_use]
    pub const fn with_routing_facts(
        mut self,
        followed_skill: bool,
        skill_covered_step: bool,
    ) -> Self {
        self.followed_skill = Some(followed_skill);
        self.skill_covered_step = Some(skill_covered_step);
        self
    }
}

/// One persisted, routed verdict. The stack's layers 2 and 3 read these rows:
/// ONE-1738 projects `skill.reliability` from the skill-subject judgments,
/// ONE-1739 writes `actor.*` from the actor-subject ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionJudgment {
    /// Monotonic id: the evidence sequence this judgment was routed from.
    pub sequence: u64,
    pub verdict: AttributionVerdict,
    /// SKILL entity for `SkillDefect`/`Discovery`, ACTOR entity for
    /// `ExecutionLapse` — the routing decision, made concrete.
    pub subject: EntityId,
    /// RS1 receipt ids this verdict rests on (trace-or-derivation).
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classifies one piece of evidence, or ABSTAINS (`Ok(None)`) when it cannot.
///
/// Abstention is a first-class answer: a judge that guesses on unsettled facts
/// is exactly the false-pass bias [`run_attribution_audit`] exists to expose.
///
/// The production LLM tier is a host-supplied implementation calling the
/// engine's existing LLM surface under [`attribution_call_purpose`]; this
/// module never constructs a client.
pub trait AttributionJudge {
    /// Returns the verdict for `evidence`, or `None` to abstain.
    fn judge(&self, evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>>;
}

/// The [`CallPurpose`] an LLM-tier judge must stamp, so attribution calls are
/// budgeted and audited as their own class rather than hiding inside another
/// purpose's totals.
#[must_use]
pub fn attribution_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: ATTRIBUTION_CALL_PURPOSE_NAME.to_owned(),
    }
}

/// The deterministic routing tier (ARCH-0053 §4).
///
/// | outcome | followed skill | skill covered step | verdict |
/// |---|---|---|---|
/// | failed | yes | yes | `SkillDefect` — the content was wrong |
/// | failed | no | — | `ExecutionLapse` — the executor departed from it |
/// | failed | yes | no | `Discovery` — the content was missing |
/// | succeeded | — | — | abstain — a win attributes nothing here |
/// | any fact unsettled | | | abstain — the LLM tier's case |
///
/// A SUCCEEDED attempt abstains on purpose: this projector routes BLAME.
/// Crediting a win is the reliability posterior's job (ONE-1738), which reads
/// the same receipts.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleAttributionJudge;

impl AttributionJudge for RuleAttributionJudge {
    fn judge(&self, evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
        if evidence.outcome != AttemptOutcome::Failed {
            return Ok(None);
        }
        let Some(followed_skill) = evidence.followed_skill else {
            return Ok(None);
        };
        if !followed_skill {
            return Ok(Some(AttributionVerdict::ExecutionLapse));
        }
        // The remaining branches attribute to the SKILL, so an evidence row
        // with no skill in the manifest cannot be routed: fail to the actor's
        // lane would be a fabrication, so abstain.
        let Some(skill_covered_step) = evidence.skill_covered_step else {
            return Ok(None);
        };
        if evidence.skill.is_none() {
            return Ok(None);
        }
        Ok(Some(if skill_covered_step {
            AttributionVerdict::SkillDefect
        } else {
            AttributionVerdict::Discovery
        }))
    }
}

/// The entity a verdict routes to, or `None` when the evidence cannot carry it.
fn verdict_subject(verdict: AttributionVerdict, evidence: &OutcomeEvidence) -> Option<EntityId> {
    match verdict {
        AttributionVerdict::ExecutionLapse => Some(evidence.actor),
        AttributionVerdict::SkillDefect | AttributionVerdict::Discovery => evidence.skill,
    }
}

// ---------------------------------------------------------------------------
// Evidence door + projector
// ---------------------------------------------------------------------------

/// Records one outcome for later attribution, returning its sequence.
///
/// Recording never classifies: the projector owns the verdict, so evidence can
/// be captured on the hot path and routed in a later pass (the ARCH-0035
/// posture, and the reason a re-run can be replayed against a fixed judge).
pub fn record_attribution_evidence(vault: &Vault, evidence: &OutcomeEvidence) -> Result<u64> {
    validate_evidence(evidence)?;
    vault.with_write_txn(|wtxn| {
        let sequence = next_evidence_sequence_in_txn(vault, wtxn)?;
        let encoded = encode_value(&encode_evidence(evidence, sequence))?;
        vault
            .store
            .vault_meta
            .put(wtxn, &sequenced_key(EVIDENCE_PREFIX, sequence), &encoded)?;
        Ok(sequence)
    })
}

/// Reads the projector cursor: the highest evidence sequence already routed.
/// An absent row IS cursor 0 (bootstrap).
pub fn read_attribution_cursor(vault: &Vault) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.vault_meta.get(&rtxn, CURSOR_KEY)? else {
        return Ok(0);
    };
    decode_u64(&raw, "attribution cursor")
}

/// Runs one ordered, idempotent attribution pass over evidence recorded after
/// `since_cursor`, using the deterministic tier.
///
/// Returns the judgments minted by THIS pass. Re-running with the same cursor
/// re-routes the same evidence to the same verdicts; running with the persisted
/// cursor ([`read_attribution_cursor`]) processes only what is new.
pub fn run_attribution_projector(
    vault: &Vault,
    since_cursor: u64,
) -> Result<Vec<AttributionJudgment>> {
    run_attribution_projector_with_judge(vault, since_cursor, &RuleAttributionJudge)
}

/// [`run_attribution_projector`] with an explicit judge — the seam the LLM
/// tier and the audit harness both use.
///
/// Abstained evidence is left unjudged but still ADVANCES the cursor: an
/// abstention is a completed routing decision ("this evidence attributes to
/// nobody"), not a retryable failure, so it must not re-enter every pass.
pub fn run_attribution_projector_with_judge(
    vault: &Vault,
    since_cursor: u64,
    judge: &dyn AttributionJudge,
) -> Result<Vec<AttributionJudgment>> {
    let pending = evidence_after(vault, since_cursor)?;
    let mut judgments = Vec::new();
    let mut highest = since_cursor;
    for (sequence, evidence) in pending {
        highest = highest.max(sequence);
        let Some(verdict) = judge.judge(&evidence)? else {
            continue;
        };
        let Some(subject) = verdict_subject(verdict, &evidence) else {
            continue;
        };
        judgments.push(AttributionJudgment {
            sequence,
            verdict,
            subject,
            evidence_receipts: vec![evidence.receipt_ref.clone()],
            at: evidence.at,
        });
    }

    vault.with_write_txn(|wtxn| {
        for judgment in &judgments {
            let encoded = encode_value(&encode_judgment(judgment));
            vault.store.vault_meta.put(
                wtxn,
                &sequenced_key(JUDGMENT_PREFIX, judgment.sequence),
                &encoded?,
            )?;
        }
        if highest > since_cursor {
            vault
                .store
                .vault_meta
                .put(wtxn, CURSOR_KEY, &highest.to_be_bytes())?;
        }
        Ok(())
    })?;

    Ok(judgments)
}

/// Every persisted judgment, in routing order. ONE-1738 and ONE-1739 consume
/// this: it is the stack seam.
pub fn attribution_judgments(vault: &Vault) -> Result<Vec<AttributionJudgment>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, JUDGMENT_PREFIX)? {
        let (_, raw) = row?;
        out.push(decode_judgment(&raw)?);
    }
    Ok(out)
}

/// The judgments that mint gated skill EDIT PROPOSALS rather than claims
/// (§4 discovery routing). The proposal lands through the gated write path
/// (`dreamer_promotion` envelope precedent / `supersede_skill_record` archive
/// law); this projector only names which judgments demand one.
pub fn pending_edit_proposals(vault: &Vault) -> Result<Vec<AttributionJudgment>> {
    Ok(attribution_judgments(vault)?
        .into_iter()
        .filter(|judgment| judgment.verdict.mints_edit_proposal())
        .collect())
}

// ---------------------------------------------------------------------------
// Defect-injection audit (Blind Curator guard)
// ---------------------------------------------------------------------------

/// One held-out audit case: evidence whose correct verdict is already known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditFixture {
    pub evidence: OutcomeEvidence,
    pub expected: AttributionVerdict,
}

/// Aggregate result of one audit pass.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttributionAuditReport {
    pub total: usize,
    /// Cases the judge got right.
    pub passed: usize,
    /// Cases the judge abstained on. Counted against the pass-rate — a judge
    /// that abstains on everything must not score 100%.
    pub abstained: usize,
    pub at: u64,
}

impl AttributionAuditReport {
    /// Passed over total. An empty fixture set scores 0.0, never 1.0: "nothing
    /// was checked" is the worst evidence, not the best.
    #[must_use]
    pub fn pass_rate(&self) -> f32 {
        if self.total == 0 {
            return 0.0;
        }
        // Precision loss here is intended: this is a reported metric, not an
        // accumulator, and both counts are bounded by the fixture set.
        #[expect(
            clippy::cast_precision_loss,
            reason = "reported aggregate metric over a bounded fixture set"
        )]
        {
            self.passed as f32 / self.total as f32
        }
    }
}

/// Runs the built-in held-out audit against the deterministic tier, persists
/// the report, and returns the pass-rate.
///
/// A judge biased toward false passes moves this number, so the bias is
/// visible in an aggregate metric instead of hiding inside individual verdicts.
pub fn run_attribution_audit(vault: &Vault) -> Result<f32> {
    let fixtures = held_out_audit_fixtures();
    let report = run_attribution_audit_with_judge(
        vault,
        &fixtures,
        &RuleAttributionJudge,
        crate::unix_seconds_now(),
    )?;
    Ok(report.pass_rate())
}

/// The generic audit harness: any fixture set, any judge.
///
/// Deliberately not specialized to skill attribution — ED-03 reuses this shape
/// for amendment evidence, so the harness stays generic over the evidence class
/// by taking its fixtures as an argument.
pub fn run_attribution_audit_with_judge(
    vault: &Vault,
    fixtures: &[AuditFixture],
    judge: &dyn AttributionJudge,
    at: u64,
) -> Result<AttributionAuditReport> {
    let mut passed = 0;
    let mut abstained = 0;
    for fixture in fixtures {
        match judge.judge(&fixture.evidence)? {
            Some(verdict) if verdict == fixture.expected => passed += 1,
            Some(_) => {}
            None => abstained += 1,
        }
    }
    let report = AttributionAuditReport {
        total: fixtures.len(),
        passed,
        abstained,
        at,
    };

    vault.with_write_txn(|wtxn| {
        let sequence = next_evidence_sequence_in_txn(vault, wtxn)?;
        let mut key = Vec::with_capacity(AUDIT_PREFIX.len() + SEQUENCE_LEN * 2);
        key.extend_from_slice(AUDIT_PREFIX);
        key.extend_from_slice(&at.to_be_bytes());
        key.extend_from_slice(&sequence.to_be_bytes());
        let encoded = encode_value(&encode_audit(&report))?;
        vault.store.vault_meta.put(wtxn, &key, &encoded)?;
        Ok(())
    })?;

    Ok(report)
}

/// Every persisted audit report, oldest first.
pub fn attribution_audit_reports(vault: &Vault) -> Result<Vec<AttributionAuditReport>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, AUDIT_PREFIX)? {
        let (_, raw) = row?;
        out.push(decode_audit(&raw)?);
    }
    Ok(out)
}

/// The held-out set: one case per verdict plus the two abstention shapes.
///
/// Subject ids are minted fresh per call. They are never written to the vault —
/// the routing table reasons over the outcome and the two routing facts, so the
/// identities are placeholders and a fixed seed would only risk aliasing a real
/// entity.
#[must_use]
pub fn held_out_audit_fixtures() -> Vec<AuditFixture> {
    let actor = EntityId::now();
    let skill = EntityId::now();
    let failed = |followed: bool, covered: bool, receipt: &str| {
        OutcomeEvidence::new(receipt, actor, AttemptOutcome::Failed, 1)
            .with_skill(skill)
            .with_routing_facts(followed, covered)
    };
    vec![
        AuditFixture {
            evidence: failed(true, true, "audit:skill_defect"),
            expected: AttributionVerdict::SkillDefect,
        },
        AuditFixture {
            evidence: failed(false, true, "audit:execution_lapse"),
            expected: AttributionVerdict::ExecutionLapse,
        },
        AuditFixture {
            evidence: failed(false, false, "audit:execution_lapse.uncovered"),
            expected: AttributionVerdict::ExecutionLapse,
        },
        AuditFixture {
            evidence: failed(true, false, "audit:discovery"),
            expected: AttributionVerdict::Discovery,
        },
    ]
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

fn validate_evidence(evidence: &OutcomeEvidence) -> Result<()> {
    if evidence.receipt_ref.is_empty() {
        return Err(invalid("attribution evidence must cite a receipt"));
    }
    Ok(())
}

fn sequenced_key(prefix: &[u8], sequence: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + SEQUENCE_LEN);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

fn next_evidence_sequence_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>) -> Result<u64> {
    let current = match vault.store.vault_meta.get(wtxn, EVIDENCE_SEQUENCE_KEY)? {
        Some(raw) => decode_u64(&raw, "attribution evidence sequence")?,
        None => 0,
    };
    let next = current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("attribution evidence sequence"))?;
    vault
        .store
        .vault_meta
        .put(wtxn, EVIDENCE_SEQUENCE_KEY, &next.to_be_bytes())?;
    Ok(next)
}

fn evidence_after(vault: &Vault, since_cursor: u64) -> Result<Vec<(u64, OutcomeEvidence)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, EVIDENCE_PREFIX)? {
        let (key, raw) = row?;
        let sequence = evidence_sequence_from_key(&key)?;
        if sequence <= since_cursor {
            continue;
        }
        out.push((sequence, decode_evidence(&raw)?));
    }
    // Big-endian sequence suffixes already sort in routing order; sorting keeps
    // the contract explicit rather than implied by the key encoding.
    out.sort_by_key(|(sequence, _)| *sequence);
    Ok(out)
}

fn evidence_sequence_from_key(key: &[u8]) -> Result<u64> {
    let suffix = key
        .get(EVIDENCE_PREFIX.len()..)
        .ok_or(invalid("attribution evidence key is truncated"))?;
    decode_u64(suffix, "attribution evidence key")
}

fn decode_u64(raw: &[u8], context: &'static str) -> Result<u64> {
    let _ = context;
    let bytes: [u8; SEQUENCE_LEN] = raw
        .try_into()
        .map_err(|_| invalid("attribution counter must be 8 bytes"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn optional_entity(id: Option<EntityId>) -> Value {
    id.map_or(Value::Nil, |id| Value::Binary(id.as_bytes().to_vec()))
}

fn optional_bool(flag: Option<bool>) -> Value {
    flag.map_or(Value::Nil, Value::Boolean)
}

fn encode_evidence(evidence: &OutcomeEvidence, sequence: u64) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_SEQUENCE), Value::from(sequence)),
        (
            Value::from(KEY_RECEIPT_REF),
            Value::from(evidence.receipt_ref.as_str()),
        ),
        (
            Value::from(KEY_ACTOR),
            Value::Binary(evidence.actor.as_bytes().to_vec()),
        ),
        (Value::from(KEY_SKILL), optional_entity(evidence.skill)),
        (
            Value::from(KEY_OUTCOME),
            Value::from(evidence.outcome.as_str()),
        ),
        (
            Value::from(KEY_FOLLOWED_SKILL),
            optional_bool(evidence.followed_skill),
        ),
        (
            Value::from(KEY_SKILL_COVERED_STEP),
            optional_bool(evidence.skill_covered_step),
        ),
        (Value::from(KEY_AT), Value::from(evidence.at)),
    ])
}

fn decode_evidence(raw: &[u8]) -> Result<OutcomeEvidence> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut receipt_ref = None;
    let mut actor = None;
    let mut skill = None;
    let mut outcome = None;
    let mut followed_skill = None;
    let mut skill_covered_step = None;
    let mut at = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_SEQUENCE => {}
            KEY_RECEIPT_REF => receipt_ref = value.as_str().map(str::to_owned),
            KEY_ACTOR => actor = Some(decode_entity(value)?),
            KEY_SKILL => skill = decode_optional_entity(value)?,
            KEY_OUTCOME => outcome = value.as_str().and_then(AttemptOutcome::parse),
            KEY_FOLLOWED_SKILL => followed_skill = value.as_bool(),
            KEY_SKILL_COVERED_STEP => skill_covered_step = value.as_bool(),
            KEY_AT => at = value.as_u64(),
            _ => return Err(invalid("attribution evidence key is not pinned")),
        }
    }
    Ok(OutcomeEvidence {
        receipt_ref: receipt_ref.ok_or(invalid("attribution evidence missing receipt"))?,
        actor: actor.ok_or(invalid("attribution evidence missing actor"))?,
        skill,
        outcome: outcome.ok_or(invalid("attribution evidence missing outcome"))?,
        followed_skill,
        skill_covered_step,
        at: at.ok_or(invalid("attribution evidence missing timestamp"))?,
    })
}

fn encode_judgment(judgment: &AttributionJudgment) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_SEQUENCE), Value::from(judgment.sequence)),
        (
            Value::from(KEY_VERDICT),
            Value::from(judgment.verdict.as_str()),
        ),
        (
            Value::from(KEY_SUBJECT),
            Value::Binary(judgment.subject.as_bytes().to_vec()),
        ),
        (
            Value::from(KEY_EVIDENCE_RECEIPTS),
            Value::Array(
                judgment
                    .evidence_receipts
                    .iter()
                    .map(|receipt| Value::from(receipt.as_str()))
                    .collect(),
            ),
        ),
        (Value::from(KEY_AT), Value::from(judgment.at)),
    ])
}

fn decode_judgment(raw: &[u8]) -> Result<AttributionJudgment> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut sequence = None;
    let mut verdict = None;
    let mut subject = None;
    let mut evidence_receipts = None;
    let mut at = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_SEQUENCE => sequence = value.as_u64(),
            KEY_VERDICT => verdict = value.as_str().and_then(AttributionVerdict::parse),
            KEY_SUBJECT => subject = Some(decode_entity(value)?),
            KEY_EVIDENCE_RECEIPTS => {
                let rows = value
                    .as_array()
                    .ok_or(invalid("attribution judgment evidence must be an array"))?;
                let mut receipts = Vec::with_capacity(rows.len());
                for row in rows {
                    receipts.push(
                        row.as_str()
                            .ok_or(invalid("attribution judgment evidence must be strings"))?
                            .to_owned(),
                    );
                }
                evidence_receipts = Some(receipts);
            }
            KEY_AT => at = value.as_u64(),
            _ => return Err(invalid("attribution judgment key is not pinned")),
        }
    }
    Ok(AttributionJudgment {
        sequence: sequence.ok_or(invalid("attribution judgment missing sequence"))?,
        verdict: verdict.ok_or(invalid("attribution judgment missing verdict"))?,
        subject: subject.ok_or(invalid("attribution judgment missing subject"))?,
        evidence_receipts: evidence_receipts
            .ok_or(invalid("attribution judgment missing evidence"))?,
        at: at.ok_or(invalid("attribution judgment missing timestamp"))?,
    })
}

fn encode_audit(report: &AttributionAuditReport) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(SKILL_ATTRIBUTION_SCHEMA_VERSION),
        ),
        (Value::from(KEY_TOTAL), Value::from(report.total as u64)),
        (Value::from(KEY_PASSED), Value::from(report.passed as u64)),
        (
            Value::from(KEY_ABSTAINED),
            Value::from(report.abstained as u64),
        ),
        (Value::from(KEY_AT), Value::from(report.at)),
    ])
}

fn decode_audit(raw: &[u8]) -> Result<AttributionAuditReport> {
    let value = decode_value(raw)?;
    let entries = expect_map(&value)?;
    let mut total = None;
    let mut passed = None;
    let mut abstained = None;
    let mut at = None;
    for (key, value) in entries {
        match expect_key(key)? {
            KEY_SCHEMA_VERSION => require_schema_version(value)?,
            KEY_TOTAL => total = value.as_u64(),
            KEY_PASSED => passed = value.as_u64(),
            KEY_ABSTAINED => abstained = value.as_u64(),
            KEY_AT => at = value.as_u64(),
            _ => return Err(invalid("attribution audit key is not pinned")),
        }
    }
    let count = |value: Option<u64>| -> Result<usize> {
        usize::try_from(value.ok_or(invalid("attribution audit missing count"))?)
            .map_err(|_| invalid("attribution audit count exceeds usize"))
    };
    Ok(AttributionAuditReport {
        total: count(total)?,
        passed: count(passed)?,
        abstained: count(abstained)?,
        at: at.ok_or(invalid("attribution audit missing timestamp"))?,
    })
}

fn require_schema_version(value: &Value) -> Result<()> {
    if value.as_u64() == Some(SKILL_ATTRIBUTION_SCHEMA_VERSION) {
        return Ok(());
    }
    Err(invalid("unsupported skill attribution schema"))
}

fn decode_entity(value: &Value) -> Result<EntityId> {
    let bytes: [u8; 16] = value
        .as_slice()
        .ok_or(invalid("attribution entity ref must be binary"))?
        .try_into()
        .map_err(|_| invalid("attribution entity ref must be 16 bytes"))?;
    EntityId::from_bytes(bytes)
}

fn decode_optional_entity(value: &Value) -> Result<Option<EntityId>> {
    if matches!(value, Value::Nil) {
        return Ok(None);
    }
    decode_entity(value).map(Some)
}

fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| invalid("skill attribution MessagePack encode failed"))?;
    Ok(encoded)
}

fn decode_value(raw: &[u8]) -> Result<Value> {
    rmpv::decode::read_value(&mut Cursor::new(raw))
        .map_err(|_| invalid("skill attribution MessagePack decode failed"))
}

fn expect_map(value: &Value) -> Result<&Vec<(Value, Value)>> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid("skill attribution row must be a MessagePack map")),
    }
}

fn expect_key(key: &Value) -> Result<&str> {
    key.as_str()
        .ok_or(invalid("skill attribution keys must be strings"))
}

#[cfg(test)]
mod tests;
