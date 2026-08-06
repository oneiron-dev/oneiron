//! ARCH-0053 §4/§9 `actor.*` claim ledger (SK-06, ONE-1739): what the system
//! has learned ABOUT AN ACTOR, written by projectors and the Dreamer — never
//! by the actor itself.
//!
//! ```text
//! TASK lane   ATTEMPT receipt ─▶ SK-04 projector ─▶ ExecutionLapse judgment ─┐
//!                                                                            ├─▶ write_actor_claim ─▶ actor.* CLAIM
//! CHAT lane   SESSION/TURN ────▶ SessionEnd wake ─▶ Dreamer distill ─────────┘        (the ONE door)
//! ```
//!
//! **Two inlets, one ledger.** The lanes differ in what they observe (a task's
//! receipts vs. a sitting's turns) and in nothing else: both mint the same four
//! rows, through the same chokepoint, with the same evidence obligation. That
//! is the shape ARCH-0053 §3 asks for — chat and task COMPOSE, they never blur
//! — and it is why [`write_actor_claim`] takes the evidence as a typed enum
//! rather than letting each caller stamp its own provenance.
//!
//! **The rows (§G.1 cardinalities are the contract).**
//!
//! | predicate | value | cardinality |
//! |---|---|---|
//! | [`PREDICATE_ACTOR_LESSON`] | normalized note | SET, keyed on the text |
//! | [`PREDICATE_ACTOR_FAILURE_MODE`] | normalized note | SET, keyed on the text |
//! | [`PREDICATE_ACTOR_SCOPE_NOTE`] | normalized note | SET, keyed on the text |
//! | [`PREDICATE_ACTOR_SKILL_FIT`] | fit in `0..=1` | ONE per `(actor, skill)`, superseding |
//!
//! A set row DEDUPES rather than supersedes: two different lessons are two
//! standing facts, and re-observing one is not news. `skill_fit` is the
//! opposite — it is a current estimate, so a new one closes the old head and
//! the pair scope (`{skill}`) is the conflict-set key. Scoping fit per PAIR
//! rather than per actor is load-bearing: an actor good at one skill and bad at
//! another has two live rows, and the router ([`skill_fit_for`], SK-05's
//! bandit) reads exactly the one it asked about.
//!
//! **Namespace, not `agent.*` (r1).** Actors are agents AND humans AND peers
//! AND connectors; the ledger is about whoever acted. `actor.*` joins `edge.*`
//! and `skill.*` as an engine-reserved namespace: these are STATES with
//! meaning-by-projection (doc-13 r1/r3), so a public `put_claim` of one is
//! rejected with [`Error::ReservedPredicate`] and every write goes through an
//! engine door. That reservation also closes the hole
//! [`crate::provider_confidence`] documented on its own `actor.confidence_prior`
//! head — a policy-authorized generic write could plant a trust-bearing prior
//! this engine would then honor. It cannot any more.
//!
//! **Lineage is derived, never declared.** The claim body is built INSIDE the
//! writer (the `dreamer_promotion` house law: callers never construct their own
//! provenance, so source honesty is unforgeable). Two provenance facts ride
//! different fields, deliberately:
//!
//! * `src` is [`ClaimSource::Observed`] on every row — the projector and the
//!   Dreamer OBSERVED the trace, which is the same stamp the sibling
//!   `actor.confidence_prior` and `skill.reliability` projections carry. It is
//!   also this ledger's federation boundary: the cross-vault door restamps
//!   foreign claims `src → Imported`, and [`validate_actor_claim_structure`]
//!   then refuses them, so a peer's opinion of who is careless never enters
//!   this vault's routing signal. (`src` is additionally the consent axis: a
//!   derived source demands an explicit policy auto-permit, and these rows are
//!   `Auto`, so a `ToolOutput` stamp here would not be a truer label — it would
//!   be a different, wrong claim about consent.)
//! * [`ACTOR_CLAIM_LINEAGE_KEY`] inside the evidence map carries the EVIDENCE
//!   MEET: `tool_output` for a TASK-lane row resting on attempt receipts,
//!   `generated` for a CHAT-lane row distilled from turns. That is the fact
//!   ONE-1314's posture protects — a trivially-`generated` restamp of
//!   receipt-derived evidence would launder the trail — and it is enforced at
//!   the door rather than kept by convention: a row whose evidence carries no
//!   known lineage is refused on every write path, replication included.
//!
//! **The engine distills nothing.** Turning a sitting into a craft note is a
//! generative act, so [`run_session_end_actor_distill`] takes a
//! [`SessionActorDistiller`] — the same host-supplied-tier seam
//! [`crate::skill_attribution::AttributionJudge`] uses, budgeted under
//! [`actor_distill_call_purpose`]. This module constructs no LLM client. The
//! TASK lane needs none: `ExecutionLapse` is a routing DECISION with exactly
//! one derivable class, so its two rows are derivations, not inventions.

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::llm::CallPurpose;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION,
    ENTITY_TYPE_TURN,
};
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict, attribution_judgments};
use crate::temporal::TimeRange;

/// Distilled craft note about an actor. SET cardinality (§G.1).
pub const PREDICATE_ACTOR_LESSON: &str = "actor.lesson";

/// Recurring lapse pattern — the routing signal a spawner reads. SET.
pub const PREDICATE_ACTOR_FAILURE_MODE: &str = "actor.failure_mode";

/// What this actor is FOR, feeding spawn/routing decisions. SET.
pub const PREDICATE_ACTOR_SCOPE_NOTE: &str = "actor.scope_note";

/// Per-`(actor, skill)` effectiveness in `0..=1`. ONE per pair, superseding.
pub const PREDICATE_ACTOR_SKILL_FIT: &str = "actor.skill_fit";

/// Scope key naming the SKILL half of a [`PREDICATE_ACTOR_SKILL_FIT`] pair.
/// The scope IS the conflict set: two rows collide iff their skill matches.
pub const ACTOR_SKILL_FIT_SCOPE_KEY: &str = "skill";

/// [`CallPurpose::Other`] name for the CHAT-lane distillation tier, so session
/// distillation is budgeted and audited as its own class instead of hiding
/// inside consolidation's totals.
pub const ACTOR_DISTILL_CALL_PURPOSE_NAME: &str = "actor_session_distill";

/// Maximum UTF-8 length of a note. Notes are craft memory, not transcripts —
/// a row that needs more than this is citing, not distilling.
pub const ACTOR_NOTE_MAX_BYTES: usize = 1024;

/// Upper bound on the evidence refs one row cites. The trace is a citation
/// list, and a citation list that grows without bound turns a claim body into
/// a ledger (the `skill.reliability` bound, same reasoning).
pub const ACTOR_CLAIM_MAX_CITED_EVIDENCE: usize = 64;

/// The failure mode `ExecutionLapse` names.
///
/// SK-04 routes `ExecutionLapse` on exactly one fact pattern: a FAILED attempt
/// whose actor departed from a skill its pack had loaded. So this is a
/// derivation of the routing decision, not a judgement of taste — and the token
/// is machine-readable because the router reads it back.
pub const LAPSE_FAILURE_MODE: &str = "departed_from_loaded_skill";

/// The lesson that lapse class teaches. Pinned beside the class it belongs to:
/// one class, one remedy. Situation-specific notes are the CHAT lane's
/// distiller tier, which is why this table does not grow with usage — it grows
/// only when SK-04 learns to route a new lapse class.
pub const LAPSE_LESSON: &str = "re-read a loaded skill before improvising a step it covers";

/// `actor_claims:distill_pending:v1:` + session id (16 B) → ended_at (8 BE).
///
/// The durable SessionEnd → distill JOB. Written in the SAME transaction that
/// closes the sitting, so a crash between "session ended" and "distill queued"
/// is not representable; consumed by [`run_session_end_actor_distill`].
const DISTILL_PENDING_PREFIX: &[u8] = b"actor_claims:distill_pending:v1:";

/// Evidence-map key carrying the EVIDENCE MEET of a row: the
/// [`ClaimSource`] wire string of what the row actually rests on. See the
/// module header — this is the lineage `src` deliberately does not carry.
pub const ACTOR_CLAIM_LINEAGE_KEY: &str = "lineage";

const KEY_LANE: &str = "lane";
const KEY_RECEIPTS: &str = "receipts";
const KEY_SESSION: &str = "session";
const KEY_TURNS: &str = "turns";
const KEY_AT: &str = "at";

const LANE_TASK: &str = "task";
const LANE_CHAT: &str = "chat";

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// One `actor.*` row, before it is a claim.
///
/// Owning the four shapes in one enum is what makes [`write_actor_claim`] a
/// chokepoint rather than a convention: a fifth row kind cannot be written
/// without a variant here, and every variant lands through the same door.
/// (ED-03/ONE-1759 adds its `EditCost` arm here after this stack merges.)
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ActorClaimRow {
    Lesson {
        actor: EntityId,
        text: String,
    },
    FailureMode {
        actor: EntityId,
        text: String,
    },
    ScopeNote {
        actor: EntityId,
        text: String,
    },
    SkillFit {
        actor: EntityId,
        skill: EntityId,
        fit: f32,
    },
}

/// Which of the three SET-cardinality note rows a distilled note becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ActorNoteKind {
    Lesson,
    FailureMode,
    ScopeNote,
}

impl ActorNoteKind {
    /// The predicate this note kind writes.
    #[must_use]
    pub const fn predicate(self) -> &'static str {
        match self {
            Self::Lesson => PREDICATE_ACTOR_LESSON,
            Self::FailureMode => PREDICATE_ACTOR_FAILURE_MODE,
            Self::ScopeNote => PREDICATE_ACTOR_SCOPE_NOTE,
        }
    }

    fn row(self, actor: EntityId, text: String) -> ActorClaimRow {
        match self {
            Self::Lesson => ActorClaimRow::Lesson { actor, text },
            Self::FailureMode => ActorClaimRow::FailureMode { actor, text },
            Self::ScopeNote => ActorClaimRow::ScopeNote { actor, text },
        }
    }
}

/// One note a distiller produced, naming the actor it is ABOUT.
///
/// The actor rides the note rather than the brief because a sitting can teach
/// about several actors at once (the agent, a peer it consulted, the human):
/// "actors = agents + humans + peers + connectors" is the namespace's whole
/// point, and a brief-level actor would flatten it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorNote {
    pub actor: EntityId,
    pub kind: ActorNoteKind,
    pub text: String,
}

impl ActorClaimRow {
    /// The predicate this row writes.
    #[must_use]
    pub const fn predicate(&self) -> &'static str {
        match self {
            Self::Lesson { .. } => PREDICATE_ACTOR_LESSON,
            Self::FailureMode { .. } => PREDICATE_ACTOR_FAILURE_MODE,
            Self::ScopeNote { .. } => PREDICATE_ACTOR_SCOPE_NOTE,
            Self::SkillFit { .. } => PREDICATE_ACTOR_SKILL_FIT,
        }
    }

    /// The ACTOR entity this row is about.
    #[must_use]
    pub const fn actor(&self) -> EntityId {
        match self {
            Self::Lesson { actor, .. }
            | Self::FailureMode { actor, .. }
            | Self::ScopeNote { actor, .. }
            | Self::SkillFit { actor, .. } => *actor,
        }
    }

    /// Validates the payload and renders `(value, scope)`.
    ///
    /// Notes normalize before they are compared, so the SET key is the note's
    /// MEANING as far as the ledger can see it: `"  Cite the receipt  "` and
    /// `"cite the receipt"` are the same standing fact and must not become two
    /// rows.
    fn value_and_scope(&self) -> Result<(Value, Option<Value>)> {
        match self {
            Self::Lesson { text, .. }
            | Self::FailureMode { text, .. }
            | Self::ScopeNote { text, .. } => Ok((Value::from(normalize_note(text)?), None)),
            Self::SkillFit { skill, fit, .. } => {
                // Non-finite is rejected explicitly: NaN fails every range
                // comparison, so a `contains` check ALONE would silently admit
                // it and poison every downstream ranking.
                if !fit.is_finite() || !(0.0..=1.0).contains(fit) {
                    return Err(invalid("actor.skill_fit must be a finite fit in 0..=1"));
                }
                Ok((Value::F32(*fit), Some(skill_fit_scope(skill))))
            }
        }
    }
}

/// Trims and collapses interior whitespace; rejects an empty or oversized note.
fn normalize_note(text: &str) -> Result<String> {
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        return Err(invalid("actor note must be non-empty"));
    }
    if normalized.len() > ACTOR_NOTE_MAX_BYTES {
        return Err(invalid("actor note exceeds the note length bound"));
    }
    Ok(normalized)
}

fn skill_fit_scope(skill: &EntityId) -> Value {
    Value::Map(vec![(
        Value::from(ACTOR_SKILL_FIT_SCOPE_KEY),
        Value::Binary(skill.as_bytes().to_vec()),
    )])
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// Which inlet observed the fact, and what it observed.
///
/// This is not a label: the writer derives the claim's `src` lineage and its
/// evidence payload from this value, so an inlet cannot claim a trail it does
/// not have.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ActorClaimLane {
    /// RS1 pack-receipt ids the routed judgment rested on.
    Task { receipts: Vec<String> },
    /// The sitting and the turns it distilled from.
    Chat {
        session: EntityId,
        turns: Vec<EntityId>,
    },
}

/// The trace a row rests on, plus when it was observed.
///
/// Constructed through the two lane constructors — there is no "no evidence"
/// shape, because a row with nothing to cite is the thing the doctrine header
/// exists to refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorClaimEvidence {
    lane: ActorClaimLane,
    at: u64,
}

impl ActorClaimEvidence {
    /// TASK-lane evidence: the pack receipts the judgment cited.
    pub fn task(receipts: Vec<String>, at: u64) -> Result<Self> {
        if receipts.is_empty() {
            return Err(invalid("a task-lane actor row must cite a receipt"));
        }
        if receipts.len() > ACTOR_CLAIM_MAX_CITED_EVIDENCE {
            return Err(invalid("actor row cites more evidence than the bound"));
        }
        Ok(Self {
            lane: ActorClaimLane::Task { receipts },
            at,
        })
    }

    /// CHAT-lane evidence: the sitting and the turns distilled from it.
    pub fn chat(session: EntityId, turns: Vec<EntityId>, at: u64) -> Result<Self> {
        if turns.is_empty() {
            return Err(invalid("a chat-lane actor row must cite a turn"));
        }
        if turns.len() > ACTOR_CLAIM_MAX_CITED_EVIDENCE {
            return Err(invalid("actor row cites more evidence than the bound"));
        }
        Ok(Self {
            lane: ActorClaimLane::Chat { session, turns },
            at,
        })
    }

    /// When the observation happened.
    #[must_use]
    pub const fn at(&self) -> u64 {
        self.at
    }

    /// The evidence meet this lane earns — see the module header's lineage
    /// note. Derived here and nowhere else, so it cannot be passed in.
    const fn lineage(&self) -> ClaimSource {
        match self.lane {
            // Attempt receipts ARE tool output; a row resting on them says so.
            ActorClaimLane::Task { .. } => ClaimSource::ToolOutput,
            // A distilled note is model-written prose over turns.
            ActorClaimLane::Chat { .. } => ClaimSource::Generated,
        }
    }

    fn to_value(&self) -> Value {
        let mut entries = vec![
            (Value::from(KEY_AT), Value::from(self.at)),
            (
                Value::from(ACTOR_CLAIM_LINEAGE_KEY),
                Value::from(self.lineage().as_str()),
            ),
        ];
        match &self.lane {
            ActorClaimLane::Task { receipts } => {
                entries.push((Value::from(KEY_LANE), Value::from(LANE_TASK)));
                entries.push((
                    Value::from(KEY_RECEIPTS),
                    Value::Array(receipts.iter().map(|r| Value::from(r.as_str())).collect()),
                ));
            }
            ActorClaimLane::Chat { session, turns } => {
                entries.push((Value::from(KEY_LANE), Value::from(LANE_CHAT)));
                entries.push((
                    Value::from(KEY_SESSION),
                    Value::Binary(session.as_bytes().to_vec()),
                ));
                entries.push((
                    Value::from(KEY_TURNS),
                    Value::Array(
                        turns
                            .iter()
                            .map(|id| Value::Binary(id.as_bytes().to_vec()))
                            .collect(),
                    ),
                ));
            }
        }
        Value::Map(entries)
    }
}

// ---------------------------------------------------------------------------
// The write chokepoint
// ---------------------------------------------------------------------------

/// THE `actor.*` write door. Both inlets land here or they do not land.
///
/// The claim body is built here — approval, confidence, source and evidence are
/// the writer's, never the caller's — so "projector-authored, evidence-carrying"
/// is a structural property of the ledger rather than a habit callers keep.
///
/// Cardinality is enforced in the same write transaction that lands the row:
///
/// * SET rows (lesson / failure_mode / scope_note) DEDUPE on the normalized
///   note. A duplicate returns the standing row's id and writes nothing — an
///   observation repeated is not an observation added.
/// * [`PREDICATE_ACTOR_SKILL_FIT`] SUPERSEDES every active head sharing its
///   `(actor, skill)` scope. Every head, not the first found: `EntityId::now()`
///   is per-replica unique, so two replicas that each estimated this pair hold
///   two distinct claim entities, and after a sync both are Active. Closing one
///   would leave the other live forever.
pub fn write_actor_claim(
    vault: &Vault,
    row: ActorClaimRow,
    evidence: &ActorClaimEvidence,
) -> Result<EntityId> {
    let predicate = row.predicate();
    let actor = row.actor();
    let (value, scope) = row.value_and_scope()?;
    require_actor_entity(vault, &actor)?;
    if let ActorClaimRow::SkillFit { skill, .. } = &row {
        require_skill_entity(vault, skill)?;
    }

    let at = evidence.at;
    let evidence_value = evidence.to_value();

    vault.with_write_txn(move |wtxn| {
        let heads = active_heads_in_txn(vault, wtxn, &actor, predicate)?;
        // The SET key is the value; the fit key is the scope. Same lookup, two
        // conflict definitions — which is exactly what §G.1 pins.
        if scope.is_none()
            && let Some((id, _, _)) = heads.iter().find(|(_, body, _)| body.value == value)
        {
            return Ok(*id);
        }

        let claim_id = EntityId::now();
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(actor),
            value,
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.evidence = Some(evidence_value);
        body.scope = scope;
        body.valid_from = Some(at);
        body.source = Some(ClaimSource::Observed);
        vault.put_reserved_claim_in_txn(
            wtxn,
            &claim_id,
            &body,
            TimeRange { start: at, end: at },
            at,
        )?;

        if body.scope.is_some() {
            for (head_id, head, head_start) in &heads {
                if head.scope != body.scope {
                    continue;
                }
                // `at.max(head_start)` mirrors the scan-verdict clamp: the
                // supersession re-Puts the old row over `{head_start, now}`,
                // and an out-of-order event time would make that range invalid
                // and roll the whole transaction back — permanently, since the
                // retry re-derives the same `at`.
                vault.supersede_reserved_claim_in_txn(
                    wtxn,
                    &claim_id,
                    head_id,
                    at.max(*head_start),
                )?;
            }
        }
        Ok(claim_id)
    })
}

/// The active `(actor, predicate)` heads with their occurred-start stamps.
fn active_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    actor: &EntityId,
    predicate: &str,
) -> Result<Vec<(EntityId, ClaimBody, u64)>> {
    let mut rows = Vec::new();
    for id in vault.claims_for_subject_in_txn(rtxn, actor)? {
        let Some(body) = vault.get_claim_in_txn(rtxn, &id)? else {
            continue;
        };
        if body.predicate != predicate || body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        let raw = vault
            .store
            .entities
            .get(rtxn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("actor claim entity"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        rows.push((id, body, header.occurred_start));
    }
    Ok(rows)
}

/// An `actor.*` subject must be an entity that can ACT (the D13 actor matrix:
/// PERSON covers humans and agent identities, AGENT_DEF is a defined agent,
/// MACHINE is a system actor). Claiming a lesson against a TURN or an ORG is a
/// routing bug, and a ledger that accepts it is unreadable by the router.
fn require_actor_entity(vault: &Vault, actor: &EntityId) -> Result<()> {
    match vault.get_entity_type(actor)? {
        Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF | ENTITY_TYPE_MACHINE) => Ok(()),
        Some(_) => Err(invalid("actor.* subject must be an actor entity")),
        None => Err(Error::EntityNotFound),
    }
}

/// The skill half of a fit pair must be a real SKILL record — otherwise the
/// scope names nothing and the conflict set is undefined.
fn require_skill_entity(vault: &Vault, skill: &EntityId) -> Result<()> {
    if vault.get_skill_record(skill)?.is_none() {
        return Err(Error::EntityNotFound);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Read path (router / SK-05 bandit join point)
// ---------------------------------------------------------------------------

/// The live fit estimate for `(actor, skill)`, or `None` when the pair has none.
///
/// The join point ED-07 and the SK-05 bandit read. Two active heads for one
/// pair is a legitimate post-sync convergence state (see [`write_actor_claim`]),
/// not corruption, so the newest head wins deterministically — by `valid_from`,
/// then claim id — rather than bricking every read with an error.
pub fn skill_fit_for(vault: &Vault, actor: &EntityId, skill: &EntityId) -> Result<Option<f32>> {
    let scope = skill_fit_scope(skill);
    let rtxn = vault.store.env.read_txn()?;
    let mut best: Option<(u64, EntityId, f32)> = None;
    for (id, body, _) in active_heads_in_txn(vault, &rtxn, actor, PREDICATE_ACTOR_SKILL_FIT)? {
        if body.scope.as_ref() != Some(&scope) {
            continue;
        }
        let Value::F32(fit) = body.value else {
            return Err(invalid("actor.skill_fit value must be a fit in 0..=1"));
        };
        let valid_from = body.valid_from.unwrap_or(0);
        let newer = match &best {
            None => true,
            Some((best_from, best_id, _)) => {
                valid_from > *best_from || (valid_from == *best_from && id > *best_id)
            }
        };
        if newer {
            best = Some((valid_from, id, fit));
        }
    }
    Ok(best.map(|(_, _, fit)| fit))
}

// ---------------------------------------------------------------------------
// TASK lane — SK-04 lapse judgments → rows
// ---------------------------------------------------------------------------

/// Projects `ExecutionLapse` judgments into `actor.lesson` +
/// `actor.failure_mode` rows, returning the claim ids this pass landed.
///
/// **Every judgment is re-grounded, not trusted** (the ONE-1738 posture, same
/// reasoning): [`AttributionJudgment`] is a public type with public fields, so
/// the argument is caller-owned data, and this function authors reserved truth.
/// A row counts only if it IS the row SK-04's projector persisted at that
/// sequence, its subject is a real actor entity, and its citation resolves to a
/// stamped pack receipt. Ungrounded rows are SKIPPED rather than fatal: one
/// forged row must not deny a whole pass.
///
/// Idempotent by cardinality, not by cursor: the lapse class writes the same
/// two normalized notes every time, and SET rows dedupe, so re-running a pass
/// over the same judgments re-returns the same two ids instead of growing the
/// ledger.
pub fn project_actor_claims_from_judgments(
    vault: &Vault,
    judgments: &[AttributionJudgment],
) -> Result<Vec<EntityId>> {
    let persisted = attribution_judgments(vault)?;
    let mut written = Vec::new();
    for judgment in judgments {
        if judgment.verdict != AttributionVerdict::ExecutionLapse {
            continue;
        }
        if require_actor_entity(vault, &judgment.subject).is_err() {
            continue;
        }
        // A judgment with nothing to cite has no trace, and a citation naming
        // no stamped receipt is a trace only in shape.
        let Some(receipt_ref) = judgment.evidence_receipts.first() else {
            continue;
        };
        if crate::receipt::attempt_pack_receipt(vault, receipt_ref)?.is_none() {
            continue;
        }
        // Grounded is not authorized: this row must also BE the row SK-04
        // routed at this sequence.
        if !persisted
            .iter()
            .any(|row| row.sequence == judgment.sequence && row == judgment)
        {
            continue;
        }

        let evidence = ActorClaimEvidence::task(judgment.evidence_receipts.clone(), judgment.at)?;
        for (kind, text) in [
            (ActorNoteKind::FailureMode, LAPSE_FAILURE_MODE),
            (ActorNoteKind::Lesson, LAPSE_LESSON),
        ] {
            written.push(write_actor_claim(
                vault,
                kind.row(judgment.subject, text.to_owned()),
                &evidence,
            )?);
        }
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// CHAT lane — SessionEnd distillation
// ---------------------------------------------------------------------------

/// One turn of the sitting, as the distiller sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDistillTurn {
    pub turn: EntityId,
    pub speaker: Option<String>,
    pub text: Option<String>,
}

/// What a session-end distillation gets to reason over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDistillBrief {
    /// The ended sitting.
    pub session: EntityId,
    /// When it ended — the `at` every minted row is stamped with.
    pub ended_at: u64,
    /// Its turns, in `(learned_at, id)` scan order.
    pub turns: Vec<SessionDistillTurn>,
}

/// Distills an ended sitting into actor notes, or returns none.
///
/// The host-supplied LLM tier implements this against the engine's existing LLM
/// surface under [`actor_distill_call_purpose`]; this module constructs no
/// client (the `dreamer_consolidation` extract/merge posture). Returning an
/// empty vec is a first-class answer: a sitting that taught nothing teaches
/// nothing, and a distiller that invents a lesson to have one is the failure
/// mode this seam exists to keep out of the engine.
pub trait SessionActorDistiller {
    /// The notes `brief` supports.
    fn distill(&self, brief: &SessionDistillBrief) -> Result<Vec<ActorNote>>;
}

/// The [`CallPurpose`] a distiller's LLM tier must stamp.
#[must_use]
pub fn actor_distill_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: ACTOR_DISTILL_CALL_PURPOSE_NAME.to_owned(),
    }
}

/// Registers the SessionEnd → distill job inside the caller's close
/// transaction (`Vault::end_session_with_wake`'s commit).
///
/// Same transaction as the close on purpose: the job row is what makes "this
/// sitting is over and unlearned-from" a durable fact rather than a live
/// process's intention.
pub(crate) fn register_session_end_distill_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    session: &EntityId,
    ended_at: u64,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .put(wtxn, &distill_job_key(session), &ended_at.to_be_bytes())?;
    Ok(())
}

/// Sittings that have ended and not yet been distilled, in id order.
pub fn pending_session_actor_distills(vault: &Vault) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut out = Vec::new();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, DISTILL_PENDING_PREFIX)?
    {
        let (key, _) = row?;
        let Some(raw) = key.get(DISTILL_PENDING_PREFIX.len()..) else {
            continue;
        };
        let bytes: [u8; ENTITY_ID_LEN] = raw
            .try_into()
            .map_err(|_| Error::CorruptedIndex("actor distill job key"))?;
        out.push(
            EntityId::from_bytes(bytes)
                .map_err(|_| Error::CorruptedIndex("actor distill job key"))?,
        );
    }
    Ok(out)
}

/// Runs the CHAT-lane inlet for one ended sitting: brief → distiller → the same
/// [`write_actor_claim`] door the TASK lane uses. Returns the claim ids landed.
///
/// **Plain chatting mints no TASK (08b r13).** This path writes CLAIM entities
/// and clears its own job row; it has no task-minting door in reach, and that
/// is the boundary rather than a promise. The moment a sitting spawns real
/// work, THAT moment mints a TASK through the surface that spawns it — lanes
/// compose, they never blur.
///
/// The job row is required: distillation runs at session END, and without the
/// row there is no evidence the sitting is over. The row is cleared in the same
/// pass, so a re-run over an already-distilled sitting is a typed no-such-job
/// rather than a second helping of the same notes.
pub fn run_session_end_actor_distill(
    vault: &Vault,
    session: &EntityId,
    distiller: &dyn SessionActorDistiller,
) -> Result<Vec<EntityId>> {
    let ended_at = take_distill_job(vault, session)?;
    let brief = SessionDistillBrief {
        session: *session,
        ended_at,
        turns: session_turns(vault, session)?,
    };
    if brief.turns.is_empty() {
        return Ok(Vec::new());
    }

    let turn_ids: Vec<EntityId> = brief.turns.iter().map(|turn| turn.turn).collect();
    let evidence = ActorClaimEvidence::chat(*session, turn_ids, ended_at)?;
    let mut written = Vec::new();
    for note in distiller.distill(&brief)? {
        written.push(write_actor_claim(
            vault,
            note.kind.row(note.actor, note.text),
            &evidence,
        )?);
    }
    Ok(written)
}

/// Claims the pending job for `session`, returning its `ended_at`.
fn take_distill_job(vault: &Vault, session: &EntityId) -> Result<u64> {
    vault.with_write_txn(|wtxn| {
        let key = distill_job_key(session);
        let Some(raw) = vault.store.vault_meta.get(&*wtxn, &key)? else {
            return Err(invalid("no session-end distill job for this session"));
        };
        let bytes: [u8; 8] = raw
            .as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("actor distill job row"))?;
        let ended_at = u64::from_be_bytes(bytes);
        vault.store.vault_meta.delete(wtxn, &key)?;
        Ok(ended_at)
    })
}

/// The sitting's turns: TURN entities with a `ChildOf` edge into the session.
fn session_turns(vault: &Vault, session: &EntityId) -> Result<Vec<SessionDistillTurn>> {
    if vault.get_entity_type(session)? != Some(ENTITY_TYPE_SESSION) {
        return Err(invalid("session-end distill subject must be a SESSION"));
    }
    // `edges_in` reports the FAR end in `target`, so these are the children.
    let children: Vec<EntityId> = vault
        .edges_in(session)?
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::ChildOf)
        .map(|edge| edge.target)
        .collect();

    let rtxn = vault.store.env.read_txn()?;
    let mut turns: Vec<(u64, SessionDistillTurn)> = Vec::new();
    for child in children {
        let Some(raw) = vault.store.entities.get(&rtxn, child.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_TURN {
            continue;
        }
        let (speaker, text) = turn_speaker_and_text(&raw[ENTITY_METADATA_HEADER_LEN..]);
        turns.push((
            header.learned_at,
            SessionDistillTurn {
                turn: child,
                speaker,
                text,
            },
        ));
    }
    turns.sort_by_key(|(learned_at, turn)| (*learned_at, turn.turn));
    Ok(turns.into_iter().map(|(_, turn)| turn).collect())
}

/// Reads the two documented TURN body keys (both spellings), tolerating any
/// other shape: an undecodable turn is still a turn that happened.
fn turn_speaker_and_text(raw: &[u8]) -> (Option<String>, Option<String>) {
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(raw)) else {
        return (None, None);
    };
    let mut speaker = None;
    let mut text = None;
    for (key, value) in entries {
        match key.as_str() {
            Some("spkr" | "speaker") if speaker.is_none() => {
                speaker = value.as_str().map(str::to_owned);
            }
            Some("txt" | "text") if text.is_none() => text = value.as_str().map(str::to_owned),
            _ => {}
        }
    }
    (speaker, text)
}

fn distill_job_key(session: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(DISTILL_PENDING_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(DISTILL_PENDING_PREFIX);
    key.extend_from_slice(session.as_bytes());
    key
}

// ---------------------------------------------------------------------------
// Structural validator (the claim.rs predicate-aware branch)
// ---------------------------------------------------------------------------

/// Whether `predicate` is one of the four §G.1 `actor.*` rows this module owns.
///
/// `actor.confidence_prior` is deliberately NOT here: it is
/// [`crate::provider_confidence`]'s row, with its own structural validator, and
/// it shares only the reserved namespace.
#[must_use]
pub fn is_actor_claim_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        PREDICATE_ACTOR_LESSON
            | PREDICATE_ACTOR_FAILURE_MODE
            | PREDICATE_ACTOR_SCOPE_NOTE
            | PREDICATE_ACTOR_SKILL_FIT
    )
}

/// Validates a stored `actor.*` body — the shape [`write_actor_claim`] writes.
///
/// Runs on EVERY write door including sync replay, so it is the property that
/// survives replication: a peer cannot land a bare, human-approved, or
/// wrong-typed `actor.*` row this vault would then read as its own projection.
///
/// The source pin mirrors `actor.confidence_prior`'s trust boundary exactly.
/// Same-owner multi-device sync preserves `src`, so a user's own rows replicate
/// and materialize; the cross-vault federation door restamps foreign claims
/// `src → Imported`, and this pin then rejects them. That is the intended
/// injection defense, not an oversight: a peer's opinion of who is careless
/// must never enter this vault's routing signal.
pub(crate) fn validate_actor_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid("actor.* claim subject must be an entity"));
    }
    if body.confidence != 1.0 {
        return Err(invalid("actor.* claim confidence must be 1.0"));
    }
    if body.approval != ClaimApprovalStatus::Auto {
        return Err(invalid("actor.* claim approval must be auto"));
    }
    if body.source != Some(ClaimSource::Observed) {
        return Err(invalid("actor.* claim source must be observed"));
    }
    if actor_claim_lineage(body).is_none() {
        return Err(invalid(
            "actor.* claim evidence must carry a known lineage class",
        ));
    }
    if body.predicate == PREDICATE_ACTOR_SKILL_FIT {
        let Value::F32(fit) = body.value else {
            return Err(invalid("actor.skill_fit value must be a fit in 0..=1"));
        };
        if !fit.is_finite() || !(0.0..=1.0).contains(&fit) {
            return Err(invalid("actor.skill_fit must be a finite fit in 0..=1"));
        }
        if skill_fit_scope_skill(body.scope.as_ref()).is_none() {
            return Err(invalid(
                "actor.skill_fit must scope its (actor, skill) pair",
            ));
        }
    } else {
        let Some(text) = body.value.as_str() else {
            return Err(invalid("actor note value must be a string"));
        };
        if normalize_note(text)? != text {
            return Err(invalid("actor note value must be normalized"));
        }
        if body.scope.is_some() {
            return Err(invalid("actor note rows carry no scope"));
        }
    }
    Ok(())
}

/// The EVIDENCE MEET a stored row rests on: `ToolOutput` for a TASK-lane row
/// citing attempt receipts, `Generated` for a CHAT-lane distilled note.
///
/// This is the lineage `src` deliberately does not carry (module header), and
/// the read ED-03 uses to tell a receipt-grounded row from a distilled one.
/// `None` means the row carries no legible lineage, which the validator refuses
/// on every write path.
#[must_use]
pub fn actor_claim_lineage(body: &ClaimBody) -> Option<ClaimSource> {
    let Some(Value::Map(entries)) = body.evidence.as_ref() else {
        return None;
    };
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() != Some(ACTOR_CLAIM_LINEAGE_KEY) {
            continue;
        }
        if found.is_some() {
            // A duplicate key is two answers to one question — no answer.
            return None;
        }
        found = match value.as_str() {
            Some(wire) if wire == ClaimSource::ToolOutput.as_str() => Some(ClaimSource::ToolOutput),
            Some(wire) if wire == ClaimSource::Generated.as_str() => Some(ClaimSource::Generated),
            // Only the two lanes' meets are legible here; anything else is a
            // row claiming a lineage this ledger does not mint.
            _ => return None,
        };
    }
    found
}

/// The SKILL a fit scope names, or `None` when the scope is not one.
fn skill_fit_scope_skill(scope: Option<&Value>) -> Option<EntityId> {
    let Some(Value::Map(entries)) = scope else {
        return None;
    };
    if entries.len() != 1 {
        return None;
    }
    let (key, value) = entries.first()?;
    if key.as_str() != Some(ACTOR_SKILL_FIT_SCOPE_KEY) {
        return None;
    }
    let Value::Binary(bytes) = value else {
        return None;
    };
    let raw: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().ok()?;
    EntityId::from_bytes(raw).ok()
}

#[cfg(test)]
mod tests;
