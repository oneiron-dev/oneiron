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
//! | [`PREDICATE_ACTOR_EDIT_COST`] | cost in `0..=1` | ONE per `(actor, scope)`, superseding |
//!
//! A set row DEDUPES rather than supersedes: two different lessons are two
//! standing facts, and re-observing one is not news. `skill_fit` is the
//! opposite — it is a current estimate, so a new one closes the old head and
//! the pair scope (`{skill}`) is the conflict-set key. Scoping fit per PAIR
//! rather than per actor is load-bearing: an actor good at one skill and bad at
//! another has two live rows, and the router ([`skill_fit_for`], SK-05's
//! bandit) reads exactly the one it asked about. `edit_cost` (ED-03, ONE-1759)
//! is the same estimate shape on a different axis — `{scope}` instead of
//! `{skill}` — and its third evidence lane cites amendment receipts rather than
//! attempt receipts.
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
//! * [`ACTOR_CLAIM_LINEAGE_KEY`] — the engine's own `evidence_taint` SCOPE
//!   entry (ONE-1385/ONE-1314) — carries the EVIDENCE MEET: `tool_output` for
//!   a TASK-lane row resting on attempt receipts, `generated` for a CHAT-lane
//!   row distilled from turns. It rides that key and no private one because
//!   the meet has to be READ by the trust lattice to mean anything:
//!   `claim_evidence_taint` is what blocks a `tool_output`-derived row from
//!   consolidating without a human re-stamp, and a bespoke evidence-map key no
//!   trust code looks at would be a label, not a lineage. Enforced at the door
//!   rather than kept by convention: a row whose scope carries no known
//!   lineage is refused on every write path, replication included.
//!
//! **The engine distills nothing.** Turning a sitting into a craft note is a
//! generative act, so [`run_session_end_actor_distill`] takes a
//! [`SessionActorDistiller`] — the same host-supplied-tier seam
//! [`crate::skill_attribution::AttributionJudge`] uses, budgeted under
//! [`actor_distill_call_purpose`]. This module constructs no LLM client. The
//! TASK lane needs none, and writes no lesson for the same reason: a routing
//! DECISION derives the failure-mode CLASS ([`LAPSE_FAILURE_MODE`]) and stops
//! there, because "what to do instead" is not recoverable from a boolean.

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    CLAIM_SCOPE_EVIDENCE_TAINT_KEY, ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus,
    ClaimSource, ClaimSubject, PREDICATE_ACTOR_EDIT_COST, claim_evidence_taint,
};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::llm::CallPurpose;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
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

/// Scope key naming the SCOPE half of a [`PREDICATE_ACTOR_EDIT_COST`] pair
/// (ED-03). Same shape and same job as [`ACTOR_SKILL_FIT_SCOPE_KEY`]: two cost
/// rows collide iff they speak about the same scope.
pub const ACTOR_EDIT_COST_SCOPE_KEY: &str = "scope";

/// Longest accepted `actor.edit_cost` scope, borrowed from the consent bound
/// the ED lane measures every other scope axis against
/// (`edit_distance::escalation`).
pub const ACTOR_EDIT_COST_SCOPE_MAX_BYTES: usize = crate::consent::MAX_CONSENT_REF_LEN;

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
/// whose actor departed from a skill its pack had loaded. So this token is a
/// DERIVATION of the routing decision, not a judgement of taste — and it is a
/// token rather than prose because the router reads it back. It grows into a
/// table only when SK-04 learns to route a second lapse class.
///
/// A lapse mints this row and NOTHING else. The lesson such a lapse teaches is
/// situation-specific prose, which no deterministic router can derive — that is
/// the distiller tier's work, and inventing a house sentence here to fill the
/// slot would be the engine writing content it has no evidence for.
pub const LAPSE_FAILURE_MODE: &str = "departed_from_loaded_skill";

/// `actor_claims:distill_pending:v1:` + session id (16 B) → ended_at (8 BE).
///
/// The durable SessionEnd → distill JOB. Written in the SAME transaction that
/// closes the sitting, so a crash between "session ended" and "distill queued"
/// is not representable; consumed by [`run_session_end_actor_distill`].
const DISTILL_PENDING_PREFIX: &[u8] = b"actor_claims:distill_pending:v1:";

/// `temporal_learned` key layout: `learned_at` (8 BE) + entity id.
const TEMPORAL_LEARNED_KEY_LEN: usize = 8 + ENTITY_ID_LEN;

/// Scope key carrying the EVIDENCE MEET of a row: the [`ClaimSource`] wire
/// string of what the row actually rests on. See the module header — this is
/// the lineage `src` deliberately does not carry.
///
/// It IS the engine's `evidence_taint` key (`claim.rs`, ONE-1385), not a
/// namespace of this ledger's own: the meet is written to be read by
/// `claim_evidence_taint` and the consolidation/corroboration gates that call
/// it. A private key would stamp a fact nothing enforces.
pub const ACTOR_CLAIM_LINEAGE_KEY: &str = CLAIM_SCOPE_EVIDENCE_TAINT_KEY;

const KEY_LANE: &str = "lane";
const KEY_RECEIPTS: &str = "receipts";
const KEY_SESSION: &str = "session";
const KEY_TURNS: &str = "turns";
const KEY_AT: &str = "at";

const LANE_TASK: &str = "task";
const LANE_CHAT: &str = "chat";
const LANE_AMENDMENT: &str = "amendment";

const fn invalid(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// One `actor.*` row, before it is a claim.
///
/// Owning every shape in one enum is what makes [`write_actor_claim`] a
/// chokepoint rather than a convention: a new row kind cannot be written
/// without a variant here, and every variant lands through the same door.
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
    /// Per-`(actor, scope)` amendment cost in `0..=1` (ED-03, ONE-1759). ONE
    /// per pair, superseding — the `skill_fit` cardinality, for the same
    /// reason: it is a current estimate, not a standing fact.
    ///
    /// `cost` is an AGGREGATE the judge earned, never a raw Δ:
    /// [`crate::edit_distance::attribution::project_edit_cost_claims`] is the
    /// only writer, and it takes judgments rather than deltas so an
    /// unclassified edit has no path to this row.
    EditCost {
        actor: EntityId,
        scope: String,
        cost: f32,
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
            Self::EditCost { .. } => PREDICATE_ACTOR_EDIT_COST,
        }
    }

    /// The ACTOR entity this row is about.
    #[must_use]
    pub const fn actor(&self) -> EntityId {
        match self {
            Self::Lesson { actor, .. }
            | Self::FailureMode { actor, .. }
            | Self::ScopeNote { actor, .. }
            | Self::SkillFit { actor, .. }
            | Self::EditCost { actor, .. } => *actor,
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
                if !valid_unit_interval(*fit) {
                    return Err(invalid("actor.skill_fit must be a finite fit in 0..=1"));
                }
                Ok((Value::F32(*fit), Some(skill_fit_scope(skill))))
            }
            Self::EditCost { scope, cost, .. } => {
                if !valid_unit_interval(*cost) {
                    return Err(invalid("actor.edit_cost must be a finite cost in 0..=1"));
                }
                Ok((
                    Value::F32(*cost),
                    Some(edit_cost_scope(normalize_edit_cost_scope(scope)?)),
                ))
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

/// The `{scope}` pair map of an `*.edit_cost` row — the writer both the
/// `actor.*` door and the `skill.*` door in
/// [`crate::edit_distance::attribution`] share, so one row shape means one
/// conflict-set key lane-wide.
pub(crate) fn edit_cost_scope(scope: &str) -> Value {
    Value::Map(vec![(
        Value::from(ACTOR_EDIT_COST_SCOPE_KEY),
        Value::from(scope),
    )])
}

/// The trimmed scope of an `actor.edit_cost` row, or the reason it is not one.
///
/// Trimmed before it becomes a conflict-set key, so `"outbound"` and
/// `" outbound "` are one pair rather than two live rows about the same thing —
/// the note rows' normalization law, applied to the axis this row is keyed on.
fn normalize_edit_cost_scope(scope: &str) -> Result<&str> {
    let trimmed = scope.trim();
    if trimmed.is_empty() || trimmed.len() > ACTOR_EDIT_COST_SCOPE_MAX_BYTES {
        return Err(invalid(
            "actor.edit_cost scope must be non-empty and within the consent-ref bound",
        ));
    }
    Ok(trimmed)
}

/// A fit or a cost is a finite estimate in the unit interval. The finiteness
/// half is explicit: NaN fails every range comparison, so a `contains` check
/// ALONE would silently admit it and poison every downstream ranking.
fn valid_unit_interval(estimate: f32) -> bool {
    estimate.is_finite() && (0.0..=1.0).contains(&estimate)
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
    /// Receipt ids whose ARCH-0056 amendment Δ a judgment rested on (ED-03).
    ///
    /// A third lane rather than a reuse of [`Self::Task`] because the two cite
    /// different ledgers: a task row cites an attempt PACK receipt, an
    /// amendment row cites the receipt ED-01 measured a Δ against, and
    /// grounding one against the other's index would answer "no such receipt"
    /// for a citation that is plainly readable.
    Amendment { receipts: Vec<String> },
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

    /// AMENDMENT-lane evidence: the receipts whose Δs the judgment rested on
    /// (ED-03, ARCH-0056 §5).
    pub fn amendment(receipts: Vec<String>, at: u64) -> Result<Self> {
        if receipts.is_empty() {
            return Err(invalid("an amendment-lane actor row must cite a receipt"));
        }
        if receipts.len() > ACTOR_CLAIM_MAX_CITED_EVIDENCE {
            return Err(invalid("actor row cites more evidence than the bound"));
        }
        Ok(Self {
            lane: ActorClaimLane::Amendment { receipts },
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

    /// The evidence meet this lane earns — see the module header's lineage
    /// note. Derived here and nowhere else, so it cannot be passed in.
    const fn lineage(&self) -> ClaimSource {
        match self.lane {
            // Attempt receipts ARE tool output; a row resting on them says so.
            // An amendment Δ is the same class of fact: the engine MEASURED two
            // bodies it holds, so the row rests on machine output rather than on
            // anything a model wrote.
            ActorClaimLane::Task { .. } | ActorClaimLane::Amendment { .. } => {
                ClaimSource::ToolOutput
            }
            // A distilled note is model-written prose over turns.
            ActorClaimLane::Chat { .. } => ClaimSource::Generated,
        }
    }

    fn to_value(&self) -> Value {
        let mut entries = vec![(Value::from(KEY_AT), Value::from(self.at))];
        match &self.lane {
            ActorClaimLane::Task { receipts } => {
                entries.push((Value::from(KEY_LANE), Value::from(LANE_TASK)));
                entries.push((
                    Value::from(KEY_RECEIPTS),
                    Value::Array(receipts.iter().map(|r| Value::from(r.as_str())).collect()),
                ));
            }
            ActorClaimLane::Amendment { receipts } => {
                entries.push((Value::from(KEY_LANE), Value::from(LANE_AMENDMENT)));
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
/// The claim body is built here — approval, confidence, source, scope and
/// evidence are the writer's, never the caller's — so "projector-authored,
/// evidence-carrying" is a structural property of the ledger rather than a
/// habit callers keep.
///
/// **The citation is RESOLVED, not read.** [`ActorClaimEvidence`] is built from
/// caller-owned strings and ids, and this function authors reserved truth off
/// it, so every cited receipt must resolve to a stamped attempt pack receipt
/// and every cited session/turn to the entity it names (the ONE-1738 loss-door
/// posture, same reasoning). A row citing a receipt nobody stamped is a trace
/// only in shape.
///
/// Cardinality is enforced in the same write transaction that lands the row:
///
/// * SET rows (lesson / failure_mode / scope_note) DEDUPE on the normalized
///   note: one standing head that already carries this evidence meet re-returns
///   its id and writes nothing — an observation repeated is not an observation
///   added.
/// * [`PREDICATE_ACTOR_SKILL_FIT`] SUPERSEDES the active heads sharing its
///   `(actor, skill)` pair.
///
/// Both kinds close EVERY conflicting head, not the first found:
/// `EntityId::now()` is per-replica unique, so two replicas that each observed
/// this fact hold two distinct claim entities, and after a sync both are
/// Active. Closing one would leave the other live forever — the ONE-1738
/// convergence shape, which a `find`-and-return SET path silently skipped.
pub fn write_actor_claim(
    vault: &Vault,
    row: ActorClaimRow,
    evidence: &ActorClaimEvidence,
) -> Result<EntityId> {
    ground_actor_claim(vault, &row, evidence)?;
    vault.with_write_txn(|wtxn| write_actor_claim_in_txn(vault, wtxn, &row, evidence))
}

/// Resolves everything a row asserts BEFORE any transaction opens: the actor,
/// the fit pair's skill, and every cited piece of evidence.
///
/// Split from the write so the two inlets can differ on policy without
/// differing on the check — the CHAT and TASK lanes both SKIP an ungrounded row
/// rather than failing a whole pass, while the door itself refuses one.
fn ground_actor_claim(
    vault: &Vault,
    row: &ActorClaimRow,
    evidence: &ActorClaimEvidence,
) -> Result<()> {
    require_actor_entity(vault, &row.actor())?;
    if let ActorClaimRow::SkillFit { skill, .. } = row {
        require_skill_entity(vault, skill)?;
    }
    match &evidence.lane {
        ActorClaimLane::Task { receipts } => {
            for receipt in receipts {
                if crate::receipt::attempt_pack_receipt(vault, receipt)?.is_none() {
                    return Err(invalid("actor row cites an unstamped attempt receipt"));
                }
            }
        }
        ActorClaimLane::Amendment { receipts } => {
            for receipt in receipts {
                // The Δ side-ledger IS the resolution: a receipt with a
                // recorded Δ is one this engine measured an amendment on. A
                // receipt whose capture FAILED reads as absent here, which is
                // the right answer — an unmeasured edit has no cost to charge.
                if crate::edit_distance::delta::amendment_delta(vault, receipt)?.is_none() {
                    return Err(invalid("actor row cites an unmeasured amendment receipt"));
                }
            }
        }
        ActorClaimLane::Chat { session, turns } => {
            require_session_entity(vault, session)?;
            for turn in turns {
                if vault.get_entity_type(turn)? != Some(ENTITY_TYPE_TURN) {
                    return Err(invalid("actor row cites a turn that is not a TURN"));
                }
            }
        }
    }
    Ok(())
}

/// [`write_actor_claim`]'s body, composable into a caller's transaction so a
/// batch of rows lands all-or-nothing (the CHAT lane's notes and the job that
/// authorized them commit together).
fn write_actor_claim_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &ActorClaimRow,
    evidence: &ActorClaimEvidence,
) -> Result<EntityId> {
    let predicate = row.predicate();
    let actor = row.actor();
    let (value, pair_scope) = row.value_and_scope()?;
    let at = evidence.at;

    // The SET key is the value; a pair-scoped key is the scope entry. Same
    // lookup, two conflict definitions — which is exactly what §G.1 pins.
    let conflict = ConflictKey::from_scope(pair_scope.as_ref());
    let heads = active_heads_in_txn(vault, wtxn, &actor, predicate)?;
    // A head stamped LATER than this write is not this write's to close: a
    // backfill landing at=50 must not retire the estimate the ledger already
    // holds at 100 and leave the stale one sole-active.
    let (supersedable, newer): (Vec<_>, Vec<_>) = heads
        .iter()
        .filter(|(_, head, _)| conflict.collides(head, &value))
        .partition(|(_, head, start)| head_event_time(head, *start) <= at);

    if conflict.is_set() {
        // SET, backfill: a note a later head already stands for is not news, so
        // this write adds no row (the value IS the key — a second row would
        // break the cardinality). It still converges the fork by folding the
        // older duplicates INTO that standing head.
        if let Some((head_id, _, _)) = newest_head(&newer) {
            for (old_id, _, old_start) in &supersedable {
                vault.supersede_reserved_claim_in_txn(wtxn, head_id, old_id, at.max(*old_start))?;
            }
            return Ok(*head_id);
        }
    }

    // The E1 supersession taint fold (ONE-1314 R3): a head's meet folds into
    // the row that closes it, so a receipt-grounded head superseded by a
    // distilled one does not launder its way back up the lattice.
    let meet = supersedable
        .iter()
        .filter_map(|(_, head, _)| actor_claim_lineage(head))
        .fold(evidence.lineage(), lineage_meet);

    // SET, no-op: ONE standing head that already says exactly this, on evidence
    // of exactly this lineage. Two heads is a fork that must collapse even when
    // the surviving value is unchanged.
    if conflict.is_set()
        && let [(head_id, head, _)] = supersedable.as_slice()
        && actor_claim_lineage(head) == Some(meet)
    {
        return Ok(*head_id);
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
    body.evidence = Some(evidence.to_value());
    body.scope = Some(scope_with_lineage(pair_scope, meet));
    body.valid_from = Some(at);
    body.source = Some(ClaimSource::Observed);
    vault.put_reserved_claim_in_txn(
        wtxn,
        &claim_id,
        &body,
        TimeRange { start: at, end: at },
        at,
    )?;

    for (head_id, _, head_start) in &supersedable {
        // `at.max(head_start)` mirrors the scan-verdict clamp: the supersession
        // re-Puts the old row over `{head_start, now}`, and an out-of-order
        // event time would make that range invalid and roll the whole
        // transaction back — permanently, since the retry re-derives the same
        // `at`.
        vault.supersede_reserved_claim_in_txn(wtxn, &claim_id, head_id, at.max(*head_start))?;
    }
    Ok(claim_id)
}

/// What makes two active heads of one predicate collide.
///
/// Derived from the row's own pair scope, so the §G.1 cardinality of every row
/// kind is read off ONE value rather than restated at each comparison. A row
/// with no pair scope is a SET row and dedupes on its value; a pair-scoped row
/// supersedes whatever head shares its pair.
enum ConflictKey<'a> {
    /// SET rows (lesson / failure_mode / scope_note): the note IS the key.
    Value,
    /// [`PREDICATE_ACTOR_SKILL_FIT`]: the `(actor, skill)` pair.
    Skill(EntityId),
    /// [`PREDICATE_ACTOR_EDIT_COST`]: the `(actor, scope)` pair.
    Scope(&'a str),
}

impl<'a> ConflictKey<'a> {
    fn from_scope(scope: Option<&'a Value>) -> Self {
        if let Some(skill) = skill_fit_scope_skill(scope) {
            return Self::Skill(skill);
        }
        if let Some(name) = edit_cost_scope_name(scope) {
            return Self::Scope(name);
        }
        Self::Value
    }

    /// Whether `head` is in the conflict set of a row valued `value`.
    fn collides(&self, head: &ClaimBody, value: &Value) -> bool {
        match self {
            Self::Value => head.value == *value,
            Self::Skill(skill) => skill_fit_scope_skill(head.scope.as_ref()) == Some(*skill),
            Self::Scope(scope) => edit_cost_scope_name(head.scope.as_ref()) == Some(*scope),
        }
    }

    /// Whether this key dedupes (SET) rather than supersedes.
    const fn is_set(&self) -> bool {
        matches!(self, Self::Value)
    }
}

/// When a head says its fact happened. `valid_from` is what this door stamps;
/// the entity's `occurred_start` is the fallback for a head that carries none.
fn head_event_time(head: &ClaimBody, occurred_start: u64) -> u64 {
    head.valid_from.unwrap_or(occurred_start)
}

/// The newest of a head set, by `(event time, claim id)` — the same total
/// order [`skill_fit_for`] resolves a fork with.
fn newest_head<'a>(
    heads: &'a [&'a (EntityId, ClaimBody, u64)],
) -> Option<&'a (EntityId, ClaimBody, u64)> {
    heads
        .iter()
        .copied()
        .max_by_key(|(id, head, start)| (head_event_time(head, *start), *id))
}

/// The meet of two evidence lineages in the D10 trust order.
///
/// This ledger mints exactly two, and `Generated` is its bottom: a note that
/// rests even partly on model-written prose is prose-derived, whatever else it
/// also rests on. A row observed from both inlets therefore carries the meet,
/// never the flattering half.
const fn lineage_meet(left: ClaimSource, right: ClaimSource) -> ClaimSource {
    match (left, right) {
        (ClaimSource::Generated, _) | (_, ClaimSource::Generated) => ClaimSource::Generated,
        _ => ClaimSource::ToolOutput,
    }
}

/// Appends the lineage meet to a row's scope map (the `dreamer_promotion`
/// `scope_with_taint` shape — the writer owns this key).
fn scope_with_lineage(pair_scope: Option<Value>, meet: ClaimSource) -> Value {
    let mut entries = match pair_scope {
        Some(Value::Map(entries)) => entries,
        _ => Vec::new(),
    };
    entries.retain(|(key, _)| key.as_str() != Some(ACTOR_CLAIM_LINEAGE_KEY));
    entries.push((
        Value::from(ACTOR_CLAIM_LINEAGE_KEY),
        Value::from(meet.as_str()),
    ));
    Value::Map(entries)
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

/// A CHAT-lane citation names a SITTING; anything else is a row citing
/// evidence this ledger cannot go back and read.
fn require_session_entity(vault: &Vault, session: &EntityId) -> Result<()> {
    match vault.get_entity_type(session)? {
        Some(ENTITY_TYPE_SESSION) => Ok(()),
        Some(_) => Err(invalid("a chat-lane citation must name a SESSION")),
        None => Err(Error::EntityNotFound),
    }
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
    let rtxn = vault.store.env.read_txn()?;
    let mut best: Option<(u64, EntityId, f32)> = None;
    for (id, body, _) in active_heads_in_txn(vault, &rtxn, actor, PREDICATE_ACTOR_SKILL_FIT)? {
        // The PAIR is the conflict key, so the pair entry is what a read
        // matches on — the scope map also carries the row's lineage meet, and
        // comparing whole maps would make two lanes' estimates of one pair
        // look like estimates of two different pairs.
        if skill_fit_scope_skill(body.scope.as_ref()) != Some(*skill) {
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

/// Projects `ExecutionLapse` judgments into [`PREDICATE_ACTOR_FAILURE_MODE`]
/// rows, returning the claim ids this pass landed.
///
/// ONE lapse is ONE row ([`LAPSE_FAILURE_MODE`]) — the class the routing
/// decision names, and nothing beyond it. A lapse says the executor departed
/// from a loaded skill; it does not say what to do instead, and a projector
/// that also emitted a lesson would be sourcing prose from a boolean.
///
/// **Every judgment is re-grounded, not trusted** (the ONE-1738 posture, same
/// reasoning): [`AttributionJudgment`] is a public type with public fields, so
/// the argument is caller-owned data, and this function authors reserved truth.
/// A row counts only if it IS the row SK-04's projector persisted at that
/// sequence, its subject is a real actor entity, and its citation resolves to a
/// stamped pack receipt. Ungrounded rows are SKIPPED rather than fatal: one
/// forged row must not deny a whole pass.
///
/// Idempotent by cardinality, not by cursor: the class writes the same
/// normalized token every time and SET rows dedupe, so re-running a pass over
/// the same judgments re-returns the same ids instead of growing the ledger.
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
        // Grounded is not authorized: this row must also BE the row SK-04
        // routed at this sequence.
        if !persisted
            .iter()
            .any(|row| row.sequence == judgment.sequence && row == judgment)
        {
            continue;
        }
        // A judgment with nothing to cite has no trace at all.
        let Ok(evidence) =
            ActorClaimEvidence::task(judgment.evidence_receipts.clone(), judgment.at)
        else {
            continue;
        };
        let row = ActorClaimRow::FailureMode {
            actor: judgment.subject,
            text: LAPSE_FAILURE_MODE.to_owned(),
        };
        // …and a citation naming no stamped receipt is a trace only in shape.
        // The door's own check, run here so an ungrounded row is skipped rather
        // than fatal.
        if ground_actor_claim(vault, &row, &evidence).is_err() {
            continue;
        }
        written.push(
            vault.with_write_txn(|wtxn| write_actor_claim_in_txn(vault, wtxn, &row, &evidence))?,
        );
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// CHAT lane — SessionEnd distillation
// ---------------------------------------------------------------------------

/// One thing said in a sitting: who spoke, and their words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDistillUtterance {
    pub speaker: Option<String>,
    pub text: Option<String>,
}

/// One turn of the sitting, as the distiller sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDistillTurn {
    pub turn: EntityId,
    /// What was said, in write order. A turn is a LIST because production
    /// writes two shapes: the core turn door puts one utterance in the TURN
    /// body (`spkr`/`txt`), while the witness door writes the turn as an empty
    /// container and the words as its MESSAGE children — so a witnessed turn
    /// holding a question and its answer yields two utterances, and flattening
    /// them into one speaker would attribute half the turn to the wrong actor.
    pub said: Vec<SessionDistillUtterance>,
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
/// row there is no evidence the sitting is over.
///
/// **The job is CONSUMED AFTER the work, in the transaction that lands it.**
/// A distiller is a host-supplied LLM tier — the one step here that fails for
/// reasons that pass — so deleting the job first would trade a transient
/// timeout for the permanent loss of that sitting's distillation. Notes and the
/// job's deletion commit together or neither does, which also means a pass that
/// dies halfway leaves no partial helping of notes behind. A re-run over an
/// already-distilled sitting is still a typed no-such-job.
pub fn run_session_end_actor_distill(
    vault: &Vault,
    session: &EntityId,
    distiller: &dyn SessionActorDistiller,
) -> Result<Vec<EntityId>> {
    let ended_at = distill_job(vault, session)?;
    let sitting = sitting_window(vault, session, ended_at)?;
    let brief = SessionDistillBrief {
        session: *session,
        ended_at,
        turns: session_turns(vault, sitting)?,
    };
    if brief.turns.is_empty() {
        // Nothing to learn from, and nothing that can arrive later: the sitting
        // is closed and its turns are what they are. The job is spent.
        return vault
            .with_write_txn(|wtxn| consume_distill_job_in_txn(vault, wtxn, session, ended_at))
            .map(|()| Vec::new());
    }

    let turn_ids: Vec<EntityId> = brief.turns.iter().map(|turn| turn.turn).collect();
    let evidence = ActorClaimEvidence::chat(*session, turn_ids, ended_at)?;
    // Grounded before the transaction opens, and SKIPPED rather than fatal —
    // the TASK lane's posture: a distiller naming an entity that cannot hold a
    // lesson must not deny the notes that named real ones, nor poison the job
    // into failing every retry the same way.
    let rows: Vec<ActorClaimRow> = distiller
        .distill(&brief)?
        .into_iter()
        .map(|note| note.kind.row(note.actor, note.text))
        .filter(|row| ground_actor_claim(vault, row, &evidence).is_ok())
        .collect();

    vault.with_write_txn(|wtxn| {
        let mut written = Vec::with_capacity(rows.len());
        for row in &rows {
            written.push(write_actor_claim_in_txn(vault, wtxn, row, &evidence)?);
        }
        // LAST, deliberately: the job authorized this pass, so it is spent only
        // once the pass has landed.
        consume_distill_job_in_txn(vault, wtxn, session, ended_at)?;
        Ok(written)
    })
}

/// Reads the pending job for `session`, returning its `ended_at`.
fn distill_job(vault: &Vault, session: &EntityId) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, &distill_job_key(session))?
    else {
        return Err(invalid("no session-end distill job for this session"));
    };
    decode_distill_job(&raw)
}

/// Spends the job inside the transaction that lands the pass.
///
/// Identity-bound like the session close it descends from (ONE-1685): the row
/// is re-read here and must still be the job this pass planned against, so two
/// runners racing one sitting cannot both commit their notes.
fn consume_distill_job_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    session: &EntityId,
    expected_ended_at: u64,
) -> Result<()> {
    let key = distill_job_key(session);
    let Some(raw) = vault.store.vault_meta.get(&*wtxn, &key)? else {
        return Err(invalid("the session-end distill job is no longer pending"));
    };
    if decode_distill_job(&raw)? != expected_ended_at {
        return Err(invalid("the session-end distill job was re-registered"));
    }
    vault.store.vault_meta.delete(wtxn, &key)?;
    Ok(())
}

fn decode_distill_job(raw: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = raw
        .try_into()
        .map_err(|_| Error::CorruptedIndex("actor distill job row"))?;
    Ok(u64::from_be_bytes(bytes))
}

/// The window a sitting covers: `[started_at, ended_at]` in unix seconds.
#[derive(Debug, Clone, Copy)]
struct SittingWindow {
    started_at: u64,
    ended_at: u64,
}

/// Resolves the ended sitting's window, refusing a subject that is not one.
fn sitting_window(vault: &Vault, session: &EntityId, ended_at: u64) -> Result<SittingWindow> {
    require_session_entity(vault, session)?;
    let Some(record) = vault.session_lifecycle_record(session)? else {
        return Err(invalid("session-end distill needs the sitting's clock"));
    };
    Ok(SittingWindow {
        started_at: record.started_at,
        ended_at: ended_at.max(record.started_at),
    })
}

/// The sitting's turns — derived from what production actually writes.
///
/// **There is no SESSION→TURN edge in this engine**, so there is none to read.
/// The witness door (`MemoryFacade::witness`) writes CONVERSATION/TURN/MESSAGE
/// and bumps the open sitting's activity clock; the core turn door writes a
/// TURN plus a `ChildOf` edge into its CONVERSATION. What binds a turn to a
/// SITTING is TIME, and at most one sitting is open per vault
/// (`session_lifecycle`), so the sitting's window names exactly the turns
/// learned during it — which is also the index `dreamer_consolidation` walks to
/// find turns to dream about.
///
/// Both production body shapes are read, because production writes both: the
/// core door's `spkr`/`txt` TURN body, and — when the turn body says nothing,
/// as the witness door's empty container always does — the turn's MESSAGE
/// children, where the witnessed words actually live.
///
/// Bounded by [`ACTOR_CLAIM_MAX_CITED_EVIDENCE`], keeping the LAST turns: the
/// brief and the citation list are the same set of turns, so a long sitting
/// cannot produce a brief the evidence bound would then refuse to cite.
fn session_turns(vault: &Vault, window: SittingWindow) -> Result<Vec<SessionDistillTurn>> {
    let mut turn_ids = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut lower = [0_u8; TEMPORAL_LEARNED_KEY_LEN];
        lower[..8].copy_from_slice(&window.started_at.to_be_bytes());
        let mut upper = [u8::MAX; TEMPORAL_LEARNED_KEY_LEN];
        upper[..8].copy_from_slice(&window.ended_at.to_be_bytes());
        for entry in vault.store.temporal_learned.range(
            &rtxn,
            &(
                std::ops::Bound::Included(&lower[..]),
                std::ops::Bound::Included(&upper[..]),
            ),
        )? {
            let (key, _) = entry?;
            let Some(raw) = key.get(8..TEMPORAL_LEARNED_KEY_LEN) else {
                continue;
            };
            let Ok(bytes) = <[u8; ENTITY_ID_LEN]>::try_from(raw) else {
                continue;
            };
            let Ok(id) = EntityId::from_bytes(bytes) else {
                continue;
            };
            if vault.get_entity_type_in_txn(&rtxn, &id)? == Some(ENTITY_TYPE_TURN) {
                turn_ids.push(id);
            }
        }
    }
    if turn_ids.len() > ACTOR_CLAIM_MAX_CITED_EVIDENCE {
        turn_ids.drain(..turn_ids.len() - ACTOR_CLAIM_MAX_CITED_EVIDENCE);
    }

    let mut turns = Vec::with_capacity(turn_ids.len());
    for turn in turn_ids {
        let said = match turn_utterance(vault, &turn)? {
            Some(utterance) => vec![utterance],
            None => turn_message_utterances(vault, &turn)?,
        };
        turns.push(SessionDistillTurn { turn, said });
    }
    Ok(turns)
}

/// The utterance a TURN body carries itself, or `None` when it carries none —
/// the witness door's turns are empty containers, and their words are children.
fn turn_utterance(vault: &Vault, turn: &EntityId) -> Result<Option<SessionDistillUtterance>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.entities.get(&rtxn, turn.as_bytes())? else {
        return Ok(None);
    };
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(None);
    };
    let utterance = decode_utterance(body, "spkr", "txt");
    Ok((utterance.speaker.is_some() || utterance.text.is_some()).then_some(utterance))
}

/// The witnessed words of a turn: its MESSAGE children, in `(order, id)`.
fn turn_message_utterances(vault: &Vault, turn: &EntityId) -> Result<Vec<SessionDistillUtterance>> {
    // `edges_in` reports the FAR end in `target`, so these are the messages
    // that named this turn as their part-of container.
    let messages: Vec<EntityId> = vault
        .edges_in(turn)?
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::PartOf)
        .map(|edge| edge.target)
        .collect();

    let rtxn = vault.store.env.read_txn()?;
    let mut said: Vec<(u64, EntityId, SessionDistillUtterance)> = Vec::new();
    for message in messages {
        let Some(raw) = vault.store.entities.get(&rtxn, message.as_bytes())? else {
            continue;
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if header.entity_type != ENTITY_TYPE_MESSAGE {
            continue;
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        said.push((
            message_order(body),
            message,
            decode_utterance(body, "author", "content"),
        ));
    }
    said.sort_by_key(|(order, id, _)| (*order, *id));
    Ok(said
        .into_iter()
        .map(|(_, _, utterance)| utterance)
        .collect())
}

/// Reads one utterance from a MessagePack body, tolerating any other shape: an
/// undecodable turn is still a turn that happened.
///
/// Both documented spellings of each key are accepted (`spkr`/`speaker`,
/// `txt`/`text`), the same tolerance `dreamer_consolidation` reads turns with.
fn decode_utterance(raw: &[u8], speaker_key: &str, text_key: &str) -> SessionDistillUtterance {
    let mut utterance = SessionDistillUtterance {
        speaker: None,
        text: None,
    };
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(raw)) else {
        return utterance;
    };
    for (key, value) in entries {
        let Some(key) = key.as_str() else { continue };
        if (key == speaker_key || key == "speaker") && utterance.speaker.is_none() {
            utterance.speaker = value.as_str().map(str::to_owned);
        } else if (key == text_key || key == "text") && utterance.text.is_none() {
            utterance.text = value.as_str().map(str::to_owned);
        }
    }
    utterance
}

/// A witnessed message's position inside its turn; absent reads as first.
fn message_order(raw: &[u8]) -> u64 {
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(raw)) else {
        return 0;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("order"))
        .and_then(|(_, value)| value.as_u64())
        .unwrap_or(0)
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

/// Whether `predicate` is one of the §G.1 `actor.*` rows this module owns.
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
            | PREDICATE_ACTOR_EDIT_COST
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
    if body.evidence.is_none() {
        return Err(invalid("actor.* claim must carry the trace it rests on"));
    }
    if actor_claim_lineage(body).is_none() {
        return Err(invalid(
            "actor.* claim scope must carry a known lineage class",
        ));
    }
    // The pair key this predicate's rows are keyed on, or `None` for the SET
    // note rows — which is also what the scope check below is exact against.
    let pair_key = match body.predicate.as_str() {
        PREDICATE_ACTOR_SKILL_FIT => {
            let Value::F32(fit) = body.value else {
                return Err(invalid("actor.skill_fit value must be a fit in 0..=1"));
            };
            if !valid_unit_interval(fit) {
                return Err(invalid("actor.skill_fit must be a finite fit in 0..=1"));
            }
            if skill_fit_scope_skill(body.scope.as_ref()).is_none() {
                return Err(invalid(
                    "actor.skill_fit must scope its (actor, skill) pair",
                ));
            }
            Some(ACTOR_SKILL_FIT_SCOPE_KEY)
        }
        PREDICATE_ACTOR_EDIT_COST => {
            let Value::F32(cost) = body.value else {
                return Err(invalid("actor.edit_cost value must be a cost in 0..=1"));
            };
            if !valid_unit_interval(cost) {
                return Err(invalid("actor.edit_cost must be a finite cost in 0..=1"));
            }
            let Some(scope) = edit_cost_scope_name(body.scope.as_ref()) else {
                return Err(invalid(
                    "actor.edit_cost must scope its (actor, scope) pair",
                ));
            };
            if normalize_edit_cost_scope(scope)? != scope {
                return Err(invalid("actor.edit_cost scope must be normalized"));
            }
            Some(ACTOR_EDIT_COST_SCOPE_KEY)
        }
        _ => {
            let Some(text) = body.value.as_str() else {
                return Err(invalid("actor note value must be a string"));
            };
            if normalize_note(text)? != text {
                return Err(invalid("actor note value must be normalized"));
            }
            None
        }
    };
    // The scope map is the writer's, key for key: the lineage meet on every
    // row and the pair key on a pair-scoped row. A row carrying anything else
    // is scoping a conflict set this ledger does not define — including a
    // sensitivity or federation stamp a peer hoped this vault would honor.
    if !actor_scope_is_exact(body.scope.as_ref(), pair_key) {
        return Err(invalid(
            "actor.* claim scope carries a key this ledger does not write",
        ));
    }
    Ok(())
}

/// Whether a row's scope is EXACTLY the writer's keys: the lineage meet, plus
/// `pair_key` on a pair-scoped row, each once.
fn actor_scope_is_exact(scope: Option<&Value>, pair_key: Option<&str>) -> bool {
    let Some(Value::Map(entries)) = scope else {
        return false;
    };
    let mut lineage = 0_usize;
    let mut pair = 0_usize;
    for (key, _) in entries {
        match key.as_str() {
            Some(ACTOR_CLAIM_LINEAGE_KEY) => lineage += 1,
            Some(key) if Some(key) == pair_key => pair += 1,
            _ => return false,
        }
    }
    lineage == 1 && pair == usize::from(pair_key.is_some())
}

/// The EVIDENCE MEET a stored row rests on: `ToolOutput` for a TASK-lane row
/// citing attempt receipts, `Generated` for a CHAT-lane distilled note.
///
/// This is the lineage `src` deliberately does not carry (module header), and
/// the read ED-03 uses to tell a receipt-grounded row from a distilled one. It
/// is the ENGINE's evidence-taint read narrowed to the two meets this ledger
/// mints, so the same stamp the trust lattice enforces is the one this module
/// reasons about — one fact, one channel.
///
/// `None` means the row carries no legible lineage — including the taint
/// reader's own fail-closed answers (an unparseable or duplicated stamp reads
/// `Imported`, which this ledger never mints) — and the validator refuses that
/// on every write path.
#[must_use]
pub fn actor_claim_lineage(body: &ClaimBody) -> Option<ClaimSource> {
    match claim_evidence_taint(body) {
        Some(meet @ (ClaimSource::ToolOutput | ClaimSource::Generated)) => Some(meet),
        _ => None,
    }
}

/// The SKILL a scope map names, or `None` when it names none.
///
/// Reads the ONE pair entry rather than the whole map: an `actor.skill_fit`
/// scope also carries the row's lineage meet, and a duplicated pair key is two
/// answers to one question — so no answer, which the validator then refuses.
fn skill_fit_scope_skill(scope: Option<&Value>) -> Option<EntityId> {
    let Some(Value::Map(entries)) = scope else {
        return None;
    };
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() != Some(ACTOR_SKILL_FIT_SCOPE_KEY) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let Value::Binary(bytes) = value else {
            return None;
        };
        let raw: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().ok()?;
        found = Some(EntityId::from_bytes(raw).ok()?);
    }
    found
}

/// The SCOPE an `*.edit_cost` scope map names, or `None` when it names none —
/// [`skill_fit_scope_skill`]'s sibling, duplicated-key rule included. Shared
/// with [`crate::edit_distance::attribution`]'s reads: a row's scope map also
/// carries the lineage meet, so a read matches on the ONE scope entry rather
/// than on the whole map.
pub(crate) fn edit_cost_scope_name(scope: Option<&Value>) -> Option<&str> {
    let Some(Value::Map(entries)) = scope else {
        return None;
    };
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() != Some(ACTOR_EDIT_COST_SCOPE_KEY) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(value.as_str()?);
    }
    found
}

#[cfg(test)]
mod tests;
