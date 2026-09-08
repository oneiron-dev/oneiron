//! The `actor.*` write chokepoint, cardinality core, and TASK-lane projector.

use rmpv::Value;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION,
    ENTITY_TYPE_TURN,
};
use crate::skill_attribution::{AttributionJudgment, AttributionVerdict, attribution_judgments};
use crate::temporal::TimeRange;

use super::evidence::{ActorClaimEvidence, ActorClaimLane};
use super::invalid;
use super::rows::{
    ACTOR_CLAIM_LINEAGE_KEY, ActorClaimRow, LAPSE_FAILURE_MODE, PREDICATE_ACTOR_SKILL_FIT,
};
use super::validate::{actor_claim_lineage, edit_cost_scope_name, skill_fit_scope_skill};

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
pub(super) fn ground_actor_claim(
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
pub(super) fn write_actor_claim_in_txn(
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
pub(super) fn scope_with_lineage(pair_scope: Option<Value>, meet: ClaimSource) -> Value {
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
///
/// Crate-visible so an inlet that FEEDS this door can refuse the same shape at
/// the point of observation: an evidence row this check would reject is a
/// projection pass that fails after durable state has already landed (ED-03).
pub(crate) fn require_actor_entity(vault: &Vault, actor: &EntityId) -> Result<()> {
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
pub(super) fn require_session_entity(vault: &Vault, session: &EntityId) -> Result<()> {
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
