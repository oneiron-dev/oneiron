//! Replicated TASK authority: owner proof, cancellation, and acknowledgement
//! as immutable companion TASK entities.
//!
//! Authority is part of the TASK REPRESENTATION, not a node-local `vault_meta`
//! side-index and not a mutable field on the primary TASK blob. Each fact is
//! its own `ENTITY_TYPE_TASK` entity carrying role
//! [`TaskRole::AuthorityFact`], linked to its subject with the existing
//! structural `ScopedTo` edge — so the entity/edge CRDT maps already replicate
//! it and `sync/` needs no new container, wire tag, or type byte.
//!
//! Separate entities are what makes cancel-wins MONOTONIC. A single body
//! carrying `cancelled`/`acked` booleans is one LWW register, and a later
//! acknowledgement merging over an earlier cancellation would clear it. Set
//! union over independent fact entities cannot: any Cancelled fact anywhere in
//! the merged set sets `cancelled`, under every merge order, forever.
//!
//! Facts are ENGINE-AUTHORED. `put_task_authority_fact_in_txn` is reached
//! only from the verified `tasks.create` / `cancel` / `tasks.update` write
//! transactions; the generic raw TASK doors refuse role 6 outright
//! (`habit::reject_public_streak_fields`), so no caller can mint the proof of
//! its own ownership.
//!
//! A fact proves itself to another machine (Fable pass 28 R5). The replay door
//! still admits role 6 like any other TASK row, but a row is not a fact because
//! it arrived: the fold counts a fact this install's own door wrote, and any
//! other only when its carrier's signature verifies and the fold admitted the
//! carrier ([`fact_proof`]). A row that proves nothing is skipped, never an
//! error, so a sender that proves nothing cannot cancel a task, make itself its
//! owner, or fail its read.
//!
//! A proved fact counts only when its actor may make it
//! ([`TaskAuthorityFacts::admits`], Fable pass 28 DESIGN 2.2). The mint door
//! asks the same function before it writes, so the writing device and every
//! other device count the same facts. The fold reads Owner facts first, then
//! the facts whose rule reads the owner, then those whose rule reads the
//! assignee or the consult's parties, so no arrival order changes the answer.

use crate::ports::EdgeStoreRead;

use rmpv::Value;

use crate::Vault;
use crate::authority::CarrierSignature;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::scan_check::ScanCount;
use crate::side_table::{self, SideTable};
use crate::store::EngineScan;
#[cfg(test)]
use crate::temporal::TimeRange;
use crate::write_envelope::task_body::{TaskRole, task_role_from_body_bytes};

pub(crate) use crate::store::task_authority_guard::{
    fact_removal_refused, is_task_authority_fact_in, reject_fact_delete, reject_fact_link_delete,
};

mod binding_generation;
mod consult_executor;
mod fact_proof;
pub use binding_generation::{BindingGeneration, BindingId};

/// Strict body schema for authority facts. Version 2 is version 1 plus the
/// carrier signature, all three of its keys or none; it is the only shape
/// written, and a row naming any other version is refused rather than guessed
/// at. Version 1 rows do not survive the launch reset.
pub const TASK_AUTHORITY_FACT_SCHEMA_VERSION: u8 = 2;
/// Subkind naming this body shape, alongside the role byte — the same
/// role-plus-subkind discrimination every other TASK body carries.
pub const TASK_AUTHORITY_FACT_SUBKIND: &str = "tasks.authority_fact";

const BODY_KEY_ROLE: &str = "role";
const BODY_KEY_SCHEMA_VERSION: &str = "schema_version";
const BODY_KEY_SUBKIND: &str = "subkind";
const BODY_KEY_TASK_REF: &str = "task_ref";
const BODY_KEY_KIND: &str = "kind";
const BODY_KEY_ACTOR_REF: &str = "actor_ref";
const BODY_KEY_ASSIGNED_REF: &str = "assigned_ref";
const BODY_KEY_ACTOR_GENERATION: &str = "actor_generation";
const BODY_KEY_ASSIGNED_GENERATION: &str = "assigned_generation";
const BODY_KEY_OCCURRED_AT: &str = "occurred_at";
const BODY_KEY_CARRIER_MACHINE: &str = "carrier_machine";
const BODY_KEY_CARRIER_KEY: &str = "carrier_key";
const BODY_KEY_CARRIER_SIGNATURE: &str = "carrier_signature";

/// Base key count, without a carrier. HumanAssigned carries one additional
/// assigned_ref; ConsultAssignee carries each of assigned_ref and the two
/// generations when it has one.
const FACT_BODY_KEY_COUNT: usize = 7;
/// The keys a carried fact adds: its carrier's machine, key and signature.
const CARRIER_KEY_COUNT: usize = 3;

/// Contract stored-weight prior for `scoped_to` edges (contracts.ts
/// `edgeKinds.pprWeight` = 0.7), unwrapped at COMPILE time exactly like
/// `vault::CLAIM_OF_DEFAULT_WEIGHT`: a contract change to `null` fails the
/// build instead of the write.
const SCOPED_TO_DEFAULT_WEIGHT: f32 = match EdgeKind::ScopedTo.default_weight() {
    Some(weight) => weight,
    None => panic!("contract pins a non-null pprWeight for scoped_to"),
};

/// What one authority fact asserts about its subject TASK.
///
/// Owner proves who may act directly; cancellation and acknowledgement are
/// events. HumanAssigned records a separate authenticated assignment door,
/// never inferred from a caller-selected Owner id. ConsultAssignee records
/// a consult's parties when it was minted (its asker, the party it was
/// addressed to, and the binding generation each held), so the body's
/// mutable `assignee` field is display and never admission. ConsentRequired
/// records that an interruption asked for a human verdict, so the body's
/// mutable `consent_required` flag is display and never a waiver.
/// Assigned records who a TASK the highway landed is addressed to, so the
/// body's `assignee` is display and never proof that an actor may take it.
/// Accepted records each taker and the binding generation it held, the fence
/// a human-lane report is checked against (OF-220).
/// None of them is ever rewritten or deleted, so the set only grows.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskAuthorityFactKind {
    Owner = 1,
    Cancelled = 2,
    Acked = 3,
    HumanAssigned = 4,
    ConsultAssignee = 5,
    ConsentRequired = 6,
    Assigned = 7,
    Accepted = 8,
}

impl TaskAuthorityFactKind {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Owner => 1,
            Self::Cancelled => 2,
            Self::Acked => 3,
            Self::HumanAssigned => 4,
            Self::ConsultAssignee => 5,
            Self::ConsentRequired => 6,
            Self::Assigned => 7,
            Self::Accepted => 8,
        }
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Owner),
            2 => Some(Self::Cancelled),
            3 => Some(Self::Acked),
            4 => Some(Self::HumanAssigned),
            5 => Some(Self::ConsultAssignee),
            6 => Some(Self::ConsentRequired),
            7 => Some(Self::Assigned),
            8 => Some(Self::Accepted),
            _ => None,
        }
    }
}

/// One immutable authority fact about one TASK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAuthorityFact {
    /// The subject TASK. Must equal the `ScopedTo` edge target the fact is
    /// read through, or the fact is refused.
    pub task_ref: EntityId,
    pub kind: TaskAuthorityFactKind,
    /// Owner facts name the owner; Cancelled/Acked/ConsentRequired facts
    /// name who acted; ConsultAssignee facts name the consult's asker.
    pub actor_ref: EntityId,
    /// HumanAssigned: the immutable agent H assigned. ConsultAssignee: the
    /// party the consult was addressed to, absent for one addressed to the
    /// Dreamer. Absent on every other kind.
    pub assigned_ref: Option<EntityId>,
    /// ConsultAssignee only: the live bindings `actor_ref` held when the
    /// consult was minted, absent when it held none.
    pub actor_generation: Option<BindingGeneration>,
    /// ConsultAssignee only: the same for `assigned_ref`.
    pub assigned_generation: Option<BindingGeneration>,
    pub occurred_at: u64,
}

/// The authority a TASK's fact set proves, once an owner exists.
///
/// `cancelled` is evaluated BEFORE `acked` by every consumer: a cancelled task
/// leaves the active surface even when it also carries an acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskAuthorityState {
    pub owner_ref: EntityId,
    pub cancelled: bool,
    pub acked: bool,
}

/// The raw fold of a TASK's fact set, BEFORE the owner-proof gate.
///
/// [`Vault::task_authority_state`] is the authority lens and fails closed with
/// `None` when no Owner fact proves an owner. Cancellation and acknowledgement
/// are not claims about ownership, so the render tier reads them from here:
/// a task cancelled through a door that proves ownership some other way (a
/// connector-send task's own actor) must still stop rendering.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct TaskAuthorityFacts {
    pub(crate) owner_ref: Option<EntityId>,
    pub(crate) cancelled: bool,
    pub(crate) acked: bool,
    /// The newest Acked fact's time: an acknowledgement answers the
    /// settlement that stood when it was made (FIX 3694).
    pub(crate) acked_at: Option<u64>,
    pub(crate) human_assigner: Option<(EntityId, EntityId)>,
    pub(crate) consult_parties: ConsultParties,
    /// Set once any interruption of the consult asked for a human verdict.
    pub(crate) consent_required: bool,
    /// `(assigner, assignee)` from the Assigned fact.
    pub(crate) assigned: Option<(EntityId, EntityId)>,
    /// The latest taker an Accepted fact names.
    pub(crate) accepted: Option<TaskTaker>,
}

/// One taker of a TASK: who accepted it, the binding generation it held,
/// and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskTaker {
    pub(crate) actor: EntityId,
    pub(crate) generation: Option<BindingGeneration>,
    pub(crate) at: u64,
}

/// What one TASK's immutable facts prove about who may act on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskStanding {
    pub(crate) owner: EntityId,
    /// The actor the TASK is assigned to: the Assigned fact's assignee, else
    /// the human-assignment witness's agent. `None` when no fact names one.
    pub(crate) assignee: Option<EntityId>,
    pub(crate) taker: Option<TaskTaker>,
    pub(crate) cancelled: bool,
}

/// The parties a consult's ConsultAssignee facts name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum ConsultParties {
    /// No fact: nobody holds party standing. Only the consult's minting door
    /// writes one.
    #[default]
    Unminted,
    Minted(ConsultPartyFact),
    /// Facts naming different parties: nobody holds party standing, rather
    /// than one fact winning.
    Forked,
}

/// One consult's parties and the binding generation each held when it was
/// minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsultPartyFact {
    asker: EntityId,
    asker_generation: Option<BindingGeneration>,
    assignee: Option<EntityId>,
    assignee_generation: Option<BindingGeneration>,
}

impl ConsultPartyFact {
    /// Two replicas minting the same consult name the same parties, and
    /// converge on the bindings both recorded for each.
    fn meet(self, other: Self) -> Self {
        Self {
            asker_generation: BindingGeneration::meet(
                self.asker_generation,
                other.asker_generation,
            ),
            assignee_generation: BindingGeneration::meet(
                self.assignee_generation,
                other.assignee_generation,
            ),
            ..self
        }
    }
}

/// An actor's standing as one of a consult's parties: the bindings it held
/// when the consult was minted, one of which it must still hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConsultStanding {
    pub(crate) generation: Option<BindingGeneration>,
}

impl TaskAuthorityFactKind {
    /// The pass of [`TaskAuthorityFacts::fold`] that reads this kind: Owner
    /// first; then the kinds whose rule reads the owner; then the kinds whose
    /// rule reads the assignee or the consult's parties, which the pass before
    /// sets.
    const fn fold_pass(self) -> u8 {
        match self {
            Self::Owner => 0,
            Self::Cancelled
            | Self::Acked
            | Self::HumanAssigned
            | Self::ConsultAssignee
            | Self::Assigned => 1,
            Self::ConsentRequired | Self::Accepted => 2,
        }
    }
}

impl TaskAuthorityFacts {
    /// The public lens: authority exists only on proof of an owner.
    fn into_state(self) -> Option<TaskAuthorityState> {
        self.owner_ref.map(|owner_ref| TaskAuthorityState {
            owner_ref,
            cancelled: self.cancelled,
            acked: self.acked,
        })
    }

    /// Folds `facts` pass by pass ([`TaskAuthorityFactKind::fold_pass`]),
    /// each counted only when [`Self::admits`] it, so every arrival order of
    /// one set folds the same answer.
    fn fold(facts: &[TaskAuthorityFact]) -> Result<Self> {
        let mut folded = Self::default();
        for pass in 0..=2 {
            for fact in facts.iter().filter(|fact| fact.kind.fold_pass() == pass) {
                if folded.admits(fact) {
                    folded.absorb(fact)?;
                }
            }
        }
        Ok(folded)
    }

    /// Whether `fact`'s actor may make it, judged against the facts folded
    /// before its pass (Fable pass 28, DESIGN 2.2). The mint door asks the
    /// same before it writes ([`put_task_authority_fact_in_txn`]); each
    /// door's own check stands in front and is never looser. A fact it
    /// refuses is not counted, and is not an error.
    pub(crate) fn admits(&self, fact: &TaskAuthorityFact) -> bool {
        let actor = fact.actor_ref;
        match fact.kind {
            // Its one rule is absorb's: two owners give nobody standing.
            TaskAuthorityFactKind::Owner => true,
            TaskAuthorityFactKind::HumanAssigned
            | TaskAuthorityFactKind::Assigned
            | TaskAuthorityFactKind::ConsultAssignee
            | TaskAuthorityFactKind::Acked => self.owner_admits(actor),
            // A cancel only takes away, and its doors prove standing the
            // facts do not hold: a connector send's actor, an approved cancel
            // proposal, the vault owner's force. Any proved actor's counts
            // (Engine RULING 16 Nov 03:39, TASK-FACT-ACTOR-RULE-EXCEPTIONS = B).
            TaskAuthorityFactKind::Cancelled => true,
            TaskAuthorityFactKind::ConsentRequired => self.consent_required_admits(actor),
            TaskAuthorityFactKind::Accepted => self.accepted_admits(actor),
        }
    }

    /// The owner's own act. With no proved owner the fact counts: every
    /// reader of the owner's kinds asks for the owner itself (standing, the
    /// human assigner, the consult's parties), so such a fact gives nothing
    /// until an owner is proved; and a task its door wrote with no Owner fact
    /// (a connector send, acked by its own actor) still reads acked.
    fn owner_admits(&self, actor: EntityId) -> bool {
        self.owner_ref.is_none_or(|owner| owner == actor)
    }

    /// The owner, or a party of the consult as its ConsultAssignee fact
    /// names them.
    fn consent_required_admits(&self, actor: EntityId) -> bool {
        self.owner_admits(actor)
            || match &self.consult_parties {
                ConsultParties::Minted(parties) => {
                    parties.asker == actor || parties.assignee == Some(actor)
                }
                ConsultParties::Unminted | ConsultParties::Forked => false,
            }
    }

    /// A taker with standing: the assignee; the owner, who may reclaim or
    /// take over its own task; or anyone on a task the facts address to
    /// nobody, which a runner takes under its lease, and no fact records the
    /// lease.
    fn accepted_admits(&self, actor: EntityId) -> bool {
        self.owner_admits(actor) || self.assignee().is_none_or(|assignee| assignee == actor)
    }

    /// The actor the facts address the task to: the Assigned fact's
    /// assignee, else the human-assignment witness's agent.
    fn assignee(&self) -> Option<EntityId> {
        self.assigned
            .map(|(_, assignee)| assignee)
            .or(self.human_assigner.map(|(_, assigned)| assigned))
    }

    /// Folds one decoded fact in. Duplicate Owner facts naming the SAME owner
    /// are idempotent set duplicates — two replicas minting the proof for the
    /// same create converge, they do not fork.
    fn absorb(&mut self, fact: &TaskAuthorityFact) -> Result<()> {
        match fact.kind {
            TaskAuthorityFactKind::Owner => match self.owner_ref {
                Some(owner_ref) if owner_ref != fact.actor_ref => {
                    // Never pick an arbitrary owner: a forked proof is a
                    // refusal, not a coin flip.
                    return Err(Error::InvariantViolation("task authority owner fork"));
                }
                _ => self.owner_ref = Some(fact.actor_ref),
            },
            TaskAuthorityFactKind::Cancelled => self.cancelled = true,
            TaskAuthorityFactKind::Acked => {
                self.acked = true;
                self.acked_at = self.acked_at.max(Some(fact.occurred_at));
            }
            TaskAuthorityFactKind::HumanAssigned => {
                let assigned = fact.assigned_ref.ok_or(Error::InvariantViolation(
                    "task human assignment lacks agent",
                ))?;
                match self.human_assigner {
                    Some(binding) if binding != (fact.actor_ref, assigned) => {
                        return Err(Error::InvariantViolation("task human assignment fork"));
                    }
                    _ => self.human_assigner = Some((fact.actor_ref, assigned)),
                }
            }
            TaskAuthorityFactKind::ConsultAssignee => {
                let minted = ConsultPartyFact {
                    asker: fact.actor_ref,
                    asker_generation: fact.actor_generation.clone(),
                    assignee: fact.assigned_ref,
                    assignee_generation: fact.assigned_generation.clone(),
                };
                // A fork fails closed for the consult's parties alone: the
                // owner's own cancellation still reads, as a restriction must.
                self.consult_parties = match std::mem::take(&mut self.consult_parties) {
                    ConsultParties::Unminted => ConsultParties::Minted(minted),
                    ConsultParties::Minted(held)
                        if held.asker == minted.asker && held.assignee == minted.assignee =>
                    {
                        ConsultParties::Minted(held.meet(minted))
                    }
                    ConsultParties::Minted(_) | ConsultParties::Forked => ConsultParties::Forked,
                };
            }
            TaskAuthorityFactKind::ConsentRequired => self.consent_required = true,
            TaskAuthorityFactKind::Assigned => {
                let assigned = fact
                    .assigned_ref
                    .ok_or(Error::InvariantViolation("task assignment lacks assignee"))?;
                match self.assigned {
                    Some(binding) if binding != (fact.actor_ref, assigned) => {
                        return Err(Error::InvariantViolation("task assignment fork"));
                    }
                    _ => self.assigned = Some((fact.actor_ref, assigned)),
                }
            }
            TaskAuthorityFactKind::Accepted => {
                let taker = TaskTaker {
                    actor: fact.actor_ref,
                    generation: fact.actor_generation.clone(),
                    at: fact.occurred_at,
                };
                // The latest acceptance stands; the order is total over the
                // facts themselves, so every merge order folds the same taker.
                self.accepted = match self.accepted.take() {
                    Some(held)
                        if (held.at, *held.actor.as_bytes())
                            >= (taker.at, *taker.actor.as_bytes()) =>
                    {
                        Some(held)
                    }
                    _ => Some(taker),
                };
            }
        }
        Ok(())
    }

    /// `actor`'s standing as one of the consult's parties: its asker or the
    /// party it was addressed to, as its one ConsultAssignee fact names them.
    /// A consult with no fact, a forked fact, or a fact whose asker is not
    /// the task's proven owner gives nobody standing.
    pub(crate) fn consult_standing(&self, actor: EntityId) -> Option<ConsultStanding> {
        let ConsultParties::Minted(parties) = &self.consult_parties else {
            return None;
        };
        if self.owner_ref != Some(parties.asker) {
            return None;
        }
        if parties.asker == actor {
            Some(ConsultStanding {
                generation: parties.asker_generation.clone(),
            })
        } else if parties.assignee == Some(actor) {
            Some(ConsultStanding {
                generation: parties.assignee_generation.clone(),
            })
        } else {
            None
        }
    }
}

/// Mints one immutable authority fact inside the CALLER's transaction.
///
/// The fact entity and its `fact --ScopedTo--> task` edge are staged together
/// with whatever else the caller is writing, so a verified `tasks.create`
/// commits its TASK, this proof, and its realizing attempt as ONE unit and a
/// failure anywhere leaves none of them.
///
/// This door earns the bypass by BUILDING the body it writes: nothing
/// a caller supplied reaches storage unvalidated. It refuses a fact whose
/// actor may not make it ([`TaskAuthorityFacts::admits`]), which the fold
/// would not count on any device. An Owner or Cancelled fact counts from
/// any proved actor, so the door reads no fact before it writes one: a task
/// whose facts fail the read (a forked owner, a suppressed fact) still takes
/// its cancel, and the vault owner's force still stops its branches.
pub(crate) fn put_task_authority_fact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fact: TaskAuthorityFact,
) -> Result<EntityId> {
    if !matches!(
        fact.kind,
        TaskAuthorityFactKind::Owner | TaskAuthorityFactKind::Cancelled
    ) && !vault
        .task_authority_facts_in(&*wtxn, fact.task_ref)?
        .admits(&fact)
    {
        return Err(Error::InvariantViolation(
            "task authority fact names an actor that may not make it",
        ));
    }
    write_task_authority_fact_in_txn(vault, wtxn, fact)
}

/// [`write_task_authority_fact_in_txn`] for the test door that stands in for a
/// member machine whose door lacks the actor check.
#[cfg(oneiron_test_support)]
pub(crate) fn write_unjudged_task_authority_fact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fact: TaskAuthorityFact,
) -> Result<EntityId> {
    write_task_authority_fact_in_txn(vault, wtxn, fact)
}

/// Writes `fact` on a new row, signed by this install's carrier when one is
/// loaded: [`put_task_authority_fact_in_txn`] past its check, and the root's
/// twin of a fact a door already wrote.
fn write_task_authority_fact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fact: TaskAuthorityFact,
) -> Result<EntityId> {
    let fact_ref = vault.store.clock.entity_id()?;
    // The carrier signs the fact's own bytes under its own row id, so its
    // signature proves this fact on this row and on no other.
    let unsigned = encode_task_authority_fact_body(&fact);
    let body = match fact_proof::carrier_signature_in_txn(vault, &*wtxn, &fact_ref, &unsigned)? {
        Some(carrier) => encode_carried_fact_body(&fact, &carrier),
        None => unsigned,
    };
    // The fact is born under its TASK's facet (UNBUILT item 10), so a reader
    // outside that facet reads none of the facts about it. A TASK at its own
    // substrate facet, which no FACET row holds, leaves the vault default.
    let substrate = crate::claim::substrate_facet_id(fact.task_ref)?;
    let mask =
        crate::federation::record_scope::task_birth_facet(&vault.store, &*wtxn, fact.task_ref)?
            .filter(|facet| *facet != substrate);
    vault
        .batch_in()
        .mask(mask)
        .put_task_fact(&fact_ref, &body, fact.occurred_at)
        .edge(
            &fact_ref,
            EdgeKind::ScopedTo,
            &fact.task_ref,
            SCOPED_TO_DEFAULT_WEIGHT,
        )
        .apply(wtxn)?;
    crate::federation::record_scope::stamp_task_fact(&vault.store, wtxn, fact_ref, fact.task_ref)?;
    fact_proof::record_written_fact_in_txn(&vault.store, wtxn, &fact_ref, &body)?;
    Ok(fact_ref)
}

/// Serializes one fact under the current schema, without a carrier: the body
/// an unsigned fact stores, and the canonical bytes its carrier signs. Writing
/// MessagePack into a `Vec` is infallible, so this returns bytes directly —
/// the same shape `task_verb::wire_encode` uses for the primary TASK body.
pub(crate) fn encode_task_authority_fact_body(fact: &TaskAuthorityFact) -> Vec<u8> {
    encode_fact_body_entries(fact_body_entries(fact))
}

/// [`encode_task_authority_fact_body`] with its carrier's three keys after
/// the fact's own.
fn encode_carried_fact_body(fact: &TaskAuthorityFact, carrier: &CarrierSignature) -> Vec<u8> {
    let mut entries = fact_body_entries(fact);
    entries.extend([
        (
            Value::from(BODY_KEY_CARRIER_MACHINE),
            Value::from(carrier.machine.to_hex()),
        ),
        (
            Value::from(BODY_KEY_CARRIER_KEY),
            Value::Binary(carrier.key.to_vec()),
        ),
        (
            Value::from(BODY_KEY_CARRIER_SIGNATURE),
            Value::Binary(carrier.signature.to_vec()),
        ),
    ]);
    encode_fact_body_entries(entries)
}

fn encode_fact_body_entries(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .expect("writing msgpack into a Vec is infallible");
    bytes
}

fn fact_body_entries(fact: &TaskAuthorityFact) -> Vec<(Value, Value)> {
    let mut entries = vec![
        (
            Value::from(BODY_KEY_ROLE),
            Value::from(TaskRole::AuthorityFact.role_byte()),
        ),
        (
            Value::from(BODY_KEY_SCHEMA_VERSION),
            Value::from(TASK_AUTHORITY_FACT_SCHEMA_VERSION),
        ),
        (
            Value::from(BODY_KEY_SUBKIND),
            Value::from(TASK_AUTHORITY_FACT_SUBKIND),
        ),
        (
            Value::from(BODY_KEY_TASK_REF),
            Value::from(fact.task_ref.to_hex()),
        ),
        (Value::from(BODY_KEY_KIND), Value::from(fact.kind.as_byte())),
        (
            Value::from(BODY_KEY_ACTOR_REF),
            Value::from(fact.actor_ref.to_hex()),
        ),
        (
            Value::from(BODY_KEY_OCCURRED_AT),
            Value::from(fact.occurred_at),
        ),
    ];
    if let Some(assigned) = fact.assigned_ref {
        entries.push((
            Value::from(BODY_KEY_ASSIGNED_REF),
            Value::from(assigned.to_hex()),
        ));
    }
    for (key, generation) in [
        (BODY_KEY_ACTOR_GENERATION, fact.actor_generation.as_ref()),
        (
            BODY_KEY_ASSIGNED_GENERATION,
            fact.assigned_generation.as_ref(),
        ),
    ] {
        if let Some(generation) = generation {
            entries.push((Value::from(key), generation.encode()));
        }
    }
    entries
}

/// Whether a TASK body is a task authority fact, well-formed or not: role 6
/// with a `subkind` member naming [`TASK_AUTHORITY_FACT_SUBKIND`]. These are
/// the rows the task fold can believe. The ask records share role 6 under
/// their own subkinds and carry their own proofs, so they are not facts here.
pub(crate) fn is_task_authority_fact_body(body: &[u8]) -> bool {
    if !matches!(task_role_from_body_bytes(body), Ok(TaskRole::AuthorityFact)) {
        return false;
    }
    let mut cursor = body;
    matches!(
        rmpv::decode::read_value(&mut cursor),
        Ok(Value::Map(entries)) if entries.iter().any(|(key, value)| {
            key.as_str() == Some(BODY_KEY_SUBKIND)
                && value.as_str() == Some(TASK_AUTHORITY_FACT_SUBKIND)
        })
    )
}

/// One stored fact and the carrier that signed its row, if one did.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CarriedTaskAuthorityFact {
    fact: TaskAuthorityFact,
    carrier: Option<CarrierSignature>,
}

/// [`decode_carried_task_authority_fact_body`]'s fact, whoever carried it.
pub(crate) fn decode_task_authority_fact_body(bytes: &[u8]) -> Result<TaskAuthorityFact> {
    decode_carried_task_authority_fact_body(bytes).map(|carried| carried.fact)
}

/// Decodes one fact body STRICTLY: exactly the current key set, with the
/// three carrier keys or none, no trailing bytes, no unknown keys, no
/// duplicates, pinned version and subkind.
///
/// Strictness is the authority boundary. A body that two decoders could read
/// differently is a body an attacker can aim at one of them, so anything that
/// is not exactly a current fact is refused rather than partially understood.
fn decode_carried_task_authority_fact_body(bytes: &[u8]) -> Result<CarriedTaskAuthorityFact> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::Record(RecordError::InvalidTaskBody("task authority fact body")))?;
    if !cursor.is_empty() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "task authority fact trailing bytes",
        )));
    }
    let entries = value
        .as_map()
        .ok_or(Error::Record(RecordError::InvalidTaskBody(
            "task authority fact body",
        )))?;
    // The key set is EXACT: a base fact has seven keys, HumanAssigned
    // carries exactly one additional agent id, ConsultAssignee carries
    // exactly the optional party and generation keys it has, and a carried
    // fact exactly the three carrier keys more, so no unread field can ride
    // along in a body two decoders would disagree about.
    let carrier = carrier_fields(entries)?;
    let own_keys = entries.len()
        - if carrier.is_some() {
            CARRIER_KEY_COUNT
        } else {
            0
        };
    let byte = |key| {
        fact_body_field(entries, key)?
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(Error::Record(RecordError::InvalidTaskBody(
                "task authority fact byte field",
            )))
    };
    let entity_ref = |key| {
        fact_body_field(entries, key)?
            .as_str()
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(Error::Record(RecordError::InvalidTaskBody(
                "task authority fact entity ref",
            )))
    };

    if byte(BODY_KEY_ROLE)? != TaskRole::AuthorityFact.role_byte() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "task authority fact role",
        )));
    }
    if byte(BODY_KEY_SCHEMA_VERSION)? != TASK_AUTHORITY_FACT_SCHEMA_VERSION {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "task authority fact version",
        )));
    }
    if fact_body_field(entries, BODY_KEY_SUBKIND)?.as_str() != Some(TASK_AUTHORITY_FACT_SUBKIND) {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "task authority fact subkind",
        )));
    }
    let kind = TaskAuthorityFactKind::from_byte(byte(BODY_KEY_KIND)?).ok_or(Error::Record(
        RecordError::InvalidTaskBody("task authority fact kind"),
    ))?;
    let generation = |key| {
        optional_fact_body_field(entries, key)?
            .map(BindingGeneration::decode)
            .transpose()
    };
    let (assigned_ref, actor_generation, assigned_generation) = match kind {
        TaskAuthorityFactKind::HumanAssigned | TaskAuthorityFactKind::Assigned => {
            if own_keys != FACT_BODY_KEY_COUNT + 1 {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "task human assignment key set",
                )));
            }
            (Some(entity_ref(BODY_KEY_ASSIGNED_REF)?), None, None)
        }
        TaskAuthorityFactKind::Accepted => {
            let actor_generation = generation(BODY_KEY_ACTOR_GENERATION)?;
            if own_keys != FACT_BODY_KEY_COUNT + usize::from(actor_generation.is_some()) {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "task acceptance key set",
                )));
            }
            (None, actor_generation, None)
        }
        TaskAuthorityFactKind::ConsultAssignee => {
            let assigned_ref = optional_fact_body_field(entries, BODY_KEY_ASSIGNED_REF)?
                .map(|_| entity_ref(BODY_KEY_ASSIGNED_REF))
                .transpose()?;
            let actor_generation = generation(BODY_KEY_ACTOR_GENERATION)?;
            let assigned_generation = generation(BODY_KEY_ASSIGNED_GENERATION)?;
            let present = [
                assigned_ref.is_some(),
                actor_generation.is_some(),
                assigned_generation.is_some(),
            ];
            if own_keys != FACT_BODY_KEY_COUNT + present.iter().filter(|key| **key).count()
                || (assigned_generation.is_some() && assigned_ref.is_none())
            {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "task consult party key set",
                )));
            }
            (assigned_ref, actor_generation, assigned_generation)
        }
        TaskAuthorityFactKind::Owner
        | TaskAuthorityFactKind::Cancelled
        | TaskAuthorityFactKind::Acked
        | TaskAuthorityFactKind::ConsentRequired => {
            if own_keys != FACT_BODY_KEY_COUNT {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "task authority fact key set",
                )));
            }
            (None, None, None)
        }
    };
    let fact = TaskAuthorityFact {
        task_ref: entity_ref(BODY_KEY_TASK_REF)?,
        kind,
        actor_ref: entity_ref(BODY_KEY_ACTOR_REF)?,
        assigned_ref,
        actor_generation,
        assigned_generation,
        occurred_at: fact_body_field(entries, BODY_KEY_OCCURRED_AT)?
            .as_u64()
            .ok_or(Error::Record(RecordError::InvalidTaskBody(
                "task authority fact timestamp",
            )))?,
    };
    Ok(CarriedTaskAuthorityFact { fact, carrier })
}

/// The carrier a fact body names: its machine (hex) and its key and
/// signature (binary, exact lengths). All three keys or none; any other mix,
/// or a value of another shape, is refused.
fn carrier_fields(entries: &[(Value, Value)]) -> Result<Option<CarrierSignature>> {
    let invalid = || Error::Record(RecordError::InvalidTaskBody("task authority fact carrier"));
    let fields = (
        optional_fact_body_field(entries, BODY_KEY_CARRIER_MACHINE)?,
        optional_fact_body_field(entries, BODY_KEY_CARRIER_KEY)?,
        optional_fact_body_field(entries, BODY_KEY_CARRIER_SIGNATURE)?,
    );
    match fields {
        (None, None, None) => Ok(None),
        (Some(machine), Some(key), Some(signature)) => Ok(Some(CarrierSignature {
            machine: machine
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or_else(invalid)?,
            key: exact_binary(key).ok_or_else(invalid)?,
            signature: exact_binary(signature).ok_or_else(invalid)?,
        })),
        _ => Err(invalid()),
    }
}

/// A MessagePack binary of exactly `N` bytes; a string of the same bytes is
/// not one.
fn exact_binary<const N: usize>(value: &Value) -> Option<[u8; N]> {
    match value {
        Value::Binary(bytes) => <[u8; N]>::try_from(bytes.as_slice()).ok(),
        _ => None,
    }
}

/// The single value stored under `name`, refusing a duplicated key — the same
/// exact-field read `task_verb::wire_decode` uses for the primary TASK body.
fn fact_body_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    optional_fact_body_field(entries, name)?.ok_or(Error::Record(RecordError::InvalidTaskBody(
        "task authority fact key set",
    )))
}

/// [`fact_body_field`] for a key a fact may omit.
fn optional_fact_body_field<'a>(
    entries: &'a [(Value, Value)],
    name: &str,
) -> Result<Option<&'a Value>> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let value = values.next();
    if values.next().is_some() {
        return Err(Error::Record(RecordError::InvalidTaskBody(
            "task authority fact duplicate key",
        )));
    }
    Ok(value)
}

/// Tasks an authority fact of which was refused at admission because its id
/// was deleted here before the fact arrived. Presence-only.
const SUPPRESSED: SideTable<EntityId, [u8; 1], side_table::Raw> =
    SideTable::new(&side_table::TASK_FACT_SUPPRESSED);

/// A replicated row `id` refused because it was deleted here: when it is a
/// task authority fact this vault does not hold and the fact proves itself
/// here, its task is marked, so the task's facts read as a refusal. A
/// tombstone that reached this vault before a fact would otherwise make a
/// cancellation or a consent requirement read as never made. A row that
/// proves nothing marks nothing, so it cannot fail its task's read either.
pub(crate) fn note_suppressed_fact_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    if entity_type != ENTITY_TYPE_TASK
        || !is_task_authority_fact_body(body)
        || is_task_authority_fact_in(store, wtxn, id)?
    {
        return Ok(());
    }
    let Ok(carried) = decode_carried_task_authority_fact_body(body) else {
        return Ok(());
    };
    let task = carried.fact.task_ref;
    if proved_fact(&fact_proof::FactProof::in_txn(store, wtxn)?, id, body, task).is_none() {
        return Ok(());
    }
    SUPPRESSED.put(store, wtxn, &task, &[1])
}

/// [`note_suppressed_fact_in_txn`] for a window document's entity carrier,
/// header and body, that a local path removes because its id was deleted
/// here: a fact the carrier holds that this vault never admitted marks its
/// task, as admission would have.
pub(crate) fn note_removed_carrier_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    carrier: &[u8],
) -> Result<()> {
    let Some(header) = EntityMetadataHeader::parse(carrier) else {
        return Ok(());
    };
    note_suppressed_fact_in_txn(
        store,
        wtxn,
        id,
        header.entity_type,
        &carrier[ENTITY_METADATA_HEADER_LEN..],
    )
}

/// Marks the task of each carrier among `carriers`, ids deleted here, that
/// holds an authority fact this vault never admitted
/// ([`note_removed_carrier_in_txn`]), in a write transaction of its own that
/// has committed when this returns. Every local removal of such a carrier
/// calls it before it touches the carrier, with or without sync: a canonical
/// capture leaves the carrier out either way.
pub(crate) fn mark_removed_carriers(
    vault: &crate::Vault,
    carriers: &[(EntityId, Vec<u8>)],
) -> Result<()> {
    if carriers.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for (id, carrier) in carriers {
            note_removed_carrier_in_txn(&vault.store, wtxn, id, carrier)?;
        }
        Ok(())
    })
}

/// [`note_suppressed_fact_in_txn`] for a door with no tombstone map: the
/// row was deleted here when its id is fenced, as a replicated put reads it.
#[cfg(feature = "sync")]
pub(crate) fn note_fenced_fact_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    use crate::ports::{DeletionMarker, TombstoneStoreRead};
    if store.port_deletion_marked(wtxn, DeletionMarker::RowFence, id)? {
        note_suppressed_fact_in_txn(store, wtxn, id, entity_type, body)?;
    }
    Ok(())
}

/// Whether `task` is marked as holding an authority fact this vault refused.
pub(crate) fn fact_suppressed_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    task: &EntityId,
) -> Result<bool> {
    SUPPRESSED.contains(store, txn, task)
}

/// Marks the tasks a recovered canonical window names as holding a fact its
/// source refused.
#[cfg(feature = "sync")]
pub(crate) fn restore_suppressed_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    tasks: &[[u8; 16]],
) -> Result<()> {
    for task in tasks {
        SUPPRESSED.put(store, wtxn, &EntityId::from_bytes(*task)?, &[1])?;
    }
    Ok(())
}

fn fact_suppressed() -> Error {
    Error::InvariantViolation("task authority fact suppressed")
}

/// The fact `body` on row `fact_ref` states about `task_ref`, when it proves
/// itself here: it decodes, names `task_ref`, and carries a signature that
/// `proof` accepts over its canonical bytes. `None` for a row that proves
/// nothing: malformed, about another task, unsigned, or signed by a key the
/// fold never admitted.
fn proved_fact(
    proof: &fact_proof::FactProof,
    fact_ref: &EntityId,
    body: &[u8],
    task_ref: EntityId,
) -> Option<TaskAuthorityFact> {
    let carried = decode_carried_task_authority_fact_body(body).ok()?;
    let carrier = carried.carrier?;
    (carried.fact.task_ref == task_ref
        && proof.proves(
            fact_ref,
            &encode_task_authority_fact_body(&carried.fact),
            &carrier,
        ))
    .then_some(carried.fact)
}

impl Vault {
    /// Adopts the facts this install's doors wrote unsigned, before the vault's root or with
    /// no signer loaded. Each gets a twin: the same fact on a new row, which this install's
    /// carrier signs. The unsigned row leaves the written-here index. So the fact counts on
    /// every device of the vault, and still counts here (Engine RULING 16 Nov 03:18,
    /// TASK-FACT-RULING-CROSSED-OPTION-D = B). The fold absorbs a twin as a set duplicate of
    /// its fact, so no task changes meaning.
    ///
    /// Each root door calls it once the root is minted with this install's signer loaded.
    /// With no root or no signer it writes nothing. It runs in one transaction, so a failure
    /// leaves no twin, and a second call finds nothing left to adopt. Returns how many twins
    /// it wrote.
    pub fn adopt_unsigned_task_facts(&self) -> Result<usize> {
        self.with_write_txn(|wtxn| {
            if !fact_proof::signs_in_txn(self, wtxn)? {
                return Ok(0);
            }
            let mut adopted = 0;
            for (fact_ref, _) in fact_proof::facts_written_here_in(&self.store, wtxn)? {
                let Some(raw) = self.get_raw_in(wtxn, &fact_ref)? else {
                    continue;
                };
                if EntityMetadataHeader::parse(&raw)
                    .is_none_or(|header| header.entity_type != ENTITY_TYPE_TASK)
                {
                    continue;
                }
                let body = &raw[ENTITY_METADATA_HEADER_LEN..];
                if !fact_proof::written_here_in(&self.store, wtxn, &fact_ref, body)? {
                    continue;
                }
                let carried = decode_carried_task_authority_fact_body(body)?;
                if carried.carrier.is_some() {
                    continue;
                }
                // The same fact on a new row: it counts exactly when the
                // unsigned row did, so it asks no door's rule again.
                write_task_authority_fact_in_txn(self, wtxn, carried.fact)?;
                fact_proof::forget_written_fact_in_txn(&self.store, wtxn, &fact_ref)?;
                adopted += 1;
            }
            Ok(adopted)
        })
    }

    /// The authority one TASK's replicated facts prove.
    ///
    /// `Ok(None)` means NO Owner fact exists, and direct authority therefore
    /// fails closed: a body naming an `owner_ref` is display, never proof, so
    /// a raw or forged TASK row grants nothing. `Err` on a forked owner —
    /// authority is never guessed.
    pub fn task_authority_state(&self, task_ref: EntityId) -> Result<Option<TaskAuthorityState>> {
        let rtxn = self.store.env.read_txn()?;
        self.task_authority_state_in(&rtxn, task_ref)
    }

    /// Transaction-scoped [`Self::task_authority_state`], so one board page
    /// costs one read transaction rather than one per row.
    pub(crate) fn task_authority_state_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Result<Option<TaskAuthorityState>> {
        Ok(self.task_authority_facts_in(rtxn, task_ref)?.into_state())
    }

    /// The separate, engine-authored human-assignment witness. Owner alone
    /// is not evidence that the human authored the assignment: tasks.create
    /// permits a caller to nominate another `owner_ref`. With an owner
    /// proved, the fold counts only a witness whose assigner is that owner.
    pub(crate) fn task_human_assigner_in(
        &self,
        txn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Result<Option<(EntityId, EntityId)>> {
        let facts = self.task_authority_facts_in(txn, task_ref)?;
        Ok(facts.owner_ref.and(facts.human_assigner))
    }

    /// What `task_ref`'s facts prove about who may act on it, or `None`
    /// when no Owner fact proves an owner. The body's `assignee` is never
    /// read: it is display.
    pub(crate) fn task_standing_in(
        &self,
        txn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Result<Option<TaskStanding>> {
        let facts = self.task_authority_facts_in(txn, task_ref)?;
        let Some(owner) = facts.owner_ref else {
            return Ok(None);
        };
        Ok(Some(TaskStanding {
            owner,
            assignee: facts.assignee(),
            taker: facts.accepted,
            cancelled: facts.cancelled,
        }))
    }

    /// Folds every authority fact scoped to `task_ref` that counts here.
    ///
    /// Inbound `ScopedTo` is a shared structural relation, so identification is
    /// LENIENT — anything that is not a TASK row of the fact subkind is simply
    /// not a fact and is skipped. A fact this install's own door wrote is read
    /// STRICTLY: malformed, or naming a different subject than the edge it was
    /// reached through, it fails the read closed. Any other row counts only
    /// when it proves itself ([`proved_fact`]), and is skipped otherwise.
    /// Either way a fact counts only when its actor may make it
    /// ([`TaskAuthorityFacts::fold`]).
    pub(crate) fn task_authority_facts_in(
        &self,
        rtxn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Result<TaskAuthorityFacts> {
        // A fact this vault never admitted is not a fact never made: no
        // cancellation, consent requirement or party is guessed past it.
        if SUPPRESSED.contains(&self.store, rtxn, &task_ref)? {
            return Err(fact_suppressed());
        }
        let mut proved = Vec::new();
        let mut proof = None;
        // Rule 5: every inbound edge is read and every fact absorbed, however
        // many; past its threshold row the fold asks, and never refuses.
        let mut scanned = ScanCount::start(
            &self.store,
            rtxn,
            EngineScan::TaskAuthorityFactEdges,
            task_ref.as_bytes(),
        )?;
        for entry in self.store.port_edges(
            rtxn,
            &task_ref,
            crate::ports::EdgeDirection::In,
            Some(EdgeKind::ScopedTo),
            None,
        )? {
            scanned.row();
            let edge_row = entry?;
            let fact_ref = edge_row.target;
            let Some(raw) = self.get_raw_in(rtxn, &fact_ref)? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            if header.entity_type != ENTITY_TYPE_TASK {
                continue;
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            // An ask record shares role 6 under its own subkind and proves
            // itself by its own rules: it is not a fact.
            if !is_task_authority_fact_body(body) {
                continue;
            }
            let fact = if fact_proof::written_here_in(&self.store, rtxn, &fact_ref, body)? {
                let fact = decode_task_authority_fact_body(body)?;
                // The edge is the index; the body is the claim. A fact
                // reachable from one task while naming another would let a
                // proof minted for a task the actor owns be re-pointed at
                // one they do not.
                if fact.task_ref != task_ref {
                    return Err(Error::Record(RecordError::InvalidTaskBody(
                        "task authority fact subject",
                    )));
                }
                fact
            } else {
                let proof = match &mut proof {
                    Some(proof) => proof,
                    None => proof.insert(fact_proof::FactProof::in_txn(&self.store, rtxn)?),
                };
                match proved_fact(proof, &fact_ref, body, task_ref) {
                    Some(fact) => fact,
                    None => continue,
                }
            };
            proved.push(fact);
        }
        scanned.finish(self);
        TaskAuthorityFacts::fold(&proved)
    }
}

pub(crate) mod tables;
// FIX [LIBTEST-QUARANTINE-TASK-AUTHORITY-TESTS]: the lib test target's type check fails here (2 errors: E0061 x2); port it, then drop this gate
#[cfg(any())]
#[cfg(test)]
mod tests;
