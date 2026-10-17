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
//! its own ownership. The replication/replay door admits role 6 exactly like
//! any other TASK row — a peer's facts are already facts.

use crate::ports::EdgeStoreRead;

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::habit::{TaskRole, task_role_from_body_bytes};
use crate::registry::ENTITY_TYPE_TASK;
use crate::side_table::{self, SideTable};
#[cfg(test)]
use crate::temporal::TimeRange;
use crate::vault::MAX_EDGE_QUERY_RESULTS;

mod binding_generation;
pub use binding_generation::{BindingGeneration, BindingId, MAX_GENERATION_BINDINGS};

/// Strict body schema for authority facts. Version 1 is the only shape ever
/// written; a row naming any other version is refused rather than guessed at.
pub const TASK_AUTHORITY_FACT_SCHEMA_VERSION: u8 = 1;
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

/// Base v1 key count. HumanAssigned carries one additional assigned_ref;
/// ConsultAssignee carries each of assigned_ref and the two generations when
/// it has one.
const FACT_BODY_KEY_COUNT: usize = 7;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct TaskAuthorityFacts {
    pub(crate) owner_ref: Option<EntityId>,
    pub(crate) cancelled: bool,
    pub(crate) acked: bool,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskTaker {
    pub(crate) actor: EntityId,
    pub(crate) generation: Option<BindingGeneration>,
    pub(crate) at: u64,
}

/// What one TASK's immutable facts prove about who may act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskStanding {
    pub(crate) owner: EntityId,
    /// The actor the TASK is assigned to: the Assigned fact's assignee, else
    /// the human-assignment witness's agent. `None` when no fact names one.
    pub(crate) assignee: Option<EntityId>,
    pub(crate) taker: Option<TaskTaker>,
    pub(crate) cancelled: bool,
}

/// The parties a consult's ConsultAssignee facts name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::large_enum_variant,
    reason = "a fold value read once per consult; boxing would cost the fold its Copy"
)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsultStanding {
    pub(crate) generation: Option<BindingGeneration>,
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
            TaskAuthorityFactKind::Acked => self.acked = true,
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
                    asker_generation: fact.actor_generation,
                    assignee: fact.assigned_ref,
                    assignee_generation: fact.assigned_generation,
                };
                // A fork fails closed for the consult's parties alone: the
                // owner's own cancellation still reads, as a restriction must.
                self.consult_parties = match self.consult_parties {
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
                    generation: fact.actor_generation,
                    at: fact.occurred_at,
                };
                // The latest acceptance stands; the order is total over the
                // facts themselves, so every merge order folds the same taker.
                self.accepted = match self.accepted {
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
        let ConsultParties::Minted(parties) = self.consult_parties else {
            return None;
        };
        if self.owner_ref != Some(parties.asker) {
            return None;
        }
        if parties.asker == actor {
            Some(ConsultStanding {
                generation: parties.asker_generation,
            })
        } else if parties.assignee == Some(actor) {
            Some(ConsultStanding {
                generation: parties.assignee_generation,
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
/// a caller supplied reaches storage unvalidated.
pub(crate) fn put_task_authority_fact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fact: TaskAuthorityFact,
) -> Result<EntityId> {
    let fact_ref = vault.store.clock.entity_id()?;
    vault
        .batch_in()
        .put_task_fact(
            &fact_ref,
            &encode_task_authority_fact_body(&fact),
            fact.occurred_at,
        )
        .edge(
            &fact_ref,
            EdgeKind::ScopedTo,
            &fact.task_ref,
            SCOPED_TO_DEFAULT_WEIGHT,
        )
        .apply(wtxn)?;
    crate::federation::record_scope::stamp_task_fact(&vault.store, wtxn, fact_ref, fact.task_ref)?;
    Ok(fact_ref)
}

/// Serializes one fact under schema v1. Writing MessagePack into a `Vec` is
/// infallible, so this returns bytes directly — the same shape
/// `task_verb::wire_encode` uses for the primary TASK body.
pub(crate) fn encode_task_authority_fact_body(fact: &TaskAuthorityFact) -> Vec<u8> {
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
        (BODY_KEY_ACTOR_GENERATION, fact.actor_generation),
        (BODY_KEY_ASSIGNED_GENERATION, fact.assigned_generation),
    ] {
        if let Some(generation) = generation {
            entries.push((Value::from(key), generation.encode()));
        }
    }
    let value = Value::Map(entries);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .expect("writing msgpack into a Vec is infallible");
    bytes
}

/// Decodes one fact body STRICTLY: exactly the v1 key set, no trailing bytes,
/// no unknown keys, no duplicates, pinned version and subkind.
///
/// Strictness is the authority boundary. A body that two decoders could read
/// differently is a body an attacker can aim at one of them, so anything that
/// is not exactly a v1 fact is refused rather than partially understood.
pub(crate) fn decode_task_authority_fact_body(bytes: &[u8]) -> Result<TaskAuthorityFact> {
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
    // carries exactly one additional agent id, and ConsultAssignee carries
    // exactly the optional party and generation keys it has, so no unread
    // field can ride along in a body two decoders would disagree about.
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
            if entries.len() != FACT_BODY_KEY_COUNT + 1 {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "task human assignment key set",
                )));
            }
            (Some(entity_ref(BODY_KEY_ASSIGNED_REF)?), None, None)
        }
        TaskAuthorityFactKind::Accepted => {
            let actor_generation = generation(BODY_KEY_ACTOR_GENERATION)?;
            if entries.len() != FACT_BODY_KEY_COUNT + usize::from(actor_generation.is_some()) {
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
            if entries.len() != FACT_BODY_KEY_COUNT + present.iter().filter(|key| **key).count()
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
            if entries.len() != FACT_BODY_KEY_COUNT {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "task authority fact key set",
                )));
            }
            (None, None, None)
        }
    };
    Ok(TaskAuthorityFact {
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
    })
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

/// Whether `id` is a stored authority fact.
pub(crate) fn is_task_authority_fact_in(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, txn, id)? else {
        return Ok(false);
    };
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("task authority fact guard header"))?;
    Ok(header.entity_type == ENTITY_TYPE_TASK
        && raw.len() > ENTITY_METADATA_HEADER_LEN
        && matches!(
            task_role_from_body_bytes(&raw[ENTITY_METADATA_HEADER_LEN..]),
            Ok(TaskRole::AuthorityFact)
        ))
}

/// Tasks an authority fact of which was refused at admission because its id
/// was deleted here before the fact arrived. Presence-only.
const SUPPRESSED: SideTable<EntityId, [u8; 1], side_table::Raw> =
    SideTable::new(&side_table::TASK_FACT_SUPPRESSED);

/// A replicated row `id` refused because it was deleted here: when it is a
/// task authority fact this vault does not hold, its task is marked, so the
/// task's facts read as a refusal. A tombstone that reached this vault before
/// a fact would otherwise make a cancellation or a consent requirement read
/// as never made.
pub(crate) fn note_suppressed_fact_in_txn(
    store: &crate::store::Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<()> {
    if entity_type != ENTITY_TYPE_TASK || is_task_authority_fact_in(store, wtxn, id)? {
        return Ok(());
    }
    let Ok(fact) = decode_task_authority_fact_body(body) else {
        return Ok(());
    };
    SUPPRESSED.put(store, wtxn, &fact.task_ref, &[1])
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

/// A fact is read through its `fact --ScopedTo--> task` link, so removing
/// the link, or the fact, would read as a requirement never made or a party
/// never named, and let the next fact stand as the first. No door removes
/// either; a hard delete of the subject takes the link with its row.
pub(crate) fn reject_fact_link_delete(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    src: &EntityId,
    kind: EdgeKind,
) -> Result<()> {
    if kind == EdgeKind::ScopedTo && is_task_authority_fact_in(store, txn, src)? {
        return Err(fact_removal_refused());
    }
    Ok(())
}

/// [`reject_fact_link_delete`] for the fact row itself.
pub(crate) fn reject_fact_delete(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if is_task_authority_fact_in(store, txn, id)? {
        return Err(fact_removal_refused());
    }
    Ok(())
}

pub(crate) fn fact_removal_refused() -> Error {
    Error::Record(RecordError::InvalidTaskBody(
        "task authority facts are immutable",
    ))
}

impl Vault {
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
    /// permits a caller to nominate another `owner_ref`.
    pub(crate) fn task_human_assigner_in(
        &self,
        txn: &heed::RoTxn<'_>,
        task_ref: EntityId,
    ) -> Result<Option<(EntityId, EntityId)>> {
        let facts = self.task_authority_facts_in(txn, task_ref)?;
        match (facts.owner_ref, facts.human_assigner) {
            (Some(owner), Some((assigner, assigned))) if owner == assigner => {
                Ok(Some((owner, assigned)))
            }
            (Some(_), Some(_)) => Err(Error::InvariantViolation(
                "task human assigner is not owner",
            )),
            _ => Ok(None),
        }
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
        let witnessed = match facts.human_assigner {
            Some((assigner, assigned)) if assigner == owner => Some(assigned),
            _ => None,
        };
        Ok(Some(TaskStanding {
            owner,
            assignee: facts.assigned.map(|(_, assignee)| assignee).or(witnessed),
            taker: facts.accepted,
            cancelled: facts.cancelled,
        }))
    }

    /// Folds every authority fact scoped to `task_ref`.
    ///
    /// Inbound `ScopedTo` is a shared structural relation, so identification is
    /// LENIENT — anything that is not a role-6 TASK entity is simply not a fact
    /// and is skipped — while validation is STRICT: a row that claims to be a
    /// fact and is malformed, or whose body names a different subject than the
    /// edge it was reached through, fails the read closed.
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
        let mut facts = TaskAuthorityFacts::default();
        for (scanned, entry) in self
            .store
            .port_edges(
                rtxn,
                &task_ref,
                crate::ports::EdgeDirection::In,
                Some(EdgeKind::ScopedTo),
                None,
            )?
            .enumerate()
        {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("task authority facts"));
            }
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
            if !matches!(task_role_from_body_bytes(body), Ok(TaskRole::AuthorityFact)) {
                continue;
            }
            let fact = decode_task_authority_fact_body(body)?;
            // The edge is the index; the body is the claim. A fact reachable
            // from one task while naming another would let a proof minted for
            // a task the actor owns be re-pointed at one they do not.
            if fact.task_ref != task_ref {
                return Err(Error::Record(RecordError::InvalidTaskBody(
                    "task authority fact subject",
                )));
            }
            facts.absorb(&fact)?;
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests;
