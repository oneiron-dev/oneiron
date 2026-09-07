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
//! Facts are ENGINE-AUTHORED. [`put_task_authority_fact_in_txn`] is reached
//! only from the verified `tasks.create` / `tasks.cancel` / `tasks.ack` write
//! transactions; the generic raw TASK doors refuse role 6 outright
//! (`habit::reject_public_streak_fields`), so no caller can mint the proof of
//! its own ownership. The replication/replay door admits role 6 exactly like
//! any other TASK row — a peer's facts are already facts.

use std::sync::atomic::Ordering;

use rmpv::Value;

use crate::Vault;
use crate::affect::Vad;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::habit::{TaskRole, task_role_from_body_bytes};
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;
use crate::vault::{MAX_EDGE_QUERY_RESULTS, edge_kind_prefix, parse_edge_record};

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
const BODY_KEY_OCCURRED_AT: &str = "occurred_at";

/// The exact v1 key count. A fact carries these seven keys and nothing else.
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
/// The three kinds are independent: an Owner fact is a PROOF (who may act
/// directly), a Cancelled fact and an Acked fact are EVENTS that happened.
/// None of them is ever rewritten or deleted, so the set only grows.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskAuthorityFactKind {
    Owner = 1,
    Cancelled = 2,
    Acked = 3,
}

impl TaskAuthorityFactKind {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Owner => 1,
            Self::Cancelled => 2,
            Self::Acked => 3,
        }
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Owner),
            2 => Some(Self::Cancelled),
            3 => Some(Self::Acked),
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
    /// Owner facts name the owner; Cancelled/Acked facts name who acted.
    pub actor_ref: EntityId,
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
        }
        Ok(())
    }
}

/// Mints one immutable authority fact inside the CALLER's transaction.
///
/// The fact entity and its `fact --ScopedTo--> task` edge are staged together
/// with whatever else the caller is writing, so a verified `tasks.create`
/// commits its TASK, this proof, and its realizing attempt as ONE unit and a
/// failure anywhere leaves none of them.
///
/// The ops are staged directly rather than through a batch builder because the
/// builders run the raw-door TASK refusals, and role 6 is exactly what those
/// refuse. This door earns the bypass by BUILDING the body it writes: nothing
/// a caller supplied reaches storage unvalidated.
pub(crate) fn put_task_authority_fact_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    fact: TaskAuthorityFact,
) -> Result<EntityId> {
    let fact_ref = EntityId::now();
    let occurred = TimeRange {
        start: fact.occurred_at,
        end: fact.occurred_at,
    };
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![
            BatchOp::Put {
                id: fact_ref,
                entity_type: ENTITY_TYPE_TASK,
                occurred,
                learned_at: fact.occurred_at,
                data: encode_task_authority_fact_body(&fact),
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
            BatchOp::Edge {
                src: fact_ref,
                kind: EdgeKind::ScopedTo,
                tgt: fact.task_ref,
                weight: SCOPED_TO_DEFAULT_WEIGHT,
                vad: Vad::NEUTRAL,
            },
        ],
        vault.text_index_trusted.load(Ordering::Acquire),
        false,
        true,
    )?;
    Ok(fact_ref)
}

/// Serializes one fact under schema v1. Writing MessagePack into a `Vec` is
/// infallible, so this returns bytes directly — the same shape
/// `task_verb::wire_encode` uses for the primary TASK body.
pub(crate) fn encode_task_authority_fact_body(fact: &TaskAuthorityFact) -> Vec<u8> {
    let value = Value::Map(vec![
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
    ]);
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
        .map_err(|_| Error::InvalidTaskBody("task authority fact body"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidTaskBody("task authority fact trailing bytes"));
    }
    let entries = value
        .as_map()
        .ok_or(Error::InvalidTaskBody("task authority fact body"))?;
    // The key set is EXACT: a v1 fact has these seven keys and nothing else,
    // so no unread field can ride along in a body two decoders would disagree
    // about.
    if entries.len() != FACT_BODY_KEY_COUNT {
        return Err(Error::InvalidTaskBody("task authority fact key set"));
    }
    let byte = |key| {
        fact_body_field(entries, key)?
            .as_u64()
            .and_then(|raw| u8::try_from(raw).ok())
            .ok_or(Error::InvalidTaskBody("task authority fact byte field"))
    };
    let entity_ref = |key| {
        fact_body_field(entries, key)?
            .as_str()
            .and_then(|hex| EntityId::from_hex(hex).ok())
            .ok_or(Error::InvalidTaskBody("task authority fact entity ref"))
    };

    if byte(BODY_KEY_ROLE)? != TaskRole::AuthorityFact.role_byte() {
        return Err(Error::InvalidTaskBody("task authority fact role"));
    }
    if byte(BODY_KEY_SCHEMA_VERSION)? != TASK_AUTHORITY_FACT_SCHEMA_VERSION {
        return Err(Error::InvalidTaskBody("task authority fact version"));
    }
    if fact_body_field(entries, BODY_KEY_SUBKIND)?.as_str() != Some(TASK_AUTHORITY_FACT_SUBKIND) {
        return Err(Error::InvalidTaskBody("task authority fact subkind"));
    }
    Ok(TaskAuthorityFact {
        task_ref: entity_ref(BODY_KEY_TASK_REF)?,
        kind: TaskAuthorityFactKind::from_byte(byte(BODY_KEY_KIND)?)
            .ok_or(Error::InvalidTaskBody("task authority fact kind"))?,
        actor_ref: entity_ref(BODY_KEY_ACTOR_REF)?,
        occurred_at: fact_body_field(entries, BODY_KEY_OCCURRED_AT)?
            .as_u64()
            .ok_or(Error::InvalidTaskBody("task authority fact timestamp"))?,
    })
}

/// The single value stored under `name`, refusing a duplicated key — the same
/// exact-field read `task_verb::wire_decode` uses for the primary TASK body.
fn fact_body_field<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value> {
    let mut values = entries
        .iter()
        .filter(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value);
    let value = values
        .next()
        .ok_or(Error::InvalidTaskBody("task authority fact key set"))?;
    if values.next().is_some() {
        return Err(Error::InvalidTaskBody("task authority fact duplicate key"));
    }
    Ok(value)
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
        let prefix = edge_kind_prefix(&task_ref, EdgeKind::ScopedTo);
        let mut facts = TaskAuthorityFacts::default();
        for (scanned, entry) in self.store.edges_in.prefix_iter(rtxn, &prefix)?.enumerate() {
            if scanned >= MAX_EDGE_QUERY_RESULTS {
                return Err(Error::IndexOverflow("task authority facts"));
            }
            let (key, value) = entry?;
            let fact_ref = parse_edge_record(&key, &value)?.target;
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
                return Err(Error::InvalidTaskBody("task authority fact subject"));
            }
            facts.absorb(&fact)?;
        }
        Ok(facts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::config::VaultConfig;

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
        (dir, vault)
    }

    fn id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("entity id")
    }

    fn fact(
        task_ref: EntityId,
        kind: TaskAuthorityFactKind,
        actor_ref: EntityId,
    ) -> TaskAuthorityFact {
        TaskAuthorityFact {
            task_ref,
            kind,
            actor_ref,
            occurred_at: 100,
        }
    }

    fn put_fact(vault: &Vault, fact: TaskAuthorityFact) -> EntityId {
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        let fact_ref = put_task_authority_fact_in_txn(vault, &mut wtxn, fact).expect("put fact");
        wtxn.commit().expect("commit fact");
        fact_ref
    }

    fn facts(vault: &Vault, task_ref: EntityId) -> Result<TaskAuthorityFacts> {
        let rtxn = vault.store.env.read_txn().expect("read txn");
        vault.task_authority_facts_in(&rtxn, task_ref)
    }

    fn rewrite_body(body: &[u8], mutate: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
        let mut cursor = body;
        let Value::Map(mut entries) =
            rmpv::decode::read_value(&mut cursor).expect("decode fact body")
        else {
            panic!("a fact body is a map")
        };
        mutate(&mut entries);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("encode fact body");
        out
    }

    fn body_with(body: &[u8], key: &str, value: Value) -> Vec<u8> {
        rewrite_body(body, move |entries| {
            let index = entries
                .iter()
                .position(|(entry_key, _)| entry_key.as_str() == Some(key))
                .expect("replaced key is present");
            entries[index].1 = value;
        })
    }

    /// The wire is the contract: every field survives a round trip, and every
    /// shape that is not exactly a v1 fact is refused rather than guessed at.
    #[test]
    fn strict_v1_bodies_round_trip_and_reject_everything_else() {
        let original = TaskAuthorityFact {
            task_ref: id(0xA1),
            kind: TaskAuthorityFactKind::Cancelled,
            actor_ref: id(0xA2),
            occurred_at: 1_700_000_000,
        };
        let encoded = encode_task_authority_fact_body(&original);
        assert_eq!(
            decode_task_authority_fact_body(&encoded).expect("round trip"),
            original
        );
        assert_eq!(
            crate::habit::task_role_from_body_bytes(&encoded).expect("role decodes"),
            TaskRole::AuthorityFact
        );

        let mut trailing = encoded.clone();
        trailing.push(0xC0);
        let mut cases: Vec<Vec<u8>> = vec![trailing, b"not msgpack at all".to_vec()];
        for (key, value) in [
            (BODY_KEY_ROLE, Value::from(TaskRole::Task.role_byte())),
            (BODY_KEY_SCHEMA_VERSION, Value::from(2_u8)),
            (BODY_KEY_SUBKIND, Value::from("typed")),
            (BODY_KEY_KIND, Value::from(4_u8)),
            (BODY_KEY_TASK_REF, Value::from("not-a-hex-id")),
            (BODY_KEY_OCCURRED_AT, Value::from("not-a-number")),
        ] {
            cases.push(body_with(&encoded, key, value));
        }
        // A dropped key and a smuggled extra key are both refusals: the key
        // set is exact, so nothing can ride along unread.
        cases.push(rewrite_body(&encoded, |entries| {
            entries.retain(|(key, _)| key.as_str() != Some(BODY_KEY_ACTOR_REF));
        }));
        cases.push(rewrite_body(&encoded, |entries| {
            entries.push((Value::from("extra"), Value::from(1_u8)));
        }));
        for (index, case) in cases.iter().enumerate() {
            assert!(
                decode_task_authority_fact_body(case).is_err(),
                "case {index} must be refused"
            );
        }
    }

    /// Direct authority fails CLOSED: no Owner fact, no owner — while the
    /// cancellation the task really carries stays visible to the render tier.
    #[test]
    fn zero_owner_facts_prove_no_authority_but_keep_cancellation() {
        let (_dir, vault) = open_vault();
        let task_ref = id(0xB1);
        assert_eq!(
            vault.task_authority_state(task_ref).expect("empty state"),
            None
        );

        put_fact(
            &vault,
            fact(task_ref, TaskAuthorityFactKind::Cancelled, id(0xB2)),
        );
        assert_eq!(
            vault.task_authority_state(task_ref).expect("state"),
            None,
            "a cancellation is not a proof of ownership"
        );
        assert!(facts(&vault, task_ref).expect("facts").cancelled);
    }

    /// Two facts naming the SAME owner are one owner: replicas that both
    /// minted the proof converge instead of forking.
    #[test]
    fn duplicate_same_owner_facts_are_idempotent() {
        let (_dir, vault) = open_vault();
        let task_ref = id(0xC1);
        let owner = id(0xC2);
        put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, owner));
        put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, owner));

        assert_eq!(
            vault.task_authority_state(task_ref).expect("state"),
            Some(TaskAuthorityState {
                owner_ref: owner,
                cancelled: false,
                acked: false,
            })
        );
    }

    /// Two owners is not "pick one": it is a refusal.
    #[test]
    fn conflicting_owner_facts_fail_closed() {
        let (_dir, vault) = open_vault();
        let task_ref = id(0xD1);
        put_fact(
            &vault,
            fact(task_ref, TaskAuthorityFactKind::Owner, id(0xD2)),
        );
        put_fact(
            &vault,
            fact(task_ref, TaskAuthorityFactKind::Owner, id(0xD3)),
        );

        assert!(matches!(
            vault.task_authority_state(task_ref),
            Err(Error::InvariantViolation("task authority owner fork"))
        ));
    }

    /// Set union, not arrival order: both merge orders and the concurrent pair
    /// land on the same state, and cancellation is never cleared.
    #[test]
    fn cancel_wins_under_every_merge_order() {
        let (_dir, vault) = open_vault();
        let actor = id(0xE9);
        let orders: [(EntityId, [TaskAuthorityFactKind; 2]); 2] = [
            (
                id(0xE1),
                [
                    TaskAuthorityFactKind::Acked,
                    TaskAuthorityFactKind::Cancelled,
                ],
            ),
            (
                id(0xE2),
                [
                    TaskAuthorityFactKind::Cancelled,
                    TaskAuthorityFactKind::Acked,
                ],
            ),
        ];
        for (task_ref, kinds) in orders {
            put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, actor));
            for kind in kinds {
                put_fact(&vault, fact(task_ref, kind, actor));
            }
            assert_eq!(
                vault.task_authority_state(task_ref).expect("state"),
                Some(TaskAuthorityState {
                    owner_ref: actor,
                    cancelled: true,
                    acked: true,
                }),
                "{}",
                task_ref.to_hex()
            );
        }
    }

    /// The edge is the index and the body is the claim; a fact reachable from
    /// a task it does not name is refused, so a proof cannot be re-pointed at
    /// another principal's task.
    #[test]
    fn fact_body_subject_must_equal_the_edge_target() {
        let (_dir, vault) = open_vault();
        let owned = id(0xF1);
        let foreign = id(0xF2);
        let fact_ref = put_fact(&vault, fact(owned, TaskAuthorityFactKind::Owner, id(0xF3)));
        vault
            .batch()
            .edge(&fact_ref, EdgeKind::ScopedTo, &foreign, 0.7)
            .commit()
            .expect("re-point the proof");

        assert!(vault.task_authority_state(owned).is_ok());
        assert!(matches!(
            vault.task_authority_state(foreign),
            Err(Error::InvalidTaskBody("task authority fact subject"))
        ));
    }

    /// Inbound `ScopedTo` is a shared structural relation. Anything that is
    /// not a role-6 TASK row is simply not a fact, and must not poison the
    /// read of the facts that are.
    #[test]
    fn non_fact_scoped_edges_are_not_facts() {
        let (_dir, vault) = open_vault();
        let task_ref = id(0x11);
        let owner = id(0x12);
        let neighbour = id(0x13);
        vault
            .put_entity(
                &neighbour,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                1,
                &crate::habit::task_body_for_test(TaskRole::Task),
            )
            .expect("store a plain TASK");
        vault
            .batch()
            .edge(&neighbour, EdgeKind::ScopedTo, &task_ref, 0.7)
            .commit()
            .expect("scope it to the task");
        put_fact(&vault, fact(task_ref, TaskAuthorityFactKind::Owner, owner));

        assert_eq!(
            vault.task_authority_state(task_ref).expect("state"),
            Some(TaskAuthorityState {
                owner_ref: owner,
                cancelled: false,
                acked: false,
            })
        );
    }

    /// Only the engine door mints authority. A caller who could write a role-6
    /// body through a generic door could prove it owned any task it liked.
    #[test]
    fn generic_write_doors_refuse_the_reserved_role() {
        let (_dir, vault) = open_vault();
        let forged = encode_task_authority_fact_body(&fact(
            id(0x21),
            TaskAuthorityFactKind::Owner,
            id(0x22),
        ));
        let bare_role = crate::habit::task_body_for_test(TaskRole::AuthorityFact);
        let occurred = TimeRange { start: 1, end: 1 };

        for body in [forged, bare_role] {
            let entity = EntityId::now();
            assert!(matches!(
                vault.put_entity(&entity, ENTITY_TYPE_TASK, occurred, 1, &body),
                Err(Error::InvalidTaskBody(_))
            ));
            let mut wtxn = vault.store.env.write_txn().expect("write txn");
            let internal = vault
                .batch_in()
                .put_internal(&EntityId::now(), ENTITY_TYPE_TASK, occurred, 1, &body)
                .apply(&mut wtxn);
            assert!(matches!(internal, Err(Error::InvalidTaskBody(_))));
            drop(wtxn);
            assert!(vault.get(&entity).expect("read back").is_none());
        }
    }
}
