//! Protected replicated ask facts. No winner index lives in vault_meta.
use super::ask_types::{TaskAskAnswer, TaskAskHoldReason, TaskAskStatus};
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::error::{Error, RecordError, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};
use rmpv::Value;
use serde::{Deserialize, Serialize};

const GROUP: &str = "tasks.ask_group";
const ANSWER: &str = "tasks.ask_answer";
const MAX_MEMBERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AskMember {
    pub task: String,
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AskGroup {
    pub owner: String,
    pub request_digest: String,
    pub question: String,
    pub members: Vec<AskMember>,
    pub no_live_route: bool,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskAnswerFact {
    group: String,
    task: String,
    actor: String,
    result: String,
    /// Lamport order over observed answers, not caller-chosen wall time.
    /// Causally later answers cannot replace an observed winner. Concurrent
    /// first answers converge by task id, because there is no global clock.
    order: u64,
}

pub(super) fn invalid() -> Error {
    Error::Record(RecordError::InvalidTaskBody("tasks.ask.fact"))
}

pub(super) fn entity(reference: &str) -> Result<EntityId> {
    EntityId::from_hex(reference).map_err(|_| invalid())
}

/// Device-local intent namespace. It is dedupe mechanics, never authority.
/// Two devices can independently admit an actor's same caller key against
/// different live grant snapshots without overwriting one immutable group.
pub(super) fn group_id(vault: &Vault, actor: EntityId, intent_key: &str) -> Result<EntityId> {
    const ORIGIN_KEY: &[u8] = b"tasks.ask.origin.v1";
    let origin = vault.with_write_txn(|txn| {
        if let Some(raw) = vault.store.vault_meta.get(&*txn, ORIGIN_KEY)? {
            let bytes: [u8; 16] = raw.as_ref().try_into().map_err(|_| invalid())?;
            return EntityId::from_bytes(bytes);
        }
        let origin = EntityId::now();
        vault
            .store
            .vault_meta
            .put(txn, ORIGIN_KEY, origin.as_bytes())?;
        Ok(origin)
    })?;
    let actor_origin = derived_id(b"oneiron.tasks.ask.origin.v1", origin, actor.as_bytes())?;
    derived_id(
        b"oneiron.tasks.ask.intent.v1",
        actor_origin,
        intent_key.as_bytes(),
    )
}

pub(super) fn member_id(group: EntityId, actor: EntityId) -> Result<EntityId> {
    derived_id(b"oneiron.tasks.ask.member.v1", group, actor.as_bytes())
}

fn answer_id(group: EntityId, task: EntityId) -> Result<EntityId> {
    derived_id(b"oneiron.tasks.ask.answer.v1", group, task.as_bytes())
}

fn derived_id(domain: &[u8], parent: EntityId, value: &[u8]) -> Result<EntityId> {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(parent.as_bytes());
    hash.update(value);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    EntityId::from_bytes(id)
}

fn value<T: Serialize>(subkind: &str, record: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_string(record).map_err(|_| invalid())?;
    let body = Value::Map(vec![
        (
            Value::from("role"),
            Value::from(crate::habit::TaskRole::AuthorityFact.role_byte()),
        ),
        (Value::from("schema_version"), Value::from(1)),
        (Value::from("subkind"), Value::from(subkind)),
        (Value::from("record"), Value::from(json)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).map_err(|_| invalid())?;
    Ok(bytes)
}

fn read<T: serde::de::DeserializeOwned>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    subkind: &str,
) -> Result<Option<T>> {
    let Some(raw) = vault.get_raw_in(txn, &id)? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    let mut cursor = &raw[ENTITY_METADATA_HEADER_LEN..];
    let body = rmpv::decode::read_value(&mut cursor).map_err(|_| invalid())?;
    if !cursor.is_empty() {
        return Err(invalid());
    }
    let Some(map) = body.as_map() else {
        return Ok(None);
    };
    let get = |key: &str| -> Result<&Value> {
        let mut matches = map.iter().filter(|(k, _)| k.as_str() == Some(key));
        let result = matches.next().ok_or_else(invalid)?;
        if matches.next().is_some() {
            return Err(invalid());
        }
        Ok(&result.1)
    };
    // Non-ask TASKs are not groups. A claimed group has one exact schema.
    if !map
        .iter()
        .any(|(k, v)| k.as_str() == Some("subkind") && v.as_str() == Some(subkind))
    {
        return Ok(None);
    }
    if map.len() != 4
        || get("role")?.as_u64() != Some(6)
        || get("schema_version")?.as_u64() != Some(1)
        || get("subkind")?.as_str() != Some(subkind)
    {
        return Err(invalid());
    }
    serde_json::from_str(get("record")?.as_str().ok_or_else(invalid)?)
        .map(Some)
        .map_err(|_| invalid())
}

fn put<T: Serialize>(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    subkind: &str,
    record: &T,
    now: u64,
) -> Result<()> {
    let encoded = value(subkind, record)?;
    // Immutable, including retries. A collision never overwrites foreign data.
    if let Some(raw) = vault.get_raw_in(&*txn, &id)? {
        if raw.get(ENTITY_METADATA_HEADER_LEN..) == Some(encoded.as_slice()) {
            return Ok(());
        }
        return Err(invalid());
    }
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_TASK,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
            data: encoded,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(())
}

pub(super) fn read_group(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<AskGroup>> {
    let Some(group) = read::<AskGroup>(vault, txn, id, GROUP)? else {
        return Ok(None);
    };
    entity(&group.owner)?;
    if group.members.is_empty() || group.members.len() > MAX_MEMBERS {
        return Err(invalid());
    }
    let mut tasks = std::collections::BTreeSet::new();
    let mut actors = std::collections::BTreeSet::new();
    for member in &group.members {
        if !tasks.insert(entity(&member.task)?) || !actors.insert(entity(&member.actor)?) {
            return Err(invalid());
        }
    }
    Ok(Some(group))
}

pub(super) fn put_group(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<()> {
    if group.members.is_empty() || group.members.len() > MAX_MEMBERS {
        return Err(invalid());
    }
    put(vault, txn, id, GROUP, group, group.created_at)
}

fn answer_facts(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<Vec<AskAnswerFact>> {
    let mut facts = Vec::new();
    for member in &group.members {
        let task = entity(&member.task)?;
        let Some(fact) = read::<AskAnswerFact>(vault, txn, answer_id(id, task)?, ANSWER)? else {
            continue;
        };
        if fact.group != id.to_hex()
            || fact.task != member.task
            || fact.actor != member.actor
            || fact.order == 0
        {
            return Err(invalid());
        }
        entity(&fact.result)?;
        facts.push(fact);
    }
    Ok(facts)
}

pub(super) fn record_answer(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    body: &super::consult_result::TaskVerbBody,
    actor: EntityId,
    terminal: &super::TaskTerminalRecord,
    now: u64,
) -> Result<Option<EntityId>> {
    let Some(payload) = &body.consult else {
        return Ok(None);
    };
    let id = payload.correlation_ref;
    let Some(group) = read_group(vault, &*txn, id)? else {
        return Ok(None);
    };
    // Correlation alone NEVER confers group membership. A forged sibling may
    // settle itself, but cannot settle an unrelated handle or mutate siblings.
    if !group
        .members
        .iter()
        .any(|m| m.task == task.to_hex() && m.actor == actor.to_hex())
    {
        return Ok(None);
    }
    if group.owner != body.owner_ref
        || group.question != payload.question_ref.short_ref()
        || vault
            .task_authority_state_in(&*txn, task)?
            .is_none_or(|state| state.owner_ref.to_hex() != group.owner)
    {
        return Err(invalid());
    }
    if !matches!(
        terminal.summary,
        Some(super::ConsultResultSummary::Answer { .. })
    ) {
        return Ok(Some(id));
    }
    let fact_id = answer_id(id, task)?;
    let result = terminal.result_ref.ok_or_else(invalid)?.to_hex();
    if let Some(existing) = read::<AskAnswerFact>(vault, &*txn, fact_id, ANSWER)? {
        if existing.group == id.to_hex()
            && existing.task == task.to_hex()
            && existing.actor == actor.to_hex()
            && existing.result == result
        {
            return Ok(Some(id));
        }
        return Err(invalid());
    }
    let order = answer_facts(vault, &*txn, id, &group)?
        .iter()
        .map(|f| f.order)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(invalid)?;
    put(
        vault,
        txn,
        fact_id,
        ANSWER,
        &AskAnswerFact {
            group: id.to_hex(),
            task: task.to_hex(),
            actor: actor.to_hex(),
            result,
            order,
        },
        now,
    )?;
    Ok(Some(id))
}

pub(super) fn status_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<TaskAskStatus> {
    if let Some(winner) = answer_facts(vault, txn, id, group)?
        .into_iter()
        .min_by(|a, b| (a.order, &a.task).cmp(&(b.order, &b.task)))
    {
        return Ok(TaskAskStatus::Answered(TaskAskAnswer {
            task_ref: entity(&winner.task)?,
            actor_ref: entity(&winner.actor)?,
            result_ref: entity(&winner.result)?,
        }));
    }
    let mut exhausted = true;
    for member in &group.members {
        let body = super::create_validation::task_body_in_txn(vault, txn, entity(&member.task)?)
            .map_err(|_| invalid())?;
        exhausted &= body.terminal().is_some() || body.settled_ladder_disposition().is_some();
    }
    if exhausted {
        return Ok(TaskAskStatus::Exhausted);
    }
    Ok(TaskAskStatus::Pending {
        hold: group
            .no_live_route
            .then_some(TaskAskHoldReason::NoLiveRoute),
    })
}

pub(crate) fn ask_is_terminal(vault: &Vault, id: EntityId) -> Result<Option<bool>> {
    let txn = vault.store.env.read_txn()?;
    read_group(vault, &txn, id)?
        .map(|group| {
            status_in(vault, &txn, id, &group)
                .map(|status| !matches!(status, TaskAskStatus::Pending { .. }))
        })
        .transpose()
}
