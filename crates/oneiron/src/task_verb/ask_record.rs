//! Protected replicated ask facts. No winner index lives in vault_meta.
mod guard;
use super::ask_types::{
    TaskAskAnswer, TaskAskEvidence, TaskAskEvidenceReason, TaskAskHoldReason,
    TaskAskPersonEvidence, TaskAskPersonKind, TaskAskSource, TaskAskStatus, TaskAskWord,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, RecordError, Result};
use crate::habit::TaskRole;
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_TASK;
use crate::side_table::{self, SideTable};
use crate::{EntityId, Vault};
pub(super) use guard::validate_notice_companion;
use guard::validate_word;
pub(crate) use guard::{guard_ask_fact_put, waits_for_ask_group};
use rmpv::Value;
use serde::{Deserialize, Serialize};

mod link_proof;
mod word_admission;
pub(super) use link_proof::{
    mint_key as mint_link_key, sign_settlement as sign_link_settlement,
    verify_settlement as verify_link_settlement,
};
pub(super) use word_admission::{admit_link_word, admit_word};

/// Node-local origin id this device mints ask intents under. Key: `()`.
const ASK_ORIGIN: SideTable<(), EntityId, side_table::Raw> =
    SideTable::new(&side_table::TASK_ASK_ORIGIN);

const GROUP: &str = "tasks.ask_group";
const ANSWER: &str = "tasks.ask_answer";
const MAX_MEMBERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AskMember {
    pub task: String,
    pub actor: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AskGroup {
    pub base_policy_version: u16,
    pub owner: String,
    pub request_digest: String,
    pub requested: super::TaskAskSpec,
    pub effective: super::TaskAskSpec,
    pub context_class: Option<super::TaskAskClass>,
    pub question_digest: [u8; 32],
    pub link_verify_key: [u8; 32],
    pub members: Vec<AskMember>,
    pub no_live_route: bool,
    pub created_at: u64,
    /// Disjoint FEDERATION_GRANT entity IDs, keyed by the guest's person.
    #[serde(default)]
    pub guest_grants: std::collections::BTreeMap<EntityId, EntityId>,
    pub policy_surface: super::TaskAskSurface,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskAnswerFact {
    group: EntityId,
    task: EntityId,
    actor: EntityId,
    source: TaskAskSource,
    word: TaskAskWord,
    #[serde(default)]
    link_proof: Option<link_proof::LinkProof>,
    order: u64,
    #[serde(default)]
    delegation_grant_ref: Option<String>,
    at: u64,
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
pub(super) fn group_id(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    intent_key: &str,
) -> Result<EntityId> {
    let origin = if let Some(origin) = ASK_ORIGIN.get(&vault.store, txn, &())? {
        origin
    } else {
        let origin = vault.store.clock.entity_id()?;
        ASK_ORIGIN.put(&vault.store, txn, &(), &origin)?;
        origin
    };
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

fn answer_id(
    group: EntityId,
    task: EntityId,
    actor: EntityId,
    source: TaskAskSource,
    word: &TaskAskWord,
) -> Result<EntityId> {
    let bytes = rmp_serde::to_vec_named(&(task, actor, source, word)).map_err(|_| invalid())?;
    derived_id(b"oneiron.tasks.ask.answer.v1", group, &bytes)
}

pub(super) fn owns_revision(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<bool> {
    let Some(origin) = ASK_ORIGIN.get(&vault.store, txn, &())? else {
        return Ok(false);
    };
    let actor_origin = derived_id(
        b"oneiron.tasks.ask.origin.v1",
        origin,
        entity(&group.owner)?.as_bytes(),
    )?;
    Ok(derived_id(
        b"oneiron.tasks.ask.intent.v1",
        actor_origin,
        group.requested.intent_key.as_bytes(),
    )? == id)
}

pub(super) fn derived_id(domain: &[u8], parent: EntityId, value: &[u8]) -> Result<EntityId> {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(parent.as_bytes());
    hash.update(value);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    EntityId::from_bytes(id)
}

fn value<T: Serialize>(subkind: &str, record: &T) -> Result<Vec<u8>> {
    let named = rmp_serde::to_vec_named(record).map_err(|_| invalid())?;
    let Value::Map(mut fields) =
        rmpv::decode::read_value(&mut named.as_slice()).map_err(|_| invalid())?
    else {
        return Err(invalid());
    };
    fields.extend([
        (
            Value::from("role"),
            Value::from(TaskRole::AuthorityFact.role_byte()),
        ),
        (Value::from("schema_version"), Value::from(1)),
        (Value::from("subkind"), Value::from(subkind)),
    ]);
    let body = Value::Map(fields);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).map_err(|_| invalid())?;
    Ok(bytes)
}

pub(super) fn read<T: serde::de::DeserializeOwned>(
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
    decode(
        raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?,
        subkind,
    )
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8], subkind: &str) -> Result<Option<T>> {
    let mut cursor = bytes;
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
    if get("role")?.as_u64() != Some(u64::from(TaskRole::AuthorityFact.role_byte()))
        || get("schema_version")?.as_u64() != Some(1)
        || get("subkind")?.as_str() != Some(subkind)
    {
        return Err(invalid());
    }
    let fields = map
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), Some("role" | "schema_version" | "subkind")))
        .cloned()
        .collect();
    let named = rmp_serde::to_vec_named(&Value::Map(fields)).map_err(|_| invalid())?;
    rmp_serde::from_slice(&named)
        .map(Some)
        .map_err(|_| invalid())
}

fn read_answer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<AskAnswerFact>> {
    let Some(raw) = vault.get_raw_in(txn, &id)? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(invalid)?;
    if header.entity_type != ENTITY_TYPE_TASK {
        return Ok(None);
    }
    let fact = decode::<AskAnswerFact>(
        raw.get(ENTITY_METADATA_HEADER_LEN..).ok_or_else(invalid)?,
        ANSWER,
    )?;
    if fact.as_ref().is_some_and(|fact| {
        fact.at != header.learned_at
            || fact.at != header.occurred_start
            || fact.at != header.occurred_end
    }) {
        return Err(invalid());
    }
    Ok(fact)
}

pub(super) fn put<T: Serialize>(
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
    vault
        .batch_in()
        .put_task_fact(&id, &encoded, now)
        .apply(txn)?;
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
    if group.base_policy_version != 1
        || group.members.is_empty()
        || group.members.len() > MAX_MEMBERS
    {
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
    if group.base_policy_version != 1
        || group.members.is_empty()
        || group.members.len() > MAX_MEMBERS
    {
        return Err(invalid());
    }
    put(vault, txn, id, GROUP, group, group.created_at)
}

pub(super) fn evidence_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<Vec<TaskAskEvidence>> {
    let mut evidence = Vec::new();
    for (count, row) in vault
        .store
        .port_edges(
            txn,
            &id,
            crate::ports::EdgeDirection::In,
            Some(crate::EdgeKind::About),
            None,
        )?
        .enumerate()
    {
        if count >= 4096 {
            return Err(Error::IndexOverflow("ask words"));
        }
        let word_ref = row?.target;
        let Some(fact) = read_answer(vault, txn, word_ref)? else {
            continue;
        };
        if fact.group != id {
            continue;
        }
        let person = fact
            .word
            .inform_for
            .or(fact.word.companion_for)
            .unwrap_or(fact.actor);
        if !group
            .members
            .iter()
            .any(|member| member.task == fact.task.to_hex() && member.actor == person.to_hex())
            || fact.order == 0
            || fact.at == 0
            || (fact.source == TaskAskSource::Inform) != fact.word.inform_for.is_some()
            || (fact.source == TaskAskSource::Inform && fact.actor.to_hex() != group.owner)
            || (fact.source == TaskAskSource::ForeignStated
                && (fact.word.inform_for.is_some()
                    || vault.get_entity_type_in_txn(txn, &fact.actor)?
                        != Some(crate::registry::ENTITY_TYPE_PERSON)))
            || (fact.source == TaskAskSource::Companion) != fact.word.companion_for.is_some()
            || (fact.source != TaskAskSource::Companion && fact.delegation_grant_ref.is_some())
            || fact.delegation_grant_ref.as_ref().is_some_and(|reference| {
                !super::ask_guest::check_delegation_record(
                    vault,
                    txn,
                    person,
                    fact.actor,
                    group.effective.what.class_key.as_deref(),
                    reference,
                )
                .unwrap_or(false)
            })
            || answer_id(id, fact.task, fact.actor, fact.source, &fact.word)? != word_ref
        {
            return Err(invalid());
        }
        validate_word(group, &fact.word).map_err(|_| Error::CorruptedIndex("tasks.ask.word"))?;
        link_proof::validate_source(&vault.store, txn, word_ref, group, &fact)?;
        if fact.word.confirmation.is_some() {
            if fact.source != TaskAskSource::Human {
                return Err(invalid());
            }
            super::ask_soft_confirm::validate_confirmation(
                vault, txn, id, group, fact.actor, &fact.word,
            )?;
        }
        if fact.source == TaskAskSource::Companion {
            super::ask_guest::validate_companion_fact(
                vault, txn, id, group, fact.actor, &fact.word,
            )?;
        }
        evidence.push(TaskAskEvidence {
            answer: TaskAskAnswer {
                task_ref: fact.task,
                actor_ref: fact.actor,
                result_ref: fact.word.result_ref,
                word_ref,
            },
            word: fact.word,
            source: fact.source,
            person_ref: person,
            order: fact.order,
            reason: TaskAskEvidenceReason::OutsideElectorate,
            ladder_changed: None,
            soft_confirm: fact.source == TaskAskSource::Companion
                && group.effective.what.commitment,
            delegation_grant_ref: fact.delegation_grant_ref,
        });
    }
    evidence.sort_by_key(|entry| (entry.order, entry.answer.word_ref));
    Ok(evidence)
}

/// Projects all admitted words without erasing their speakers. A person
/// without a word becomes unknown only when the cutoff has passed or settled.
pub(super) fn person_evidence_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    now: u64,
) -> Result<Vec<TaskAskPersonEvidence>> {
    let settled = super::ask_settlement::read_result(vault, txn, id)?;
    let cutoff = settled
        .as_ref()
        .map(|result| result.settlement.at)
        .or_else(|| group.effective.until.filter(|until| *until <= now));
    let words = super::ask_settlement::evidence(vault, txn, id, group)?;
    let mut answers = Vec::with_capacity(group.members.len());
    for member in &group.members {
        let who = entity(&member.actor)?;
        let selected = words
            .iter()
            .filter(|entry| entry.person_ref == who)
            .max_by_key(|entry| {
                (
                    u8::from(matches!(
                        entry.source,
                        TaskAskSource::Human | TaskAskSource::ForeignStated
                    )),
                    entry.order,
                )
            });
        if let Some(entry) = selected {
            let fact = read_answer(vault, txn, entry.answer.word_ref)?.ok_or_else(invalid)?;
            answers.push(TaskAskPersonEvidence {
                who,
                answer: Some(entry.word.clone()),
                kind: if matches!(
                    entry.source,
                    TaskAskSource::Human | TaskAskSource::ForeignStated
                ) {
                    TaskAskPersonKind::Word
                } else {
                    TaskAskPersonKind::Companion
                },
                at: fact.at,
                source: Some(entry.answer.actor_ref),
            });
        } else if let Some(at) = cutoff {
            answers.push(TaskAskPersonEvidence {
                who,
                answer: None,
                kind: TaskAskPersonKind::Unknown,
                at,
                source: None,
            });
        }
    }
    Ok(answers)
}

/// The terminal register does not carry the option. A replay of an ask answer
/// must also match the immutable word recorded for this member. If two words
/// with the same terminal payload disagree on the option, the terminal alone
/// cannot identify the original word, so refuse the ambiguous replay.
pub(super) fn replay_answer_option_matches(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    body: &super::consult_result::TaskVerbBody,
    actor: EntityId,
    terminal: &super::TaskTerminalRecord,
    option: Option<&super::TaskAskOptionId>,
) -> Result<bool> {
    // Outside an ask-group member there is no durable ask word to compare.
    // The terminal equality check already established the replay payload;
    // the option was irrelevant on first settlement and remains so here.
    let Some(payload) = &body.consult else {
        return Ok(true);
    };
    let Some(group) = read_group(vault, txn, payload.correlation_ref)? else {
        return Ok(true);
    };
    if !group
        .members
        .iter()
        .any(|member| member.task == task.to_hex() && member.actor == actor.to_hex())
    {
        return Ok(true);
    }
    let Some(super::ConsultResultSummary::Answer { evidence_refs }) = &terminal.summary else {
        return Ok(false);
    };
    let word = TaskAskWord {
        result_ref: terminal.result_ref.ok_or_else(invalid)?,
        option: option.cloned(),
        inform_for: None,
        companion_for: None,
        confirmation: None,
        provenance_refs: evidence_refs.iter().copied().collect(),
    };
    validate_word(&group, &word)?;
    let mut matching = evidence_in(vault, txn, payload.correlation_ref, &group)?
        .into_iter()
        .filter(|entry| {
            entry.answer.task_ref == task
                && entry.answer.actor_ref == actor
                && entry.word.result_ref == word.result_ref
                && entry.word.inform_for.is_none()
                && entry.word.provenance_refs == word.provenance_refs
        });
    let Some(first) = matching.next() else {
        return Ok(false);
    };
    Ok(first.word.option == word.option && matching.all(|entry| entry.word.option == word.option))
}

pub(super) fn record_answer(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    task: EntityId,
    body: &super::consult_result::TaskVerbBody,
    actor: crate::WriteActor,
    answer: (&super::TaskTerminalRecord, Option<&super::TaskAskOptionId>),
    now: u64,
) -> Result<Option<EntityId>> {
    let (terminal, option) = answer;
    let Some(payload) = &body.consult else {
        return Ok(None);
    };
    let id = payload.correlation_ref;
    let Some(group) = read_group(vault, txn, id)? else {
        return Ok(None);
    };
    // Correlation alone NEVER confers group membership. A forged sibling may
    // settle itself, but cannot settle an unrelated handle or mutate siblings.
    if !group
        .members
        .iter()
        .any(|member| member.task == task.to_hex() && member.actor == actor.entity_ref().to_hex())
    {
        return Ok(None);
    }
    if let Some(super::ConsultResultSummary::Answer { evidence_refs }) = &terminal.summary {
        admit_word(
            vault,
            txn,
            id,
            &group,
            actor,
            &TaskAskWord {
                result_ref: terminal.result_ref.ok_or_else(invalid)?,
                option: option.cloned(),
                inform_for: None,
                companion_for: None,
                confirmation: None,
                provenance_refs: evidence_refs.iter().copied().collect(),
            },
            now,
        )?;
    }
    Ok(Some(id))
}

pub(super) fn status_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
) -> Result<TaskAskStatus> {
    if let Some(result) = super::ask_settlement::read_result(vault, txn, id)? {
        return Ok(TaskAskStatus::Settled(Box::new(result)));
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
        .map(|_| super::ask_settlement::read_result(vault, &txn, id).map(|result| result.is_some()))
        .transpose()
}

/// An ask retains its deadline wake after its last notice. Ending a ladder
/// never closes the response window.
pub(crate) fn ask_notice_at_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task: EntityId,
    sent: u32,
) -> Result<Option<(Option<u64>, u64)>> {
    let Some(body) = super::wire_decode::task_verb_body_in(vault, txn, task)? else {
        return Ok(None);
    };
    let Some(payload) = body.consult else {
        return Ok(None);
    };
    let Some(group) = read_group(vault, txn, payload.correlation_ref)? else {
        return Ok(None);
    };
    if !group
        .members
        .iter()
        .any(|member| member.task == task.to_hex())
    {
        return Ok(None);
    }
    let deadline = group.effective.until.ok_or_else(invalid)?;
    if super::ask_settlement::read_result(vault, txn, payload.correlation_ref)?.is_some() {
        return Ok(Some((None, deadline)));
    }
    let ladder = group.effective.remind.as_deref().ok_or_else(invalid)?;
    let due = usize::try_from(sent)
        .ok()
        .and_then(|index| ladder.get(index))
        .map(|delay| group.created_at.checked_add(*delay).ok_or_else(invalid))
        .transpose()?;
    Ok(Some((due, deadline)))
}

#[cfg(test)]
mod tests;
