//! Direct leader chats: same-vault routing, shared-ancestor rule clamp and speaker scope.
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject};
use crate::conversation::{ConversationBody, ConversationKind};
use crate::error::RecordError;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::write_envelope::WriteActor;

const CHAT: &[u8] = b"project.leader_chat.v1/";
pub(crate) const CHAT_FIELD: &str = "project_leader_chat_v1";
/// A rule row about a PROJECT. `false` narrows leader chat; `true` cannot widen it.
pub const LEADER_CHAT_RULE_PREDICATE: &str = "project.leader_chat";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaderChat {
    pub projects: [EntityId; 2],
    pub actors: [EntityId; 2],
    pub persons: [EntityId; 2],
}

fn key(prefix: &[u8], id: EntityId) -> Vec<u8> {
    [prefix, id.as_bytes()].concat()
}
pub(super) fn denied() -> Error {
    RecordError::ConversationDenied.into()
}
pub(super) fn project_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<ProjectRecord> {
    record(&vault.store, txn, id, vault.project_type_byte()?)?.ok_or_else(denied)
}
pub(super) fn lineage(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    start: EntityId,
) -> Result<Vec<EntityId>> {
    let mut result = Vec::new();
    let mut next = Some(start);
    while let Some(id) = next {
        if result.len() >= 256 || result.contains(&id) {
            return Err(denied());
        }
        let project = project_in(vault, txn, id)?;
        result.push(id);
        next = project
            .parent
            .map(|parent| EntityId::from_hex(&parent))
            .transpose()?;
    }
    Ok(result)
}
fn speaker_person(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    at: u64,
) -> Result<EntityId> {
    let person = if vault.get_entity_type_in_txn(txn, &actor)? == Some(ENTITY_TYPE_PERSON) {
        actor
    } else {
        crate::subject_model::actor_subject_anchor_in_txn(vault, txn, &actor, at)?
            .ok_or_else(denied)?
            .subject_ref
    };
    if vault.get_entity_type_in_txn(txn, &person)? != Some(ENTITY_TYPE_PERSON) {
        return Err(denied());
    }
    Ok(person)
}
fn ensure_leaders(vault: &Vault, txn: &heed::RoTxn<'_>, chat: &LeaderChat, at: u64) -> Result<()> {
    for i in 0..2 {
        if chat.projects[i] == chat.projects[1 - i]
            || project_in(vault, txn, chat.projects[i])?.leader != chat.actors[i].to_hex()
            || speaker_person(vault, txn, chat.actors[i], at)? != chat.persons[i]
        {
            return Err(denied());
        }
    }
    if chat.actors[0] == chat.actors[1] || chat.persons[0] == chat.persons[1] {
        return Err(denied());
    }
    Ok(())
}
fn check_rule(vault: &Vault, txn: &heed::RoTxn<'_>, chat: &LeaderChat, at: u64) -> Result<()> {
    let other: BTreeSet<_> = lineage(vault, txn, chat.projects[1])?.into_iter().collect();
    for ancestor in lineage(vault, txn, chat.projects[0])? {
        if !other.contains(&ancestor) {
            continue;
        }
        // Streaming bounded claim lookup is the same indexed subject path used
        // by ordinary rule claims. Invalid matching rows fail closed.
        if let Some(rule) = vault.find_claim_for_subject_in_txn(txn, &ancestor, |id, claim| {
            (claim.predicate == LEADER_CHAT_RULE_PREDICATE
                && claim.subject == ClaimSubject::Entity(ancestor)
                && claim.approval == ClaimApprovalStatus::Approved
                && claim.lifecycle == ClaimLifecycleStatus::Active
                && !claim.stale
                && claim.valid_from.is_none_or(|from| from <= at)
                && claim.valid_to.is_none_or(|to| at < to)
                && claim.value == rmpv::Value::Boolean(false))
            .then_some(*id)
        })? {
            return Err(RecordError::LeaderChatRule { rule }.into());
        }
    }
    Ok(())
}

impl Vault {
    /// Open an ordinary direct Conversation without an ask. Both leaders must
    /// still hold their own project roles when a message is witnessed.
    pub fn open_leader_chat(
        &self,
        id: EntityId,
        projects: [EntityId; 2],
        actor: WriteActor,
        at: u64,
    ) -> Result<LeaderChat> {
        self.with_write_txn(|txn| {
            let actors = [
                EntityId::from_hex(&project_in(self, txn, projects[0])?.leader)?,
                EntityId::from_hex(&project_in(self, txn, projects[1])?.leader)?,
            ];
            if actor.entity_ref() != actors[0] && actor.entity_ref() != actors[1] {
                return Err(denied());
            }
            let chat = LeaderChat {
                projects,
                actors,
                persons: [
                    speaker_person(self, txn, actors[0], at)?,
                    speaker_person(self, txn, actors[1], at)?,
                ],
            };
            // Event time is caller-chosen; authority is checked at admission.
            let now = self.store.clock.now_recorded_at();
            ensure_leaders(self, txn, &chat, now)?;
            check_rule(self, txn, &chat, now)?;
            let mut body = ConversationBody {
                kind: ConversationKind::Direct,
                member_ids: chat.persons.to_vec(),
                ..Default::default()
            };
            let bytes = encode(&chat)?;
            body.extra.insert(
                CHAT_FIELD.to_owned(),
                rmp_serde::from_slice(&bytes).map_err(|_| denied())?,
            );
            // The private admission marker is checked by the common put door.
            // The body binding itself travels with replicated conversations.
            self.store.vault_meta.put(txn, &key(CHAT, id), &bytes)?;
            crate::conversation::create_in_txn(
                self,
                txn,
                id,
                &body,
                actor,
                TimeRange { start: at, end: at },
                at,
                &[],
            )?;
            Ok(chat)
        })
    }

    /// Project audience of one attributed MESSAGE, derived from durable room
    /// binding and AuthoredBy edge. The same answer survives sync and reopen.
    pub fn leader_chat_message_scope(&self, message: EntityId) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let room = match crate::conversation::room_for_record_in(self, &txn, message) {
            Ok(room) => room,
            Err(Error::EntityNotFound) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(room) = room else {
            return Ok(None);
        };
        let body = crate::conversation::body_in(self, &txn, room)?;
        let Some(value) = body.extra.get(CHAT_FIELD) else {
            return Ok(None);
        };
        let bytes = rmp_serde::to_vec_named(value).map_err(|_| denied())?;
        let chat: LeaderChat = decode(&bytes).map_err(|_| denied())?;
        let raw = self
            .store
            .entities
            .get(&txn, message.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or_else(denied)?;
        if header.entity_type == crate::registry::ENTITY_TYPE_TURN {
            let value: rmpv::Value =
                rmp_serde::from_slice(&raw[ENTITY_METADATA_HEADER_LEN..]).map_err(|_| denied())?;
            let fields = value.as_map().ok_or_else(denied)?;
            let field = |name| {
                let mut values = fields.iter().filter(|(key, _)| key.as_str() == Some(name));
                let value = values
                    .next()
                    .ok_or_else(denied)?
                    .1
                    .as_str()
                    .ok_or_else(denied)?;
                if values.next().is_some() {
                    return Err(denied());
                }
                EntityId::from_hex(value).map_err(|_| denied())
            };
            let actor = field("actor")?;
            let project = field("scope_project_id")?;
            if !chat
                .actors
                .iter()
                .zip(chat.projects)
                .any(|(a, p)| *a == actor && p == project)
            {
                return Err(denied());
            }
            return Ok(Some(project));
        }
        if header.entity_type != crate::registry::ENTITY_TYPE_MESSAGE {
            return Ok(None);
        }
        let authors = crate::conversation_dag::edge_ids(
            &self.store,
            &txn,
            &message,
            crate::EdgeKind::AuthoredBy,
            false,
            crate::limits::MAX_ANCESTOR_DEPTH,
        )?;
        if authors.len() != 1 {
            return Err(denied());
        }
        let slot = chat
            .actors
            .iter()
            .position(|actor| *actor == authors[0])
            .ok_or_else(denied)?;
        Ok(Some(chat.projects[slot]))
    }
}

/// Shared transactional admission for both typed MESSAGE witness and DAG TURN append.
/// The returned project is a scope label, never an access grant.
pub(crate) fn admit_turn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
    has_unattributed_message: bool,
) -> Result<Option<EntityId>> {
    if vault.store.entities.get(txn, room.as_bytes())?.is_none() {
        return Ok(None); // ordinary witness may mint a fresh Conversation
    }
    let body = crate::conversation::body_in(vault, txn, room)?;
    let Some(value) = body.extra.get(CHAT_FIELD) else {
        return Ok(None);
    };
    let bytes = rmp_serde::to_vec_named(value).map_err(|_| denied())?;
    let chat: LeaderChat = decode(&bytes).map_err(|_| denied())?;
    // A caller cannot backdate a turn to speak past a newly narrowed rule.
    let now = vault.store.clock.now_recorded_at();
    ensure_leaders(vault, txn, &chat, now)?;
    if body.kind != ConversationKind::Direct
        || body.member_ids != chat.persons
        || has_unattributed_message
    {
        return Err(denied());
    }
    check_rule(vault, txn, &chat, now)?;
    let slot = chat
        .actors
        .iter()
        .position(|candidate| *candidate == actor)
        .ok_or_else(denied)?;
    Ok(Some(chat.projects[slot]))
}

pub(crate) fn admit_witness(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    actor: EntityId,
    has_unattributed_message: bool,
) -> Result<()> {
    admit_turn(vault, txn, room, actor, has_unattributed_message).map(|_| ())
}
