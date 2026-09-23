//! Atomic append, explicit HEAD moves and canonical-index repair.

use super::graph::{
    self, CANONICAL, HEAD, actor_in_txn, chain, edge_ids, invalid, key, read_id, require_member,
    require_type,
};
use super::migration::migrate_in_txn;
use super::{AppendRecord, AppendedRecord, DagPage, DagPageRequest};
use crate::affect::Vad;
use crate::batch::EdgeValueFields;
use crate::edge::EdgeKind;
use crate::error::{Error, RecordError, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::{EntityId, Vault};
use heed::RwTxn;
use rmpv::Value;

pub(super) fn value(created_at: u64) -> EdgeValueFields {
    EdgeValueFields {
        weight: 1.0,
        created_at,
        vad: Vad::NEUTRAL,
        provenance: None,
    }
}

fn stamp_body(
    body: &[u8],
    actor: crate::WriteActor,
    session: Option<EntityId>,
    thread: bool,
) -> Result<Vec<u8>> {
    let mut input = body;
    let decoded = rmpv::decode::read_value(&mut input)
        .map_err(|_| invalid("record body must be MessagePack"))?;
    let Value::Map(mut entries) = decoded else {
        return Err(invalid("record body must be a map"));
    };
    if !input.is_empty() {
        return Err(invalid("trailing record body bytes"));
    }
    let mut keys = std::collections::HashSet::new();
    for (key, _) in &entries {
        let key = key
            .as_str()
            .ok_or_else(|| invalid("record keys must be strings"))?;
        if !keys.insert(key) {
            return Err(invalid("duplicate record body key"));
        }
        if matches!(
            key,
            "actor"
                | "actor_class"
                | "reply_to"
                | "addr"
                | "to"
                | "summary"
                | "dag_session_ref"
                | "dag_kind"
        ) {
            return Err(invalid("record body contains door-owned fields"));
        }
    }
    entries.push((
        Value::from("dag_kind"),
        Value::from(if thread { "thread" } else { "record" }),
    ));
    entries.push((
        Value::from("actor"),
        Value::from(actor.entity_ref().to_hex()),
    ));
    entries.push((
        Value::from("actor_class"),
        Value::from(actor.actor_class() as u8),
    ));
    if let Some(session) = session {
        entries.push((
            Value::from("dag_session_ref"),
            Value::from(session.to_hex()),
        ));
    }
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .map_err(|_| invalid("record encode failed"))?;
    Ok(bytes)
}

/// The summary association is stamped only by the summary door. Reply
/// revisions are captured from the target body in this transaction.
pub(crate) fn append_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    input: &AppendRecord,
    summary: Option<EntityId>,
    thread: bool,
) -> Result<AppendedRecord> {
    actor_in_txn(&vault.store, txn, input.actor)?;
    if thread && input.advance {
        return Err(invalid("HEAD never enters a thread"));
    }
    if input.kind != ENTITY_TYPE_TURN {
        return Err(invalid("append_record admits TURN only"));
    }
    require_type(
        &vault.store,
        txn,
        &input.conversation,
        ENTITY_TYPE_CONVERSATION,
    )?;
    migrate_in_txn(vault, txn, &input.conversation)?;
    let old_head = graph::canonical_chain(&vault.store, txn, &input.conversation)?
        .last()
        .copied();
    if input.advance && input.parent != old_head {
        return Err(RecordError::HeadAdvanceOffTrunk.into());
    }
    let spawning_turn = if let Some(session) = input.session {
        require_type(&vault.store, txn, &session, ENTITY_TYPE_SESSION)?;
        let parents = edge_ids(&vault.store, txn, &session, EdgeKind::SpawnedBy, false, 2)?;
        if parents.len() > 1 {
            return Err(invalid("session has multiple SpawnedBy edges"));
        }
        if let Some(turn) = parents.first() {
            require_member(&vault.store, txn, &input.conversation, turn)?;
        }
        parents.first().copied()
    } else {
        None
    };
    if spawning_turn.is_some() && input.advance {
        return Err(RecordError::HeadAdvanceOffTrunk.into());
    }
    if let Some(parent) = input.parent {
        let path = chain(&vault.store, txn, &input.conversation, parent)?;
        for ancestor in &path {
            if !thread && graph::is_thread_record(&vault.store, txn, ancestor)? {
                return Err(invalid("thread continuations must use reply_in_thread"));
            }
        }
        if path.len() >= crate::limits::MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        let parent_session =
            crate::compaction::turn_session_membership_in_txn(&vault.store, txn, &parent)?;
        if spawning_turn.is_some()
            && spawning_turn != Some(parent)
            && parent_session != input.session
        {
            return Err(invalid(
                "sub-session parent must be its spawning turn or its own record",
            ));
        }
        if graph::is_sub_session_record(&vault.store, txn, &parent)?
            && parent_session != input.session
            && spawning_turn != Some(parent)
        {
            return Err(invalid("cannot append across sub-session boundaries"));
        }
    } else {
        if spawning_turn.is_some() {
            return Err(invalid("sub-session root must continue its spawning turn"));
        }
        if !edge_ids(
            &vault.store,
            txn,
            &input.conversation,
            EdgeKind::ChildOf,
            true,
            crate::limits::MAX_ANCESTOR_DEPTH,
        )?
        .is_empty()
        {
            return Err(invalid("nonempty conversation requires a Parent"));
        }
    }
    let mut body = stamp_body(&input.body, input.actor, input.session, thread)?;
    if let Some(asking) = input.reply_to {
        require_member(&vault.store, txn, &input.conversation, &asking)?;
        let asking_body = require_type(&vault.store, txn, &asking, ENTITY_TYPE_TURN)?;
        let mut entries = match rmpv::decode::read_value(&mut body.as_slice())
            .map_err(|_| invalid("record decode failed"))?
        {
            Value::Map(entries) => entries,
            _ => return Err(invalid("record body must be a map")),
        };
        entries.extend([
            (Value::from("addr"), Value::from("reply")),
            (
                Value::from("reply_to"),
                Value::Map(vec![
                    (Value::from("record"), Value::from(asking.to_hex())),
                    (
                        Value::from("revision"),
                        Value::from(blake3::hash(&asking_body).to_hex().to_string()),
                    ),
                ]),
            ),
        ]);
        if let Some(summary) = summary {
            entries.push((Value::from("summary"), Value::from(summary.to_hex())));
        }
        body.clear();
        rmpv::encode::write_value(&mut body, &Value::Map(entries))
            .map_err(|_| invalid("record encode failed"))?;
    }
    let id = vault.store.clock.entity_id()?;
    super::policy::check_append_policy(vault, txn, &id, input, &body)?;
    let fields: Vec<_> = input
        .text
        .iter()
        .map(|(field, text)| (field.as_str(), text.as_str()))
        .collect();
    let mut batch = vault
        .batch_in()
        .put(&id, input.kind, input.occurred, input.learned_at, &body)
        .edge(&id, EdgeKind::ChildOf, &input.conversation, 1.0);
    if !fields.is_empty() {
        batch = batch.text(&id, &fields);
    }
    if let Some(parent) = input.parent {
        batch =
            batch.edge_with_value_fields(&id, EdgeKind::Parent, &parent, value(input.learned_at));
    }
    if let Some(asking) = input.reply_to {
        batch = batch.edge_with_value_fields(
            &id,
            EdgeKind::RepliesTo,
            &asking,
            value(input.learned_at),
        );
    }
    super::admission::permit(&vault.store, txn, &id, &input.conversation)?;
    batch.apply(txn)?;
    super::admission::finish(&vault.store, txn, &id)?;
    crate::compaction::record_turn_session_membership_in_txn(
        &vault.store,
        txn,
        &id,
        input.session,
    )?;
    if input.advance {
        vault
            .store
            .vault_meta
            .put(txn, &key(HEAD, &input.conversation), id.as_bytes())?;
        if let Some(parent) = input.parent {
            vault
                .store
                .vault_meta
                .put(txn, &key(CANONICAL, &parent), id.as_bytes())?;
        }
    }
    Ok(AppendedRecord {
        id,
        head: if input.advance { Some(id) } else { old_head },
        parent: input.parent,
    })
}

pub(super) fn set_head_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    conversation: &EntityId,
    record: EntityId,
) -> Result<()> {
    let path = chain(&vault.store, txn, conversation, record)?;
    for id in &path {
        if graph::is_thread_record(&vault.store, txn, id)? {
            return Err(invalid("HEAD never enters a thread"));
        }
        if graph::is_sub_session_record(&vault.store, txn, id)? {
            return Err(invalid("sub-session records cannot enter the trunk"));
        }
    }
    if let Some(old) = read_id(&vault.store, txn, HEAD, conversation)? {
        for id in chain(&vault.store, txn, conversation, old)? {
            vault.store.vault_meta.delete(txn, &key(CANONICAL, &id))?;
        }
    }
    // Also clear a stale terminal mark on the new HEAD.
    for id in &path {
        vault.store.vault_meta.delete(txn, &key(CANONICAL, id))?;
    }
    for pair in path.windows(2) {
        vault
            .store
            .vault_meta
            .put(txn, &key(CANONICAL, &pair[0]), pair[1].as_bytes())?;
    }
    vault
        .store
        .vault_meta
        .put(txn, &key(HEAD, conversation), record.as_bytes())?;
    Ok(())
}

impl Vault {
    /// Appends one immutable TURN and atomically updates topology and membership.
    pub fn append_dag_record(&self, input: &AppendRecord) -> Result<AppendedRecord> {
        self.with_write_txn(|txn| append_in_txn(self, txn, input, None, false))
    }

    /// Explicit fork selection. Rewrites canonical marks on both old and new paths.
    pub fn move_head(&self, conversation: &EntityId, record: &EntityId) -> Result<()> {
        self.with_write_txn(|txn| {
            migrate_in_txn(self, txn, conversation)?;
            set_head_in_txn(self, txn, conversation, *record)
        })
    }

    /// Local HEAD; legacy conversations migrate before the first read.
    pub fn head(&self, conversation: &EntityId) -> Result<Option<EntityId>> {
        Ok(self
            .main_line(
                conversation,
                DagPageRequest {
                    limit: 1,
                    ..Default::default()
                },
            )?
            .head)
    }

    /// Reads a coherent root-first page; never returns a truncated safety walk.
    pub fn main_line(&self, conversation: &EntityId, page: DagPageRequest) -> Result<DagPage> {
        self.with_write_txn(|txn| {
            migrate_in_txn(self, txn, conversation)?;
            let head = read_id(&self.store, txn, HEAD, conversation)?;
            let path = graph::canonical_chain(&self.store, txn, conversation)?;
            let start = match page.after {
                Some(after) => {
                    path.iter()
                        .position(|id| *id == after)
                        .ok_or_else(|| invalid("cursor is not on current main line"))?
                        + 1
                }
                None => 0,
            };
            let limit = if page.limit == 0 {
                100
            } else {
                page.limit.min(1000)
            };
            let end = start.saturating_add(limit).min(path.len());
            let main_line = path[start..end].to_vec();
            let next = if end < path.len() {
                main_line.last().copied()
            } else {
                None
            };
            Ok(DagPage {
                head,
                root: path.first().copied(),
                main_line,
                next,
            })
        })
    }

    /// Rebuilds local canonical marks from HEAD without changing HEAD state.
    pub fn rebuild_conversation_canonical(&self, conversation: &EntityId) -> Result<()> {
        self.with_write_txn(|txn| {
            migrate_in_txn(self, txn, conversation)?;
            let records = edge_ids(
                &self.store,
                txn,
                conversation,
                EdgeKind::ChildOf,
                true,
                crate::limits::MAX_ANCESTOR_DEPTH,
            )?;
            for id in records {
                self.store.vault_meta.delete(txn, &key(CANONICAL, &id))?;
            }
            if let Some(head) = read_id(&self.store, txn, HEAD, conversation)? {
                set_head_in_txn(self, txn, conversation, head)?;
            }
            Ok(())
        })
    }
}
