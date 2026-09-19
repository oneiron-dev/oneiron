//! Record-kind-independent parent edges, canonical path and scoped walks.
use super::*;
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use crate::{EdgeKind, TimeRange};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
const INITIALIZED: &[u8] = b"conversation_dag:initialized:v1:";
const HEAD: &[u8] = b"conversation_dag:head:v1:";
const CANONICAL: &[u8] = b"conversation_dag:canon:v1:";
pub const MAX_ANCESTOR_DEPTH: usize = 10_000;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeSelector {
    Canonical(EntityId),
    Branch(EntityId),
    SubSession(EntityId),
}
#[derive(Debug, Clone)]
pub struct AppendRecord {
    pub conversation: EntityId,
    pub id: EntityId,
    pub parent: Option<EntityId>,
    pub advance: bool,
    pub body: serde_json::Value,
    pub occurred: TimeRange,
    pub learned_at: u64,
    pub actor: WriteActor,
}

pub(super) fn pointer(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prefix: &[u8],
    id: EntityId,
) -> Result<Option<EntityId>> {
    vault
        .store
        .vault_meta
        .get(txn, &key(prefix, id))?
        .map(|v| {
            EntityId::from_bytes(
                v.as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("DAG pointer"))?,
            )
        })
        .transpose()
}
pub(super) fn put_pointer(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    prefix: &[u8],
    id: EntityId,
    target: EntityId,
) -> Result<()> {
    vault
        .store
        .vault_meta
        .put(txn, &key(prefix, id), target.as_bytes())?;
    Ok(())
}
pub(super) fn peers(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: EdgeKind,
    incoming: bool,
) -> Result<Vec<EntityId>> {
    let mut prefix = id.as_bytes().to_vec();
    prefix.push(kind as u8);
    let db = if incoming {
        &vault.store.edges_in
    } else {
        &vault.store.edges_out
    };
    let mut ids = Vec::new();
    for row in db.prefix_iter(txn, &prefix)? {
        let (k, _) = row?;
        if k.len() != 33 {
            return Err(Error::CorruptedIndex("DAG edge"));
        }
        if ids.len() == MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("DAG peers"));
        }
        ids.push(EntityId::from_bytes(
            k[17..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("DAG id"))?,
        )?);
    }
    Ok(ids)
}
pub(super) fn single_parent(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<EntityId>> {
    let parents = peers(vault, txn, id, EdgeKind::Parent, false)?;
    if parents.len() > 1 {
        return Err(Error::CorruptedIndex("multiple DAG parents"));
    }
    Ok(parents.first().copied())
}
pub(super) fn put_edge(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    from: EntityId,
    kind: EdgeKind,
    to: EntityId,
    at: u64,
) -> Result<()> {
    vault
        .batch_in()
        .edge_with_value_fields(
            &from,
            kind,
            &to,
            crate::batch::EdgeValueFields {
                weight: kind.default_weight().unwrap_or(1.0),
                created_at: at,
                vad: crate::affect::Vad::NEUTRAL,
                provenance: None,
            },
        )
        .apply(txn)
}
pub(super) fn require_room(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
    room: EntityId,
) -> Result<()> {
    if visibility::room_for_record_in(vault, txn, record)? != Some(room) {
        return Err(state("record belongs to another conversation"));
    }
    Ok(())
}

impl Vault {
    fn initialize_conversation_dag(&self, room: EntityId) -> Result<()> {
        {
            let txn = self.store.env.read_txn()?;
            if self
                .store
                .vault_meta
                .get(&txn, &key(INITIALIZED, room))?
                .is_some()
            {
                return Ok(());
            }
        }
        self.with_write_txn(|txn| {
            body::body_in(self, txn, room)?;
            backfill_in(self, txn, room)
        })
    }
    pub fn conversation_head(&self, conversation: EntityId) -> Result<Option<EntityId>> {
        self.initialize_conversation_dag(conversation)?;
        let txn = self.store.env.read_txn()?;
        body::body_in(self, &txn, conversation)?;
        pointer(self, &txn, HEAD, conversation)
    }
    pub fn canonical_child(&self, parent: EntityId) -> Result<Option<EntityId>> {
        let room = {
            let txn = self.store.env.read_txn()?;
            visibility::room_for_record_in(self, &txn, parent)?
        };
        if let Some(room) = room {
            self.initialize_conversation_dag(room)?;
        }
        let txn = self.store.env.read_txn()?;
        pointer(self, &txn, CANONICAL, parent)
    }
    pub fn append_record(&self, record: &AppendRecord) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            append_in(self, txn, record, false)?;
            Ok(record.id)
        })
    }
    /// Switch the active branch, but never enter a thread. Re-mark the entire
    /// ancestor path atomically; a partial path can never become a HEAD.
    pub fn move_conversation_head(
        &self,
        conversation: EntityId,
        to: EntityId,
        actor: WriteActor,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            authorize(self, txn, actor)?;
            body::body_in(self, txn, conversation)?;
            require_kind(self, txn, to, ENTITY_TYPE_TURN)?;
            require_room(self, txn, to, conversation)?;
            let mut child = to;
            let mut seen = BTreeSet::new();
            loop {
                if !seen.insert(child) || seen.len() > MAX_ANCESTOR_DEPTH {
                    return Err(state("DAG cycle or depth bound"));
                }
                if threads::thread_trunk_in(self, txn, child)?.is_some() {
                    return Err(state("HEAD never enters a thread"));
                }
                let Some(parent) = single_parent(self, txn, child)? else {
                    break;
                };
                put_pointer(self, txn, CANONICAL, parent, child)?;
                child = parent;
            }
            put_pointer(self, txn, HEAD, conversation, to)
        })
    }
    pub fn resolve_scope(
        &self,
        scope: &ScopeSelector,
        include_forks: bool,
    ) -> Result<Vec<EntityId>> {
        if let ScopeSelector::Canonical(room) = scope {
            self.initialize_conversation_dag(*room)?;
        }
        let txn = self.store.env.read_txn()?;
        resolve_in(self, &txn, scope, include_forks)
    }
    pub fn spawn_sub_session(
        &self,
        session: EntityId,
        spawning_record: EntityId,
        actor: WriteActor,
        at: u64,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            authorize(self, txn, actor)?;
            if visibility::room_for_record_in(self, txn, spawning_record)?.is_none() {
                return Err(state("spawning record has no room"));
            }
            if self.store.entities.get(txn, session.as_bytes())?.is_some() {
                return Err(state("session already exists"));
            }
            self.batch_in()
                .put(
                    &session,
                    ENTITY_TYPE_SESSION,
                    TimeRange { start: at, end: at },
                    at,
                    &encode(&serde_json::json!({}))?,
                )
                .apply(txn)?;
            put_edge(self, txn, session, EdgeKind::SpawnedBy, spawning_record, at)
        })
    }
    /// Attach a record to a sub-session without changing its room or HEAD.
    pub fn attach_sub_session_record(
        &self,
        session: EntityId,
        record: EntityId,
        actor: WriteActor,
        at: u64,
    ) -> Result<()> {
        self.with_write_txn(|txn| {
            authorize(self, txn, actor)?;
            require_kind(self, txn, session, ENTITY_TYPE_SESSION)?;
            let room = visibility::room_for_record_in(self, txn, session)?
                .ok_or(state("sub-session has no room"))?;
            require_room(self, txn, record, room)?;
            put_edge(self, txn, record, EdgeKind::BelongsTo, session, at)
        })
    }
}

pub(super) fn append_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    record: &AppendRecord,
    thread: bool,
) -> Result<()> {
    authorize(vault, txn, record.actor)?;
    body::body_in(vault, txn, record.conversation)?;
    if vault
        .store
        .entities
        .get(txn, record.id.as_bytes())?
        .is_some()
    {
        return Err(state("record is append-only"));
    }
    backfill_in(vault, txn, record.conversation)?;
    let old_head = pointer(vault, txn, HEAD, record.conversation)?;
    let parent = record.parent.or(old_head);
    if let Some(parent) = parent {
        if parent == record.id {
            return Err(state("self parent"));
        }
        require_room(vault, txn, parent, record.conversation)?;
        if record.advance && threads::thread_trunk_in(vault, txn, parent)?.is_some() {
            return Err(state("HEAD never enters a thread"));
        }
    }
    let map = record
        .body
        .as_object()
        .ok_or(invalid("record body must be object"))?;
    let addr = map
        .get("addr")
        .map(|v| v.as_str().ok_or(invalid("addressing")))
        .transpose()?
        .unwrap_or("broadcast");
    if !["broadcast", "direct", "reply"].contains(&addr) {
        return Err(invalid("addressing"));
    }
    let recipients: Vec<EntityId> = map
        .get("to")
        .map(|v| serde_json::from_value(v.clone()).map_err(|_| invalid("recipients")))
        .transpose()?
        .unwrap_or_default();
    if addr == "direct" && recipients.is_empty() {
        return Err(invalid("direct requires recipients"));
    }
    if recipients.iter().copied().collect::<BTreeSet<_>>().len() != recipients.len() {
        return Err(invalid("duplicate recipients"));
    }
    for person in &recipients {
        require_kind(vault, txn, *person, ENTITY_TYPE_PERSON)?;
    }
    let reply: Option<EntityId> = map
        .get("reply_to")
        .map(|v| serde_json::from_value(v.clone()).map_err(|_| invalid("reply pointer")))
        .transpose()?;
    if addr == "reply" && reply.is_none() {
        return Err(invalid("reply requires pointer"));
    }
    if let Some(reply) = reply {
        require_room(vault, txn, reply, record.conversation)?;
    }
    // TURN is the first record adapter. MESSAGE uses the witness-ceiling door
    // and can attach to this DAG without ever permitting an ungated raw MESSAGE.
    vault
        .batch_in()
        .put(
            &record.id,
            ENTITY_TYPE_TURN,
            record.occurred,
            record.learned_at,
            &encode(&record.body)?,
        )
        .edge(&record.id, EdgeKind::ChildOf, &record.conversation, 1.0)
        .apply(txn)?;
    if let Some(text) = map.get("txt").and_then(|v| v.as_str()) {
        vault
            .batch_in()
            .text(&record.id, &[("body", text)])
            .apply(txn)?;
    }
    if let Some(parent) = parent {
        put_edge(
            vault,
            txn,
            record.id,
            EdgeKind::Parent,
            parent,
            record.learned_at,
        )?;
    }
    for person in recipients {
        put_edge(
            vault,
            txn,
            record.id,
            EdgeKind::AddressedTo,
            person,
            record.learned_at,
        )?;
    }
    if let Some(reply) = reply {
        put_edge(
            vault,
            txn,
            record.id,
            EdgeKind::RepliesTo,
            reply,
            record.learned_at,
        )?;
    }
    if record.advance {
        // Re-point through the same path marking rule as an explicit switch.
        let mut child = record.id;
        let mut seen = BTreeSet::new();
        while let Some(parent) = single_parent(vault, txn, child)? {
            if !seen.insert(child) || seen.len() > MAX_ANCESTOR_DEPTH {
                return Err(state("DAG cycle"));
            }
            put_pointer(vault, txn, CANONICAL, parent, child)?;
            child = parent;
        }
        put_pointer(vault, txn, HEAD, record.conversation, record.id)?;
    } else if !thread && let Some(parent) = parent {
        // A branch is not a thread merely because HEAD did not advance.
        require_room(vault, txn, parent, record.conversation)?;
    }
    vault.store.vault_meta.put(
        txn,
        &key(b"conversation_dag:record:v1:", record.id),
        record.conversation.as_bytes(),
    )?;
    Ok(())
}

pub(super) fn backfill_in(vault: &Vault, txn: &mut heed::RwTxn<'_>, room: EntityId) -> Result<()> {
    if vault
        .store
        .vault_meta
        .get(txn, &key(INITIALIZED, room))?
        .is_some()
    {
        return Ok(());
    }
    let mut records = Vec::new();
    for id in peers(vault, txn, room, EdgeKind::ChildOf, true)? {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &id)?.is_live()
            || vault.archive_tombstone_in_txn(txn, &id)?.is_some()
        {
            continue;
        }
        let Some(raw) = vault.store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("record header"))?;
        if h.entity_type == ENTITY_TYPE_TURN && threads::thread_trunk_in(vault, txn, id)?.is_none()
        {
            records.push((h.occurred_start, id));
        }
    }
    records.sort();
    for pair in records.windows(2) {
        if single_parent(vault, txn, pair[1].1)?.is_none() {
            put_edge(
                vault,
                txn,
                pair[1].1,
                EdgeKind::Parent,
                pair[0].1,
                pair[1].0,
            )?;
        }
        put_pointer(vault, txn, CANONICAL, pair[0].1, pair[1].1)?;
    }
    if let Some((_, last)) = records.last() {
        put_pointer(vault, txn, HEAD, room, *last)?;
    }
    vault
        .store
        .vault_meta
        .put(txn, &key(INITIALIZED, room), &[1])?;
    Ok(())
}
pub(super) fn resolve_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    scope: &ScopeSelector,
    include_forks: bool,
) -> Result<Vec<EntityId>> {
    match scope {
        ScopeSelector::Canonical(room) => {
            body::body_in(vault, txn, *room)?;
            let Some(mut current) = pointer(vault, txn, HEAD, *room)? else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            let mut seen = BTreeSet::new();
            loop {
                if !seen.insert(current) || seen.len() > MAX_ANCESTOR_DEPTH {
                    return Err(state("DAG cycle or depth bound"));
                }
                out.push(current);
                let Some(parent) = single_parent(vault, txn, current)? else {
                    break;
                };
                if pointer(vault, txn, CANONICAL, parent)? != Some(current) {
                    return Err(Error::CorruptedIndex("canonical path"));
                }
                current = parent;
            }
            out.reverse();
            if include_forks {
                resolve_in(vault, txn, &ScopeSelector::Branch(current), true)
            } else {
                Ok(out)
            }
        }
        ScopeSelector::Branch(root) => {
            if vault.store.entities.get(txn, root.as_bytes())?.is_none() {
                return Err(Error::EntityNotFound);
            }
            let mut pending = vec![*root];
            let mut out = Vec::new();
            let mut seen = BTreeSet::new();
            while let Some(id) = pending.pop() {
                if !seen.insert(id) || seen.len() > MAX_ANCESTOR_DEPTH {
                    return Err(state("DAG cycle or depth bound"));
                }
                out.push(id);
                let mut children = peers(vault, txn, id, EdgeKind::Parent, true)?;
                // Threads anchored on a branch record are independent scopes.
                let trunk = threads::thread_trunk_in(vault, txn, id)?;
                let mut kept = Vec::new();
                for child in children {
                    if include_forks || threads::thread_trunk_in(vault, txn, child)? == trunk {
                        kept.push(child);
                    }
                }
                children = kept;
                if !include_forks {
                    let next = pointer(vault, txn, CANONICAL, id)?
                        .filter(|c| children.contains(c))
                        .or_else(|| children.first().copied());
                    children = next.into_iter().collect();
                }
                pending.extend(children.into_iter().rev());
            }
            Ok(out)
        }
        ScopeSelector::SubSession(session) => {
            require_kind(vault, txn, *session, ENTITY_TYPE_SESSION)?;
            let mut records = Vec::new();
            for id in peers(vault, txn, *session, EdgeKind::BelongsTo, true)? {
                let raw = vault
                    .store
                    .entities
                    .get(txn, id.as_bytes())?
                    .ok_or(Error::EntityNotFound)?;
                let h = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("record header"))?;
                records.push((h.occurred_start, id));
            }
            records.sort();
            Ok(records.into_iter().map(|(_, id)| id).collect())
        }
    }
}
