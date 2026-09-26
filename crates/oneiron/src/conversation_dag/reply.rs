//! Revision-bound reply strips. Missing or edited targets never expose a
//! replacement body as though it were the historical quotation.

use super::graph::{
    CANONICAL, conversation_of, edge_ids, invalid, key, read_id, require_member, require_type,
};
use super::{AppendRecord, AppendedRecord};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use rmpv::Value;
use std::collections::{HashSet, VecDeque};

/// Renderer-neutral reply strip over an exact content revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyStrip {
    /// Target of the historical reply pointer.
    pub record: EntityId,
    /// BLAKE3 content hash captured at the merge move.
    pub revision: String,
    /// Target's txt field, only when it is still live at the pinned revision.
    pub text: Option<String>,
    /// Target is missing, deleted or no longer at the pinned revision.
    pub stale: bool,
}

impl Vault {
    /// Projects a revision-bound reply strip. Never reconstructs or invents text.
    pub fn reply_strip(&self, record: &EntityId) -> Result<Option<ReplyStrip>> {
        let txn = self.store.env.read_txn()?;
        let bytes = require_type(&self.store, &txn, record, ENTITY_TYPE_TURN)?;
        let mut input = bytes.as_slice();
        let value =
            rmpv::decode::read_value(&mut input).map_err(|_| invalid("invalid record body"))?;
        let Value::Map(fields) = value else {
            return Err(invalid("invalid record body"));
        };
        if !input.is_empty() {
            return Err(invalid("trailing record bytes"));
        }
        let pointers: Vec<_> = fields
            .iter()
            .filter(|(key, _)| key.as_str() == Some("reply_to"))
            .collect();
        if pointers.is_empty() {
            return Ok(None);
        }
        if pointers.len() != 1 {
            return Err(invalid("duplicate reply pointer"));
        }
        let Value::Map(pointer) = &pointers[0].1 else {
            return Err(invalid("invalid reply pointer"));
        };
        let get = |name| -> Result<&Value> {
            let mut values = pointer.iter().filter(|(key, _)| key.as_str() == Some(name));
            let (_, value) = values
                .next()
                .ok_or_else(|| invalid("incomplete reply pointer"))?;
            if values.next().is_some() {
                return Err(invalid("duplicate reply pointer field"));
            }
            Ok(value)
        };
        let target = EntityId::from_hex(
            get("record")?
                .as_str()
                .ok_or_else(|| invalid("invalid reply target"))?,
        )?;
        let revision = get("revision")?
            .as_str()
            .ok_or_else(|| invalid("invalid reply revision"))?
            .to_owned();
        if revision.len() != 64 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("invalid reply hash"));
        }
        if edge_ids(&self.store, &txn, record, EdgeKind::RepliesTo, false, 2)? != [target] {
            return Err(Error::CorruptedIndex("reply pointer index"));
        }
        let (text, stale) = match live_entity_row_in_txn(&self.store, &txn, &target)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                body,
            } => {
                if conversation_of(&self.store, &txn, &target)?
                    != conversation_of(&self.store, &txn, record)?
                {
                    return Err(invalid("reply target is outside conversation"));
                }
                if blake3::hash(&body).to_hex().as_str() != revision {
                    (None, true)
                } else {
                    let value = rmpv::decode::read_value(&mut body.as_slice())
                        .map_err(|_| invalid("invalid reply target body"))?;
                    let text = value
                        .as_map()
                        .and_then(|fields| {
                            fields.iter().find(|(key, _)| key.as_str() == Some("txt"))
                        })
                        .and_then(|(_, value)| value.as_str())
                        .map(str::to_owned);
                    (text, false)
                }
            }
            _ => (None, true),
        };
        Ok(Some(ReplyStrip {
            record: target,
            revision,
            text,
            stale,
        }))
    }
}

const THREAD_META: &[u8] = b"conversation_dag:thread_meta:v1:";

/// Cached projection of a trunk's thread; absent for a trunk with no replies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadMeta {
    pub root: EntityId,
    pub count: u64,
    pub last_at: u64,
}

fn meta_in_txn(vault: &Vault, txn: &RoTxn<'_>, trunk: &EntityId) -> Result<Option<ThreadMeta>> {
    let Some(raw) = vault.store.vault_meta.get(txn, &key(THREAD_META, trunk))? else {
        return Ok(None);
    };
    if raw.len() != 33 || raw[0] != 1 {
        return Err(Error::CorruptedIndex("conversation thread metadata"));
    }
    let root = EntityId::from_bytes(
        raw[1..17]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("conversation thread metadata"))?,
    )
    .map_err(|_| Error::CorruptedIndex("conversation thread metadata"))?;
    let count = u64::from_be_bytes(
        raw[17..25]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("conversation thread metadata"))?,
    );
    let last_at = u64::from_be_bytes(
        raw[25..33]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("conversation thread metadata"))?,
    );
    if count == 0 {
        return Err(Error::CorruptedIndex("conversation thread metadata"));
    }
    Ok(Some(ThreadMeta {
        root,
        count,
        last_at,
    }))
}

fn rebuild_thread_meta_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    trunk: EntityId,
) -> Result<Option<ThreadMeta>> {
    let thread = thread_in_txn(vault, txn, trunk)?;
    let meta = thread.root.map(|root| ThreadMeta {
        root,
        count: thread.count,
        last_at: thread.last_at.expect("nonempty thread has timestamp"),
    });
    let key = key(THREAD_META, &trunk);
    if let Some(ref meta) = meta {
        let mut value = Vec::with_capacity(33);
        value.push(1);
        value.extend_from_slice(meta.root.as_bytes());
        value.extend_from_slice(&meta.count.to_be_bytes());
        value.extend_from_slice(&meta.last_at.to_be_bytes());
        vault.store.vault_meta.put(txn, &key, &value)?;
    } else {
        vault.store.vault_meta.delete(txn, &key)?;
    }
    Ok(meta)
}

fn roots_in_txn(vault: &Vault, txn: &RoTxn<'_>, trunk: EntityId) -> Result<Vec<EntityId>> {
    let conversation = conversation_of(&vault.store, txn, &trunk)?;
    let canonical = read_id(&vault.store, txn, CANONICAL, &trunk)?;
    let mut roots = Vec::new();
    for child in edge_ids(
        &vault.store,
        txn,
        &trunk,
        EdgeKind::RepliesTo,
        true,
        MAX_ANCESTOR_DEPTH,
    )? {
        if !live_entity_row_in_txn(&vault.store, txn, &child)?.is_live() {
            continue;
        }
        require_member(&vault.store, txn, &conversation, &child)?;
        if edge_ids(&vault.store, txn, &child, EdgeKind::RepliesTo, false, 2)? != [trunk] {
            return Err(invalid("record needs exactly one reply target"));
        }
        if Some(child) != canonical && super::graph::is_thread_record(&vault.store, txn, &child)? {
            roots.push(child);
        }
    }
    roots.sort_unstable();
    Ok(roots)
}

/// A bounded root-first reply walk and its derived metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    pub conversation: EntityId,
    pub root: Option<EntityId>,
    pub replies: Vec<EntityId>,
    pub count: u64,
    pub last_at: Option<u64>,
}

pub(crate) fn thread_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    trunk: EntityId,
) -> Result<Thread> {
    let conversation = conversation_of(&vault.store, txn, &trunk)?;
    let mut queue = VecDeque::from([trunk]);
    let mut seen = HashSet::from([trunk]);
    let mut replies = Vec::new();
    let mut examined = 0;
    let mut last_at = None;
    while let Some(target) = queue.pop_front() {
        let mut children = edge_ids(
            &vault.store,
            txn,
            &target,
            EdgeKind::RepliesTo,
            true,
            MAX_ANCESTOR_DEPTH.saturating_sub(examined),
        )?;
        examined += children.len();
        children.sort_unstable();
        for child in children {
            if !seen.insert(child) {
                return Err(crate::error::RegistryError::CycleDetected.into());
            }
            if !live_entity_row_in_txn(&vault.store, txn, &child)?.is_live() {
                continue;
            }
            require_member(&vault.store, txn, &conversation, &child)?;
            if edge_ids(&vault.store, txn, &child, EdgeKind::RepliesTo, false, 2)? != [target] {
                return Err(invalid("record needs exactly one reply target"));
            }
            if !super::graph::is_thread_record(&vault.store, txn, &child)? {
                continue;
            }
            let row = vault
                .store
                .port_entity_record(txn, &child)?
                .ok_or(Error::EntityNotFound)?;
            last_at = Some(last_at.unwrap_or(0).max(row.occurred.start));
            replies.push(child);
            queue.push_back(child);
        }
    }
    Ok(Thread {
        conversation,
        root: replies.first().copied(),
        count: replies.len() as u64,
        replies,
        last_at,
    })
}

/// Picks the first root's chain tip, not a sibling root's reply.
pub(crate) fn thread_tip_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    trunk: EntityId,
) -> Result<EntityId> {
    let root = roots_in_txn(vault, txn, trunk)?
        .into_iter()
        .next()
        .ok_or_else(|| invalid("trunk has no thread"))?;
    let thread = thread_in_txn(vault, txn, trunk)?;
    for id in thread.replies.into_iter().rev() {
        if super::graph::chain(&vault.store, txn, &thread.conversation, id)?.contains(&root) {
            return Ok(id);
        }
    }
    Err(invalid("thread root is missing"))
}

impl Vault {
    /// Finds all immediate thread roots; a canonical fork is not a root.
    pub fn thread_roots(&self, trunk: EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        roots_in_txn(self, &txn, trunk)
    }

    /// Reads the cached meta line without walking the reply chain.
    pub fn thread_meta(&self, trunk: EntityId) -> Result<Option<ThreadMeta>> {
        let txn = self.store.env.read_txn()?;
        conversation_of(&self.store, &txn, &trunk)?;
        meta_in_txn(self, &txn, &trunk)
    }

    /// Reconstructs a missing/stale projection from the retained reply chain.
    pub fn rebuild_thread_meta(&self, trunk: EntityId) -> Result<Option<ThreadMeta>> {
        self.with_write_txn(|txn| rebuild_thread_meta_in_txn(self, txn, trunk))
    }

    pub fn thread(&self, trunk: EntityId) -> Result<Thread> {
        let txn = self.store.env.read_txn()?;
        thread_in_txn(self, &txn, trunk)
    }

    /// Continues the reply chain without changing the conversation HEAD.
    pub fn reply_in_thread(&self, trunk: EntityId, input: &AppendRecord) -> Result<AppendedRecord> {
        self.with_write_txn(|txn| {
            require_member(&self.store, txn, &input.conversation, &trunk)?;
            let thread = thread_in_txn(self, txn, trunk)?;
            let mut target = trunk;
            for reply in thread.replies.iter().rev() {
                if crate::compaction::turn_session_membership_in_txn(&self.store, txn, reply)?
                    == input.session
                {
                    target = *reply;
                    break;
                }
            }
            let mut input = input.clone();
            input.parent = Some(target);
            input.reply_to = Some(target);
            input.advance = false;
            let appended = super::append_in_txn(self, txn, &input, None, true)?;
            // A nested reply also changes the ancestor trunk's meta line.
            let mut cursor = Some(trunk);
            let mut visited = HashSet::new();
            while let Some(id) = cursor {
                if !visited.insert(id) || visited.len() > MAX_ANCESTOR_DEPTH {
                    return Err(Error::IndexOverflow("conversation_dag_walk"));
                }
                rebuild_thread_meta_in_txn(self, txn, id)?;
                if !super::graph::is_thread_record(&self.store, txn, &id)? {
                    break;
                }
                cursor = super::graph::parent(&self.store, txn, &id)?;
            }
            Ok(appended)
        })
    }
}
