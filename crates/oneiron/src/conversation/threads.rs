//! Threads are ordinary branches with a rebuildable trunk metadata projection.
use super::*;
use crate::EdgeKind;
use serde::{Deserialize, Serialize};
const THREAD_OF: &[u8] = b"conversation_dag:thread_of:v1:";
const META: &[u8] = b"conversation_dag:thread_meta:v1:";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadMeta {
    pub v: u8,
    pub root: EntityId,
    pub count: u64,
    pub last_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thread {
    pub root: Option<EntityId>,
    pub replies: Vec<EntityId>,
    pub count: u64,
    pub last_at: Option<u64>,
}
pub(super) fn thread_trunk_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: EntityId,
) -> Result<Option<EntityId>> {
    dag::pointer(vault, txn, THREAD_OF, record)
}
fn roots_in(vault: &Vault, txn: &heed::RoTxn<'_>, trunk: EntityId) -> Result<Vec<EntityId>> {
    let mut roots = Vec::new();
    for id in dag::peers(vault, txn, trunk, EdgeKind::RepliesTo, true)? {
        if dag::single_parent(vault, txn, id)? == Some(trunk)
            && thread_trunk_in(vault, txn, id)? == Some(trunk)
        {
            roots.push(id);
        }
    }
    Ok(roots)
}
fn thread_in(vault: &Vault, txn: &heed::RoTxn<'_>, trunk: EntityId) -> Result<Thread> {
    let root = roots_in(vault, txn, trunk)?.first().copied();
    let replies = root
        .map(|r| dag::resolve_in(vault, txn, &ScopeSelector::Branch(r), false))
        .transpose()?
        .unwrap_or_default();
    let mut last_at = None;
    for id in &replies {
        let raw = vault
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let h = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("thread record"))?;
        last_at = Some(last_at.unwrap_or(0).max(h.occurred_start));
    }
    Ok(Thread {
        root,
        count: replies.len() as u64,
        replies,
        last_at,
    })
}
fn rebuild_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    trunk: EntityId,
) -> Result<Option<ThreadMeta>> {
    let thread = thread_in(vault, txn, trunk)?;
    let meta = thread.root.map(|root| ThreadMeta {
        v: 1,
        root,
        count: thread.count,
        last_at: thread.last_at.unwrap_or(0),
    });
    if let Some(meta) = &meta {
        vault
            .store
            .vault_meta
            .put(txn, &key(META, trunk), &encode(meta)?)?;
    } else {
        vault.store.vault_meta.delete(txn, &key(META, trunk))?;
    }
    Ok(meta)
}
impl Vault {
    pub fn thread_roots(&self, trunk: EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        roots_in(self, &txn, trunk)
    }
    pub fn thread(&self, trunk: EntityId) -> Result<Thread> {
        let txn = self.store.env.read_txn()?;
        thread_in(self, &txn, trunk)
    }
    pub fn thread_meta(&self, trunk: EntityId) -> Result<Option<ThreadMeta>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &key(META, trunk))?
            .map(|v| decode(&v))
            .transpose()
    }
    pub fn rebuild_thread_meta(&self, trunk: EntityId) -> Result<Option<ThreadMeta>> {
        self.with_write_txn(|txn| rebuild_in(self, txn, trunk))
    }
    pub fn reply_in_thread(&self, trunk: EntityId, record: &AppendRecord) -> Result<EntityId> {
        self.write_thread_reply(trunk, record, false)
    }
    /// Start another root on the same trunk. One-thread-per-message is an app
    /// choice, not an engine restriction. Nested trunks work the same way.
    pub fn start_thread(&self, trunk: EntityId, record: &AppendRecord) -> Result<EntityId> {
        self.write_thread_reply(trunk, record, true)
    }
    fn write_thread_reply(
        &self,
        trunk: EntityId,
        record: &AppendRecord,
        new_root: bool,
    ) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            dag::require_room(self, txn, trunk, record.conversation)?;
            let existing = thread_in(self, txn, trunk)?;
            let parent = if new_root {
                trunk
            } else {
                existing.replies.last().copied().unwrap_or(trunk)
            };
            let mut input = record.clone();
            input.parent = Some(parent);
            input.advance = false;
            dag::append_in(self, txn, &input, true)?;
            dag::put_pointer(self, txn, THREAD_OF, input.id, trunk)?;
            dag::put_edge(
                self,
                txn,
                input.id,
                EdgeKind::RepliesTo,
                parent,
                input.learned_at,
            )?;
            rebuild_in(self, txn, trunk)?;
            Ok(input.id)
        })
    }
}
