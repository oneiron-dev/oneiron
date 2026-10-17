//! Revision-bound reply strips. Missing or edited targets never expose a
//! replacement body as though it were the historical quotation.

use super::graph::{
    CANONICAL, conversation_of, edge_ids, invalid, read_id, require_member, require_type,
};
use super::policy::{self, AppendFailure};
use super::thread_projection::{chain_in_txn, selected_thread_in_txn};
use super::{AppendRecord, AppendedRecord};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::limits::MAX_ANCESTOR_DEPTH;
use crate::memory::{Memory, MemoryResult};
use crate::registry::ENTITY_TYPE_TURN;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use rmpv::Value;
use std::collections::HashSet;

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
    /// Target has been erased (rather than merely edited or not yet received).
    pub redacted: bool,
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
        let target_row = live_entity_row_in_txn(&self.store, &txn, &target)?;
        let redacted = matches!(target_row, LiveEntityRow::DeletedShell)
            || self.local_hard_delete_marker_exists_in_txn(&txn, &target)?;
        let edges = edge_ids(&self.store, &txn, record, EdgeKind::RepliesTo, false, 2)?;
        // HardErase tears incident edges. The pinned pointer survives in the
        // immutable reply body, but must never hydrate erased content. A live
        // target still requires the exact structural edge.
        if edges != [target] && !(redacted && edges.is_empty()) {
            return Err(Error::CorruptedIndex("reply pointer index"));
        }
        let (text, stale) = match target_row {
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
            redacted,
        }))
    }
}

/// Cached thread projection of a trunk. Key: id16 (trunk).
const THREAD_META: SideTable<EntityId, ThreadMeta, Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_THREAD_META);

/// Cached projection of a trunk's thread; absent for a trunk with no replies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadMeta {
    pub root: EntityId,
    pub count: u64,
    pub last_at: u64,
}

/// `[1]`, the root id, then the reply count and the last reply time, both big-endian.
impl RawValue for ThreadMeta {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut value = Vec::with_capacity(33);
        value.push(1);
        value.extend_from_slice(self.root.as_bytes());
        value.extend_from_slice(&self.count.to_be_bytes());
        value.extend_from_slice(&self.last_at.to_be_bytes());
        Ok(value)
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        let corrupt = || Error::CorruptedIndex("conversation thread metadata");
        if raw.len() != 33 || raw[0] != 1 {
            return Err(corrupt().into());
        }
        let root = EntityId::from_bytes(raw[1..17].try_into().map_err(|_| corrupt())?)
            .map_err(|_| corrupt())?;
        let count = u64::from_be_bytes(raw[17..25].try_into().map_err(|_| corrupt())?);
        let last_at = u64::from_be_bytes(raw[25..33].try_into().map_err(|_| corrupt())?);
        if count == 0 {
            return Err(corrupt().into());
        }
        Ok(ThreadMeta {
            root,
            count,
            last_at,
        })
    }
}

fn meta_in_txn(vault: &Vault, txn: &RoTxn<'_>, trunk: &EntityId) -> Result<Option<ThreadMeta>> {
    THREAD_META.get(&vault.store, txn, trunk)
}

fn rebuild_thread_meta_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    trunk: EntityId,
) -> Result<Option<ThreadMeta>> {
    let selected = selected_thread_in_txn(vault, txn, trunk)?;
    let meta = selected.map(|selected| ThreadMeta {
        root: selected.root,
        count: selected.replies.len() as u64,
        last_at: selected.last_at,
    });
    if let Some(ref meta) = meta {
        THREAD_META.put(&vault.store, txn, &trunk, meta)?;
    } else {
        THREAD_META.delete(&vault.store, txn, &trunk)?;
    }
    THREAD_DIRTY.delete(&vault.store, txn, &trunk)?;
    Ok(meta)
}

fn roots_in_txn(vault: &Vault, txn: &RoTxn<'_>, trunk: EntityId) -> Result<Vec<EntityId>> {
    let conversation = conversation_of(&vault.store, txn, &trunk)?;
    let canonical = read_id(&vault.store, txn, CANONICAL, &trunk)?;
    let mut roots = Vec::new();
    // A thread hangs off its trunk on Parent; its reply targets may point anywhere.
    for child in edge_ids(
        &vault.store,
        txn,
        &trunk,
        EdgeKind::Parent,
        true,
        MAX_ANCESTOR_DEPTH,
    )? {
        if !live_entity_row_in_txn(&vault.store, txn, &child)?.is_live() {
            continue;
        }
        require_member(&vault.store, txn, &conversation, &child)?;
        if super::graph::parent(&vault.store, txn, &child)? != Some(trunk) {
            return Err(invalid("record needs exactly one Parent"));
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

/// Single-byte `[1]` marker that a trunk's cached thread projection is stale. Key: id16.
const THREAD_DIRTY: SideTable<EntityId, [u8; 1], Raw> =
    SideTable::new(&side_table::CONVERSATION_DAG_THREAD_META_DIRTY);

/// Whether `record` is a thread record; `None` while its body has not arrived.
fn thread_kind(
    store: &crate::store::Store,
    txn: &RoTxn<'_>,
    record: &EntityId,
) -> Result<Option<bool>> {
    match super::graph::is_thread_record(store, txn, record) {
        Ok(thread) => Ok(Some(thread)),
        Err(Error::EntityNotFound) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Invalidates the cached projection along a thread chain: `start` and each
/// Parent ancestor up to the first that is not a thread record (its trunk).
/// A record whose body has not arrived may still be a thread record, so the
/// walk goes on past it. Called before edge removal and after edge/body
/// materialization, in the same transaction.
pub(crate) fn invalidate_thread_meta(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    start: EntityId,
) -> Result<()> {
    let mut cursor = Some(start);
    let mut seen = HashSet::new();
    while let Some(id) = cursor {
        if !seen.insert(id) {
            break; // The read walk reports the malformed cycle; keep the cache dirty.
        }
        if seen.len() > MAX_ANCESTOR_DEPTH {
            return Err(Error::IndexOverflow("conversation_dag_walk"));
        }
        THREAD_DIRTY.put(store, txn, &id, &[1])?;
        if thread_kind(store, txn, &id)? == Some(false) {
            break;
        }
        cursor = super::graph::parent(store, txn, &id)?;
    }
    Ok(())
}

/// Folds every trunk's thread projection again from the retained thread
/// Parent edges. Thread meta is a derived cache: a checkpoint never carries it, so a
/// restore rebuilds it here instead of trusting copied rows. A trunk whose
/// chain does not fold stays dirty, and its first read reports the error a
/// live vault would. Returns the number of trunks rebuilt.
pub(crate) fn rebuild_thread_meta_projection_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
) -> Result<usize> {
    let mut trunks = std::collections::BTreeSet::new();
    for row in crate::ports::EdgeStoreInventory::port_edge_rows_raw(&vault.store, txn)? {
        let (key, _) = row?;
        if key.len() == 33 && key[16] == EdgeKind::Parent as u8 {
            let id = |bytes: &[u8]| -> Result<EntityId> {
                EntityId::from_bytes(bytes.try_into().map_err(|_| invalid("parent edge"))?)
                    .map_err(|_| invalid("parent edge"))
            };
            // Only a thread record's Parent names a trunk; one that does not
            // fold is still rebuilt, so its trunk stays dirty below.
            match thread_kind(&vault.store, txn, &id(&key[..16])?) {
                Ok(Some(false)) => {}
                Err(error @ (Error::Storage(_) | Error::MapFull | Error::Io(_))) => {
                    return Err(error);
                }
                _ => {
                    trunks.insert(id(&key[17..])?);
                }
            }
        }
    }
    let mut rebuilt = 0;
    for trunk in trunks {
        match rebuild_thread_meta_in_txn(vault, txn, trunk) {
            Ok(_) => rebuilt += 1,
            Err(error @ (Error::Storage(_) | Error::MapFull | Error::Io(_))) => return Err(error),
            Err(_) => THREAD_DIRTY.put(&vault.store, txn, &trunk, &[1])?,
        }
    }
    Ok(rebuilt)
}

/// A replayed TURN body may arrive after its Parent edge, and a record's
/// thread replies before its own body.
pub(crate) fn invalidate_thread_meta_for_turn_put(
    store: &crate::store::Store,
    txn: &mut RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let mut chained = thread_kind(store, txn, &id)? != Some(false);
    if !chained {
        for child in edge_ids(store, txn, &id, EdgeKind::Parent, true, MAX_ANCESTOR_DEPTH)? {
            if thread_kind(store, txn, &child)? == Some(true) {
                chained = true;
                break;
            }
        }
    }
    if chained {
        invalidate_thread_meta(store, txn, id)?;
    }
    Ok(())
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
        let dirty = THREAD_DIRTY.contains(&self.store, &txn, &trunk)?;
        if dirty {
            drop(txn);
            return self.with_write_txn_grouped(|txn| rebuild_thread_meta_in_txn(self, txn, trunk));
        }
        meta_in_txn(self, &txn, &trunk)
    }

    /// Reconstructs a missing/stale projection from the retained reply chain.
    pub fn rebuild_thread_meta(&self, trunk: EntityId) -> Result<Option<ThreadMeta>> {
        self.with_write_txn_grouped(|txn| rebuild_thread_meta_in_txn(self, txn, trunk))
    }

    pub fn thread(&self, trunk: EntityId) -> Result<Thread> {
        let txn = self.store.env.read_txn()?;
        let selected = selected_thread_in_txn(self, &txn, trunk)?;
        Ok(match selected {
            Some(selected) => Thread {
                conversation: selected.conversation,
                root: Some(selected.root),
                count: selected.replies.len() as u64,
                replies: selected.replies,
                last_at: Some(selected.last_at),
            },
            None => Thread {
                conversation: conversation_of(&self.store, &txn, &trunk)?,
                root: None,
                count: 0,
                replies: Vec::new(),
                last_at: None,
            },
        })
    }

    /// [`Self::thread`] and [`Self::thread_roots`] as `read` reads them
    /// (FIX 2951): the roots under `trunk` it admits, and the first of them,
    /// with its chain chosen as [`Self::thread`] chooses one and its count
    /// and time taken from the replies it admits, never from the cached meta
    /// line. A trunk whose every thread it withholds reads as one with none.
    pub fn thread_under(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        trunk: EntityId,
    ) -> Result<(Thread, Vec<EntityId>)> {
        let (conversation, roots) = {
            let txn = self.store.env.read_txn()?;
            (
                conversation_of(&self.store, &txn, &trunk)?,
                roots_in_txn(self, &txn, trunk)?,
            )
        };
        let mut admitted = Vec::new();
        for root in roots {
            if read.is_entity_readable(&root)? {
                admitted.push(root);
            }
        }
        admitted.sort_unstable();
        let Some(&root) = admitted.first() else {
            let none = Thread {
                conversation,
                root: None,
                count: 0,
                replies: Vec::new(),
                last_at: None,
            };
            return Ok((none, admitted));
        };
        let chain = {
            let txn = self.store.env.read_txn()?;
            let mut chain = vec![root];
            chain.extend(chain_in_txn(self, &txn, conversation, root, None)?);
            let mut timed = Vec::with_capacity(chain.len());
            for id in chain {
                let row =
                    crate::ports::EntityStoreRead::port_entity_record(&self.store, &txn, &id)?
                        .ok_or(Error::EntityNotFound)?;
                timed.push((id, row.occurred.start));
            }
            timed
        };
        let mut replies = Vec::new();
        let mut last_at: Option<u64> = None;
        for (id, at) in chain {
            if read.is_entity_readable(&id)? {
                replies.push(id);
                last_at = Some(last_at.map_or(at, |last| last.max(at)));
            }
        }
        let thread = Thread {
            conversation,
            root: Some(root),
            count: replies.len() as u64,
            replies,
            last_at,
        };
        Ok((thread, admitted))
    }

    /// [`Self::thread_meta`] as `read` reads it: [`Self::thread_under`]'s
    /// root, count and time, never the cached raw line.
    pub fn thread_meta_under(
        &self,
        read: &crate::claim::ScopedRead<'_>,
        trunk: EntityId,
    ) -> Result<Option<ThreadMeta>> {
        let (thread, _) = self.thread_under(read, trunk)?;
        Ok(thread.root.map(|root| ThreadMeta {
            root,
            count: thread.count,
            last_at: thread.last_at.unwrap_or_default(),
        }))
    }

    /// Continues the thread chain on Parent without changing the conversation
    /// HEAD. The reply target stays the caller's (or the quoted message's
    /// TURN), so a thread reply may answer a trunk message; absent both, it
    /// answers the chain's tip. `writer` binds it as it binds
    /// [`Vault::append_dag_record`] (OF-063): the trunk and every typed ref
    /// must read for the writer, and so must the parent this door picks, in
    /// the reply's own transaction.
    pub fn reply_in_thread(
        &self,
        writer: &Memory<'_>,
        trunk: EntityId,
        input: &AppendRecord,
    ) -> MemoryResult<AppendedRecord> {
        let lane = policy::open_append(self, writer, policy::REPLY_ROW, input)?;
        let refs = policy::append_references(input, Some(trunk));
        let replied = self.try_with_write_txn_grouped::<_, _, AppendFailure>(|txn| {
            policy::require_append_references_in_txn(self, &lane, txn, input, &refs)?;
            require_member(&self.store, txn, &input.conversation, &trunk)?;
            let mut target = trunk;
            let conversation = conversation_of(&self.store, txn, &trunk)?;
            let candidates = chain_in_txn(self, txn, conversation, trunk, Some(input.session))?;
            if let Some(last) = candidates.last() {
                target = *last;
            }
            // The tip is chosen in this transaction, so a concurrent reply
            // never puts an unchecked parent under the writer.
            if target != trunk
                && let Some(pointer) = policy::unresolved_append_reference_in_txn(
                    &lane,
                    txn,
                    &[("/parent".to_owned(), target)],
                )?
            {
                return Err(AppendFailure::Unresolved(pointer));
            }
            let mut input = input.clone();
            input.parent = Some(target);
            if input.reply_to.is_none() && input.quote.is_none() {
                input.reply_to = Some(target);
            }
            input.advance = false;
            let appended = super::append_in_txn(self, txn, &input, None, true)?;
            // A nested reply also changes the ancestor trunk's meta line.
            let mut cursor = Some(target);
            let mut visited = HashSet::new();
            while let Some(id) = cursor {
                if !visited.insert(id) || visited.len() > MAX_ANCESTOR_DEPTH {
                    return Err(Error::IndexOverflow("conversation_dag_walk").into());
                }
                rebuild_thread_meta_in_txn(self, txn, id)?;
                if !super::graph::is_thread_record(&self.store, txn, &id)? {
                    break;
                }
                cursor = super::graph::parent(&self.store, txn, &id)?;
            }
            // The caller may have selected a higher trunk than the actual parent.
            if !visited.contains(&trunk) {
                rebuild_thread_meta_in_txn(self, txn, trunk)?;
            }
            Ok(appended)
        });
        policy::settle_append(writer, policy::REPLY_ROW, input, replied)
    }
}
