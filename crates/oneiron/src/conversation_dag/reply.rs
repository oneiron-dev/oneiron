//! Revision-bound reply strips. Missing or edited targets never expose a
//! replacement body as though it were the historical quotation.

use super::graph::{
    CANONICAL, all_edge_ids, conversation_of, edge_ids, invalid, read_id, require_member,
    require_type, walk_count,
};
use super::policy::{self, AppendFailure};
use super::thread_projection::{chain_in_txn, selected_thread_in_txn};
use super::{AppendRecord, AppendedRecord};
use crate::claim::ScopedRead;
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use std::collections::HashSet;

mod thread_reads;

/// Renderer-neutral reply strip over an exact content revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyStrip {
    /// Target of the historical reply pointer: a TURN, or one MESSAGE of a
    /// TURN (FIX 9771).
    pub record: EntityId,
    /// BLAKE3 content hash captured at the merge move.
    pub revision: String,
    /// The typed target, with the TURN a MESSAGE target is placed against.
    pub target: super::DagReplyTarget,
    /// Target's text, a TURN's txt field or a MESSAGE's content, only when
    /// it is still live at the pinned revision and not `withheld`.
    pub text: Option<String>,
    /// Target is missing, deleted or no longer at the pinned revision;
    /// `None` for a `withheld` target, which reports no stale bit, so its
    /// reader learns nothing of whether it changed (FIX 5871).
    pub stale: Option<bool>,
    /// Target has been erased (rather than merely edited or not yet received).
    pub redacted: bool,
    /// Target's words sit in a private-thread turn the reader does not read
    /// (FIX 5652), or, below the owner, in a turn its lane does not read (FIX
    /// 5938): `text` is `None` though the target stands at its revision.
    pub withheld: bool,
}

impl Vault {
    /// Whether `read`'s caller reads the words of the row `id` under each
    /// private thread it sits in, turn by turn, the opener included (FIX
    /// 5652): the one bound the TURN routes hold the owner's read to
    /// ([`Self::turn_doors_owner`]). None of `read`'s other gates is asked;
    /// `read` reads this vault. A row with no record has no thread to
    /// withhold it.
    pub fn private_threads_admit(&self, read: &ScopedRead<'_>, id: &EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        read.private_threads_admit_in(&txn, id)
    }

    /// Whether the TURN doors serve `read`'s caller as the vault owner (FIX
    /// 5938, 5939): his own key, a self-hosted root's or the dev mode's
    /// acting as him, or a narrower credential of his while he is still the
    /// bound owner (`ScopedReadActorKey::facets_owner_exempt_in`). He reads
    /// and writes there as before, held to private threads alone; any other
    /// caller reads and writes only what its own lane reads.
    pub fn turn_doors_owner(&self, read: &ScopedRead<'_>) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.turn_doors_owner_in(read, &txn)
    }

    /// [`Self::turn_doors_owner`], judged in `txn`.
    pub(crate) fn turn_doors_owner_in(
        &self,
        read: &ScopedRead<'_>,
        txn: &RoTxn<'_>,
    ) -> Result<bool> {
        read.actor_key().facets_owner_exempt_in(self, txn)
    }

    /// Projects a revision-bound reply strip for `read`'s caller. Never
    /// reconstructs or invents text. A reply the caller does not read
    /// (`turn_doors_admit_in`) is not found; a target it does not read
    /// keeps its place and revision, never its words, so one added to a
    /// private thread from a later turn on reads a reply to a turn before
    /// its add without that turn's text (FIX 5652). Such a target is
    /// `withheld`, with no stale bit (FIX 5871) and not redacted.
    pub fn reply_strip(
        &self,
        read: &ScopedRead<'_>,
        record: &EntityId,
    ) -> Result<Option<ReplyStrip>> {
        let txn = self.store.env.read_txn()?;
        // A MESSAGE the append door added keeps its pointer too (FIX 9771).
        let (kind, bytes) = match live_entity_row_in_txn(&self.store, &txn, record)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_MESSAGE,
                body,
            } => (ENTITY_TYPE_MESSAGE, body),
            _ => (
                ENTITY_TYPE_TURN,
                require_type(&self.store, &txn, record, ENTITY_TYPE_TURN)?,
            ),
        };
        let owner = self.turn_doors_owner_in(read, &txn)?;
        if !turn_doors_admit_in(read, &txn, record, owner)? {
            return Err(Error::EntityNotFound);
        }
        let Some(target) = super::quote::stored_target(kind, &bytes)? else {
            return Ok(None);
        };
        let (answered, placement) = (target.record(), target.placement());
        let gone = |id: &EntityId| -> Result<bool> {
            Ok(matches!(
                live_entity_row_in_txn(&self.store, &txn, id)?,
                LiveEntityRow::DeletedShell
            ) || self.local_hard_delete_marker_exists_in_txn(&txn, id)?)
        };
        let redacted = gone(&answered)?;
        // A TURN's `RepliesTo` names the TURN it is placed against; a
        // door-added MESSAGE's names the exact record it answers.
        let edge_target = if kind == ENTITY_TYPE_MESSAGE {
            answered
        } else {
            placement
        };
        let edges = edge_ids(&self.store, &txn, record, EdgeKind::RepliesTo, false, 2)?;
        // HardErase tears incident edges. The pinned pointer survives in the
        // immutable reply body, but must never hydrate erased content. A live
        // target still requires the exact structural edge.
        if edges != [edge_target] && !((redacted || gone(&edge_target)?) && edges.is_empty()) {
            return Err(Error::CorruptedIndex("reply pointer index"));
        }
        let source_room = if kind == ENTITY_TYPE_MESSAGE {
            crate::conversation::room_message_owner_in(&self.store, &txn, *record)?
                .ok_or_else(|| invalid("reply is outside conversation"))?
        } else {
            conversation_of(&self.store, &txn, record)?
        };
        let target_row = live_entity_row_in_txn(&self.store, &txn, &answered)?;
        let mut withheld = false;
        let live_kind = match (&target, &target_row) {
            (super::DagReplyTarget::Turn { .. }, LiveEntityRow::Live { entity_type, .. })
                if *entity_type == ENTITY_TYPE_TURN =>
            {
                true
            }
            (super::DagReplyTarget::Message { .. }, LiveEntityRow::Live { entity_type, .. })
                if *entity_type == ENTITY_TYPE_MESSAGE =>
            {
                true
            }
            _ => false,
        };
        let (text, stale) = match target_row {
            LiveEntityRow::Live { body, .. } if live_kind => {
                if conversation_of(&self.store, &txn, &placement)? != source_room {
                    return Err(invalid("reply target is outside conversation"));
                }
                if !turn_doors_admit_in(read, &txn, &placement, owner)?
                    || !turn_doors_admit_in(read, &txn, &answered, owner)?
                {
                    withheld = true;
                    (None, None)
                } else {
                    match &target {
                        super::DagReplyTarget::Turn { revision, .. } => {
                            if blake3::hash(&body).to_hex().as_str() != revision {
                                (None, Some(true))
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
                                (text, Some(false))
                            }
                        }
                        super::DagReplyTarget::Message { revision, .. } => {
                            let body = crate::entity_doc::resolve_record_body(
                                &self.store,
                                &txn,
                                &answered,
                                &body,
                            )?;
                            let text = super::quote::message_text(&body)?;
                            if blake3::hash(text.as_bytes()).to_hex().as_str() != revision {
                                (None, Some(true))
                            } else {
                                (Some(text), Some(false))
                            }
                        }
                    }
                }
            }
            _ => (None, Some(true)),
        };
        Ok(Some(ReplyStrip {
            record: answered,
            revision: target.revision().to_owned(),
            target,
            text,
            stale,
            redacted,
            withheld,
        }))
    }
}

/// Whether the TURN doors serve the row `id` to `read`'s caller in `txn`:
/// the owner's own read (`owner`, [`Vault::turn_doors_owner`]) under each
/// private thread alone (FIX 5652), any other under its lane's whole row
/// admission, private threads included (FIX 5938).
fn turn_doors_admit_in(
    read: &ScopedRead<'_>,
    txn: &RoTxn<'_>,
    id: &EntityId,
    owner: bool,
) -> Result<bool> {
    if owner {
        read.private_threads_admit_in(txn, id)
    } else {
        read.is_entity_readable_in(txn, id)
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
    let mut walk = walk_count(&vault.store, txn, &conversation)?;
    let children = all_edge_ids(&vault.store, txn, &trunk, EdgeKind::Parent, true, &mut walk)?;
    walk.defer(&vault.store);
    // A thread hangs off its trunk on Parent; its reply targets may point anywhere.
    for child in children {
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

/// A room-handle aggregate or a root-first native DAG chain, and its derived
/// metadata. On a project room's indexed turn it is every live reply of
/// every thread the room's index selects for the handle, with each native
/// DAG append on the chain that has no room row, by `(at, reply id)`; its
/// `root` is then the earliest of them, the aggregate's representative, not
/// a claim that the threads are one chain.
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
        THREAD_DIRTY.put(store, txn, &id, &[1])?;
        if thread_kind(store, txn, &id)? == Some(false) {
            break;
        }
        cursor = super::graph::parent(store, txn, &id)?;
    }
    // Rule 5: the chain is marked whole, however long, and counted.
    let mut walk = walk_count(store, txn, &start)?;
    walk.rows(seen.len());
    walk.defer(store);
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
        let mut walk = walk_count(store, txn, &id)?;
        let children = all_edge_ids(store, txn, &id, EdgeKind::Parent, true, &mut walk)?;
        walk.defer(store);
        for child in children {
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

/// The [`Thread`] a project room's indexed turn `trunk` selects: every live
/// reply of every thread the room's index holds for it, quoted or not, with
/// each live native DAG append on its chain that has no room row. `None`
/// when the room indexes no such turn, so the caller reads the DAG chain; an
/// indexed handle with no live reply is an empty thread, never a sibling
/// chain. Never cached: an ordinary room row does not dirty the DAG's meta.
/// A private thread's audience edit (FIX 5637) is among its replies but no
/// reply's activity (FIX 6544): neither `count` nor `last_at` holds it.
fn room_thread_in_txn(vault: &Vault, txn: &RoTxn<'_>, trunk: EntityId) -> Result<Option<Thread>> {
    let conversation = conversation_of(&vault.store, txn, &trunk)?;
    let Some(indexed) =
        crate::workspace_roster::room_thread_turns_in_txn(vault, txn, conversation, trunk)?
    else {
        return Ok(None);
    };
    let mut rows = std::collections::BTreeMap::new();
    let mut edits = HashSet::new();
    for turn in indexed.turns {
        let id = EntityId::from_hex(&turn.turn_id)?;
        let row = live_entity_row_in_txn(&vault.store, txn, &id)?;
        if row.is_live() {
            if crate::workspace_roster::is_audience_edit_row(&row) {
                edits.insert(id);
            }
            rows.insert(id, turn.at);
        }
    }
    // A native append lands no room row, so only the DAG chain holds it.
    if let Some(native) = selected_thread_in_txn(vault, txn, trunk)? {
        for id in native.replies {
            if crate::workspace_roster::replicated_turn_in(vault, txn, id)?.is_none() {
                let row =
                    crate::ports::EntityStoreRead::port_entity_record(&vault.store, txn, &id)?
                        .ok_or(Error::EntityNotFound)?;
                rows.insert(id, row.occurred.start);
            }
        }
    }
    let mut rows: Vec<(u64, EntityId)> = rows.into_iter().map(|(id, at)| (at, id)).collect();
    rows.sort_unstable();
    let spoken = || rows.iter().filter(|(_, id)| !edits.contains(id));
    Ok(Some(Thread {
        conversation,
        root: rows.first().map(|(_, id)| *id),
        count: spoken().count() as u64,
        last_at: spoken().next_back().map(|(at, _)| *at),
        replies: rows.iter().map(|(_, id)| *id).collect(),
    }))
}

impl Vault {
    /// Finds all immediate thread roots; a canonical fork is not a root. On a
    /// project room's indexed turn they are the live roots of every room
    /// thread anchored on it, with each native DAG root that has no room row.
    pub fn thread_roots(&self, trunk: EntityId) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let room = conversation_of(&self.store, &txn, &trunk)?;
        let Some(indexed) =
            crate::workspace_roster::room_thread_turns_in_txn(self, &txn, room, trunk)?
        else {
            return roots_in_txn(self, &txn, trunk);
        };
        let mut roots = Vec::new();
        for turn in indexed.turns {
            // A room thread's root names its anchor and answers no turn
            // inside the thread.
            if turn.thread_of.as_deref().is_some_and(|anchor| {
                turn.reply_to
                    .as_deref()
                    .is_none_or(|parent| parent == anchor)
            }) {
                let id = EntityId::from_hex(&turn.turn_id)?;
                if live_entity_row_in_txn(&self.store, &txn, &id)?.is_live() {
                    roots.push(id);
                }
            }
        }
        for root in roots_in_txn(self, &txn, trunk)? {
            if crate::workspace_roster::replicated_turn_in(self, &txn, root)?.is_none() {
                roots.push(root);
            }
        }
        roots.sort_unstable();
        roots.dedup();
        Ok(roots)
    }

    /// Reads the cached meta line without walking the reply chain. A project
    /// room's indexed turn reads its room aggregate instead, never cached.
    pub fn thread_meta(&self, trunk: EntityId) -> Result<Option<ThreadMeta>> {
        let txn = self.store.env.read_txn()?;
        if let Some(room) = room_thread_in_txn(self, &txn, trunk)? {
            return Ok(room
                .root
                .zip(room.last_at)
                .map(|(root, last_at)| ThreadMeta {
                    root,
                    count: room.count,
                    last_at,
                }));
        }
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
        if let Some(room) = room_thread_in_txn(self, &txn, trunk)? {
            return Ok(room);
        }
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
    /// (FIX 2951): the roots under `trunk` it reaches, and the first of them,
    /// with its chain chosen as [`Self::thread`] chooses one and its count
    /// and time taken from the replies it admits, never from the cached meta
    /// line. A root is reached as a place when `read` reads none of it for
    /// a later add (FIX 5545, [`Self::thread_record_reached`]); the root then
    /// counts as no reply, and a thread with no reply `read` admits has count
    /// 0 and no time. A trunk whose every thread it withholds reads as one
    /// with none.
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
            if self.thread_record_reached(read, root)? {
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
    /// HEAD: the first same-session thread under `trunk`, by root id, whose
    /// audience admits the writer, else a new thread. A reply that names a
    /// `thread_audience` always opens a new thread. The reply target stays
    /// the caller's (or the quoted message's TURN), so a thread reply may
    /// answer a trunk message; absent both, it answers the chain's tip. `writer` binds it as it binds
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
            // FIX 3126: continue the first same-session thread, by root id,
            // whose audience admits the writer; else open a new one. An
            // explicit audience always opens a fresh thread.
            if input.thread_audience.is_none() {
                let actor = input.actor.entity_ref();
                for root in roots_in_txn(self, txn, trunk)? {
                    if crate::compaction::turn_session_membership_in_txn(&self.store, txn, &root)?
                        != input.session
                    {
                        continue;
                    }
                    match crate::workspace_roster::thread_audience_allows_in(
                        self,
                        txn,
                        conversation,
                        root,
                        actor,
                    ) {
                        Ok(true) => {}
                        Ok(false) | Err(Error::EntityNotFound) => continue,
                        Err(e) => return Err(e.into()),
                    }
                    target = chain_in_txn(self, txn, conversation, root, Some(input.session))?
                        .last()
                        .copied()
                        .unwrap_or(root);
                    break;
                }
            }
            // The tip is chosen in this transaction, so a concurrent reply
            // never puts an unchecked parent under the writer. A tip held back
            // from the writer for its add is its place in the thread, not a
            // read (FIX 5545).
            if target != trunk
                && !writer.thread_turn_held_back_in(txn, conversation, target)?
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
                if !visited.insert(id) {
                    return Err(Error::from(crate::error::RegistryError::CycleDetected).into());
                }
                rebuild_thread_meta_in_txn(self, txn, id)?;
                if !super::graph::is_thread_record(&self.store, txn, &id)? {
                    break;
                }
                cursor = super::graph::parent(&self.store, txn, &id)?;
            }
            let mut walk = walk_count(&self.store, txn, &conversation)?;
            walk.rows(visited.len());
            walk.defer(&self.store);
            // The caller may have selected a higher trunk than the actual parent.
            if !visited.contains(&trunk) {
                rebuild_thread_meta_in_txn(self, txn, trunk)?;
            }
            Ok(appended)
        });
        policy::settle_append(writer, policy::REPLY_ROW, input, replied)
    }
}
