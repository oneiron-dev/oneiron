//! The conversation list, read as the bound actor (ARCH-0006a, DEC-0005).
//!
//! The type index names the conversations; every row the list returns, and
//! every turn and message a row's preview quotes, comes through the actor's
//! read lane, the one recall and the transcript read on. A conversation, turn
//! or message the actor may not read never shows, nor an erased or archived
//! one. A group, channel or mirror is relationship data (ARCH-0006a): a
//! reader other than the owner sees it only as a member, and then only the
//! turns its membership showed it, or on a grant that opens its
//! relationship. A room the reader is not in reads as absent, with no count,
//! whether or not the lane admits its row. Who the reader is to a room is
//! judged in the snapshot of each read that admits the room or one of its
//! turns, so a membership, history or grant that narrows during a list
//! narrows every later read of it. The receipt counts each other listed
//! conversation the reader may not read, and every listed one is read
//! whatever the page asks, so the count never says where a hidden
//! conversation falls. A preview's reads narrow the receipt but add no
//! count: a count of a conversation's hidden turns or messages would say
//! what that conversation holds.

use super::read_lane::fold_receipt;
use super::*;

use crate::claim::{
    ClaimReadStatus, PointRead, ReadRow, ScopedRead, ScopedReadReceipt, ScopedReadResult,
};
use crate::conversation::{
    ConversationBody, ConversationKind, LatestMessage, MembershipWindow, PreviewCandidates,
    snippet, turn_text,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::ports::{EntityStoreRead, TombstoneStore};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE};

/// Conversations read through the lane at a time.
const LIST_CHUNK: usize = 256;

/// Turns, or their sessions, a preview reads through the lane at a time. It
/// reads every turn it looks at before it orders any.
const PREVIEW_TURNS_PER_READ: usize = 64;

/// Rows of one turn, the turn and then its messages, a preview reads through
/// the lane at a time; only the latest message's text is kept between reads.
const PREVIEW_ROWS_PER_READ: usize = 256;

/// Which conversations a list names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConversationListFilter<'f> {
    /// Only conversations of this kind.
    pub kind: Option<ConversationKind>,
    /// Only conversations with this external id.
    pub external_id: Option<&'f str>,
}

impl ConversationListFilter<'_> {
    /// Whether the conversation body `body` is one this filter names. A body
    /// that does not decode is named only by the empty filter.
    fn names(&self, body: &[u8]) -> bool {
        if *self == Self::default() {
            return true;
        }
        ConversationBody::from_bytes(body).is_ok_and(|body| {
            self.kind.is_none_or(|kind| kind == body.kind)
                && self
                    .external_id
                    .is_none_or(|external| body.external_id.as_deref() == Some(external))
        })
    }
}

/// One conversation on a list page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationListRow {
    /// The conversation's row as the lane admitted it.
    pub row: ReadRow,
    /// The latest visible message of the conversation that the reader may
    /// read, clipped to 50 characters; for a turn with no such message, the
    /// turn's own text.
    pub last_message_snippet: Option<String>,
}

/// One page of the conversation list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationListPage {
    /// The conversations the reader may read, in index order.
    pub rows: Vec<ConversationListRow>,
    /// The cursor the next page starts after, set only when another
    /// conversation the reader may read follows.
    pub next: Option<EntityId>,
    /// How many conversations the reader may read in all, when asked.
    pub total: Option<u64>,
}

/// Which of a listed conversation's turns the reader may see, beyond what
/// the lane admits, as one snapshot holds it.
enum Sight {
    /// Every turn the lane admits.
    Whole,
    /// Only turns said inside one of the reader's membership windows: a late
    /// joiner sees only what its membership showed it.
    Windows(Vec<MembershipWindow>),
}

impl Sight {
    fn shows(&self, at: u64) -> bool {
        match self {
            Self::Whole => true,
            Self::Windows(windows) => windows.iter().any(|window| window.contains(at)),
        }
    }
}

/// What bounds a listed conversation's preview beyond the lane. Each read
/// of a bounded conversation's turns judges the reader's [`Sight`] again, in
/// that read's own snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bound {
    /// Nothing: the owner reads with its own key.
    Lane,
    /// A conversation that was no room when the list read it; it is judged
    /// by the kind it names in each read.
    Conversation(EntityId),
    /// A room when the list read it; it is judged as a room in each read,
    /// whatever kind it names by then.
    Room(EntityId),
}

/// One walk of the whole list.
struct ListWalk {
    /// The page: the first `limit` rows after the cursor the reader may read,
    /// each with what bounds its preview.
    rows: Vec<(ReadRow, Bound)>,
    /// The page's last row, set only when a row the reader may read follows.
    next: Option<EntityId>,
    /// How many listed conversations the reader may read in all.
    total: u64,
    /// The receipt of every conversation read.
    receipt: Option<ScopedReadReceipt>,
}

impl Memory<'_> {
    /// Lists up to `limit` conversations after `after` that the bound actor
    /// may read, each with its preview, and with `count` how many it may read
    /// in all. The receipt counts each existing conversation the list
    /// withheld, every listed one and not only this page's.
    ///
    /// # Errors
    ///
    /// A refused actor binding, or a failed store read.
    pub fn conversation_list(
        &self,
        filter: ConversationListFilter<'_>,
        after: Option<&EntityId>,
        limit: usize,
        count: bool,
    ) -> MemoryResult<ScopedReadResult<ConversationListPage>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let ListWalk {
            rows,
            next,
            total,
            mut receipt,
        } = self.listed(&lane, filter, after, limit)?;
        #[cfg(test)]
        BEFORE_PREVIEWS.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook(self.vault);
            }
        });
        let mut page = Vec::with_capacity(rows.len());
        for (row, bound) in rows {
            let last_message_snippet = self.preview(&lane, &row.id, bound, &mut receipt)?;
            page.push(ConversationListRow {
                row,
                last_message_snippet,
            });
        }
        let receipt = match receipt {
            Some(receipt) => receipt,
            None => lane.read_receipt(None, 0)?,
        };
        Ok(ScopedReadResult {
            value: ConversationListPage {
                rows: page,
                next,
                total: count.then_some(total),
            },
            receipt,
        })
    }

    /// Reads every listed conversation through the lane, from the first.
    /// The whole list is read whatever the page and the count ask, so what
    /// the receipt withholds says nothing about where a hidden conversation
    /// falls beside the page or the cursor.
    fn listed(
        &self,
        lane: &ScopedRead<'_>,
        filter: ConversationListFilter<'_>,
        after: Option<&EntityId>,
        limit: usize,
    ) -> MemoryResult<ListWalk> {
        let mut rows: Vec<(ReadRow, Bound)> = Vec::new();
        let mut next = None;
        let mut total = 0_u64;
        let mut receipt = None;
        let mut cursor = None;
        loop {
            let (ids, more) = self.listed_ids(cursor.as_ref(), LIST_CHUNK)?;
            for row in self
                .read_conversations(lane, filter, &ids, &mut receipt)?
                .into_iter()
                .flatten()
            {
                total = total.saturating_add(1);
                if after.is_some_and(|after| row.0.id <= *after) {
                    continue;
                }
                if rows.len() < limit {
                    rows.push(row);
                } else if next.is_none() {
                    next = rows.last().map(|(row, _)| row.id);
                }
            }
            match ids.last() {
                Some(last) if more => cursor = Some(*last),
                _ => {
                    return Ok(ListWalk {
                        rows,
                        next,
                        total,
                        receipt,
                    });
                }
            }
        }
    }

    /// Up to `want` conversation ids after `after` in index order, without
    /// erased ones, and whether the walk stopped at `want`. Only the listing
    /// reads here, and no body: every row the list returns is read again
    /// through the lane, and the filter sees only rows the lane admitted.
    fn listed_ids(
        &self,
        after: Option<&EntityId>,
        want: usize,
    ) -> MemoryResult<(Vec<EntityId>, bool)> {
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let mut ids = Vec::new();
        for id in
            self.vault
                .port_entity_ids_by_type(&txn, ENTITY_TYPE_CONVERSATION, after.copied())?
        {
            let id = id?;
            if TombstoneStore::port_tombstone_is_deleted(self.vault, &txn, &id)? {
                continue;
            }
            ids.push(id);
            if ids.len() == want {
                return Ok((ids, true));
            }
        }
        Ok((ids, false))
    }

    /// Reads `ids` through the lane: each slot is the conversation's row with
    /// its body and what bounds its preview, or `None` for a row the reader
    /// may not read, a room it is not in, or a row the filter does not name.
    /// The filter reads only admitted bodies. A row the lane withholds counts
    /// unless it is a room the reader could not see were it admitted, judged
    /// in the read's own snapshot (Sol F2): a hidden room adds no count.
    fn read_conversations(
        &self,
        lane: &ScopedRead<'_>,
        filter: ConversationListFilter<'_>,
        ids: &[EntityId],
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Vec<Option<(ReadRow, Bound)>>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let named = |row: &ReadRow| {
            row.entity_type == ENTITY_TYPE_CONVERSATION
                && row.body.as_deref().is_some_and(|body| filter.names(body))
        };
        if lane.actor_key().vault_owner_ref().is_some() {
            let read = lane.read(&reads, None)?;
            fold_receipt(receipt, read.receipt);
            return Ok(read
                .value
                .into_iter()
                .map(|row| row.filter(named).map(|row| (row, Bound::Lane)))
                .collect());
        }
        // A reader other than the owner reads under its grants, so the lane
        // persisted grant time before this snapshot opened, never inside it.
        let grants = std::cell::RefCell::new(None);
        let read = lane.read_projected_opaque(
            &reads,
            None,
            |txn, id| -> MemoryResult<bool> {
                let Some(stored) = self.vault.store.port_entity_record(txn, id)? else {
                    return Ok(false);
                };
                Ok(self
                    .sight_in(txn, *id, &stored.body, &mut grants.borrow_mut())?
                    .is_none())
            },
            |txn, rows| {
                rows.into_iter()
                    .map(|row| -> MemoryResult<Option<(ReadRow, Bound)>> {
                        let Some(row) = row.filter(named) else {
                            return Ok(None);
                        };
                        let body = row.body.as_deref().unwrap_or_default();
                        let bound = if is_room(body) {
                            Bound::Room(row.id)
                        } else {
                            Bound::Conversation(row.id)
                        };
                        let sight = self.sight_in(txn, row.id, body, &mut grants.borrow_mut())?;
                        Ok(sight.map(|_| (row, bound)))
                    })
                    .collect::<MemoryResult<Vec<_>>>()
            },
        )?;
        fold_receipt(receipt, read.receipt);
        Ok(read.value)
    }

    /// What of the conversation `id`, stored as `body`, the reader may see in
    /// the snapshot `txn`, or `None` when it may not see the conversation at
    /// all. The vault owner sees all of it, whatever credential it reads
    /// with. A group, channel or mirror is relationship data (ARCH-0006a rule
    /// 2): a member sees the turns its membership windows show, a member the
    /// ledger keeps no windows for (a derived room's) every turn, and anyone
    /// else the whole conversation only on a grant that opens its
    /// relationship. A body that does not decode is withheld.
    fn sight_in<'v>(
        &'v self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        body: &[u8],
        grants: &mut Option<crate::access_grant::AccessContext<'v>>,
    ) -> MemoryResult<Option<Sight>> {
        if self.is_vault_owner_in_txn(txn)? {
            return Ok(Some(Sight::Whole));
        }
        let Ok(decoded) = ConversationBody::from_bytes(body) else {
            return Ok(None);
        };
        if !is_room_kind(decoded.kind) {
            return Ok(Some(Sight::Whole));
        }
        self.member_sight_in(txn, id, &decoded, body, grants)
    }

    /// What of the room `id`, stored as `body` and decoded as `decoded`, a
    /// reader other than the owner may see in the snapshot `txn`, whatever
    /// kind the body names: a member the turns its windows show, or every
    /// turn when the ledger keeps none for it, and anyone else the whole room
    /// only on a grant that opens its relationship.
    fn member_sight_in<'v>(
        &'v self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        decoded: &ConversationBody,
        body: &[u8],
        grants: &mut Option<crate::access_grant::AccessContext<'v>>,
    ) -> MemoryResult<Option<Sight>> {
        let members = self
            .vault
            .room_audience_members_in_txn(txn, id)
            .unwrap_or_default();
        if members.contains(&self.actor) {
            let windows = self.vault.windows_in_txn(txn, id, self.actor)?;
            return Ok(Some(if windows.is_empty() {
                Sight::Whole
            } else {
                Sight::Windows(windows)
            }));
        }
        let Some(relationship) = decoded.relationship else {
            return Ok(None);
        };
        let Some(record) = crate::federation::record_scope::disclosure_scope_for_stored_row(
            &self.vault.store,
            txn,
            id,
            ENTITY_TYPE_CONVERSATION,
            body,
        )?
        else {
            return Ok(None);
        };
        let grants = match grants {
            Some(grants) => grants,
            None => grants.insert(crate::access_grant::AccessContext::load(
                self.vault,
                txn,
                Some(self.actor),
            )?),
        };
        Ok(grants
            .allows_at_snapshot(ENTITY_TYPE_MESSAGE, Some(relationship), false, &record)
            .then_some(Sight::Whole))
    }

    /// The reader's sight of a listed conversation as the snapshot `txn`
    /// holds it: every turn the lane admits when nothing bounds the read. A
    /// conversation the list read as a room is judged as one whatever kind it
    /// names by then, so a room turned direct mid-list shows no more than its
    /// membership did (Sol R2-F1). `None`: the reader may not see it, or it
    /// is gone.
    fn sight_now_in(&self, txn: &heed::RoTxn<'_>, bound: Bound) -> MemoryResult<Option<Sight>> {
        let (id, room) = match bound {
            Bound::Lane => return Ok(Some(Sight::Whole)),
            Bound::Conversation(id) => (id, false),
            Bound::Room(id) => (id, true),
        };
        let Some(stored) = self.vault.store.port_entity_record(txn, &id)? else {
            return Ok(None);
        };
        if !room {
            return self.sight_in(txn, id, &stored.body, &mut None);
        }
        if self.is_vault_owner_in_txn(txn)? {
            return Ok(Some(Sight::Whole));
        }
        let Ok(decoded) = ConversationBody::from_bytes(&stored.body) else {
            return Ok(None);
        };
        self.member_sight_in(txn, id, &decoded, &stored.body, &mut None)
    }

    /// The reader's sight under `bound`, as the snapshot `txn` holds it,
    /// when it shows `turn`.
    fn sight_of_in(
        &self,
        txn: &heed::RoTxn<'_>,
        bound: Bound,
        turn: &EntityId,
    ) -> MemoryResult<Option<Sight>> {
        if bound == Bound::Lane {
            return Ok(Some(Sight::Whole));
        }
        let Some(stored) = self.vault.store.port_entity_record(txn, turn)? else {
            return Ok(None);
        };
        Ok(self
            .sight_now_in(txn, bound)?
            .filter(|sight| sight.shows(stored.occurred.start)))
    }

    /// `rows`, a shown turn's own row and its messages as the lane admitted
    /// them, less each message a member's history does not show. A message
    /// keeps its own place in its room's history whatever turn quotes it, so
    /// the audience check judges it by its own time (Astra #1388b P1). A
    /// message the check cannot place in one room is not quoted, and the
    /// list goes on: one another room's turn links too, or whose ancestry
    /// passes the walk's bounds (Sol R4-F1, R5-F1). Only a broken store, a
    /// corrupt index or side-table row, or a broken invariant fails the list
    /// (Sol R6-F1).
    fn quoted_in(
        &self,
        txn: &heed::RoTxn<'_>,
        sight: &Sight,
        turn: &EntityId,
        rows: Vec<Option<ReadRow>>,
    ) -> MemoryResult<Vec<Option<ReadRow>>> {
        if matches!(sight, Sight::Whole) {
            return Ok(rows);
        }
        let mut audience = crate::conversation::AudienceCache::default();
        let mut quoted = Vec::with_capacity(rows.len());
        for row in rows {
            let shown = match &row {
                Some(row) if row.id != *turn => {
                    match audience.readable(self.vault, txn, row.id, &[self.actor]) {
                        Ok(readable) => readable,
                        Err(
                            error @ (Error::Storage(_)
                            | Error::Io(_)
                            | Error::MapFull
                            | Error::Store(_)
                            | Error::CorruptedIndex(_)
                            | Error::InvariantViolation(_)),
                        ) => return Err(error.into()),
                        Err(_) => false,
                    }
                }
                _ => true,
            };
            quoted.push(row.filter(|_| shown));
        }
        Ok(quoted)
    }

    /// `conversation`'s preview as the reader may read it. The turns it may
    /// look at are listed, the selected path or with no selected HEAD the
    /// ChildOf turns, and all read through the lane before any is ordered.
    /// With no selected HEAD the readable ones are ordered by their own
    /// learned time and proved by themselves, and a turn whose session the
    /// reader may not read is left out, so nothing hidden decides the
    /// preview. Only turns the reader's sight under `bound` shows count,
    /// before any is ordered. Then each readable turn, in order, is read again
    /// with its messages in bounded reads, until one has text. The sight is
    /// judged again in each of those reads: a turn it no longer shows gives
    /// no text, and a member's history judges each message by its own time.
    fn preview(
        &self,
        lane: &ScopedRead<'_>,
        conversation: &EntityId,
        bound: Bound,
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Option<String>> {
        let candidates = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            self.vault.preview_candidates_in(&txn, conversation)?
        };
        let order: Vec<EntityId> = match candidates {
            PreviewCandidates::Unresolved => return Ok(None),
            PreviewCandidates::Path(turns) => self
                .admitted(lane, &turns, bound, receipt)?
                .into_iter()
                .map(|(_, id)| id)
                .collect(),
            PreviewCandidates::ChildOf(turns) => {
                let readable = self.admitted(lane, &turns, bound, receipt)?;
                drop(turns);
                let readable = self.in_readable_sessions(lane, readable, receipt)?;
                match self.vault.readable_childof_order(conversation, readable)? {
                    Some(order) => order,
                    None => return Ok(None),
                }
            }
        };
        for turn in order {
            let messages = {
                let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
                self.vault.turn_message_ids_in(&txn, &turn)?
            };
            let mut rows = std::iter::once(turn).chain(messages).peekable();
            let (mut own, mut latest, mut shown) = (None, LatestMessage::default(), true);
            while shown && rows.peek().is_some() {
                let reads: Vec<_> = rows
                    .by_ref()
                    .take(PREVIEW_ROWS_PER_READ)
                    .map(PointRead::id)
                    .collect();
                let read = lane.read_projected(&reads, None, |txn, rows| {
                    self.sight_of_in(txn, bound, &turn)?
                        .map(|sight| self.quoted_in(txn, &sight, &turn, rows))
                        .transpose()
                })?;
                fold_scope(receipt, read.receipt);
                let Some(value) = read.value else {
                    shown = false;
                    continue;
                };
                for row in value.into_iter().flatten() {
                    let Some(body) = row.body.as_deref() else {
                        continue;
                    };
                    if row.id == turn {
                        own = turn_text(body);
                    } else {
                        latest.offer(row.id, body);
                    }
                }
            }
            if !shown {
                continue;
            }
            if let Some(text) = latest.text().or(own) {
                return Ok(Some(snippet(&text)));
            }
        }
        Ok(None)
    }

    /// The rows of `ids` the lane admits and the reader's sight of `room`
    /// shows, judged in each read's own snapshot, in order, each as its
    /// learned time and id, read a chunk at a time.
    fn admitted(
        &self,
        lane: &ScopedRead<'_>,
        ids: &[EntityId],
        bound: Bound,
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Vec<(u64, EntityId)>> {
        let mut admitted = Vec::new();
        for chunk in ids.chunks(PREVIEW_TURNS_PER_READ) {
            let reads: Vec<_> = chunk.iter().copied().map(PointRead::id).collect();
            let read = lane.read_projected(&reads, None, |txn, rows| {
                let sight = self.sight_now_in(txn, bound)?;
                Ok::<_, MemoryError>(
                    rows.into_iter()
                        .flatten()
                        .filter(|row| {
                            row.body.is_some()
                                && sight
                                    .as_ref()
                                    .is_some_and(|sight| sight.shows(row.occurred.start))
                        })
                        .map(|row| (row.learned_at, row.id))
                        .collect::<Vec<_>>(),
                )
            })?;
            fold_scope(receipt, read.receipt);
            admitted.extend(read.value);
        }
        Ok(admitted)
    }

    /// The `turns` whose session, where they sit in one, the lane admits. A
    /// session's body and edges decide whether its turns may be previewed,
    /// so a turn whose session a reader other than the owner may not read is
    /// left out rather than judged by what it may not read.
    fn in_readable_sessions(
        &self,
        lane: &ScopedRead<'_>,
        turns: Vec<(u64, EntityId)>,
        receipt: &mut Option<ScopedReadReceipt>,
    ) -> MemoryResult<Vec<(u64, EntityId)>> {
        // The vault owner, as itself or with its own full credential, may
        // inspect every session, a retained shell too, as its own preview
        // does: the proof judges each one.
        if lane.actor_key().vault_owner_ref().is_some() {
            return Ok(turns);
        }
        let sessions = {
            let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
            turns
                .iter()
                .map(|(_, turn)| {
                    crate::compaction::turn_session_membership_in_txn(&self.vault.store, &txn, turn)
                })
                .collect::<crate::error::Result<Vec<_>>>()?
        };
        let mut asked: Vec<EntityId> = sessions.iter().flatten().copied().collect();
        asked.sort_unstable();
        asked.dedup();
        let readable: Vec<EntityId> = self
            .admitted(lane, &asked, Bound::Lane, receipt)?
            .into_iter()
            .map(|(_, id)| id)
            .collect();
        Ok(turns
            .into_iter()
            .zip(sessions)
            .filter(|(_, session)| {
                session.is_none_or(|session| readable.binary_search(&session).is_ok())
            })
            .map(|(turn, _)| turn)
            .collect())
    }
}

impl crate::Vault {
    /// Whether `reader` would see the conversation `id` in its own list,
    /// judged in the snapshot `txn` by the list's own rule (`sight_in`): the
    /// owner sees every conversation, a room shows only to a member or on a
    /// grant that opens its relationship, and any other conversation shows.
    /// A reader no one names is no member and holds no grant. A gone row is
    /// not seen. The conversation-record GET admits by it (FIX 8153), so a
    /// conversation absent from the list is absent there too.
    pub(crate) fn conversation_list_sees_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        reader: Option<(EntityId, crate::edge::EdgeActorClass)>,
    ) -> MemoryResult<bool> {
        let Some(stored) = self.store.port_entity_record(txn, &id)? else {
            return Ok(false);
        };
        let Some((actor, class)) = reader else {
            return Ok(ConversationBody::from_bytes(&stored.body)
                .is_ok_and(|body| !is_room_kind(body.kind)));
        };
        let memory = self.memory(actor, class);
        let mut grants = None;
        Ok(memory
            .sight_in(txn, id, &stored.body, &mut grants)?
            .is_some())
    }
}

/// Whether a conversation of `kind` is relationship data: a group, a channel
/// or a mirror.
fn is_room_kind(kind: ConversationKind) -> bool {
    matches!(
        kind,
        ConversationKind::Group | ConversationKind::Channel | ConversationKind::Mirror
    )
}

/// Whether `body` decodes as a room's.
fn is_room(body: &[u8]) -> bool {
    ConversationBody::from_bytes(body).is_ok_and(|body| is_room_kind(body.kind))
}

/// Folds a preview read's narrowing into the list's receipt without its
/// count, nor the row axis derived from that count: either would say what a
/// listed conversation's turns and messages hold.
fn fold_scope(receipt: &mut Option<ScopedReadReceipt>, mut read: ScopedReadReceipt) {
    read.suppressed_count = 0;
    read.narrowed_axes.retain(|axis| axis != "row_authority");
    read.record_axes();
    fold_receipt(receipt, read);
}

/// A change a test makes to the vault between a list's rows and previews.
#[cfg(test)]
type PreviewHook = Box<dyn FnOnce(&crate::Vault)>;

#[cfg(test)]
thread_local! {
    /// A test seam: runs once, between the list's rows and their previews.
    static BEFORE_PREVIEWS: std::cell::RefCell<Option<PreviewHook>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests;
