//! A standing answer never stays in a facet its room no longer reads,
//! whichever act narrows the room (FIX STANDING-ANSWER-STAYS-IN-LEFT-FACET,
//! Engine ruling A, 19 Nov 13:29; FIX STANDING-ANSWER-LEFT-FACET-OTHER-WRITERS).
//!
//! A home room reads through its project's served view. The view reads less
//! after a signed state with a narrower set or a moved slice (the owner's set
//! door, a roster write, a seal, a fork resolution), after a history merge
//! that meets two sets, after a parent's narrowing that quarantines the
//! project, and after a replica carries any of these. Each batch end persists
//! every changed view ([`super::refresh`]) and queues here, in the same
//! transaction, the home room of each view that may now leave an answer wider
//! than its row, and of each frozen view it refreshes: a frozen view is served
//! only while it still fits its parents, so a parent's narrowing can empty its
//! room with the record unchanged. A delete or a purge that unbinds a home
//! room queues it too, with the rows it detaches. The vault's batch terminal,
//! and the delete and purge doors after their unbind, then mark stale each
//! standing answer a queued room left wider than a row it rests on, and empty
//! the queue before the transaction commits.

use super::fold::ProjectEffective;
use super::*;
use crate::store::Store;

/// [`PROJECT_ROOM_NARROWING`]'s value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NarrowedRoom {
    /// The rows standing answers rest on that a delete detached from the
    /// room; empty while every row still names the room.
    detached: Vec<EntityId>,
}

/// The rooms queued in the active write. RUNTIME: emptied before commit.
const PROJECT_ROOM_NARROWING: SideTable<EntityId, NarrowedRoom, Named> =
    SideTable::new(&side_table::PROJECT_ROOM_NARROWING);

/// What a home room reads through its project's served view, as
/// [`super::read::room_facets_in`] serves it.
#[derive(Debug, PartialEq, Eq)]
enum RoomReach {
    /// No limit: the project's authority names no facet, so the room places
    /// its rows in no facet of its own.
    Unlimited,
    /// These facets.
    Facets(BTreeSet<EntityId>),
    /// Nothing: no served view, or slices that met to nothing.
    Nothing,
}

impl RoomReach {
    fn of(effective: Option<&ProjectEffective>) -> Self {
        let Some(effective) = effective.filter(|effective| effective.slice.is_some()) else {
            return Self::Nothing;
        };
        match effective.room_facet_reach() {
            None => Self::Unlimited,
            Some(facets) if facets.is_empty() => Self::Nothing,
            Some(facets) => Self::Facets(facets),
        }
    }

    /// Whether an answer placed on a row of the room while it read `self`
    /// may sit, once it reads `after`, in a facet the row is no longer read
    /// in: a facet leaves, or the limit comes or goes, so the room places its
    /// rows anew. A room that read nothing held no answer.
    fn strands_answers_at(&self, after: &Self) -> bool {
        match (self, after) {
            (Self::Nothing, _) => false,
            (_, Self::Nothing) => true,
            (Self::Unlimited, Self::Unlimited) => false,
            (Self::Unlimited, Self::Facets(_)) | (Self::Facets(_), Self::Unlimited) => true,
            (Self::Facets(before), Self::Facets(after)) => !before.is_subset(after),
        }
    }
}

/// Queues `project`'s home room when its persisted view moves from `before`
/// to `after` in a way that may leave an answer wider than its row.
///
/// `frozen`: the record written is a frozen one. It is served only while it
/// still fits its parents' views and its seal, which each read checks again
/// (`history_policy::frozen_frontier`), so a parent's narrowing that wakes
/// it can leave its room reading nothing while the record stays the same.
/// Its room is queued whenever it read anything; the drain reads each
/// answer's rows exactly, so a room that still reads them marks none.
pub(super) fn queue_narrowed_room_in(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    before: Option<&ProjectEffective>,
    after: Option<&ProjectEffective>,
    frozen: bool,
) -> Result<()> {
    let before = RoomReach::of(before);
    let strands = if frozen {
        before != RoomReach::Nothing
    } else {
        before.strands_answers_at(&RoomReach::of(after))
    };
    if !strands {
        return Ok(());
    }
    let room = home_room_id(project)?;
    if PROJECT_ROOM_NARROWING.contains(store, txn, &room)? {
        return Ok(());
    }
    PROJECT_ROOM_NARROWING.put(store, txn, &room, &NarrowedRoom::default())
}

/// Queues `room`, which a delete is about to unbind from its project, with
/// the rows standing answers rest on in it: once unbound, those rows no
/// longer name it.
pub(super) fn queue_unbound_room_in(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<()> {
    let detached = crate::llm::decision::questions::answer_rows_in_room_in(store, txn, room)?;
    if detached.is_empty() {
        return Ok(());
    }
    PROJECT_ROOM_NARROWING.put(store, txn, &room, &NarrowedRoom { detached })
}

impl Vault {
    /// Marks stale, in `txn`, each standing answer a queued room left wider
    /// than a row it rests on, and empties the queue. Every batch terminal
    /// runs it once its apply is staged, and the delete and purge doors after
    /// their unbind, so each mark commits with the narrowing that caused it.
    pub(crate) fn mark_answers_in_narrowed_rooms_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        let mut queued = Vec::new();
        for row in PROJECT_ROOM_NARROWING.iter_raw_from(&self.store, txn, &[])? {
            let (key, value) = row?;
            let room = EntityId::from_bytes(
                key.try_into()
                    .map_err(|_| Error::CorruptedIndex("project room narrowing key"))?,
            )?;
            // A value that does not decode finds the room's rows by their
            // room edges, as a narrowing without a delete does.
            let narrowed = PROJECT_ROOM_NARROWING
                .decode_value(&value)
                .unwrap_or_default();
            queued.push((room, narrowed));
        }
        if queued.is_empty() {
            return Ok(());
        }
        // Emptied first: the marks' own batches run this again.
        for (room, _) in &queued {
            PROJECT_ROOM_NARROWING.delete(&self.store, txn, room)?;
        }
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        for (room, narrowed) in queued {
            crate::llm::decision::questions::mark_answers_stale_in_left_facets_in_txn(
                self,
                txn,
                room,
                &narrowed.detached,
                now,
            )?;
        }
        Ok(())
    }
}
