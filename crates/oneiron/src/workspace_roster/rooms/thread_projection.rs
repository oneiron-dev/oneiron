//! A trunk's or thread's reply selection from the room's own index (OF-460):
//! every room thread anchored on a trunk turn, each with all of its replies,
//! quoted or not, rather than the one chain the DAG selects on `Parent`.
use super::*;
use crate::memory::RoomTurnHandle;

/// The room turns a reply-strip handle selects.
pub(crate) struct RoomThreadSelection {
    /// The one thread selected, or `None` for every thread on a trunk turn.
    pub(crate) root: Option<EntityId>,
    /// Every reply selected, in `(at, turn id)` order.
    pub(crate) turns: Vec<RoomTurn>,
}

/// The replies `handle` selects in `room`'s index: a trunk turn selects every
/// thread anchored on it, a thread's root or any reply in it exactly that one
/// thread. `None` when the room indexes no turn `handle`, so the caller reads
/// the DAG as before; an indexed selection with no reply is empty, never a
/// different chain. Every child under the anchor is read, however many; a
/// reply link that does not close inside the room is refused.
pub(crate) fn room_thread_turns_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    handle: EntityId,
) -> Result<Option<RoomThreadSelection>> {
    let Some(turn) = TURNS.get(&vault.store, txn, &handle)? else {
        return Ok(None);
    };
    if turn.room_id != room.to_hex() {
        return Err(invalid());
    }
    let anchor = match turn.thread_of.as_deref() {
        Some(anchor) => EntityId::from_hex(anchor)?,
        None => handle,
    };
    // Every turn of every thread on the anchor sits under one index prefix.
    let prefix = [room.as_bytes().as_slice(), anchor.as_bytes().as_slice()].concat();
    let mut children = crate::scan_check::ScanCount::start(
        &vault.store,
        txn,
        crate::scan_check::EngineScan::RoomThreadChildRows,
        &prefix,
    )?;
    let mut members = Vec::new();
    for item in THREAD_CHILDREN.iter_from(&vault.store, txn, &prefix)? {
        children.row();
        let (_, child) = item?;
        let row = turn_in(vault, txn, child)?;
        if row.room_id != turn.room_id || row.thread_of.as_deref() != Some(anchor.to_hex().as_str())
        {
            return Err(Error::CorruptedIndex("room thread index"));
        }
        members.push(row);
    }
    children.finish(vault);
    // A reply may answer a turn outside its thread; the root fold walks
    // those ancestors too, so they are read as context, never selected.
    let mut known: BTreeSet<EntityId> = members
        .iter()
        .map(|member| EntityId::from_hex(&member.turn_id))
        .collect::<Result<_>>()?;
    let mut pending = Vec::new();
    for member in members
        .iter()
        .filter(|member| !super::liveness::is_thread_root(member))
    {
        pending.extend(
            member
                .reply_to
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?,
        );
    }
    let mut context = Vec::new();
    while let Some(id) = pending.pop() {
        if !known.insert(id) {
            continue;
        }
        let row = turn_in(vault, txn, id)?;
        if row.room_id != turn.room_id {
            return Err(invalid());
        }
        pending.extend(
            row.reply_to
                .as_deref()
                .map(EntityId::from_hex)
                .transpose()?,
        );
        context.push(row);
    }
    let folded: Vec<RoomTurn> = members.iter().cloned().chain(context).collect();
    let roots = thread_root_map(&folded)?;
    let root = match turn.thread_of {
        Some(_) => Some(*roots.get(&handle).ok_or_else(invalid)?),
        None => None,
    };
    let mut turns = Vec::new();
    for member in members {
        let thread = roots.get(&EntityId::from_hex(&member.turn_id)?).copied();
        if thread.is_some() && (root.is_none() || thread == root) {
            turns.push(member);
        }
    }
    turns.sort_by(|a, b| (a.at, &a.turn_id).cmp(&(b.at, &b.turn_id)));
    Ok(Some(RoomThreadSelection { root, turns }))
}

impl<'v> Memory<'v> {
    /// The reader of a room selection, behind the gate a room history read
    /// passes: one thread's own reader for `Some(root)`, the room's for a
    /// trunk's every thread. A thread-only Ready join reads its own thread
    /// without a seat, and no sibling; a bound room turn's ceiling stays.
    pub(crate) fn room_selection_reader(
        &self,
        room: EntityId,
        root: Option<EntityId>,
    ) -> MemoryResult<RoomTurnHandle<'v>> {
        {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            match root {
                None => require_reader(self.vault(), &txn, room, self.actor())?,
                Some(root) => require_thread_reader(self.vault(), &txn, room, root, self.actor())?,
            };
        }
        match root {
            None => self.for_room_projection(room),
            Some(root) => self.for_thread_projection(room, root),
        }
    }
}
