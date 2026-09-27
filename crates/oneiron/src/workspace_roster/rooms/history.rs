//! Bounded room-local history and transactional auxiliary-row cleanup.
use super::*;
use crate::federation::Scope;
use crate::store::Store;
use std::ops::Bound;

const HISTORY: &[u8] = b"rooms.history.v1/";
const HEADS: &[u8] = b"rooms.heads.v1/";
const RESPONSE: &[u8] = b"rooms.response.v1/";
const PAGE_LIMIT: usize = 256;

/// TURN records carry their ordinary stored six-axis scope. Scope admission
/// augments, rather than replaces, the existing room membership checks.
pub(super) fn turn_admitted(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    scope: &Scope,
) -> Result<bool> {
    let raw = vault
        .store
        .entities
        .get(txn, turn.as_bytes())?
        .ok_or(Error::CorruptedIndex("room turn missing"))?;
    let record = crate::federation::record_scope::scope_for_blob(&vault.store, txn, turn, &raw)?
        .ok_or(Error::CorruptedIndex("room turn scope stamp"))?;
    Ok(scope.admits("read", &record, &Scope::top()))
}

fn ordered_key(prefix: &[u8], room: EntityId, at: u64, turn: EntityId) -> Vec<u8> {
    [
        prefix,
        room.as_bytes(),
        at.to_be_bytes().as_slice(),
        turn.as_bytes(),
    ]
    .concat()
}
pub(super) fn index_turn(store: &Store, txn: &mut heed::RwTxn<'_>, turn: &RoomTurn) -> Result<()> {
    let room = EntityId::from_hex(&turn.room_id)?;
    let id = EntityId::from_hex(&turn.turn_id)?;
    store
        .vault_meta
        .put(txn, &ordered_key(HISTORY, room, turn.at, id), id.as_bytes())?;
    if turn.thread_of.is_none() {
        store
            .vault_meta
            .put(txn, &ordered_key(HEADS, room, turn.at, id), id.as_bytes())?;
    }
    Ok(())
}
fn stored_id(raw: &[u8]) -> Result<EntityId> {
    EntityId::from_bytes(
        raw.try_into()
            .map_err(|_| Error::CorruptedIndex("room history id"))?,
    )
}
pub(in crate::workspace_roster) fn delete_room_metadata(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<()> {
    let prefix = key(HISTORY, room);
    loop {
        let page = store
            .vault_meta
            .prefix_iter(txn, &prefix)?
            .take(PAGE_LIMIT)
            .map(|r| r.map(|(k, v)| (k.to_vec(), v.to_vec())))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if page.is_empty() {
            break;
        }
        for (row_key, raw) in page {
            let turn = stored_id(&raw)?;
            for prefix in [TURNS, CLAIMS, RESPONSE] {
                store.vault_meta.delete(txn, &key(prefix, turn))?;
            }
            store.vault_meta.delete(txn, &row_key)?;
        }
    }
    for prefix in [HEADS, HANDLES] {
        loop {
            let keys = store
                .vault_meta
                .prefix_iter(txn, &key(prefix, room))?
                .take(PAGE_LIMIT)
                .map(|r| r.map(|(k, _)| k.to_vec()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if keys.is_empty() {
                break;
            }
            for key in keys {
                store.vault_meta.delete(txn, &key)?;
            }
        }
    }
    Ok(())
}
impl Memory<'_> {
    /// First bounded page in chronological order. Continue with the last turn's
    /// id through `rooms_messages_page`; room membership is rechecked per page.
    pub fn rooms_messages(&self, room: EntityId) -> MemoryResult<Vec<RoomTurn>> {
        Ok(self.rooms_messages_page(room, None, PAGE_LIMIT)?.rows)
    }
    pub fn rooms_messages_page(
        &self,
        room: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<RoomPage> {
        if limit == 0 || limit > PAGE_LIMIT {
            return Err(MemoryError::from(invalid()));
        }
        let applied_scope = self.room_turn_read_scope(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        let start = if let Some(after) = after {
            let turn = turn_in(self.vault(), &txn, after)?;
            if turn.room_id != room.to_hex() {
                return Err(MemoryError::from(invalid()));
            }
            ordered_key(HISTORY, room, turn.at, after)
        } else {
            key(HISTORY, room)
        };
        let end = [key(HISTORY, room).as_slice(), &[u8::MAX; 24]].concat();
        // A room TURN is an ordinary base-world record. Bottom and world-only
        // scopes cannot see its history, even though membership still holds.
        if applied_scope.as_ref().is_some_and(|scope| {
            !scope
                .worlds
                .contains(&crate::federation::ScopeId(crate::claim::base_world_id()))
        }) {
            return Ok(RoomPage {
                rows: Vec::new(),
                next_after: None,
                applied_scope,
            });
        }
        let mut rows = self
            .vault()
            .store
            .vault_meta
            .range(
                &txn,
                &(
                    Bound::Excluded(start.as_slice()),
                    Bound::Included(end.as_slice()),
                ),
            )?
            .take(limit + 1)
            .map(|row| {
                let (_, raw) = row?;
                let id = stored_id(&raw)?;
                if let Some(scope) = &applied_scope
                    && !turn_admitted(self.vault(), &txn, id, scope)?
                {
                    return Err(MemoryError::from(Error::InvalidConfig(
                        "room turn is outside the bound scope".into(),
                    )));
                }
                Ok(turn_in(self.vault(), &txn, id)?)
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_after = if has_more {
            rows.last().map(|turn| turn.turn_id.clone())
        } else {
            None
        };
        Ok(RoomPage {
            rows,
            next_after,
            applied_scope,
        })
    }
    /// Canonical HEAD is a room-local indexed read; branch turns are excluded.
    pub fn room_head(&self, room: EntityId) -> MemoryResult<Option<RoomTurn>> {
        let scope = self.room_turn_read_scope(room)?;
        let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
        require_member(self.vault(), &txn, room, self.actor())?;
        if scope.as_ref().is_some_and(|scope| {
            !scope
                .worlds
                .contains(&crate::federation::ScopeId(crate::claim::base_world_id()))
        }) {
            return Ok(None);
        }
        let start = key(HEADS, room);
        let end = [start.as_slice(), &[u8::MAX; 24]].concat();
        self.vault()
            .store
            .vault_meta
            .rev_range(
                &txn,
                &(
                    Bound::Included(start.as_slice()),
                    Bound::Included(end.as_slice()),
                ),
            )?
            .next()
            .map(|row| {
                let (_, raw) = row?;
                let id = stored_id(&raw)?;
                if let Some(scope) = &scope
                    && !turn_admitted(self.vault(), &txn, id, scope)?
                {
                    return Err(MemoryError::from(Error::InvalidConfig(
                        "room head is outside the bound scope".into(),
                    )));
                }
                Ok(turn_in(self.vault(), &txn, id)?)
            })
            .transpose()
    }
}
