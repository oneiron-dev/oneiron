//! One thread's page of a room's history (FIX 5638): `vault.rooms.messages`
//! naming a thread by its root reads that thread alone, behind its own
//! reader and on its own lane, as `vault.rooms.get` reads it. The vault's
//! Owner or an Admin in a private thread's audience reads it so with no seat
//! in the room; the trunk turn it hangs from, that turn's own chain and every
//! other thread are never its rows. Without a thread the page is the room's
//! own ([`Memory::rooms_messages_page`]).

use super::*;

/// One page of a room's turns, or of one thread of it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoomMessagesRequest {
    pub room_ref: String,
    /// The `next_after` of the page before.
    #[serde(default)]
    pub after: Option<String>,
    /// Rows per page, 1 to 256; 256 when unset.
    #[serde(default)]
    pub limit: Option<usize>,
    /// A thread of the room, by its root turn; `None` reads the room itself.
    #[serde(default)]
    pub thread_ref: Option<String>,
}

impl Memory<'_> {
    /// `vault.rooms.messages`: one page of the turns of the room this reader
    /// may read ([`Self::rooms_messages_page`]), or with `thread_ref` of that
    /// one thread ([`Self::thread_messages_page`]).
    pub fn rooms_messages_selected(&self, request: &RoomMessagesRequest) -> MemoryResult<RoomPage> {
        let room = EntityId::from_hex(&request.room_ref)?;
        let after = request
            .after
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let limit = request.limit.unwrap_or(PAGE_LIMIT);
        match request.thread_ref.as_deref() {
            None => self.rooms_messages_page(room, after, limit),
            Some(root) => self.thread_messages_page(room, EntityId::from_hex(root)?, after, limit),
        }
    }

    /// One page of the thread rooted at `root` in `room`: behind that
    /// thread's own reader ([`require_thread_reader`]), from its snapshot
    /// ([`Self::thread_turn_snapshot`]), inside the Scope its ceiling puts on
    /// this reader now. Only a turn of that thread this reader reads fills a
    /// slot or is the cursor: the trunk turn it hangs from, that turn's own
    /// chain and a turn held back from the reader (FIX 5545) never are, and
    /// a cursor must be one of them. The whole thread is read, however long
    /// (rule 5).
    fn thread_messages_page(
        &self,
        room: EntityId,
        root: EntityId,
        after: Option<EntityId>,
        limit: usize,
    ) -> MemoryResult<RoomPage> {
        if limit == 0 || limit > PAGE_LIMIT {
            return Err(MemoryError::from(invalid()));
        }
        {
            let txn = self.vault().store.env.read_txn().map_err(Error::from)?;
            require_thread_reader(self.vault(), &txn, room, root, self.actor())?;
        }
        let scope = self.thread_ceiling(room, root)?.terms.get().room_scope();
        let reach = self.thread_turn_snapshot(room, root)?;
        let roots = super::liveness::thread_root_map(reach.placed())?;
        let mut rows: Vec<RoomTurn> = reach
            .into_read()
            .into_iter()
            .filter(|turn| {
                EntityId::from_hex(&turn.turn_id).is_ok_and(|id| roots.get(&id) == Some(&root))
            })
            .collect();
        if let Some(after) = after {
            let cursor = after.to_hex();
            let at = rows
                .iter()
                .position(|turn| turn.turn_id == cursor)
                .ok_or_else(invalid)?;
            rows.drain(..=at);
        }
        let next_after = (rows.len() > limit).then(|| rows[limit - 1].turn_id.clone());
        rows.truncate(limit);
        Ok(RoomPage {
            rows,
            next_after,
            scope,
        })
    }
}
