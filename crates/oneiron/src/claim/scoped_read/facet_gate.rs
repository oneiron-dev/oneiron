//! A credential narrowed to some facets, and a room with a facet set, limit
//! what this lane reads, by the one rule MCP uses too
//! (`federation::facet_read`). The owner is never limited (owner ruling
//! FACET-READ = A).
use super::ScopedRead;
use crate::EntityId;
use crate::error::Result;
use crate::federation::ScopeAxis;
use crate::federation::facet_read::facets_admit_in;

impl ScopedRead<'_> {
    /// Read inside `room`'s signed facets, as a turn in it does, while
    /// keeping every other term (FIX 643): the read a named-room assembly
    /// outside a turn makes. The owner's key reads past them, as past every
    /// facet.
    #[must_use]
    pub fn within_room_facets(mut self, room: EntityId) -> Self {
        self.actor_key = self.actor_key.within_room_facets(room);
        self
    }

    /// Whether a deleted row's shell may be named to this read: a read limited
    /// to facets names only a shell that still proves a place inside them, and
    /// a dangling reference with no shell proves none (DEC-0005).
    pub(super) fn facets_allow_shell_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        match self.entity_record_in(txn, id)? {
            Some(row) => self.facets_allow_in(txn, id, &row.encode()),
            None => self.facets_allow_raw_in(txn, id, None),
        }
    }

    /// Whether the row `id`, as a snapshot of its own reads it, sits inside
    /// the facets this read is limited to; see [`Self::facets_allow_in`].
    pub(crate) fn facets_allow_id(&self, id: &EntityId) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        self.facets_allow_shell_in(&txn, id)
    }

    /// Whether the stored row `row` of `id` sits outside the facets this read
    /// is limited to: such a row has no name and no count, as one outside
    /// the credential's worlds has none (DEC-0005).
    pub(super) fn outside_credential_facets_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &super::EntityRecord,
    ) -> Result<bool> {
        Ok(!self.facets_allow_in(txn, id, &row.encode())?)
    }

    /// Whether the row `id`, with header and body `raw`, sits inside the
    /// credential's facets and those the room turn this key reads through
    /// holds. The
    /// owner's key reads every facet, and so does a narrower owner credential
    /// while its exemption holds.
    pub(super) fn facets_allow_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        self.facets_allow_raw_in(txn, id, Some(raw))
    }

    /// [`Self::facets_allow_in`] for a row that may not be stored: one that
    /// is not sits in no facet.
    fn facets_allow_raw_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: Option<&[u8]>,
    ) -> Result<bool> {
        let credential = self
            .actor_key
            .authority_scope()
            .map(|scope| &scope.facets)
            .filter(|facets| !matches!(facets, ScopeAxis::All));
        // A turn holds the facets its room had when it opened and meets this
        // snapshot's into them, so it only narrows.
        let room = match &self.actor_key.room_turn {
            Some(turn) => Some(
                turn.terms.meet_facets(
                    &crate::workspace_roster::room_facets_in(self.vault, txn, turn.room)?
                        .unwrap_or(ScopeAxis::All),
                ),
            ),
            None => None,
        }
        .filter(|facets| !matches!(facets, ScopeAxis::All));
        // A named room read outside a turn takes the room's signed facets as
        // this snapshot finds them (FIX 643).
        let named = match self.actor_key.room_facets {
            Some(room) => Some(crate::context_board::room_facets_axis_in(
                self.vault, txn, room,
            )?),
            None => None,
        }
        .filter(|facets| !matches!(facets, ScopeAxis::All));
        if (credential.is_none() && room.is_none() && named.is_none())
            || self.actor_key.facets_owner_exempt_in(self.vault, txn)?
        {
            return Ok(true);
        }
        let Some(raw) = raw else {
            return Ok(false);
        };
        for facets in credential
            .into_iter()
            .chain(room.as_ref())
            .chain(named.as_ref())
        {
            let inside = match self.session_view {
                Some(view) => facets_admit_in(self.vault, view, txn, *id, raw, facets)?,
                None => facets_admit_in(self.vault, &self.vault.store, txn, *id, raw, facets)?,
            };
            if !inside {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
