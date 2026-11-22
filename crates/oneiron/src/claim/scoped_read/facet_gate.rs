//! A credential narrowed to some facets, and a room with a facet set, limit
//! what this lane reads, by the one rule MCP uses too
//! (`federation::facet_read`). The owner is never limited (owner ruling
//! FACET-READ = A).
use super::access_gate::HeldAuthority;
use super::{ScopedRead, ScopedReadActorKey};
use crate::EntityId;
use crate::error::Result;
use crate::federation::facet_read::{facets_admit_in, placed_facets_admit};
use oneiron_authority::federation::{ScopeAxis, ScopeId};

impl ScopedRead<'_> {
    /// Read inside `room`'s signed facets, as a turn in it does, while
    /// keeping every other term (FIX 643): the read a named-room assembly
    /// outside a turn makes. The owner's key reads past them, as past every
    /// facet. A reader the conversation home binds
    /// ([`ScopedReadActorKey::homed_unnamed`]) reads the room's stamped
    /// claims only if it stands in the room now
    /// ([`ScopedReadActorKey::standing_in_room_in`]); naming a room whose
    /// record it can read but that it is not in lifts no home. A store
    /// failure reading the room finds it standing in none: the home stays.
    #[must_use]
    pub fn within_room_facets(mut self, room: EntityId) -> Self {
        let key = self.actor_key.within_room_facets(room);
        self.actor_key = if key.is_homed_unnamed() {
            match Self::standing_in_room(self.vault, key.clone(), room) {
                Ok(key) => key,
                Err(error) => {
                    tracing::warn!(%error, "room standing unread; the conversation home stays");
                    key
                }
            }
        } else {
            key
        };
        self
    }

    /// `key` marked as standing in `room` in a snapshot of its own
    /// ([`ScopedReadActorKey::standing_in_room_in`]). It takes the vault, not
    /// the read: its caller has moved the key out of the read.
    fn standing_in_room(
        vault: &crate::vault::Vault,
        key: ScopedReadActorKey,
        room: EntityId,
    ) -> Result<ScopedReadActorKey> {
        let txn = vault.store.env.read_txn()?;
        key.standing_in_room_in(vault, &txn, room)
    }

    /// Whether a deleted row's shell may be named to this read: a read limited
    /// to facets names only a shell that still proves a place inside them, and
    /// a dangling reference with no shell proves none (DEC-0005). A row check
    /// of the serving txn `authority` holds takes the owner's exemption
    /// judged once there.
    pub(super) fn facets_allow_shell_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        authority: Option<&HeldAuthority>,
    ) -> Result<bool> {
        match self.entity_record_in(txn, id)? {
            Some(row) => self.facets_allow_raw_in(txn, id, Some(&row.encode()), authority),
            None => self.facets_allow_raw_in(txn, id, None, authority),
        }
    }

    /// Whether the row `id`, as a snapshot of its own reads it, sits inside
    /// the facets this read is limited to; see [`Self::facets_allow_in`].
    pub(crate) fn facets_allow_id(&self, id: &EntityId) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        self.facets_allow_shell_in(&txn, id, None)
    }

    /// Whether the stored row `row` of `id` sits outside the facets this read
    /// is limited to: such a row has no name and no count, as one outside
    /// the credential's worlds has none (DEC-0005).
    pub(super) fn outside_credential_facets_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &super::EntityRecord,
        authority: Option<&HeldAuthority>,
    ) -> Result<bool> {
        Ok(!self.facets_allow_raw_in(txn, id, Some(&row.encode()), authority)?)
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
        self.facets_allow_raw_in(txn, id, Some(raw), None)
    }

    /// [`Self::facets_allow_in`] for a row check of the serving txn
    /// `authority` holds: a narrower owner credential's exemption is judged
    /// once in that txn, not once per row (FIX
    /// FACET-GATE-OWNER-EXEMPTION-PER-ROW).
    pub(super) fn facets_allow_held_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        authority: &HeldAuthority,
    ) -> Result<bool> {
        self.facets_allow_raw_in(txn, id, Some(raw), Some(authority))
    }

    /// [`Self::facets_allow_in`] for a row that may not be stored: one that
    /// is not sits in no facet.
    fn facets_allow_raw_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: Option<&[u8]>,
        authority: Option<&HeldAuthority>,
    ) -> Result<bool> {
        let Some(limits) = self.actor_key.facet_limits_in(self.vault, txn, authority)? else {
            return Ok(true);
        };
        let Some(raw) = raw else {
            return Ok(false);
        };
        for facets in limits.axes() {
            if !self.row_inside_facets_in(txn, id, raw, facets)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Whether the stored row `id`, with header and body `raw`, sits inside
    /// `facets` as this read's store holds it (`facets_admit_in`): a whole
    /// axis holds every row, an empty one none.
    pub(super) fn row_inside_facets_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        facets: &ScopeAxis<ScopeId>,
    ) -> Result<bool> {
        match self.session_view {
            Some(view) => facets_admit_in(self.vault, view, txn, *id, raw, facets),
            None => facets_admit_in(self.vault, &self.vault.store, txn, *id, raw, facets),
        }
    }
}

/// The facets one read is limited to in one snapshot: its credential's, its
/// room turn's and its named room's, each where it names fewer than all.
struct FacetLimits<'k> {
    credential: Option<&'k ScopeAxis<ScopeId>>,
    room: Option<ScopeAxis<ScopeId>>,
    named: Option<ScopeAxis<ScopeId>>,
}

impl FacetLimits<'_> {
    /// Each axis a row must sit inside.
    fn axes(&self) -> impl Iterator<Item = &ScopeAxis<ScopeId>> {
        self.credential
            .into_iter()
            .chain(self.room.as_ref())
            .chain(self.named.as_ref())
    }
}

impl ScopedReadActorKey {
    /// The facets a read under this key is limited to in `txn`, `None` when
    /// it reads every facet: no axis names fewer than all, or the key is the
    /// owner's, or a narrower credential of the owner's while its exemption
    /// holds, judged once in `txn` when `authority` holds it.
    fn facet_limits_in(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        authority: Option<&HeldAuthority>,
    ) -> Result<Option<FacetLimits<'_>>> {
        let credential = self
            .authority_scope()
            .map(|scope| &scope.facets)
            .filter(|facets| !matches!(facets, ScopeAxis::All));
        // A turn holds the facets its room had when it opened and meets this
        // snapshot's into them, so it only narrows.
        let room = match &self.room_turn {
            Some(turn) => Some(
                turn.terms.meet_facets(
                    &crate::workspace_roster::room_facets_in(vault, txn, turn.room)?
                        .unwrap_or(ScopeAxis::All),
                ),
            ),
            None => None,
        }
        .filter(|facets| !matches!(facets, ScopeAxis::All));
        // A named room read outside a turn takes the room's signed facets as
        // this snapshot finds them (FIX 643).
        let named = match self.room_facets {
            Some(room) => Some(crate::context_board::room_facets_axis_in(vault, txn, room)?),
            None => None,
        }
        .filter(|facets| !matches!(facets, ScopeAxis::All));
        if credential.is_none() && room.is_none() && named.is_none() {
            return Ok(None);
        }
        let exempt = match authority {
            Some(authority) => self.facets_owner_exempt_held_in(vault, txn, authority)?,
            None => self.facets_owner_exempt_in(vault, txn)?,
        };
        if exempt {
            return Ok(None);
        }
        Ok(Some(FacetLimits {
            credential,
            room,
            named,
        }))
    }

    /// [`ScopedRead::facets_allow_in`] for a CLAIM whose `FacetOf` targets
    /// are `placed`, as its access class carries them (FIX 11915), in the
    /// serving txn `authority` holds where the caller holds one.
    pub(super) fn facets_allow_placed_in(
        &self,
        vault: &crate::Vault,
        txn: &heed::RoTxn<'_>,
        placed: &[EntityId],
        authority: Option<&HeldAuthority>,
    ) -> Result<bool> {
        let Some(limits) = self.facet_limits_in(vault, txn, authority)? else {
            return Ok(true);
        };
        Ok(limits
            .axes()
            .all(|facets| placed_facets_admit(facets, placed)))
    }
}
