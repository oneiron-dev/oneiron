//! The audience conjunct of a scoped read: device-local worlds, private
//! threads, an unbound agent's own entry, a room turn's ceiling and the
//! explicit audience and peer reads every admission path applies.

use super::super::access_gate::HeldAuthority;
use super::*;

impl<'v> ScopedRead<'v> {
    /// The audience conjunct every admission path applies, over the current
    /// row. Paths that serve a known revision use [`Self::audience_readable_raw_in`].
    pub(in crate::claim::scoped_read) fn audience_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if self.device_withholds_in(txn, id, None)? {
            return Ok(false);
        }
        if self.actor_key.room_turn.is_none()
            && self.actor_key.worlds.is_none()
            && self.audience.is_none()
            && self.peer_reads.is_empty()
        {
            // An unnarrowed read still meets each private thread's audience,
            // and an unbound agent's its own entry (FIX 5861).
            let Some(record) = self.entity_record_in(txn, id)? else {
                return Ok(true);
            };
            let raw = record.encode();
            return Ok(self.private_threads_readable_in(txn, id, &raw)?
                && self.own_entry_readable_in(txn, id, &raw)?);
        }
        let Some(record) = self.entity_record_in(txn, id)? else {
            return Ok(false);
        };
        self.audience_readable_raw_in(txn, id, &record.encode(), &HeldAuthority::default())
    }

    /// An unbound agent's or the system's read of the revision `raw` of
    /// `id` meets its own entry into each room it is on the roster of, as a
    /// person's own read does: added from now on, it reads nothing from
    /// before its join (FIX 5861). The class is the key's verified one, the
    /// reader the key's own actor, never another member. A read bound to a
    /// room turn, or of any other class, adds nothing here.
    fn own_entry_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let class = self.actor_key.actor_class();
        let unbound_agent = self.actor_key.room_turn.is_none()
            && [crate::EdgeActorClass::Agent, crate::EdgeActorClass::System]
                .into_iter()
                .any(|agent| class == Some(agent.gate_actor_class()));
        let Some(reader) = unbound_agent
            .then(|| EntityId::from_hex(self.actor_key.actor_ref()).ok())
            .flatten()
        else {
            return Ok(true);
        };
        self.audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .own_entry_readable_raw(self.vault, &self.store_read(), txn, *id, raw, reader)
    }

    /// The audience conjunct over the exact revision `raw` being served. A
    /// key that asked for a world set keeps the row inside it. A key bound to
    /// a room turn adds the room's world ceiling, its whole roster as an
    /// audience, P7 under the members' met clearance, and every other member's
    /// own read of that same revision, so the turn reads inside the room's
    /// Scope (ARCH-0067 §8). The roster is
    /// read in this snapshot, so a member who joined after the key was built
    /// binds this row too. Each peer's read shares `authority`'s Grants for
    /// this serving txn (FIX 7462), each reading its own.
    pub(in crate::claim::scoped_read) fn audience_readable_raw_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        if self.device_withholds_in(txn, id, Some(raw))? {
            return Ok(false);
        }
        if !self.private_threads_readable_in(txn, id, raw)?
            || !self.own_entry_readable_in(txn, id, raw)?
        {
            return Ok(false);
        }
        if self.actor_key.room_turn.is_none() && self.actor_key.worlds.is_none() {
            return self.audience_conjunct_in(txn, id, raw, authority);
        }
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let data = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let Some(world) = self.record_world_in(txn, id, header.entity_type, data)? else {
            return Ok(false);
        };
        let record = super::super::actor_key::record_world_scope(world);
        if self
            .actor_key
            .asked_world_ceiling()
            .is_some_and(|ceiling| !record.is_narrowing_of(&ceiling))
        {
            return Ok(false);
        }
        if let Some(turn) = &self.actor_key.room_turn {
            let Some(room) = self.room_ceiling_in(txn, turn)? else {
                return Ok(false);
            };
            // A member's contact clearance holds the row to P7 too: it is
            // positively public or sits under the room's Scope (ILDF2). A
            // personal ceiling's roster stands in each private thread as it
            // is now, a held one's in each turn (FIX 5545, 5636), and a
            // caller with a seat meets the room's windows by its own alone
            // (FIX 5667).
            if !room.admits_world(&record)
                || !room.discloses(self.vault, txn, *id, raw)?
                || !self
                    .audience_cache
                    .lock()
                    .map_err(|_| Error::InvariantViolation("audience cache lock"))?
                    .readable_raw(
                        self.vault,
                        txn,
                        *id,
                        raw,
                        &room.roster,
                        room.personal,
                        room.personal.then_some(room.caller),
                    )?
            {
                return Ok(false);
            }
            // The room reads only what every member may read: a row private
            // to the caller is not the room's. Its peers stand in private
            // threads as its roster does.
            if !self.peers_read_raw_in(txn, &room.peers, id, raw, room.personal, authority)? {
                return Ok(false);
            }
        }
        self.audience_conjunct_in(txn, id, raw, authority)
    }

    /// Whether the caller this read authenticates stands in each private
    /// thread (FIX 2951) the revision `raw` of `id` sits in. No read is
    /// exempt, the owner's and an unbound one included; one that
    /// authenticates no one reads no private thread. Each turn is read under
    /// the CONTENT rule, save by a personal ceiling's peer read
    /// (`room_peer`), which stands in the thread under CURRENT (FIX 5545).
    /// A private thread's notice reads only to its recipient and to readers
    /// of that thread (FIX 6473).
    pub(in crate::claim::scoped_read) fn private_threads_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let viewers: Vec<_> = self.actor_key.authenticated_person().into_iter().collect();
        if !self.thread_notice_readable_in(txn, raw, &viewers)? {
            return Ok(false);
        }
        crate::conversation::private_threads_readable_with_read_in(
            self.vault,
            &self.store_read(),
            txn,
            *id,
            raw,
            &viewers,
            self.room_peer,
        )
    }

    /// [`Self::private_threads_readable_in`] over the row `id` holds in
    /// `txn`, alone: the bound a door serving rows by record scope (the TURN
    /// routes) holds a turn's words to (FIX 5652), asking no grant, facet or
    /// floor of this read. A row with no record has no thread to withhold it.
    pub(crate) fn private_threads_admit_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        match self.entity_record_in(txn, id)? {
            Some(record) => self.private_threads_readable_in(txn, id, &record.encode()),
            None => Ok(true),
        }
    }

    /// Whether this read serves a caller off this device.
    pub(crate) fn off_device(&self) -> bool {
        self.actor_key.off_device()
    }

    /// Whether a device-local world keeps `id` from this read: a caller off
    /// this device reads none of its rows (DEC-0005), neither the revision
    /// `raw` a door serves nor the row as it stands. The worlds are judged in
    /// this snapshot for each machine the key's rows go to, its proof checked
    /// again here (mesh PR2b); only an unproved one is unknown. A row whose
    /// world cannot be read stays here too. The flag set is the vault's, read
    /// on base; the row is judged as this read sees it, so in a room a row
    /// the room stages is judged as well. Such a row carries no record-scope
    /// stamp, and one the judge cannot place is kept.
    pub(in crate::claim::scoped_read) fn device_withholds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: Option<&[u8]>,
    ) -> Result<bool> {
        if !self.actor_key.off_device() {
            return Ok(false);
        }
        let destination = self.actor_key.destination();
        let flagged = crate::settings::device_local_worlds_for(self.vault, txn, destination)?;
        let read = self.store_read();
        let withholds = match raw {
            Some(raw) => {
                crate::settings::device_only_withholds_raw(&read, txn, &flagged, id, Some(raw))
            }
            None => Ok(false),
        };
        match withholds.and_then(|held| {
            if held {
                Ok(true)
            } else {
                crate::settings::device_only_withholds(&read, txn, &flagged, id)
            }
        }) {
            Err(Error::CorruptedIndex(_)) => Ok(true),
            held => held,
        }
    }

    /// The explicit audience this read was opened for, if any. Through a
    /// personal ceiling it stands in each private thread under CURRENT, as
    /// that ceiling's roster does (FIX 5655): a member's own TASK read is
    /// narrowed to a thread's audience now, never to the turns each reads,
    /// and a room the ceiling's caller holds a seat in binds by its window
    /// alone (FIX 5667).
    fn audience_conjunct_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
        authority: &HeldAuthority<'v>,
    ) -> Result<bool> {
        let own = self
            .actor_key
            .room_turn()
            .filter(|turn| turn.personal)
            .map(|turn| turn.caller);
        if let Some(audience) = &self.audience
            && !self
                .audience_cache
                .lock()
                .map_err(|_| Error::InvariantViolation("audience cache lock"))?
                .readable_raw(self.vault, txn, *id, raw, audience, own.is_some(), own)?
        {
            return Ok(false);
        }
        self.peers_read_raw_in(txn, &self.peer_reads, id, raw, false, authority)
    }
}
