use super::*;

impl crate::vault::Vault {
    #[must_use]
    pub fn scoped_read(&self, actor_key: ScopedReadActorKey) -> ScopedRead<'_> {
        ScopedRead {
            vault: self,
            actor_key,
            audience: None,
            peer_reads: Vec::new(),
            audience_cache: Mutex::new(Default::default()),
            room_ceiling: Mutex::new(None),
            room_ceilings_built: AtomicUsize::new(0),
            session_view: None,
            claim_status: ClaimReadStatus::Surfaceable,
            recall_authority: Mutex::new(None),
            room_peer: false,
        }
    }

    /// A scoped read composed over a live session's overlay: the same
    /// admission and policy gates, applied to the union the room can see.
    ///
    /// `Vault::scoped_read` on the canonical handle keeps seeing base only.
    #[allow(
        dead_code,
        reason = "ONE-1728 arms it through the branch-store oracle's ScopedRead sweep; the \
                  lib-target caller arrives with ONE-1729's session executor binding"
    )]
    pub(crate) fn scoped_read_in_session<'a>(
        &'a self,
        actor_key: ScopedReadActorKey,
        view: &'a crate::store::SessionStoreView<'a>,
    ) -> ScopedRead<'a> {
        // Every row the room staged carries the position its write staged
        // beside it (`record_scope::stage_session_position`), and a missing
        // one is not inferred (WILL L11-01). A credential that reads only
        // some worlds reads the room's rows while the room placed each of
        // them itself; a room that restages or hides a base row, or holds a
        // row it could not place, keeps it on base alone: the room's rows
        // have no name and no count for it (DEC-0005).
        let placed = !actor_key.has_world_ceiling()
            || crate::federation::record_scope::room_rows_placed(view);
        let session_view = placed.then_some(view);
        ScopedRead {
            vault: self,
            actor_key,
            audience: None,
            peer_reads: Vec::new(),
            audience_cache: Mutex::new(Default::default()),
            room_ceiling: Mutex::new(None),
            room_ceilings_built: AtomicUsize::new(0),
            session_view,
            claim_status: ClaimReadStatus::Surfaceable,
            recall_authority: Mutex::new(None),
            room_peer: false,
        }
    }
}

impl<'a> ScopedRead<'a> {
    /// Conjoin every read with the all-of-audience rule. An explicit empty
    /// audience refuses audience-scoped records rather than widening to speaker-only reads.
    #[must_use]
    pub fn for_audience(mut self, audience: &[EntityId]) -> Self {
        let mut ids = audience.to_vec();
        ids.sort_unstable();
        ids.dedup();
        self.audience = Some(ids);
        self
    }

    /// Conjoin every read with each of `peers`' own read of the same
    /// revision: a row this read serves must be one every peer may read too.
    /// A room assembly passes the read keys of the vault's own agents, whose
    /// own grants bound what the room reads where no clearance does
    /// (ARCH-0067 §8).
    #[must_use]
    pub fn with_peer_reads(mut self, peers: Vec<ScopedReadActorKey>) -> Self {
        self.peer_reads = peers;
        self
    }

    /// Read only rows in `worlds`, each where `record_world_in` places it: a
    /// claim by its own world, a TASK and its facts by their birth, any
    /// other record as base reality. The ceiling rides the key, so a lane built
    /// from it keeps it too, and it meets any ceiling the key already holds.
    /// A room assembly passes the room's world set (ARCH-0067 §8).
    #[must_use]
    pub fn within_worlds(mut self, worlds: crate::pipeline::WorldAuthoritySet) -> Self {
        self.actor_key = self.actor_key.within_worlds(worlds);
        self
    }

    /// A channel-aware door names its destination; the proof still decides whether it is allowed.
    pub(crate) fn through_channel(mut self, channel: &str) -> Self {
        self.actor_key.channel = Some(channel.to_owned());
        self
    }

    /// Whether this read is the vault owner's own key
    /// (`ScopedReadActorKey::reads_as_vault_owner`) with no world ceiling,
    /// audience or peer read narrowing what it serves. Such a read admits
    /// every row but a claim private to another principal; no read admits
    /// every row, so none may count the vault's rows.
    #[must_use]
    pub fn is_unnarrowed_owner(&self) -> bool {
        self.actor_key.reads_as_vault_owner()
            && self.actor_key.worlds.is_none()
            && self.audience.is_none()
            && self.peer_reads.is_empty()
    }

    /// Number of immutable room ledger snapshots loaded by this read handle.
    pub fn audience_ledger_reads(&self) -> Result<usize> {
        Ok(self
            .audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .ledger_reads())
    }

    /// Number of room ceilings this read handle rebuilt from a serving
    /// snapshot because the room held someone its ceiling did not bind.
    #[cfg(test)]
    pub(crate) fn room_ceilings_built(&self) -> usize {
        self.room_ceilings_built
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The audience conjunct every admission path applies, over the current
    /// row. Paths that serve a known revision use [`Self::audience_readable_raw_in`].
    pub(super) fn audience_readable_in(
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
        self.audience_readable_raw_in(txn, id, &record.encode())
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
            .own_entry_readable_raw(self.vault, txn, *id, raw, reader)
    }

    /// The audience conjunct over the exact revision `raw` being served. A
    /// key that asked for a world set keeps the row inside it. A key bound to
    /// a room turn adds the room's world ceiling, its whole roster as an
    /// audience, P7 under the members' met clearance, and every other member's
    /// own read of that same revision, so the turn reads inside the room's
    /// Scope (ARCH-0067 §8). The roster is
    /// read in this snapshot, so a member who joined after the key was built
    /// binds this row too.
    pub(super) fn audience_readable_raw_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
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
            return self.audience_conjunct_in(txn, id, raw);
        }
        let header =
            EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
        let data = raw.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default();
        let Some(world) = self.record_world_in(txn, id, header.entity_type, data)? else {
            return Ok(false);
        };
        let record = super::actor_key::record_world_scope(world);
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
            if !self.peers_read_raw_in(txn, &room.peers, id, raw, room.personal)? {
                return Ok(false);
            }
        }
        self.audience_conjunct_in(txn, id, raw)
    }

    /// Whether the caller this read authenticates stands in each private
    /// thread (FIX 2951) the revision `raw` of `id` sits in. No read is
    /// exempt, the owner's and an unbound one included; one that
    /// authenticates no one reads no private thread. Each turn is read under
    /// the CONTENT rule, save by a personal ceiling's peer read
    /// (`room_peer`), which stands in the thread under CURRENT (FIX 5545).
    fn private_threads_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let viewers: Vec<_> = self.actor_key.authenticated_person().into_iter().collect();
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
    pub(super) fn device_withholds_in(
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

    /// Whether each of `peers` reads the revision `raw` too, under this
    /// read's claim-status contract; each as a personal ceiling's peer
    /// (`room_peer`) when `room_peer`.
    fn peers_read_raw_in(
        &self,
        txn: &heed::RoTxn<'_>,
        peers: &[ScopedReadActorKey],
        id: &EntityId,
        raw: &[u8],
        room_peer: bool,
    ) -> Result<bool> {
        for peer in peers {
            let mut peer = self
                .vault
                .scoped_read(peer.clone())
                .with_claim_status(self.claim_status);
            peer.room_peer = room_peer;
            // A member read as the owner must still be the owner in this
            // snapshot; one whose standing lapsed keeps the row out.
            match peer.owner_live_in(txn) {
                Ok(()) => {}
                Err(Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(_))) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
            let policy = peer.policy_manifest_in(txn)?;
            let filter = crate::gate::narrow_retrieval_filter(
                &policy.retrieval_floor_for_actor(Some(&peer.actor_key)),
                None,
            )?;
            if !peer.is_entity_raw_readable_with_filter_in(txn, &policy, id, raw, &filter)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The ceiling `turn` puts on a row `txn` serves; `None` once the caller
    /// is off the room's roster here. The roster is read in this snapshot,
    /// and with it the room's live speakers (FIX 1388/1389), whose incomplete
    /// call holds the read before any held ceiling serves it. While everyone
    /// on the roster and every live entry already binds the ceiling this read
    /// holds, only clearances can have narrowed, so this snapshot's clearance
    /// meets into the turn. A member or entry it does not bind yet rebuilds
    /// the room from this snapshot and conjoins it. Either way a refresh
    /// narrows the turn, for this read and every later one, and never widens
    /// it. A thread's ceiling (`turn.branch`) re-proves standing on that
    /// thread instead, which its Ready receipt gives an agent off the room
    /// (OF-529), and takes no live entry. A refresh keeps the ceiling
    /// personal or held as `turn` is ([`RoomTurnCeiling::narrowed_by`]).
    fn room_ceiling_in(
        &self,
        txn: &heed::RoTxn<'_>,
        turn: &RoomTurnCeiling,
    ) -> Result<Option<Arc<RoomTurnCeiling>>> {
        let Some(roster) = crate::context_board::room_roster_in(self.vault, txn, turn.room)? else {
            return Ok(None);
        };
        let reads = match turn.branch {
            Some(thread) => crate::context_board::thread_reader_in(
                self.vault,
                txn,
                turn.room,
                thread,
                &roster,
                turn.caller,
            )?,
            None => crate::context_board::room_reader_in(
                self.vault,
                txn,
                turn.room,
                &roster,
                turn.caller,
            )?,
        };
        if !reads {
            return Ok(None);
        }
        // A private thread's ceiling binds its audience alone (FIX 2951).
        let roster = match turn.branch {
            Some(thread) => crate::workspace_roster::thread_members_in(
                self.vault, txn, turn.room, thread, &roster,
            )?,
            None => roster,
        };
        let live = match turn.branch {
            Some(_) => None,
            None => Some(self.vault.room_live_speaker_entries_in(txn, turn.room)?),
        };
        let mut held = self
            .room_ceiling
            .lock()
            .map_err(|_| Error::InvariantViolation("room ceiling lock"))?;
        let current = held.get_or_insert_with(|| Arc::new(turn.clone()));
        if current.binds_all(&roster)
            && live
                .as_ref()
                .is_none_or(|live| current.binds_all(live.entry_refs()))
        {
            if current.terms.p7() {
                // The members' clearance alone: an entry ref is no member.
                let clearance = crate::context_board::room_clearance_in(self.vault, txn, &roster)?;
                current.terms.meet_clearance(clearance.as_ref());
                if let Some(live) = &live {
                    let unknown = self.vault.live_speaker_clearance_in(txn, live)?;
                    current.terms.meet_clearance(unknown.as_ref());
                }
            }
            return Ok(Some(Arc::clone(current)));
        }
        let now = match turn.branch {
            Some(thread) => crate::context_board::thread_ceiling_in(
                self.vault,
                txn,
                turn.room,
                thread,
                turn.caller,
            )?,
            None => crate::context_board::room_ceiling_in(self.vault, txn, turn.room, turn.caller)?,
        };
        let Some(now) = now else {
            return Ok(None);
        };
        self.room_ceilings_built
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        *current = Arc::new(current.narrowed_by(&now));
        Ok(Some(Arc::clone(current)))
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
        self.peers_read_raw_in(txn, &self.peer_reads, id, raw, false)
    }

    /// Whether membership may stand in for this read's own grant on `id`,
    /// in `txn`: the credential presented narrows no read axis (worlds,
    /// facets, entity types, audience, sensitivity), no records or channel
    /// caveat leaves `id` out, and this caller's locality reads it.
    /// Membership replaces an actor's grant on its room; it never widens the
    /// credential it was presented with, so a narrowed one needs a grant.
    pub(crate) fn reaches_by_membership_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let reads_every_row = self.actor_key.authority_scope().is_none_or(|scope| {
            crate::federation::Scope {
                verbs: crate::federation::ScopeAxis::All,
                ..scope.clone()
            } == crate::federation::Scope::top()
        });
        Ok(reads_every_row
            && self.credential_allows_id(id)
            && !self.device_withholds_in(txn, id, None)?)
    }

    pub(super) fn credential_allows_id(&self, id: &EntityId) -> bool {
        self.actor_key.proof.as_ref().is_none_or(|proof| {
            let claims = proof.claims();
            // Generic records have no proved channel context. Channel-bound
            // credentials must use their typed adapter instead of losing a caveat.
            (claims.channels.is_empty()
                || self
                    .actor_key
                    .channel
                    .as_ref()
                    .is_some_and(|channel| claims.channels.contains(channel)))
                && (claims.records.is_empty() || claims.records.contains(&id.to_hex()))
        })
    }

    /// The owner key's binding, re-verified in this read's own snapshot, so a
    /// key minted before a revocation resolves no plan after it. A host
    /// action's key also proves its root and owner again (FIX 2222): the
    /// embedded owner skips the binding below, and a live root alone does not
    /// show it still binds that owner.
    pub(super) fn owner_live_in(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        if let Some(action) = self.actor_key.host_action_guard() {
            action.holds_in(self.vault, txn)?;
        }
        // A key held to a request's owner proof (WILL-PLAN L13 row 01) proves
        // that proof again here, as an owner act does in its transaction. The
        // proof was built only for this vault's recorded, live owner, so its
        // revalidation stands in for the binding check below.
        if let Some(owner) = self.actor_key.owner_proof_guard() {
            return owner_proof_holds_in(self.vault, txn, owner).map_err(|error| {
                Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(Box::new(
                    crate::memory::MemoryError::from(error),
                )))
            });
        }
        let Some(owner) = self.actor_key.vault_owner_ref() else {
            return Ok(());
        };
        let human = crate::edge::EdgeActorClass::Human;
        crate::memory::verify_actor_binding_in_txn(self.vault, txn, owner, human)
            .and_then(|()| {
                if crate::vault::embedded_owner_actor_id().ok() == Some(owner) {
                    Ok(())
                } else {
                    crate::memory::verify_owner_actor_binding_in_txn(self.vault, txn, owner)
                }
            })
            .map_err(|error| {
                Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(Box::new(
                    error,
                )))
            })
    }

    pub(crate) fn proof_live_in(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        // A host action's key reads nothing once its root, its owner binding
        // or its owner lapses, whichever door asks (FIX 2222).
        if let Some(action) = self.actor_key.host_action_guard() {
            match action.holds_in(self.vault, txn) {
                Ok(()) => {}
                Err(error) if crate::authority::host_action_refused(&error) => return Ok(false),
                Err(error) => return Err(error),
            }
        }
        // A key held to a request's owner proof reads nothing once that
        // proof no longer holds in this snapshot (WILL-PLAN L13 row 01).
        if let Some(owner) = self.actor_key.owner_proof_guard() {
            match owner_proof_holds_in(self.vault, txn, owner) {
                Ok(()) => {}
                Err(Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(_))) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
        }
        let Some(proof) = &self.actor_key.proof else {
            return Ok(true);
        };
        let claims = proof.claims();
        let now = self.vault.instant_in_txn(txn)?.secs();
        if now < claims.issued_at || now >= claims.expires_at {
            return Ok(false);
        }
        // The shared view of this snapshot's fold: a copy of the fold costs
        // as much as the vault has agents, and this runs once per candidate.
        let fold = self.vault.authority_view_readonly_in_txn(txn)?;
        if fold.vault_id != Some(claims.vault_id) {
            return Ok(false);
        }
        // A support slip (OF-606) also reads only while its delegation's
        // wall deadline, holder and key still stand.
        Ok(fold.slip_is_live(&claims.slip_id)
            && self.vault.support_delegation_stands_in_txn(txn, claims)?)
    }

    /// Whether `judge` holds for this read and for each peer it conjoins
    /// ([`Self::with_peer_reads`]), each lane judged as itself in `txn`. A
    /// peer read as the owner that is no longer the owner there fails, as it
    /// keeps every row out of a point read.
    pub(crate) fn every_lane_in(
        &self,
        txn: &heed::RoTxn<'_>,
        mut judge: impl FnMut(&ScopedRead<'a>) -> Result<bool>,
    ) -> Result<bool> {
        if !judge(self)? {
            return Ok(false);
        }
        for peer in &self.peer_reads {
            let peer = self.vault.scoped_read(peer.clone());
            match peer.owner_live_in(txn) {
                Ok(()) => {}
                Err(Error::Claim(crate::error::ClaimError::ScopedReadOwnerNotLive(_))) => {
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
            if !judge(&peer)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[must_use]
    pub fn vault(&self) -> &'a crate::Vault {
        self.vault
    }

    /// Whether this read sees a room's rows: false outside a room, and for
    /// a credential that reads base alone in one.
    pub(crate) fn reads_room(&self) -> bool {
        self.session_view.is_some()
    }

    /// The content this read sees: its room's overlay ∪ base, or base alone.
    /// A reader handed it reads what this read admits from, with no code of
    /// its own for the room.
    pub(crate) fn store_read(&self) -> crate::store::StoreRead<'a> {
        match self.session_view {
            Some(view) => view.read(),
            None => self.vault.store.read(),
        }
    }

    /// Both canonical and session reads use the same ports. A session adapter
    /// composes overlay union base without changing policy admission. An LFS
    /// chunk no published object holds yet is no record a scoped read finds.
    pub(super) fn entity_record_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityRecord>> {
        let record = match self.session_view {
            Some(view) => view.port_entity_record(txn, id)?,
            None => self.vault.port_entity_record(txn, id)?,
        };
        match record {
            Some(row)
                if crate::origin::lfs::unpublished_lfs_chunk_in_txn(
                    &self.vault.store,
                    txn,
                    id,
                    row.entity_type,
                )? =>
            {
                Ok(None)
            }
            record => Ok(record),
        }
    }

    pub(super) fn out_edges_in<'t>(
        &self,
        txn: &'t heed::RoTxn<'_>,
        id: &EntityId,
        kind: Option<EdgeKind>,
    ) -> Result<PortRows<'t, EdgeInfo>> {
        match self.session_view {
            Some(view) => view.port_edges(txn, id, EdgeDirection::Out, kind, None),
            None => self
                .vault
                .port_edges(txn, id, EdgeDirection::Out, kind, None),
        }
    }

    #[must_use]
    pub fn actor_key(&self) -> &ScopedReadActorKey {
        &self.actor_key
    }
}

// One-snapshot scoped row projection: value and receipt contribution together.

/// An unforgeable, run-local candidate view. Only a verified `ScopedRead`
/// builds it under the pipeline's current read transaction. It is never a
/// persisted grant or a caller-supplied list of bare IDs.
pub(crate) struct ScopedDiaryCandidates(HashSet<EntityId>);
impl ScopedDiaryCandidates {
    pub(super) fn from_admission(ids: HashSet<EntityId>) -> Self {
        Self(ids)
    }
    pub(crate) fn contains(&self, id: &EntityId) -> bool {
        self.0.contains(id)
    }
}

/// A private denial and a missing row share the same observable outcome.
/// Only ordinary policy-denied rows may contribute a receipt count/hint.
pub(crate) enum ReadAdmission<T> {
    Visible(T),
    Suppressed,
    OpaqueAbsent,
}
impl<T> ReadAdmission<T> {
    pub(crate) fn into_option(self) -> Option<T> {
        match self {
            Self::Visible(value) => Some(value),
            Self::Suppressed | Self::OpaqueAbsent => None,
        }
    }
    pub(crate) fn suppression(&self) -> usize {
        usize::from(matches!(self, Self::Suppressed))
    }
    pub(crate) fn visible(&self) -> bool {
        matches!(self, Self::Visible(_))
    }
}

impl ScopedRead<'_> {
    /// Resolve value and denial metadata in the SAME transaction. A caller
    /// never tests stored existence separately after this projection.
    pub(super) fn admit_in<T>(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        read: impl FnOnce() -> Result<Option<T>>,
    ) -> Result<ReadAdmission<T>> {
        if let Some(value) = read()? {
            return Ok(ReadAdmission::Visible(value));
        }
        let Some(row) = self.entity_record_in(txn, id)? else {
            return Ok(ReadAdmission::OpaqueAbsent);
        };
        // Inside a room turn a withheld row may be another room's or a peer's
        // private one; its count would say it exists, so it reads as absent.
        // A row outside the worlds the read asked for is not withheld by
        // policy; scope honesty names its world instead. A row in a world the
        // credential cannot read, or one a device-local world keeps from a
        // caller off this device, has no name and no count (DEC-0005), and
        // neither has a TASK outside the credential's worlds or facets, nor
        // any row outside the facets it is limited to.
        if self.actor_key.room_turn.is_none()
            && !self.outside_asked_worlds_in(txn, id, &row)?
            && !self.outside_credential_worlds_in(txn, id, &row)?
            && !self.device_withholds_in(txn, id, None)?
            && !self.outside_credential_task_position_in(txn, id, &row)?
            && !self.outside_credential_facets_in(txn, id, &row)?
            && crate::note::countable_read_suppression(row.entity_type, &row.body)
        {
            Ok(ReadAdmission::Suppressed)
        } else {
            Ok(ReadAdmission::OpaqueAbsent)
        }
    }

    /// Whether this read's credential is live in `txn` and the worlds the
    /// read asked for and its Scope both admit `world` (`None` is base
    /// reality): the world ceilings every row it serves lies under, before
    /// any manifest's say.
    pub(crate) fn world_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        world: Option<EntityId>,
    ) -> Result<bool> {
        let record = super::actor_key::record_world_scope(world);
        if !record.is_narrowing_of(&self.actor_key.world_ceiling()) {
            return Ok(false);
        }
        self.proof_live_in(txn)
    }

    fn outside_asked_worlds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        let Some(ceiling) = self.actor_key.asked_world_ceiling() else {
            return Ok(false);
        };
        Ok(self
            .record_world_in(txn, id, row.entity_type, &row.body)?
            .is_none_or(|world| {
                !super::actor_key::record_world_scope(world).is_narrowing_of(&ceiling)
            }))
    }

    /// Whether `row` of `id` is a TASK, or one of its authority facts, whose
    /// birth stamp sits outside the worlds the read's verified credential
    /// grants (ARCH-0067 §5, DEC-0005). One that cannot prove its position
    /// counts as outside. Its facets are judged by the lane's one facet rule
    /// (`outside_credential_facets_in`), owner exemption included, never
    /// here.
    fn outside_credential_task_position_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        use crate::federation::record_scope::task_inside_credential;
        let Some(granted) = self.actor_key.authority_scope() else {
            return Ok(false);
        };
        if row.entity_type != crate::registry::ENTITY_TYPE_TASK {
            return Ok(false);
        }
        let worlds_only = super::actor_key::world_only(granted.worlds.clone());
        let raw = row.encode();
        let inside = match self.session_view {
            Some(view) => task_inside_credential(view, txn, *id, &raw, &worlds_only)?,
            None => task_inside_credential(&self.vault.store, txn, *id, &raw, &worlds_only)?,
        };
        Ok(!inside)
    }

    /// The world the stored row `id` sits in, read in `txn` over this read's
    /// own store (`record_scope::record_world_in`). `None` where the row
    /// cannot prove one.
    fn record_world_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        kind: u8,
        data: &[u8],
    ) -> Result<Option<Option<EntityId>>> {
        use crate::federation::record_scope::record_world_in;
        match self.session_view {
            Some(view) => record_world_in(view, txn, *id, kind, data),
            None => record_world_in(&self.vault.store, txn, *id, kind, data),
        }
    }

    /// Whether the stored row `row` of `id` sits wholly outside the worlds
    /// the read's verified credential grants: a claim at the position the
    /// read door selects it; any other record where `record_world_in` places
    /// it. A claim with no such position is judged by the other axes; a TASK
    /// or epoch SUMMARY that cannot prove its world is outside.
    fn outside_credential_worlds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        let Some(granted) = self.actor_key.authority_scope() else {
            return Ok(false);
        };
        if matches!(granted.worlds, crate::federation::ScopeAxis::All) {
            return Ok(false);
        }
        // A TASK and its authority facts, and an epoch SUMMARY, sit at their
        // birth. Every other record that is not a claim is base reality,
        // stamped or not: a row
        // replayed with no stamp is no less outside a credential that cannot
        // read base (Astra #1388b P2).
        if row.entity_type != ENTITY_TYPE_CLAIM {
            let ceiling = super::actor_key::world_only(granted.worlds.clone());
            return Ok(self
                .record_world_in(txn, id, row.entity_type, &row.body)?
                .is_none_or(|world| {
                    !super::actor_key::record_world_scope(world).is_narrowing_of(&ceiling)
                }));
        }
        // A claim with no decodable world names none, as a read that asked
        // for worlds judges it.
        if crate::claim::decode_claim_body(&row.body, true).is_err() {
            return Ok(true);
        }
        // A room's own claim sits at the position its write staged beside
        // it (WILL L11-01); every other claim at base's.
        let record = match self.session_view {
            Some(view) if view.read().room_holds(id)? => {
                crate::federation::record_scope::disclosure_scope_for_stored_row(
                    view,
                    txn,
                    *id,
                    row.entity_type,
                    &row.body,
                )?
            }
            _ => crate::federation::record_scope::disclosure_scope_for_stored_row(
                &self.vault.store,
                txn,
                *id,
                row.entity_type,
                &row.body,
            )?,
        };
        Ok(record.is_some_and(|record| record.worlds.meet(&granted.worlds).is_bottom()))
    }

    pub(super) fn admit_entity_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &crate::gate::PolicyManifestResolution,
        filter: &crate::gate::ResolvedRetrievalFilter,
        id: &EntityId,
    ) -> Result<ReadAdmission<()>> {
        self.admit_in(txn, id, || {
            self.is_entity_retrievable_with_policy_in(txn, policy, filter, id)
                .map(|allowed| allowed.then_some(()))
        })
    }
}

/// A request's owner proof, revalidated in `txn` the way an owner act
/// revalidates it in its own transaction (WILL-PLAN L13 row 01).
fn owner_proof_holds_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    owner: &crate::consent::AuthenticatedOwner,
) -> Result<()> {
    owner.revalidate_in_txn(vault, txn).map(drop)
}
