use super::*;

mod audience;
mod room_ceiling;

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
            own_owner_authority: false,
            records_cover: Default::default(),
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
            own_owner_authority: false,
            records_cover: Default::default(),
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
            self.credential_channel_allows(claims)
                && (claims.records.is_empty() || claims.records.contains(&id.to_hex()))
        })
    }

    /// The credential's channel caveat, apart from its records caveat
    /// (FIX 8245 judges the two apart). Generic records have no proved
    /// channel context. Channel-bound credentials must use their typed
    /// adapter instead of losing a caveat.
    pub(super) fn credential_channel_allows(&self, claims: &crate::authority::SlipClaims) -> bool {
        claims.channels.is_empty()
            || self
                .actor_key
                .channel
                .as_ref()
                .is_some_and(|channel| claims.channels.contains(channel))
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
        // A due Owner schedule's key (FIX 1259) proves its owner by the
        // live-owner census here, as its schedule binding does, in place of
        // an owner actor binding.
        if self.actor_key.owner_by_census() {
            if crate::policy_model::is_live_vault_owner_in_txn(self.vault, txn, &owner)? {
                return Ok(());
            }
            return Err(Error::Claim(
                crate::error::ClaimError::ScopedReadOwnerNotLive(Box::new(
                    crate::memory::MemoryError::new(
                        crate::memory::MEMORY_CODE_FORBIDDEN,
                        "a due owner schedule's owner is no longer a live owner here",
                        &[],
                    ),
                )),
            ));
        }
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
            .world_record_in(txn, id, row.entity_type, &row.body, &ceiling)?
            .is_none_or(|record| !record.is_narrowing_of(&ceiling)))
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

    /// The world-only position of the stored row `id`, read in `txn` over
    /// this read's own store (`record_scope::record_world_in`), as a read
    /// under the world ceiling `ceiling` holds it: a NOTE at its world
    /// witness there (FIX-LIST 9433). `None` where the row cannot prove one.
    fn world_record_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        kind: u8,
        data: &[u8],
        ceiling: &crate::federation::Scope,
    ) -> Result<Option<crate::federation::Scope>> {
        use crate::federation::record_scope::note_world::world_record_held_at;
        match self.session_view {
            Some(view) => world_record_held_at(view, txn, *id, kind, data, ceiling),
            None => world_record_held_at(&self.vault.store, txn, *id, kind, data, ceiling),
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
                .world_record_in(txn, id, row.entity_type, &row.body, &ceiling)?
                .is_none_or(|record| !record.is_narrowing_of(&ceiling)));
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
