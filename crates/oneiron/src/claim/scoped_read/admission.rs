use super::*;

impl crate::vault::Vault {
    #[must_use]
    pub fn scoped_read(&self, actor_key: ScopedReadActorKey) -> ScopedRead<'_> {
        ScopedRead {
            vault: self,
            actor_key,
            audience: None,
            audience_cache: Mutex::new(Default::default()),
            session_view: None,
            claim_status: ClaimReadStatus::Surfaceable,
            recall_authority: Mutex::new(None),
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
        ScopedRead {
            vault: self,
            actor_key,
            audience: None,
            audience_cache: Mutex::new(Default::default()),
            session_view: Some(view),
            claim_status: ClaimReadStatus::Surfaceable,
            recall_authority: Mutex::new(None),
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

    /// Read only rows in `worlds`; see [`ScopedReadActorKey::within_worlds`].
    /// The ceiling rides the key, so a lane built from it keeps it too.
    #[must_use]
    pub(crate) fn within_worlds(mut self, worlds: crate::pipeline::WorldAuthoritySet) -> Self {
        self.actor_key = self.actor_key.within_worlds(worlds);
        self
    }

    /// Number of immutable room ledger snapshots loaded by this read handle.
    pub fn audience_ledger_reads(&self) -> Result<usize> {
        Ok(self
            .audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .ledger_reads())
    }

    /// The audience conjunct every admission path applies, over the current
    /// row. Paths that serve a known revision use [`Self::audience_readable_raw_in`].
    pub(super) fn audience_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        if self.actor_key.room_turn.is_none()
            && self.actor_key.worlds.is_none()
            && self.audience.is_none()
        {
            return Ok(true);
        }
        let Some(record) = self.entity_record_in(txn, id)? else {
            return Ok(false);
        };
        self.audience_readable_raw_in(txn, id, &record.encode())
    }

    /// The audience conjunct over the exact revision `raw` being served. A
    /// key that asked for a world set keeps the row inside it. A key bound to
    /// a room turn adds the room's world ceiling, its whole roster as an
    /// audience, and every other member's own read of that same revision, so
    /// the turn reads inside the room's Scope (ARCH-0067 §8). The ceiling is
    /// the room as this snapshot reads it, so a member who joined after the
    /// key was built binds this row too.
    pub(super) fn audience_readable_raw_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        if self.actor_key.room_turn.is_none() && self.actor_key.worlds.is_none() {
            return self.audience_conjunct_in(txn, id, raw);
        }
        let Some(world) = revision_world(raw)? else {
            return Ok(false);
        };
        if self
            .actor_key
            .worlds
            .as_ref()
            .is_some_and(|worlds| !worlds.admits(world))
        {
            return Ok(false);
        }
        if let Some(turn) = &self.actor_key.room_turn {
            let Some(now) =
                crate::context_board::room_ceiling_in(self.vault, txn, turn.room, turn.caller)?
            else {
                return Ok(false);
            };
            let room = turn.narrowed_by(now);
            if !room.admits_world(world)
                || !self
                    .audience_cache
                    .lock()
                    .map_err(|_| Error::InvariantViolation("audience cache lock"))?
                    .readable_raw(self.vault, txn, *id, raw, &room.roster)?
            {
                return Ok(false);
            }
            // The room reads only what every member may read: a row private
            // to the caller is not the room's. Each peer reads this revision
            // under this read's claim-status contract.
            for peer in &room.peers {
                let peer = self
                    .vault
                    .scoped_read(peer.clone())
                    .with_claim_status(self.claim_status);
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
        }
        self.audience_conjunct_in(txn, id, raw)
    }

    /// The explicit audience this read was opened for, if any.
    fn audience_conjunct_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        raw: &[u8],
    ) -> Result<bool> {
        let Some(audience) = &self.audience else {
            return Ok(true);
        };
        self.audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .readable_raw(self.vault, txn, *id, raw, audience)
    }

    pub(super) fn credential_allows_id(&self, id: &EntityId) -> bool {
        self.actor_key.proof.as_ref().is_none_or(|proof| {
            let claims = proof.claims();
            // Generic records have no proved channel context. Channel-bound
            // credentials must use their typed adapter instead of losing a caveat.
            claims.channels.is_empty()
                && (claims.records.is_empty() || claims.records.contains(&id.to_hex()))
        })
    }

    /// The owner key's binding, re-verified in this read's own snapshot, so a
    /// key minted before a revocation resolves no plan after it.
    pub(super) fn owner_live_in(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
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

    pub(super) fn proof_live_in(&self, txn: &heed::RoTxn<'_>) -> Result<bool> {
        let Some(proof) = &self.actor_key.proof else {
            return Ok(true);
        };
        let claims = proof.claims();
        let now = self.vault.instant_in_txn(txn)?.secs();
        if now < claims.issued_at || now >= claims.expires_at {
            return Ok(false);
        }
        let fold = self.vault.authority_fold_readonly_in_txn(txn)?;
        if fold.vault_id != Some(claims.vault_id) {
            return Ok(false);
        }
        Ok(fold.slip_is_live(&claims.slip_id))
    }

    #[must_use]
    pub fn vault(&self) -> &'a crate::Vault {
        self.vault
    }

    /// Both canonical and session reads use the same ports. A session adapter
    /// composes overlay union base without changing policy admission.
    pub(super) fn entity_record_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityRecord>> {
        match self.session_view {
            Some(view) => view.port_entity_record(txn, id),
            None => self.vault.port_entity_record(txn, id),
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
        // policy; scope honesty names its world instead.
        if self.actor_key.room_turn.is_none()
            && !self.outside_asked_worlds(&row)
            && crate::note::countable_read_suppression(row.entity_type, &row.body)
        {
            Ok(ReadAdmission::Suppressed)
        } else {
            Ok(ReadAdmission::OpaqueAbsent)
        }
    }

    fn outside_asked_worlds(&self, row: &EntityRecord) -> bool {
        let Some(worlds) = &self.actor_key.worlds else {
            return false;
        };
        let world = if row.entity_type == ENTITY_TYPE_CLAIM {
            match crate::claim::decode_claim_body(&row.body, true) {
                Ok(body) => body.world,
                Err(_) => return true,
            }
        } else {
            None
        };
        !worlds.admits(world)
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

/// The world of the revision `raw`: a claim's own, `None` for base reality,
/// which also holds every record that is not a claim. An erased claim cannot
/// prove its world, so it has none (`Ok(None)`).
fn revision_world(raw: &[u8]) -> Result<Option<Option<EntityId>>> {
    let header = EntityMetadataHeader::parse(raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Ok(Some(None));
    }
    Ok(raw
        .get(ENTITY_METADATA_HEADER_LEN..)
        .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
        .map(|body| body.world))
}
