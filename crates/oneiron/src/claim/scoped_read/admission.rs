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

    /// Number of immutable room ledger snapshots loaded by this read handle.
    pub fn audience_ledger_reads(&self) -> Result<usize> {
        Ok(self
            .audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .ledger_reads())
    }

    pub(super) fn audience_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        let Some(audience) = &self.audience else {
            return Ok(true);
        };
        self.audience_cache
            .lock()
            .map_err(|_| Error::InvariantViolation("audience cache lock"))?
            .readable(self.vault, txn, *id, audience)
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
        if crate::note::countable_read_suppression(row.entity_type, &row.body) {
            Ok(ReadAdmission::Suppressed)
        } else {
            Ok(ReadAdmission::OpaqueAbsent)
        }
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
