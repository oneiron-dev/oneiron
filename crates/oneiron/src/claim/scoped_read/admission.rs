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
