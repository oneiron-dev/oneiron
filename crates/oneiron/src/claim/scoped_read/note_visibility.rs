//! Actor and class checks for private NOTE bodies in scoped reads.

use super::*;

impl ScopedRead<'_> {
    /// Scoped actor keys are asserted by a trusted host, not bearer secrets.
    /// A private NOTE additionally requires an exact entity id and a live,
    /// class-valid actor row in the same snapshot as its body.
    pub(super) fn note_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        bytes: &[u8],
        policy: &crate::gate::PolicyManifestResolution,
    ) -> Result<bool> {
        // A migrated NOTE retains author metadata but stores markdown on its
        // document plane. Apply the same privacy rule to that logical body.
        #[cfg(feature = "sync")]
        let resolved = crate::entity_doc::resolve_record_body(&self.vault.store, txn, id, bytes)?;
        #[cfg(feature = "sync")]
        let bytes = resolved.as_slice();
        #[cfg(not(feature = "sync"))]
        let _ = id;
        let Ok(body) = crate::note::decode_note_body_in_txn(&self.vault.store, txn, bytes) else {
            return Ok(false);
        };
        if body.kind == crate::note::NoteKind::OpinionTake {
            return Ok(true);
        }
        if crate::note::note_body_readable(&self.vault.store, txn, bytes, None)? {
            return Ok(true);
        }
        let Ok(actor) = EntityId::from_hex(self.actor_key.actor_ref()) else {
            return Ok(false);
        };
        let Some(class) = self.actor_key.actor_class().and_then(|class| match class {
            "human" => Some(crate::edge::EdgeActorClass::Human),
            "agent" => Some(crate::edge::EdgeActorClass::Agent),
            "system" => Some(crate::edge::EdgeActorClass::System),
            _ => None,
        }) else {
            return Ok(false);
        };
        let crate::vault::LiveEntityRow::Live { entity_type, .. } =
            crate::vault::live_entity_row_in_txn(&self.vault.store, txn, &actor)?
        else {
            return Ok(false);
        };
        if crate::provenance::validate_actor_class(entity_type, class).is_err() {
            return Ok(false);
        }
        if actor == body.author_ref {
            return Ok(true);
        }
        if body.kind != crate::note::NoteKind::Diary
            || !crate::note::readable_through_link(self.vault, txn, *id, actor)?
        {
            return Ok(false);
        }
        // Mutual consent grants the pair, not a bypass of the authenticated
        // reader's WORLD/FACET/sensitivity floor.
        let Some(raw) = self.entity_record_in(txn, id)?.map(|row| row.encode()) else {
            return Ok(false);
        };
        let Some(scope) =
            crate::federation::record_scope::scope_for_blob(&self.vault.store, txn, *id, &raw)?
        else {
            return Ok(false);
        };
        Ok(crate::gate::scoped_read_record_allowed(
            policy,
            &self.actor_key,
            &scope,
        ))
    }
}

impl ScopedRead<'_> {
    /// Private diary candidates admitted under this query's snapshot. The
    /// pipeline keeps the set only for this run and still performs its final
    /// current + indexed-frontier authority checks on every resulting hit.
    pub(crate) fn diary_candidates_in(
        &self,
        txn: &heed::RoTxn<'_>,
        requested: &crate::gate::ResolvedRetrievalFilter,
    ) -> Result<super::ScopedDiaryCandidates> {
        let (_, policy) = self.resolve_retrieval_filter_in(txn, None)?;
        let mut admitted = HashSet::new();
        for row in self
            .vault
            .store
            .type_index
            .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_NOTE])?
        {
            let (key, _) = row?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let Some(raw) = self.entity_record_in(txn, &id)? else {
                continue;
            };
            if raw.entity_type != crate::registry::ENTITY_TYPE_NOTE {
                continue;
            }
            #[cfg(feature = "sync")]
            let body =
                crate::entity_doc::resolve_record_body(&self.vault.store, txn, &id, &raw.body)?;
            #[cfg(not(feature = "sync"))]
            let body = std::borrow::Cow::Borrowed(raw.body.as_slice());
            if crate::note::decode_note_body_in_txn(&self.vault.store, txn, &body)
                .is_ok_and(|note| note.kind == crate::note::NoteKind::Diary)
                && self.is_entity_retrievable_with_policy_in(txn, &policy, requested, &id)?
            {
                admitted.insert(id);
            }
        }
        Ok(super::ScopedDiaryCandidates::from_admission(admitted))
    }
}
