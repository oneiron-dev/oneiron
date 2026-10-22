//! Actor and class checks for private NOTE bodies in scoped reads.

use super::*;
use crate::federation::record_scope::note_world;

impl ScopedRead<'_> {
    /// Scoped actor keys are asserted by a trusted host, not bearer secrets.
    /// A private NOTE additionally requires an exact entity id and a live,
    /// class-valid actor row in the same snapshot as its body.
    pub(crate) fn note_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        bytes: &[u8],
        policy: &crate::gate::PolicyManifestResolution,
    ) -> Result<bool> {
        self.note_readable_under_in(txn, id, bytes, policy, None)
    }

    /// [`Self::note_readable_in`] under `grant`, one live Grant of the
    /// reader's own (FIX 7462): it stands in for the linked diary's final
    /// positive check alone; every author, consent and privacy rule binds as
    /// before. `None` is today's.
    pub(super) fn note_readable_under_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        bytes: &[u8],
        policy: &crate::gate::PolicyManifestResolution,
        grant: Option<&crate::federation::Scope>,
    ) -> Result<bool> {
        // A migrated NOTE retains author metadata but stores markdown on its
        // document plane. Apply the same privacy rule to that logical body,
        // read where this read reads the row: a room's NOTE has its own. Its
        // kind, author, link and consent are judged on base.
        #[cfg(feature = "sync")]
        let resolved = crate::entity_doc::resolve_record_body(&self.store_read(), txn, id, bytes)?;
        #[cfg(feature = "sync")]
        let bytes = resolved.as_slice();
        #[cfg(not(feature = "sync"))]
        let _ = id;
        let Ok(body) = crate::note::decode_note_body_in_txn(&self.vault.store, txn, bytes) else {
            return Ok(false);
        };
        // A NOTE placed in worlds reads, on every path below, only where the
        // asked worlds, the credential's and the Grant's hold one of them
        // (FIX-LIST 9433). The vault's owner is not held to it.
        let ceiling = self.actor_key.world_ceiling();
        let held = [&ceiling.worlds, &grant.unwrap_or(&ceiling).worlds];
        let worlds = note_world::note_worlds_in(&self.store_read(), txn, *id);
        if self.actor_key.vault_owner_ref().is_none() && !worlds.readable_at(&held) {
            return Ok(false);
        }
        // A NOTE only in worlds other than base reality reads, for a reader
        // whose own policy read Grants apply, only where one of them alone
        // reaches one of its worlds (FIX-LIST 10726). An Owner, co-Owners
        // and the owner's own narrower credentials, a Grant already
        // witnessed, a base NOTE and a world lookup fault keep today's path,
        // as does a reader no policy read Grant names.
        if grant.is_none()
            && matches!(&worlds, note_world::NoteWorlds::In(set)
                if !set.contains(&crate::federation::ScopeId(crate::claim::base_world_id())))
            && !self
                .actor_key
                .facets_owner_exempt_in(self.vault, txn)
                .unwrap_or(false)
            && crate::gate::scoped_read_note_world_witness(
                policy,
                &self.actor_key,
                &worlds,
                &held,
            ) == Some(false)
        {
            return Ok(false);
        }
        // A take reads as its kind's relationship scope unless it overrides
        // that, so it has no shortcut past an owner-only override.
        if crate::note::note_explicit_only_in_txn(&self.vault.store, txn, id, &body)? {
            return Ok(true);
        }
        if crate::note::note_body_readable(&self.vault.store, txn, id, bytes, None)? {
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
        if body.author_ref.is(actor)
            || crate::note::reader_imported_note(&self.vault.store, txn, &body, actor)?
        {
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
        // The NOTE's position, where this read reads it: a room's NOTE under
        // the birth facet its write staged (WILL L11-01).
        let Some(scope) =
            crate::federation::record_scope::scope_for_blob(&self.store_read(), txn, *id, &raw)?
        else {
            return Ok(false);
        };
        // Judged under the proof, and under each Grant alone, at one world
        // it is in that every ceiling there holds (FIX-LIST 9433).
        Ok(crate::gate::scoped_read_note_allowed(
            policy,
            &self.actor_key,
            &scope,
            grant.or(self.actor_key.authority_scope()),
            (&worlds, &held[..]),
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
        for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.vault.store,
            txn,
            crate::registry::ENTITY_TYPE_NOTE,
            None,
        )? {
            let id = id?;
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
