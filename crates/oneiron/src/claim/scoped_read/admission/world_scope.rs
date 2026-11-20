//! The world axes of a scoped read: the worlds the read asked for, the
//! worlds its verified credential grants, and the world position of a
//! stored row as this read's own store places it.

use super::*;

impl ScopedRead<'_> {
    /// Whether this read's credential is live in `txn` and the worlds the
    /// read asked for and its Scope both admit `world` (`None` is base
    /// reality): the world ceilings every row it serves lies under, before
    /// any manifest's say.
    pub(crate) fn world_readable_in(
        &self,
        txn: &heed::RoTxn<'_>,
        world: Option<EntityId>,
    ) -> Result<bool> {
        let record = super::super::actor_key::record_world_scope(world);
        if !record.is_narrowing_of(&self.actor_key.world_ceiling()) {
            return Ok(false);
        }
        self.proof_live_in(txn)
    }

    pub(super) fn outside_asked_worlds_in(
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
    /// grants ([`ScopedReadActorKey::outside_credential_task_position_read_in`],
    /// through this read's own store).
    pub(super) fn outside_credential_task_position_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        self.actor_key
            .outside_credential_task_position_read_in(&self.store_read(), txn, id, row)
    }

    /// The world-only position of the stored row `id`, read in `txn` over
    /// this read's own store (`record_scope::record_world_in`), as a read
    /// under the world ceiling `ceiling` holds it: a NOTE at its world
    /// witness there (FIX-LIST 9433). `None` where the row cannot prove one.
    pub(in crate::claim::scoped_read) fn world_record_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        kind: u8,
        data: &[u8],
        ceiling: &oneiron_authority::federation::Scope,
    ) -> Result<Option<oneiron_authority::federation::Scope>> {
        use crate::federation::record_scope::note_world::world_record_held_at;
        match self.session_view {
            Some(view) => world_record_held_at(view, txn, *id, kind, data, ceiling),
            None => world_record_held_at(&self.vault.store, txn, *id, kind, data, ceiling),
        }
    }

    /// The own-row test of a BM25 scan this read admits each posting of
    /// ([`crate::ports::TextQuery::hidden_row`]), read in `txn` through this
    /// read's own store: whether a world keeps the row from the read, one its
    /// verified credential does not grant
    /// ([`ScopedReadActorKey::credential_worlds_withhold_row_in`]) or a
    /// device-local world off this device (DEC-0005). The scan serves no such
    /// row; with this test its words move no readable row's score either
    /// (FIX WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS). `None` when no world
    /// keeps a row from this read.
    ///
    /// # Errors
    /// A store or fold failure reading the device-local worlds.
    pub(crate) fn world_withheld_rows_in<'t>(
        &'t self,
        txn: &'t heed::RoTxn<'_>,
    ) -> Result<Option<Box<dyn FnMut(&EntityId) -> Result<bool> + 't>>> {
        let device_local = if self.actor_key.off_device() {
            Some(crate::settings::device_local_worlds_for(
                self.vault,
                txn,
                self.actor_key.destination(),
            )?)
            .filter(|flagged| !flagged.is_empty())
        } else {
            None
        };
        if device_local.is_none() && !self.actor_key.has_world_ceiling() {
            return Ok(None);
        }
        let store = self.store_read();
        Ok(Some(Box::new(move |id: &EntityId| {
            Ok(self
                .actor_key
                .credential_worlds_withhold_row_in(&store, txn, id)?
                || match &device_local {
                    Some(flagged) => {
                        crate::settings::device_local_keeps_among(&store, txn, flagged, id)?
                    }
                    None => false,
                })
        })))
    }

    /// Whether the stored row `row` of `id` sits wholly outside the worlds
    /// the read's verified credential grants
    /// ([`ScopedReadActorKey::outside_credential_worlds_read_in`], through
    /// this read's own store).
    pub(super) fn outside_credential_worlds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        self.actor_key
            .outside_credential_worlds_read_in(&self.store_read(), txn, id, row)
    }
}

impl ScopedReadActorKey {
    /// Whether a world keeps the stored row `id` from a read under this key,
    /// read in `txn` through `store`, the read's own content (a room's
    /// overlay ∪ base, or base alone): the row sits wholly outside the worlds
    /// the verified credential grants, or it is a TASK, or one of its
    /// authority facts, born outside them. Such a row has no name and no
    /// count (DEC-0005), and the row gate refuses it by these same two
    /// checks, so no statistic a BM25 scan of this read scores with counts
    /// its postings (FIX WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS). The
    /// worlds a read asked for are its own selection, not a refusal, and
    /// keep nothing here. False for a key whose credential grants every
    /// world, and for a row `store` does not hold.
    ///
    /// # Errors
    /// A store or decode failure reading the row or its world position.
    pub(crate) fn credential_worlds_withhold_row_in(
        &self,
        store: &crate::store::StoreRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        use crate::ports::EntityStoreRead as _;
        if !self.has_world_ceiling() {
            return Ok(false);
        }
        let Some(row) = store.port_entity_record(txn, id)? else {
            return Ok(false);
        };
        Ok(
            self.outside_credential_worlds_read_in(store, txn, id, &row)?
                || self.outside_credential_task_position_read_in(store, txn, id, &row)?,
        )
    }

    /// Whether the stored row `row` of `id`, read in `txn` through `store`,
    /// sits wholly outside the worlds this key's verified credential grants:
    /// a claim at the position the read door selects it; any other record
    /// where `record_world_in` places it. A claim with no such position is
    /// judged by the other axes; a TASK or epoch SUMMARY that cannot prove
    /// its world is outside.
    fn outside_credential_worlds_read_in(
        &self,
        store: &crate::store::StoreRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        use crate::federation::record_scope::note_world::world_record_held_at;
        let Some(granted) = self.authority_scope() else {
            return Ok(false);
        };
        if matches!(
            granted.worlds,
            oneiron_authority::federation::ScopeAxis::All
        ) {
            return Ok(false);
        }
        // A TASK and its authority facts, an epoch SUMMARY, and an identity
        // topology event (in its birth stamp's single world) sit at their
        // birth. Every other record that is not a claim is base reality,
        // stamped or not: a row
        // replayed with no stamp is no less outside a credential that cannot
        // read base (Astra #1388b P2).
        if row.entity_type != ENTITY_TYPE_CLAIM {
            let ceiling = super::super::actor_key::world_only(granted.worlds.clone());
            return Ok(world_record_held_at(
                store,
                txn,
                *id,
                row.entity_type,
                &row.body,
                &ceiling,
            )?
            .is_none_or(|record| !record.is_narrowing_of(&ceiling)));
        }
        // A claim with no decodable world names none, as a read that asked
        // for worlds judges it.
        if crate::claim::decode_claim_body(&row.body, true).is_err() {
            return Ok(true);
        }
        // A room's own claim sits at the position its write staged beside
        // it (WILL L11-01); every other claim at base's.
        let record = if store.room_holds(id)? {
            crate::federation::record_scope::disclosure_scope_for_stored_row(
                store,
                txn,
                *id,
                row.entity_type,
                &row.body,
            )?
        } else {
            crate::federation::record_scope::disclosure_scope_for_stored_row(
                store.base(),
                txn,
                *id,
                row.entity_type,
                &row.body,
            )?
        };
        Ok(record.is_some_and(|record| record.worlds.meet(&granted.worlds).is_bottom()))
    }

    /// Whether `row` of `id`, read in `txn` through `store`, is a TASK, or
    /// one of its authority facts, whose birth stamp sits outside the worlds
    /// this key's verified credential grants (ARCH-0067 §5, DEC-0005). One
    /// that cannot prove its position counts as outside. Its facets are
    /// judged by the lane's one facet rule (`outside_credential_facets_in`),
    /// owner exemption included, never here.
    fn outside_credential_task_position_read_in(
        &self,
        store: &crate::store::StoreRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        use crate::federation::record_scope::task_inside_credential;
        let Some(granted) = self.authority_scope() else {
            return Ok(false);
        };
        if row.entity_type != crate::registry::ENTITY_TYPE_TASK {
            return Ok(false);
        }
        let worlds_only = super::super::actor_key::world_only(granted.worlds.clone());
        let raw = row.encode();
        Ok(!task_inside_credential(
            store,
            txn,
            *id,
            &raw,
            &worlds_only,
        )?)
    }
}
