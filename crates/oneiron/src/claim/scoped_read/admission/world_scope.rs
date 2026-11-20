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
    /// grants (ARCH-0067 §5, DEC-0005). One that cannot prove its position
    /// counts as outside. Its facets are judged by the lane's one facet rule
    /// (`outside_credential_facets_in`), owner exemption included, never
    /// here.
    pub(super) fn outside_credential_task_position_in(
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
        let worlds_only = super::super::actor_key::world_only(granted.worlds.clone());
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

    /// Whether the stored row `row` of `id` sits wholly outside the worlds
    /// the read's verified credential grants: a claim at the position the
    /// read door selects it; any other record where `record_world_in` places
    /// it. A claim with no such position is judged by the other axes; a TASK
    /// or epoch SUMMARY that cannot prove its world is outside.
    pub(super) fn outside_credential_worlds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        let Some(granted) = self.actor_key.authority_scope() else {
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
}
