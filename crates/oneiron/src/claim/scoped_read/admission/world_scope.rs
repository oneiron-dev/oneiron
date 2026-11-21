//! The world axes of a scoped read: the worlds the read asked for, the
//! worlds its verified credential grants, and the world position of a
//! stored row as this read's own store places it.

use super::*;
use oneiron_authority::federation::{Scope, ScopeAxis, ScopeId};

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
    /// grants ([`task_outside_worlds_read_in`], through this read's own
    /// store).
    pub(super) fn outside_credential_task_position_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        let Some(granted) = self.actor_key.authority_scope() else {
            return Ok(false);
        };
        task_outside_worlds_read_in(&self.store_read(), txn, id, row, &granted.worlds)
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
    /// the read's verified credential grants ([`outside_worlds_read_in`],
    /// through this read's own store).
    pub(super) fn outside_credential_worlds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
    ) -> Result<bool> {
        let Some(granted) = self.actor_key.authority_scope() else {
            return Ok(false);
        };
        outside_worlds_read_in(&self.store_read(), txn, id, row, &granted.worlds)
    }

    /// Every world this read reads a row in, judged in `txn` under `policy`,
    /// for a key whose actor reads through its own live Grants (A) alone:
    /// the key's own floor reads no row (B: no policy row opens one, and no
    /// work-talk room binds it) and no owner alternative stands beside A
    /// (FIX 7461), so the worlds its live Grants reach, joined, are all it
    /// reads in ([`Self::grant_worlds_joined_in`]). A row outside them lies
    /// in a world hidden from the reader, which has no name and no count
    /// (DEC-0005: "Hidden worlds stay hidden: no name, no count", owner
    /// 2026-09-22; FIX GRANT-READER-BM25-DF-COUNTS-HIDDEN-WORLDS). `None`
    /// when A stands for no reader here, when the key's own floor reads some
    /// row (B then reads in every world, so A's worlds hide none), when the
    /// lane may read as its owner, when the reader holds no live Grant, or
    /// when one of its Grants reaches every world. `authority` is the
    /// serving txn's held authority, if any, whose Grants A reads.
    pub(super) fn grant_reader_worlds_in(
        &self,
        txn: &heed::RoTxn<'_>,
        policy: &crate::gate::PolicyManifestResolution,
        authority: Option<&super::super::access_gate::HeldAuthority>,
    ) -> Option<ScopeAxis<ScopeId>> {
        let reached = self.grant_worlds_joined_in(txn, authority)?;
        (!self.own_floor_reads_some_row(policy)).then_some(reached)
    }

    /// Whether the stored row `row` of `id` lies in a world hidden from a
    /// key that reads through its own live Grants alone: outside every
    /// world it reads a row in ([`Self::grant_reader_worlds_in`],
    /// [`outside_reached_worlds_in`], through this read's own store).
    /// `policy` is resolved in `txn` only for a row outside every world the
    /// reader's live Grants reach. `authority` is the serving txn's held
    /// authority, if any.
    ///
    /// # Errors
    /// A store or decode failure reading the row's world position or the
    /// policy.
    pub(super) fn in_grant_reader_hidden_world_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &EntityRecord,
        authority: Option<&super::super::access_gate::HeldAuthority>,
    ) -> Result<bool> {
        let Some(reached) = self.grant_worlds_joined_in(txn, authority) else {
            return Ok(false);
        };
        if !outside_reached_worlds_in(&self.store_read(), txn, id, row, &reached)? {
            return Ok(false);
        }
        let policy = crate::gate::resolve_policy_manifest(&self.vault.store, txn)?;
        Ok(!self.own_floor_reads_some_row(&policy))
    }

    /// The worlds this read's own live Grants reach in `txn`, joined, for a
    /// lane that may not read as its owner (A, [`Self::own_live_grants_in`]):
    /// each Grant alone admits a row, so a row outside the join is outside
    /// every one of them. `None` when A stands for no reader here, when the
    /// lane may read as its owner, when the reader holds no live Grant, or
    /// when one of its Grants reaches every world.
    fn grant_worlds_joined_in(
        &self,
        txn: &heed::RoTxn<'_>,
        authority: Option<&super::super::access_gate::HeldAuthority>,
    ) -> Option<ScopeAxis<ScopeId>> {
        if self.own_owner_authority {
            return None;
        }
        let grants = self.own_live_grants_in(txn, authority)?;
        if grants.is_empty() {
            return None;
        }
        let reached = grants
            .iter()
            .fold(ScopeAxis::Bottom, |reached, (_, grant)| {
                join_worlds(&reached, &grant.worlds)
            });
        (!matches!(reached, ScopeAxis::All)).then_some(reached)
    }

    /// Whether this key's own floor under `policy` could admit a row (B,
    /// [`crate::gate::RetrievalPolicyFloor::reads_some_row`]), a work-talk
    /// room binding included.
    fn own_floor_reads_some_row(&self, policy: &crate::gate::PolicyManifestResolution) -> bool {
        let (floor, work_talk_room) = self.own_retrieval_floor(policy);
        floor.reads_some_row() || work_talk_room.is_some()
    }
}

/// The rows a world keeps from a read under one key, for the statistics a
/// BM25 scan of that read scores with
/// ([`ScopedReadActorKey::world_withheld_rows_in`]).
pub(crate) struct WorldWithheldRows {
    /// The world ceilings a row must lie inside, each alone: the verified
    /// credential's worlds, and the worlds the holder's agent Grants
    /// standing in the snapshot reach.
    ceilings: Vec<ScopeAxis<ScopeId>>,
    /// The device-local worlds that keep their rows from the key's
    /// destination, off this device.
    device_local: Option<std::collections::BTreeSet<EntityId>>,
}

impl WorldWithheldRows {
    /// Whether a world keeps the stored row `id`, read in `txn` through
    /// `store` (the read's own content: a room's overlay ∪ base, or base
    /// alone), from the read: the row sits wholly outside a ceiling, or it
    /// is a TASK, or one of its authority facts, born outside one, or a
    /// device-local world keeps it. False for a row `store` does not hold.
    ///
    /// # Errors
    /// A store or decode failure reading the row or its world position.
    pub(crate) fn withholds_in(
        &self,
        store: &crate::store::StoreRead<'_>,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        use crate::ports::EntityStoreRead as _;
        if let Some(flagged) = &self.device_local
            && crate::settings::device_local_keeps_among(store, txn, flagged, id)?
        {
            return Ok(true);
        }
        if self.ceilings.is_empty() {
            return Ok(false);
        }
        let Some(row) = store.port_entity_record(txn, id)? else {
            return Ok(false);
        };
        for worlds in &self.ceilings {
            if outside_reached_worlds_in(store, txn, id, &row, worlds)? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Whether the stored row `row` of `id`, read in `txn` through `store`, is
/// kept from a read that reaches only `worlds`: it sits wholly outside them
/// ([`outside_worlds_read_in`]), or it is a TASK, or one of its authority
/// facts, born outside them ([`task_outside_worlds_read_in`]).
///
/// # Errors
/// A store or decode failure reading the row's world position.
pub(super) fn outside_reached_worlds_in(
    store: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    row: &EntityRecord,
    worlds: &ScopeAxis<ScopeId>,
) -> Result<bool> {
    Ok(outside_worlds_read_in(store, txn, id, row, worlds)?
        || task_outside_worlds_read_in(store, txn, id, row, worlds)?)
}

impl ScopedReadActorKey {
    /// The rows a world keeps from a read under this key, judged in `txn`:
    /// a row outside the worlds its verified credential grants, or outside
    /// the worlds the agent Grants that name its holder and stand in `txn`
    /// reach (each met with the key's own Scope, as the row gate holds a
    /// held lane to them, REVIEW-7051 P1), or one a device-local world keeps
    /// from the key's destination off this device. The row gate refuses
    /// each such row and gives it no count (DEC-0005), so no statistic a
    /// BM25 scan of the read scores with counts its postings (FIX
    /// WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS). The worlds a read asked
    /// for are its own selection, not a refusal, and keep nothing here.
    /// `None` when no world keeps a row from this key.
    ///
    /// # Errors
    /// A store, fold or clock failure reading the holder's Grants or the
    /// device-local worlds.
    pub(crate) fn world_withheld_rows_in(
        &self,
        vault: &crate::vault::Vault,
        txn: &heed::RoTxn<'_>,
    ) -> Result<Option<WorldWithheldRows>> {
        let mut ceilings = Vec::new();
        if let Some(granted) = self.authority_scope()
            && !matches!(granted.worlds, ScopeAxis::All)
        {
            ceilings.push(granted.worlds.clone());
        }
        if let Some(holder) = self.agent_grant_holder()
            && let Some(bounds) = vault.agent_grant_read_bounds_in_txn(txn, holder)?
        {
            let own = self.authority_scope().cloned().unwrap_or_else(Scope::top);
            let reached = bounds.iter().fold(ScopeAxis::Bottom, |reached, bound| {
                join_worlds(&reached, &Self::read_authority(&own.meet(bound)).worlds)
            });
            if !matches!(reached, ScopeAxis::All) {
                ceilings.push(reached);
            }
        }
        let device_local = if self.off_device() {
            Some(crate::settings::device_local_worlds_for(
                vault,
                txn,
                self.destination(),
            )?)
            .filter(|flagged| !flagged.is_empty())
        } else {
            None
        };
        Ok(
            (!ceilings.is_empty() || device_local.is_some()).then_some(WorldWithheldRows {
                ceilings,
                device_local,
            }),
        )
    }
}

/// The worlds either axis reaches.
fn join_worlds(left: &ScopeAxis<ScopeId>, right: &ScopeAxis<ScopeId>) -> ScopeAxis<ScopeId> {
    match (left, right) {
        (ScopeAxis::All, _) | (_, ScopeAxis::All) => ScopeAxis::All,
        (ScopeAxis::Bottom, other) | (other, ScopeAxis::Bottom) => other.clone(),
        (ScopeAxis::Some(left), ScopeAxis::Some(right)) => {
            ScopeAxis::Some(left.union(right).cloned().collect())
        }
    }
}

/// Whether the stored row `row` of `id`, read in `txn` through `store`,
/// sits wholly outside `worlds`: a claim at the position the read door
/// selects it; any other record where `record_world_in` places it. A claim
/// with no such position is judged by the other axes; a TASK or epoch
/// SUMMARY that cannot prove its world is outside. Every world is outside
/// none.
fn outside_worlds_read_in(
    store: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    row: &EntityRecord,
    worlds: &ScopeAxis<ScopeId>,
) -> Result<bool> {
    use crate::federation::record_scope::note_world::world_record_held_at;
    if matches!(worlds, ScopeAxis::All) {
        return Ok(false);
    }
    // A TASK and its authority facts, an epoch SUMMARY, and an identity
    // topology event (in its birth stamp's single world) sit at their
    // birth. Every other record that is not a claim is base reality,
    // stamped or not: a row
    // replayed with no stamp is no less outside a credential that cannot
    // read base (Astra #1388b P2).
    if row.entity_type != ENTITY_TYPE_CLAIM {
        let ceiling = super::super::actor_key::world_only(worlds.clone());
        return Ok(
            world_record_held_at(store, txn, *id, row.entity_type, &row.body, &ceiling)?
                .is_none_or(|record| !record.is_narrowing_of(&ceiling)),
        );
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
    Ok(record.is_some_and(|record| record.worlds.meet(worlds).is_bottom()))
}

/// Whether `row` of `id`, read in `txn` through `store`, is a TASK, or one
/// of its authority facts, whose birth stamp sits outside `worlds`
/// (ARCH-0067 §5, DEC-0005). One that cannot prove its position counts as
/// outside. Its facets are judged by the lane's one facet rule
/// (`outside_credential_facets_in`), owner exemption included, never here.
fn task_outside_worlds_read_in(
    store: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    row: &EntityRecord,
    worlds: &ScopeAxis<ScopeId>,
) -> Result<bool> {
    use crate::federation::record_scope::task_inside_credential;
    if row.entity_type != crate::registry::ENTITY_TYPE_TASK {
        return Ok(false);
    }
    let worlds_only = super::super::actor_key::world_only(worlds.clone());
    let raw = row.encode();
    Ok(!task_inside_credential(
        store,
        txn,
        *id,
        &raw,
        &worlds_only,
    )?)
}
