//! The birth placement a replicated TASK or SUMMARY carries on a copy to
//! another vault (FIX 3656, Engine ruling A).
//!
//! `stamp_put` never mints a birth position for a replicated non-CLAIM row:
//! a peer cannot place an opaque row by picking its id and bytes. A TASK and
//! a SUMMARY read their world and facet from that stamp alone
//! ([`super::record_world_in`]), so a copy that lands unstamped sits outside
//! every read narrowed on worlds or facets. The sender's stamp therefore
//! travels beside its row, in the same window update, as a
//! [`BirthPlacement`]: the one world and the one facet the row is born at,
//! which is what a read places it by. Only a stamp of the shape a local birth
//! door writes travels (a default birth, `stamp_task_birth`,
//! `settle_epoch_birth`); a raised or otherwise changed stamp stays home, and
//! its row lands as a row with no placement does.
//!
//! Federation admission validates each carried placement against the row it
//! rides with and remaps its world into the guest's foreign WORLD copy
//! ([`GuestPlacement`]). The import lands it beside the row's first put
//! here, in that put's transaction (`stamp_carried_placement`).

use serde::{Deserialize, Serialize};

use super::{SCOPE_RECORD, ScopeAxis, ScopeId, Stamp, default_stamp, singleton};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Whether a replicated row of `kind` carries its birth placement: a TASK
/// and a SUMMARY, the kinds whose world a read takes from their stamp alone
/// and whose replicated put `stamp_put` leaves unstamped.
pub(crate) const fn carries_birth_placement(kind: u8) -> bool {
    matches!(kind, ENTITY_TYPE_TASK | ENTITY_TYPE_SUMMARY)
}

/// A TASK's or SUMMARY's birth placement as its sender's stamp holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BirthPlacement {
    /// The row's kind: TASK or SUMMARY.
    pub(crate) kind: u8,
    /// The one world the row is born in, base reality among them.
    pub(crate) world: EntityId,
    /// The one facet the row is born under.
    pub(crate) facet: EntityId,
}

impl BirthPlacement {
    /// The canonical carrier: named MessagePack.
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self)
            .map_err(|_| Error::InvalidConfig("a birth placement does not encode".into()))
    }

    /// The carried placement, when `bytes` is its canonical encoding and
    /// names a kind that carries one. Decoding authenticates nothing.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let placement: Self = rmp_serde::from_slice(bytes).ok()?;
        (carries_birth_placement(placement.kind) && placement.encode().ok()? == bytes)
            .then_some(placement)
    }

    /// The stamp the row `id` is born with at this placement: a TASK's at
    /// its writer's world and facet, as `stamp_task_birth` settles it; a
    /// SUMMARY's at its run's world and facet over its own structural
    /// anchor, as `settle_epoch_birth` settles it. Every other axis is the
    /// default birth's, so a later put of the row keeps the stamp
    /// (`writer_settled`, `settled_at_birth`).
    pub(super) fn stamp(&self, id: EntityId) -> Result<Stamp> {
        let (birth_facet, mut scope) = match self.kind {
            ENTITY_TYPE_TASK => (self.facet, default_stamp(self.kind, self.facet)),
            ENTITY_TYPE_SUMMARY => {
                let anchor = crate::claim::substrate_facet_id(id)?;
                let mut scope = default_stamp(self.kind, anchor);
                scope.facets = singleton(ScopeId(self.facet));
                (anchor, scope)
            }
            other => return Err(Error::InvalidEntityType(other)),
        };
        scope.worlds = singleton(ScopeId(self.world));
        Ok(Stamp {
            version: 2,
            kind: self.kind,
            birth_facet: *birth_facet.as_bytes(),
            scope,
        })
    }

    /// This placement for a guest's row, at `copy`: the foreign WORLD copy
    /// admission maps the sender's world to (FIX 3656). `None`, a world no
    /// copy here stands for, refuses the placement and so its row: a guest's
    /// row is never placed in one of this vault's own worlds or in its base
    /// reality (ARCH-0043).
    pub(crate) fn for_guest(self, copy: Option<EntityId>) -> Result<GuestPlacement> {
        match copy {
            Some(world) if crate::entity_id::is_foreign_world_id_range(world) => {
                Ok(GuestPlacement(Self { world, ..self }))
            }
            _ => Err(Error::InvalidClaimBody(
                "a carried birth placement names no foreign WORLD copy",
            )),
        }
    }
}

/// A guest row's birth placement as admission validated it: the kind and
/// facet its sender's stamp holds, at the foreign WORLD copy its sender's
/// world lands in here. Only [`BirthPlacement::for_guest`] makes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestPlacement(BirthPlacement);

impl GuestPlacement {
    /// The kind of the row this placement lands beside.
    pub(crate) const fn kind(&self) -> u8 {
        self.0.kind
    }

    /// The stamp the row `id` lands with here.
    pub(super) fn stamp(&self, id: EntityId) -> Result<Stamp> {
        self.0.stamp(id)
    }
}

/// The placement the live row `id`, stored here as `kind`, is born at, read
/// in `txn`: its stamp, when that stamp is one a local birth door writes.
/// `None` for another kind, a row not live here as `kind`, no stamp, or a
/// stamp of any other shape.
pub(crate) fn stored_placement_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<Option<BirthPlacement>> {
    if !carries_birth_placement(kind) {
        return Ok(None);
    }
    if !matches!(
        live_entity_row_in_txn(store, txn, &id)?,
        LiveEntityRow::Live { entity_type, .. } if entity_type == kind
    ) {
        return Ok(None);
    }
    let Some(stamp) = SCOPE_RECORD.get(store, txn, &id)? else {
        return Ok(None);
    };
    let (Some(world), Some(facet)) = (only(&stamp.scope.worlds), only(&stamp.scope.facets)) else {
        return Ok(None);
    };
    let placement = BirthPlacement { kind, world, facet };
    let born = placement.stamp(id)?;
    let same = stamp.version == born.version
        && stamp.kind == born.kind
        && stamp.birth_facet == born.birth_facet
        && stamp.scope == born.scope;
    Ok(same.then_some(placement))
}

/// The one id an axis holds; `None` for any other axis.
fn only(axis: &ScopeAxis<ScopeId>) -> Option<EntityId> {
    match axis {
        ScopeAxis::Some(ids) if ids.len() == 1 => ids.first().map(|id| id.0),
        _ => None,
    }
}
