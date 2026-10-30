//! A replicated row's birth scope as it travels beside its carrier (FIX 3656;
//! Engine ruling 09:39 A).
//!
//! A row's birth position is its stamp, settled where it was born: a TASK at
//! its writer's world and facet, an epoch SUMMARY where its epoch settled it.
//! Its body names neither, and a peer cannot mint a position by picking an id
//! and bytes (`stamp_put`), so a replicated row used to land with no stamp at
//! all and every world-narrowed read kept it out. Its sender's stamp now
//! travels typed beside it: the receiver stamps the row from it, once, when
//! it holds no stamp of its own and the position is well formed and reads
//! back as that kind's stamp. A carrier that does not hold leaves the row as
//! it was, unstamped; no row is refused for its carrier.
//!
//! A guest's carrier is moved before it lands, as a guest CLAIM is (FIX 3497):
//! a TASK or SUMMARY to the foreign WORLD its sender's world maps to, a WORLD
//! row to the foreign id it lands under. A guest's row of any other kind
//! lands unstamped, as before, rather than in base reality here.

use std::collections::BTreeSet;

use super::{
    SCOPE_RECORD, ScopeAxis, ScopeId, SensitivityCeiling, Stamp, bump_scope_revision,
    carries_birth_stamp, default_stamp, singleton, stored_scope,
};
use crate::EntityId;
use crate::error::{Error, Result};
use crate::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK, ENTITY_TYPE_WORLD,
};
use crate::store::{ManifestDbs, Store};

/// The stamp version a carrier holds.
const STAMP_VERSION: u8 = 2;

/// Whether a row of `kind` travels with its birth scope: every stamped kind
/// but a CLAIM, whose body carries its position, and a NOTE or ASSET, whose
/// position every read takes from its live edges.
fn travels(kind: u8) -> bool {
    kind != ENTITY_TYPE_CLAIM && !carries_birth_stamp(kind)
}

fn encode(stamp: &Stamp) -> Result<Vec<u8>> {
    serde_json::to_vec(stamp)
        .map_err(|_| Error::InvalidConfig("a birth scope does not encode".into()))
}

/// The carried stamp, when `bytes` is its canonical encoding.
fn decode(bytes: &[u8]) -> Option<Stamp> {
    let stamp: Stamp = serde_json::from_slice(bytes).ok()?;
    (encode(&stamp).ok()? == bytes).then_some(stamp)
}

/// The birth scope the row `id` travels with, encoded: its stamp here, read
/// in `txn`, when it has one and its kind travels.
pub(crate) fn carried_birth_scope(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Option<Vec<u8>>> {
    match SCOPE_RECORD.get(store, txn, &id)? {
        Some(stamp) if stamp.version == STAMP_VERSION && travels(stamp.kind) => {
            encode(&stamp).map(Some)
        }
        _ => Ok(None),
    }
}

/// Whether `stamp` is a well-formed birth position for a row of `kind`: its
/// own band, one world, one facet, and no verbs, since a record is not a
/// capability.
fn well_formed(stamp: &Stamp, kind: u8) -> bool {
    let one = |axis: &ScopeAxis<ScopeId>| matches!(axis, ScopeAxis::Some(set) if set.len() == 1);
    stamp.version == STAMP_VERSION
        && stamp.kind == kind
        && travels(kind)
        && one(&stamp.scope.worlds)
        && one(&stamp.scope.facets)
        && stamp.scope.bands == singleton(kind)
        && matches!(stamp.scope.verbs, ScopeAxis::Bottom)
}

/// Stamps the replicated row `id` of `kind` at the birth scope `carried`,
/// in `txn`: only a row with no stamp yet, at a well-formed position that
/// reads back as that kind's stamp (`stored_scope`, its facet rule among
/// them). Any other carrier leaves the row unstamped, with a warning.
/// Returns whether it stamped.
pub(crate) fn stamp_carried_birth_scope_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    carried: &[u8],
) -> Result<bool> {
    if SCOPE_RECORD.get(store, txn, &id)?.is_some() {
        return Ok(false);
    }
    let Some(stamp) = decode(carried).filter(|stamp| well_formed(stamp, kind)) else {
        tracing::warn!(
            kind,
            "a replicated row's birth scope carrier is not a well-formed position; \
             the row stays unstamped (FIX 3656)"
        );
        return Ok(false);
    };
    bump_scope_revision(store, txn)?;
    SCOPE_RECORD.put(store, txn, &id, &stamp)?;
    if stored_scope(store, txn, id, kind)?.is_some() {
        return Ok(true);
    }
    SCOPE_RECORD.delete(store, txn, &id)?;
    tracing::warn!(
        kind,
        "a replicated row's birth scope carrier names a facet its row is not born under; \
         the row stays unstamped (FIX 3656)"
    );
    Ok(false)
}

/// The birth scope `carried`, the sender's for its row `sender`, as that row
/// lands here under `here` from a guest whose pact names `source`: a TASK or
/// SUMMARY at the foreign WORLD each of its sender's worlds maps to, base
/// reality's among them (`guest_claim_world`); a WORLD row at its own
/// substrate facet under the foreign id it lands under. `None` for a row of
/// any other kind, and for a carrier that does not read: that row lands
/// unstamped.
///
/// # Errors
///
/// A foreign WORLD or substrate facet derive error.
pub(crate) fn guest_birth_scope(
    carried: &[u8],
    source: &[u8; 32],
    sender: EntityId,
    here: EntityId,
) -> Result<Option<Vec<u8>>> {
    let Some(mut stamp) = decode(carried) else {
        return Ok(None);
    };
    match stamp.kind {
        ENTITY_TYPE_TASK | ENTITY_TYPE_SUMMARY => {
            let ScopeAxis::Some(worlds) = &stamp.scope.worlds else {
                return Ok(None);
            };
            let base = crate::claim::base_world_id();
            let mut landed = BTreeSet::new();
            for world in worlds {
                let sender_world = Some(world.0).filter(|world| *world != base);
                landed.insert(ScopeId(
                    crate::federation::guest_claim_world(source, sender_world)?.entity_id(),
                ));
            }
            stamp.scope.worlds = ScopeAxis::Some(landed);
        }
        ENTITY_TYPE_WORLD => {
            if stamp.birth_facet != *crate::claim::substrate_facet_id(sender)?.as_bytes() {
                return Ok(None);
            }
            let facet = crate::claim::substrate_facet_id(here)?;
            stamp.birth_facet = *facet.as_bytes();
            stamp.scope.facets = singleton(ScopeId(facet));
        }
        _ => return Ok(None),
    }
    encode(&stamp).map(Some)
}

/// The birth scope of the WORLD row `id` admission derives for a guest's
/// base copy (FIX 3831; Engine ruling 09:39 A): a WORLD row's own default
/// position, at `sensitivity`, the narrowest of the CLAIMs it lands with.
///
/// # Errors
///
/// A substrate facet derive error.
pub(crate) fn derived_world_birth_scope(
    id: EntityId,
    sensitivity: SensitivityCeiling,
) -> Result<Vec<u8>> {
    let facet = crate::claim::substrate_facet_id(id)?;
    let mut scope = default_stamp(ENTITY_TYPE_WORLD, facet);
    scope.sensitivity = sensitivity;
    encode(&Stamp {
        version: STAMP_VERSION,
        kind: ENTITY_TYPE_WORLD,
        birth_facet: *facet.as_bytes(),
        scope,
    })
}
