//! The birth position of an identity topology event (FIX
//! DISTINCT-EVENT-DEFAULT-PROJECT-STAMP).

use super::*;
use crate::identity_topology::{AdmissionDisposition, StoredIdentityOpAction};

/// The position the identity topology event `id` of `kind`, with body
/// `data`, is born at, under its own substrate facet. An AssertDistinct event
/// names its pair and its `entity.distinct_from` CLAIM, and that CLAIM
/// stands where the words that asserted it stand (`DistinctClaimPlace`, FIX
/// INTENT-DISTINCT-PROJECT-WORLD). So the event is born in that CLAIM's
/// project and world, as stored here, and so are the rows that annotate the
/// event: the admission disposition that signs it and its author attribution
/// and redaction sidecars. A door that judges a row by its own stamp
/// (`records_in_scope`, a selector window) then reads the event only where
/// it reads the CLAIM, never in the default project. Every other action, a
/// body that does not decode, and an anchor with no stamp of its kind here
/// (a replicated event) keep the default position. An event already stamped
/// keeps its stamp: an event is immutable, and one stored before this rule
/// reads as it was born.
pub(super) fn identity_event_position(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<(Scope, EntityId)> {
    let facet = crate::claim::substrate_facet_id(id)?;
    if let Some(stamp) = SCOPE_RECORD.get(store, txn, &id)?
        && stamp.version == 2
        && stamp.kind == kind
        && stamp.birth_facet == *facet.as_bytes()
    {
        return Ok((stamp.scope, facet));
    }
    let mut scope = default_stamp(kind, facet);
    if let Some(anchor) = anchor_position(store, txn, data)? {
        scope.worlds = anchor.worlds;
        scope.audience = anchor.audience;
    }
    Ok((scope, facet))
}

/// The stored position of the row an event takes its place from: an
/// AssertDistinct event's CLAIM, and the target event of an admission
/// disposition or an author attribution or redaction sidecar.
/// `None` for any other action, a body that does not decode, or an anchor
/// with no stamp of its kind.
fn anchor_position(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    data: &[u8],
) -> Result<Option<Scope>> {
    let Ok(event) = crate::identity_topology::decode_identity_topology_event_body(data) else {
        return Ok(None);
    };
    let (anchor, anchor_kind) = match event.action {
        StoredIdentityOpAction::AssertDistinct { claim, .. } => {
            (claim, crate::registry::ENTITY_TYPE_CLAIM)
        }
        StoredIdentityOpAction::AdmissionDisposition(AdmissionDisposition { target, .. })
        | StoredIdentityOpAction::AuthorAttribution { target, .. }
        | StoredIdentityOpAction::AuthorRedaction { target, .. } => {
            (target, crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT)
        }
        _ => return Ok(None),
    };
    Ok(SCOPE_RECORD
        .get(store, txn, &anchor)?
        .filter(|stamp| stamp.version == 2 && stamp.kind == anchor_kind)
        .map(|stamp| stamp.scope))
}

/// The world the identity topology event `id` of `kind` sits in, as
/// `record_world_in` answers it (FIX DISTINCT-EVENT-WORLD-RESIDENCE): the one
/// world its birth stamp names. An AssertDistinct event, and the disposition
/// and author sidecars that annotate it, are stamped at their CLAIM's world
/// (`identity_event_position`), so every door that judges a row by its
/// world reads them where it reads the CLAIM: a read narrowed on worlds, and
/// the exports of a world kept on this device, which then keep them here
/// with the CLAIM (`settings::device_only`). Their window partition stays
/// the base window (`sync::types::entity_world` reads bytes only): every
/// door that serves a base window's rows to a reader judges each row here
/// or by its stamp. An event with no stamp of its kind bound here (a
/// replica: a peer mints no position, FIX 11925), or with no single world
/// stamped, is base reality, as every event read before this rule; one
/// stamped before FIX DISTINCT-EVENT-DEFAULT-PROJECT-STAMP carries the default
/// base stamp and reads as before.
pub(super) fn identity_event_world(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    kind: u8,
) -> Result<Option<Option<EntityId>>> {
    let world = match stored_scope(store, txn, id, kind)?.map(|scope| scope.worlds) {
        Some(ScopeAxis::Some(worlds)) if worlds.len() == 1 => worlds
            .first()
            .map(|world| world.0)
            .filter(|world| *world != crate::claim::base_world_id()),
        _ => None,
    };
    Ok(Some(world))
}
