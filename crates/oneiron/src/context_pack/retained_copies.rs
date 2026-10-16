//! Retained courtesy copies stay out of shared retrieval (BIZ-LEGAL-0004 B2,
//! Docs Q09). When the owner answers a courtesy deletion ask with any choice
//! but delete, the copies its pact delivered stay the owner's to read, and
//! leave every pack served to anyone else. The retention choice grants no
//! use of the copy in a shared read.

use heed::RoTxn;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimBody, decode_claim_body};
use crate::disclosure::{DisclosureContext, DisclosureMode};
use crate::store::Store;
use crate::{EntityId, Result};

/// The pack clamp's admission, with retained courtesy copies withheld from
/// every audience but the owner alone. A copy is a CLAIM in a foreign world
/// that a pact with a retained ask registered. The ask's own world list
/// names the requester's ids, which this vault does not map, and no row
/// records its delivery epoch, so every world of that pact is withheld.
pub(crate) fn clamp_admits(
    ctx: &DisclosureContext,
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    claim_body: Option<&ClaimBody>,
) -> Result<bool> {
    if !ctx.admits(store, rtxn, id, entity_type, claim_body)? {
        return Ok(false);
    }
    if ctx.mode() == DisclosureMode::OwnerAlone || entity_type != crate::registry::ENTITY_TYPE_CLAIM
    {
        return Ok(true);
    }
    let world = match claim_body {
        Some(body) => body.world,
        None => {
            let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, rtxn, id)? else {
                return Ok(false);
            };
            let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
                return Ok(false);
            };
            decode_claim_body(body, true)?.world
        }
    };
    let Some(world) = world.filter(|world| crate::entity_id::is_foreign_world_id_range(*world))
    else {
        return Ok(true);
    };
    for pact in crate::deletion::courtesy_retained_pacts_in(store, rtxn)? {
        if crate::federation::world_registered_to_pact_in(store, rtxn, &pact, world)? {
            return Ok(false);
        }
    }
    Ok(true)
}
