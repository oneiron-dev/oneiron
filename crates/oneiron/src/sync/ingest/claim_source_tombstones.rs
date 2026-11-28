//! Which carrier tombstones an own-vault CLAIM put may take as a cited source's deletion. The
//! window's tombstone pass runs after its entity pass, so the put reads the carrier itself, and it
//! takes only a tombstone that pass replays (#10654 review r1): one that classifies as a replay of
//! that id, with its residence proven for the window as `stage_tombstones_in_txn` requires. A
//! wrong residence is refused there, and an unknown one in a world window is skipped unless the
//! carrier holds the id's retained shell of this window. A tombstone the pass skips proves nothing,
//! so a CLAIM put beside it never takes a durable stale mark from it.

use super::{IngestCtx, TombstoneStep};
use crate::EntityId;
use crate::error::Result;
use crate::sync::loro_support::{TombstoneIndex, map_get_bytes};
use crate::sync::types::{
    TombstoneResidence, retained_world_shell_belongs_to_window, tombstone_residence_in,
};
use std::collections::BTreeSet;

/// The sources the CLAIM in `body` cites whose carrier tombstone the tombstone pass replays.
/// Empty with no carrier, an undecodable body or no locator citation: the put then judges each
/// source on local evidence alone.
pub(in crate::sync) fn proven_carrier_deletions_in_txn(
    ctx: &IngestCtx<'_>,
    txn: &heed::RoTxn<'_>,
    body: &[u8],
) -> Result<BTreeSet<EntityId>> {
    let mut proven = BTreeSet::new();
    let (Some(doc), Some(window)) = (
        ctx.carrier_doc(),
        crate::sync::WindowKey::try_new(ctx.window_key),
    ) else {
        return Ok(proven);
    };
    let Ok(claim) = crate::claim::decode_claim_body(body, true) else {
        return Ok(proven);
    };
    let Ok(sources) = crate::dreamer_consolidation::replicated_sources::cited_sources(&claim)
    else {
        return Ok(proven);
    };
    let tombstones = doc.get_map("tombstones");
    let entities = doc.get_map("entities");
    let mut index = None;
    for source in sources {
        let hex = source.to_hex();
        let Some(value) = map_get_bytes(&tombstones, &hex) else {
            continue;
        };
        if !matches!(
            super::classify_tombstone_in_txn(ctx.vault, txn, &entities, &hex, &value),
            TombstoneStep::Replay { id, .. } if id == source
        ) {
            continue;
        }
        let replayed = match tombstone_residence_in(ctx.vault, txn, &source, &window)? {
            TombstoneResidence::Wrong => false,
            TombstoneResidence::Unknown if window.world().is_some() => {
                let index = index.get_or_insert_with(|| TombstoneIndex::build(&tombstones));
                match map_get_bytes(&entities, &hex) {
                    Some(raw) => retained_world_shell_belongs_to_window(
                        ctx.vault, txn, doc, index, &source, &raw, &window, false,
                    )?,
                    None => false,
                }
            }
            TombstoneResidence::Match | TombstoneResidence::Unknown => true,
        };
        if replayed {
            proven.insert(source);
        }
    }
    Ok(proven)
}
