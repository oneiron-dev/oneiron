//! Hydrate's half of OF-329, the forms it serves in place of image bodies,
//! for every hydrate door: the canonical one records them in the vault
//! ([`crate::memory::Memory::serve_hydrated_assets`]) and a room's in the
//! room's own store (WILL L11-01 S01-2b), each before its door answers. The
//! serving itself records nothing.

use super::{AssetConsumer, HydratedAsset, hydrated_asset};
use crate::claim::{ScopedRead, ScopedReadReceipt};
use crate::memory::read_lane::ReadTargetSlot;
use crate::memory::structural::kind_string_for_type;
use crate::memory::support::decode_body_json;
use crate::memory::{EntityView, MemoryResult};
use crate::receipt::ServedForm;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::vault::ReadMode;

/// Serves each live image ASSET among `views`, read on `lane` at `targets`,
/// with a text this reader admits, as [`hydrated_asset`] serves a reader that
/// declared no image input: its view's body becomes the rung's, and each
/// asset's read restricts `receipt`. Every other view keeps its body.
/// Answers the forms served, in view order, for the door to record before it
/// answers; none for a hydrate that served no image.
pub(in crate::memory) fn serve_hydrated_views(
    lane: &ScopedRead<'_>,
    targets: &[ReadTargetSlot],
    views: &mut [EntityView],
    receipt: &mut ScopedReadReceipt,
) -> MemoryResult<Vec<ServedForm>> {
    let asset_kind = kind_string_for_type(ENTITY_TYPE_ASSET);
    let consumer = AssetConsumer::hydrate_reader(false);
    let mut served_forms = Vec::new();
    for (target, view) in targets.iter().zip(views) {
        let Some((asset, ReadMode::Live)) = target else {
            continue;
        };
        if view.kind != asset_kind {
            continue;
        }
        let served = hydrated_asset(lane, *asset, &consumer, None, &mut |_| true, None)?;
        receipt.restrict_with(&served.receipt);
        if let HydratedAsset::Served { body, form, .. } = served.value {
            view.body = decode_body_json(&body);
            served_forms.push(form);
        }
    }
    Ok(served_forms)
}
