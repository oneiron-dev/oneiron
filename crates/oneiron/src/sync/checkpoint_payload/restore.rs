//! A window's Loro rows put back from a checkpoint (KS7-3b, FIX 5688). Each
//! carrier's values come from the copies that opened: the first copy of a
//! value whose holder and dependencies opened, with each of its actors that
//! opened filled back by its family ([`root_fill`]). A value none of whose
//! copies opened is erased: the vendored join writes it as a delete at its
//! own operation, so the history keeps every id, dependency and timestamp.
//! A row birth whose actor did not open goes the same way; another family's
//! actor that did not open leaves its no-one form. The join proves its bytes
//! against the skeleton before anything is returned, and each row is cut
//! from them again as its slice. Every restored window is marked for a full
//! resync, and one whose history lost a value or an actor is pinned
//! history-free, as an actor's erase pins it. A missing leaf never refuses;
//! an opened copy that does not read does.

use std::collections::{BTreeMap, BTreeSet};

use loro::checkpoint::{Atom, AtomId, Payload, Skeleton, SlotKind};
use loro::{LoroDoc, LoroValue};

use super::operations::{export_slice, holds_slice};
use super::owners::{root_entry, root_fill};
use super::{
    KindPlacement, LoroCarrier, LoroSlot, LoroVerdict, OpenedAtom, OpenedSyncAtoms, Placement,
    SlotCopy, SyncCarrier, SyncPayloadOwners, SyncRestoreRows, SyncUnclassified, WINDOW_ROUND_TRIP,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{SYNC_HISTORY_FREE_WINDOW, SideTableDecl, WINDOW_FULL_RESYNC_MARKER};
use crate::store::checkpoint_payload::rows::{RowDb, RowLocator, bad_part};

/// Whether a restored window whose history lost a value or an actor is
/// pinned history-free: its history now differs, at the same operation ids,
/// from the one the owner's other machines hold, as an actor's erase leaves
/// it (FIX 6387). Call, behind this one constant.
const ALTERED_WINDOW_HISTORY_FREE: bool = true;

/// The byte a window marker holds.
const MARKER: [u8; 1] = [1];

/// Every entity kind its own: an opened value is read with its family's
/// codec, not placed again.
struct AnyKind;

impl SyncPayloadOwners for AnyKind {
    fn entity_kind(&self, _: u8) -> KindPlacement {
        KindPlacement::Owner
    }
}

pub(super) fn restore(
    carriers: &[LoroCarrier],
    opened: &dyn OpenedSyncAtoms,
) -> Result<SyncRestoreRows> {
    let mut restored = SyncRestoreRows::default();
    let mut markers = BTreeMap::new();
    for carrier in carriers {
        let (bytes, lossless, equivalent) = join(carrier, opened, &mut restored.dropped)?;
        let doc = LoroDoc::from_snapshot(&bytes).map_err(|_| bad_part())?;
        for row in &carrier.rows {
            if row.at.db != row.carrier.db() || !row.at.path.is_empty() {
                return Err(bad_part());
            }
            let blob = export_slice(&doc, &row.slice)?;
            if !holds_slice(&blob, &row.slice) {
                return Err(bad_part());
            }
            let value = match row.carrier {
                SyncCarrier::WindowSnapshot | SyncCarrier::WindowUpdate => blob,
                SyncCarrier::SyncQueue => {
                    crate::sync::queue::checkpoint::queued_row(&carrier.window, &blob)?
                }
                _ => return Err(bad_part()),
            };
            restored.rows.push((row.at.clone(), value));
        }
        let resync = marker(&WINDOW_FULL_RESYNC_MARKER, &carrier.window);
        markers.insert(resync, MARKER.to_vec());
        if !lossless && ALTERED_WINDOW_HISTORY_FREE {
            let history_free = marker(&SYNC_HISTORY_FREE_WINDOW, &carrier.window);
            markers.insert(history_free, MARKER.to_vec());
        }
        restored.verdicts.push(LoroVerdict {
            window: carrier.window.clone(),
            equivalent,
            lossless,
            policy: WINDOW_ROUND_TRIP,
        });
    }
    restored.markers = markers.into_iter().collect();
    Ok(restored)
}

/// `window`'s row of the marker table `decl`.
fn marker(decl: &SideTableDecl, window: &str) -> RowLocator {
    let mut key = decl.prefix.to_vec();
    key.extend_from_slice(window.as_bytes());
    RowLocator::row(RowDb::of(decl), key)
}

/// Joins `carrier` from the copies `opened` holds: its native snapshot
/// bytes, whether every value and actor opened, and the join report's
/// verdict. Each copy of a value that went is in `dropped`.
fn join(
    carrier: &LoroCarrier,
    opened: &dyn OpenedSyncAtoms,
    dropped: &mut Vec<RowLocator>,
) -> Result<(Vec<u8>, bool, bool)> {
    let skeleton = &carrier.skeleton;
    if carrier.slots.len() != skeleton.slots.len() {
        return Err(bad_part());
    }
    let sites = sites(skeleton)?;
    let mut available = Vec::new();
    let mut erased = Vec::new();
    let mut lossless = true;
    for (index, ((slot, site), shape)) in carrier
        .slots
        .iter()
        .zip(sites)
        .zip(&skeleton.slots)
        .enumerate()
    {
        let id = AtomId::try_from(index).map_err(|_| bad_part())?;
        let (root, key) = site.ok_or_else(bad_part)?;
        if shape.kind != SlotKind::Value {
            return Err(bad_part());
        }
        match open_slot(slot, root, key, opened)? {
            Some((value, whole)) => {
                lossless &= whole;
                available.push(Atom {
                    id,
                    holders: shape.holders.clone(),
                    payload: Payload::Value(LoroValue::Binary(value.into())),
                });
            }
            None => {
                lossless = false;
                erased.push(id);
                dropped.extend(slot.copies.iter().map(|copy| copy.at.clone()));
            }
        }
    }
    let joined =
        LoroDoc::join_root_map_checkpoint(skeleton, &available, &erased).map_err(|_| bad_part())?;
    if !joined.report.equivalent {
        return Err(bad_part());
    }
    Ok((joined.bytes, lossless, joined.report.equivalent))
}

/// Each slot's root map and key, as the skeleton's operations and winners
/// name it; `None` for a slot none names. A slot two sites name apart
/// refuses.
fn sites(skeleton: &Skeleton) -> Result<Vec<Option<(&str, &str)>>> {
    let mut sites: Vec<Option<(&str, &str)>> = vec![None; skeleton.slots.len()];
    let ops = skeleton
        .changes
        .iter()
        .flat_map(|change| &change.ops)
        .map(|op| (op.root, op.key.as_str(), op.value));
    let winners = skeleton
        .shallow
        .iter()
        .flat_map(|root| &root.winners)
        .chain(&skeleton.latest)
        .map(|winner| (winner.root, winner.key.as_str(), winner.value));
    for (root, key, value) in ops.chain(winners) {
        let Some(value) = value else {
            continue;
        };
        let root = usize::try_from(root)
            .ok()
            .and_then(|root| skeleton.roots.get(root))
            .ok_or_else(bad_part)?;
        let site = usize::try_from(value)
            .ok()
            .and_then(|slot| sites.get_mut(slot))
            .ok_or_else(bad_part)?;
        let named = (root.as_str(), key);
        if site.is_some_and(|known| known != named) {
            return Err(bad_part());
        }
        *site = Some(named);
    }
    Ok(sites)
}

/// The value `slot` puts back, from its first copy that opened, and
/// whether every actor it names opened: `None` when no copy opened, or its
/// family drops it for an actor that did not.
fn open_slot(
    slot: &LoroSlot,
    root: &str,
    key: &str,
    opened: &dyn OpenedSyncAtoms,
) -> Result<Option<(Vec<u8>, bool)>> {
    for copy in &slot.copies {
        let OpenedAtom::Opened(value) = opened.atom(copy.atom) else {
            continue;
        };
        if slot.holes.is_empty() {
            check(root, key, value)?;
            return Ok(Some((value.to_vec(), true)));
        }
        let actors = opened_actors(slot, copy, opened)?;
        let whole = actors.len() == slot.holes.len();
        let Some(filled) = root_fill(root, key, value, &actors)? else {
            return Ok(None);
        };
        check(root, key, &filled)?;
        return Ok(Some((filled, whole)));
    }
    Ok(None)
}

/// The actors of `copy` that opened, each at one of its slot's fields. A
/// part naming another copy, a field the slot does not hold, one filled
/// twice, or bytes that are not the actor's id refuse.
fn opened_actors<'s>(
    slot: &'s LoroSlot,
    copy: &SlotCopy,
    opened: &dyn OpenedSyncAtoms,
) -> Result<Vec<(&'s str, EntityId)>> {
    let mut actors = Vec::new();
    let mut fields = BTreeSet::new();
    for part in opened.actor_parts(copy.atom) {
        let field = slot
            .holes
            .iter()
            .find(|hole| **hole == part.field)
            .ok_or_else(bad_part)?;
        if part.content_locator != copy.at || !fields.insert(field.as_str()) {
            return Err(bad_part());
        }
        let id: [u8; 16] = part.bytes.as_slice().try_into().map_err(|_| bad_part())?;
        let actor = EntityId::from_bytes(id)?;
        if actor != part.actor_entity {
            return Err(bad_part());
        }
        actors.push((field.as_str(), actor));
    }
    Ok(actors)
}

/// Refuses an opened value its family's codec does not read.
fn check(root: &str, key: &str, value: &[u8]) -> Result<()> {
    match root_entry(root, key, value, &AnyKind) {
        Placement::Unclassified {
            reason: SyncUnclassified::Undecodable,
            ..
        } => Err(bad_part()),
        _ => Ok(()),
    }
}
