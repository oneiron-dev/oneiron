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
//! an opened copy that does not read does, and so does one whose bytes came
//! from a home other than the one its capture placed it in (FIX 10283). A
//! room turn carried joined opens once, its actor filled back, and each slot
//! derived from it is made from its re-part (FIX 12153); a turn none of
//! whose copies opened erases every one of them.

use std::collections::{BTreeMap, BTreeSet};

use loro::checkpoint::{
    Atom, AtomId, KEY_PLACEHOLDER_PREFIX, Payload, Skeleton, SlotKind, placeholder_atom,
};
use loro::{LoroDoc, LoroValue};

use super::joined_turns::{Transport, derived_atom};
use super::operations::{export_slice, holds_slice};
use super::owners::{
    key_fill, root_entry, root_fill, withheld_client_key, withheld_key, withheld_part_key,
};
use super::{
    DerivedRole, DerivedSlot, JoinedTurn, KindPlacement, LoroCarrier, LoroSlot, LoroVerdict,
    OpenedAtom, OpenedSyncAtoms, Placement, SlotCopy, SyncCarrier, SyncPayloadOwners,
    SyncRestoreRows, SyncUnclassified, WINDOW_ROUND_TRIP,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{SYNC_HISTORY_FREE_WINDOW, SideTableDecl, WINDOW_FULL_RESYNC_MARKER};
use crate::store::checkpoint_payload::rows::{RowDb, RowLocator, bad_part};
use crate::sync::room_turns::ROOM_TURNS_MAP;
use crate::sync::room_turns::checkpoint::{ACTOR, entry_joined, fill_joined};

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
    // Each joined turn opens once, before any slot derived from it (FIX
    // 12153).
    let mut turns = Vec::with_capacity(carrier.joined.len());
    for turn in &carrier.joined {
        let transport = open_turn(turn, opened)?;
        match &transport {
            Some((_, whole)) => lossless &= *whole,
            None => {
                lossless = false;
                dropped.extend(turn.copies.iter().map(|copy| copy.at.clone()));
            }
        }
        turns.push(transport.map(|(transport, _)| transport));
    }
    // Withheld keys open first (FIX 10279): a value under one is read under
    // the key it opened to, and goes with a key that did not open.
    let mut keys: BTreeMap<AtomId, String> = BTreeMap::new();
    let mut derived_keys: BTreeMap<AtomId, DerivedSlot> = BTreeMap::new();
    for (index, ((slot, site), shape)) in carrier
        .slots
        .iter()
        .zip(&sites)
        .zip(&skeleton.slots)
        .enumerate()
    {
        if shape.kind != SlotKind::Key {
            continue;
        }
        let id = AtomId::try_from(index).map_err(|_| bad_part())?;
        let Some((root, _)) = *site else {
            return Err(bad_part());
        };
        if let Some(derived) = slot.derived {
            let DerivedRole::PartKey(_) = derived.role else {
                return Err(bad_part());
            };
            let (_, transport) = derived_from(carrier, slot, root, derived, &turns)?;
            derived_keys.insert(id, derived);
            match derived_atom(id, &shape.holders, derived.role, transport) {
                Some(atom) => {
                    let Payload::Key(key) = &atom.payload else {
                        return Err(bad_part());
                    };
                    keys.insert(id, key.clone());
                    available.push(atom);
                }
                None => {
                    lossless = false;
                    erased.push(id);
                }
            }
            continue;
        }
        match open_key(slot, root, opened)? {
            Some((key, whole)) => {
                lossless &= whole;
                keys.insert(id, key.clone());
                available.push(Atom {
                    id,
                    holders: shape.holders.clone(),
                    payload: Payload::Key(key),
                });
            }
            None => {
                lossless = false;
                erased.push(id);
                dropped.extend(slot.copies.iter().map(|copy| copy.at.clone()));
            }
        }
    }
    for (index, ((slot, site), shape)) in carrier
        .slots
        .iter()
        .zip(&sites)
        .zip(&skeleton.slots)
        .enumerate()
    {
        let id = AtomId::try_from(index).map_err(|_| bad_part())?;
        let Some((root, key)) = *site else {
            return Err(bad_part());
        };
        match shape.kind {
            SlotKind::Key => continue,
            SlotKind::Value => {}
            SlotKind::Message => return Err(bad_part()),
        }
        if let Some(derived) = slot.derived {
            let (turn, transport) = derived_from(carrier, slot, root, derived, &turns)?;
            let named = match derived.role {
                DerivedRole::Manifest => key == turn.key,
                // A part's bytes sit under its derived key: the same turn's
                // key slot at the same place.
                DerivedRole::PartValue(place) => match placeholder_atom(key) {
                    Some(Some(atom)) => {
                        derived_keys.get(&atom)
                            == Some(&DerivedSlot {
                                source: derived.source,
                                role: DerivedRole::PartKey(place),
                            })
                    }
                    _ => false,
                },
                DerivedRole::PartKey(_) => false,
            };
            if !named {
                return Err(bad_part());
            }
            match derived_atom(id, &shape.holders, derived.role, transport) {
                Some(atom) => available.push(atom),
                None => {
                    lossless = false;
                    erased.push(id);
                }
            }
            continue;
        }
        let key = match placeholder_atom(key) {
            None => Some(key),
            Some(atom) => keys.get(&atom.ok_or_else(bad_part)?).map(String::as_str),
        };
        let value = match key {
            Some(key) => open_slot(slot, root, key, opened)?,
            None => None,
        };
        match value {
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

/// The joined turn `turn` re-parted as it opened, from its first copy that
/// opened with each of its actors that did back, and whether every one did:
/// `None` when no copy opened. A copy from a home other than its capture's,
/// a field other than the turn's actor, or a turn that does not read as its
/// row under its key, or does not re-part in its parts' place, refuses.
fn open_turn(turn: &JoinedTurn, opened: &dyn OpenedSyncAtoms) -> Result<Option<(Transport, bool)>> {
    if turn.holes.len() > 1 || turn.holes.iter().any(|hole| hole != ACTOR) {
        return Err(bad_part());
    }
    let parts = usize::try_from(turn.parts).map_err(|_| bad_part())?;
    for copy in &turn.copies {
        let OpenedAtom::Opened(value) = opened.atom(copy.atom) else {
            continue;
        };
        if opened.opened_home(copy.atom) != Some(copy.home) {
            return Err(bad_part());
        }
        let actors = opened_actors(&turn.holes, copy, opened)?;
        let whole = actors.len() == turn.holes.len();
        let filled = fill_joined(value, &actors)?;
        if !matches!(
            entry_joined(&turn.key, &filled),
            Placement::Split { .. } | Placement::Owned(_)
        ) {
            return Err(bad_part());
        }
        return Ok(Some((Transport::of(&filled, parts)?, whole)));
    }
    Ok(None)
}

/// The joined turn the derived slot `slot` of `root` names, and its re-part
/// as it opened: `None` when it did not. A derived slot holding a copy or a
/// field, outside the room turn map, naming no joined turn, or a part past
/// its turn's, refuses.
fn derived_from<'c>(
    carrier: &'c LoroCarrier,
    slot: &LoroSlot,
    root: &str,
    derived: DerivedSlot,
    turns: &'c [Option<Transport>],
) -> Result<(&'c JoinedTurn, Option<&'c Transport>)> {
    if !slot.copies.is_empty() || !slot.holes.is_empty() || root != ROOM_TURNS_MAP {
        return Err(bad_part());
    }
    let source = usize::try_from(derived.source).map_err(|_| bad_part())?;
    let (Some(turn), Some(transport)) = (carrier.joined.get(source), turns.get(source)) else {
        return Err(bad_part());
    };
    if let DerivedRole::PartKey(place) | DerivedRole::PartValue(place) = derived.role
        && place >= turn.parts
    {
        return Err(bad_part());
    }
    Ok((turn, transport.as_ref()))
}

/// The withheld key `slot` puts back, from its first copy that opened, and
/// whether every actor it names opened: `None` when no copy opened, or the
/// actor it names did not. A key its family does not withhold, or one
/// spelled as a placeholder, refuses.
fn open_key(
    slot: &LoroSlot,
    root: &str,
    opened: &dyn OpenedSyncAtoms,
) -> Result<Option<(String, bool)>> {
    for copy in &slot.copies {
        let OpenedAtom::Opened(value) = opened.atom(copy.atom) else {
            continue;
        };
        if opened.opened_home(copy.atom) != Some(copy.home) {
            return Err(bad_part());
        }
        let (key, whole) = if slot.holes.is_empty() {
            let key = std::str::from_utf8(value).map_err(|_| bad_part())?;
            (key.to_owned(), true)
        } else {
            let actors = opened_actors(&slot.holes, copy, opened)?;
            let whole = actors.len() == slot.holes.len();
            let Some(key) = key_fill(root, value, &actors)? else {
                return Ok(None);
            };
            (key, whole)
        };
        if key.starts_with(KEY_PLACEHOLDER_PREFIX)
            || (withheld_key(root, &key).is_none()
                && !withheld_part_key(root, &key)
                && withheld_client_key(root, &key).is_none())
        {
            return Err(bad_part());
        }
        return Ok(Some((key, whole)));
    }
    Ok(None)
}

/// Each slot's root map and key, as the skeleton's operations and winners
/// name it; `None` for a slot none names. A withheld key's slot is named by
/// its placeholder, a delete's too. A slot two sites name apart refuses.
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
        let root = usize::try_from(root)
            .ok()
            .and_then(|root| skeleton.roots.get(root))
            .ok_or_else(bad_part)?;
        let named = (root.as_str(), key);
        let withheld = match placeholder_atom(key) {
            None => None,
            Some(atom) => Some(atom.ok_or_else(bad_part)?),
        };
        for slot in withheld.into_iter().chain(value) {
            let site = usize::try_from(slot)
                .ok()
                .and_then(|slot| sites.get_mut(slot))
                .ok_or_else(bad_part)?;
            if site.is_some_and(|known| known != named) {
                return Err(bad_part());
            }
            *site = Some(named);
        }
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
        // Opened bytes count only from the home the capture placed this copy
        // in (FIX 10283): another holder's compartment never stands in.
        if opened.opened_home(copy.atom) != Some(copy.home) {
            return Err(bad_part());
        }
        if slot.holes.is_empty() {
            check(root, key, value)?;
            return Ok(Some((value.to_vec(), true)));
        }
        let actors = opened_actors(&slot.holes, copy, opened)?;
        let whole = actors.len() == slot.holes.len();
        let holes: BTreeSet<&str> = slot.holes.iter().map(String::as_str).collect();
        let Some(filled) = root_fill(root, key, value, &actors, &holes)? else {
            return Ok(None);
        };
        check(root, key, &filled)?;
        return Ok(Some((filled, whole)));
    }
    Ok(None)
}

/// The actors of `copy` that opened, each at one of its value's fields
/// `holes`. A part naming another copy, a field the value does not hold, one
/// filled twice, or bytes that are not the actor's id refuse.
fn opened_actors<'s>(
    holes: &'s [String],
    copy: &SlotCopy,
    opened: &dyn OpenedSyncAtoms,
) -> Result<Vec<(&'s str, EntityId)>> {
    let mut actors = Vec::new();
    let mut fields = BTreeSet::new();
    for part in opened.actor_parts(copy.atom) {
        let field = holes
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
