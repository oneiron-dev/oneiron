//! The owner's discard of a world copy, projected onto the NOTE carriers a
//! persisted BASE window holds (FIX 14534 part E). Pure codec logic over the
//! five NOTE maps: the window's payload projector applies [`project_atom`]
//! to each value atom of those maps, current and historical, and installs
//! [`project_current`] as the window's current state. Neither authors an
//! operation; the projector rewrites the atoms in place.
//!
//! A row belongs to the NOTE it decodes to, never to a fork, receipt or
//! bundle id. A bundle that held a member of a discarded NOTE keeps its
//! other members, its shared explainer redacted and the bundle marked
//! incomplete, as a deletion leaves it; one left with no member goes.

use super::*;
use crate::recovery::{CanonicalHead, CanonicalHeadMove};

/// What one value atom of a NOTE carrier map becomes once the discarded
/// NOTEs left this vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NoteAtom {
    /// It names no discarded NOTE.
    Keep,
    /// A discarded NOTE owns it, or it was a bundle of discarded NOTEs alone.
    Drop,
    /// A bundle that kept other members: these bytes, redacted.
    Rewrite(Vec<u8>),
}

/// Whether `map` is one of the five NOTE carrier maps this module projects.
pub(crate) fn is_note_carrier_map(map: &str) -> bool {
    MAPS.contains(&map)
}

/// `value`, a value atom of the NOTE carrier map `map` under `key`, once
/// the NOTEs in `discarded` are gone: a proposal value, head, landing
/// receipt or fork a discarded NOTE owns goes; a bundle holding a member of
/// one keeps its other members, redacted, or goes with none left; every
/// other atom stays, the NOTE sync format row included.
///
/// # Errors
///
/// A map that is no NOTE carrier map, or an atom that does not decode as
/// its map's row: its owner is unknown, so it is never counted as erased.
pub(crate) fn project_atom(
    map: &str,
    key: &str,
    value: &[u8],
    discarded: &BTreeSet<EntityId>,
) -> Result<NoteAtom> {
    let owned = |note: &EntityId| {
        if discarded.contains(note) {
            NoteAtom::Drop
        } else {
            NoteAtom::Keep
        }
    };
    Ok(match map {
        "documents" => {
            if key == FORMAT_KEY {
                return Ok(NoteAtom::Keep);
            }
            let parts: Vec<_> = key.split(':').collect();
            if parts.len() != 4 || parts[0] != "note_proposal_doc" || parts[1] != "v1" {
                return Err(invalid("NOTE document key"));
            }
            unpack::<String>(value)?;
            owned(&id(parts[2])?)
        }
        "document_heads" => {
            let row: CanonicalHead = unpack(value)?;
            owned(&EntityId::from_bytes(row.entity_id)?)
        }
        "head_move_receipts" => {
            let wrapper: CanonicalHeadMove = unpack(value)?;
            let row: NoteLandingReceipt = unpack(&wrapper.receipt)?;
            owned(&row.note)
        }
        "note_forks" => owned(&unpack::<NoteFork>(value)?.note),
        "note_proposals" => {
            let mut carrier: BundleCarrier = unpack(value)?;
            if bundle_notes(&carrier.bundle).is_disjoint(discarded) {
                return Ok(NoteAtom::Keep);
            }
            carrier
                .bundle
                .waiting
                .retain(|fork| !discarded.contains(&fork.note));
            carrier
                .bundle
                .landed
                .retain(|receipt| !discarded.contains(&receipt.note));
            if carrier.bundle.waiting.is_empty() && carrier.bundle.landed.is_empty() {
                NoteAtom::Drop
            } else {
                carrier.redact();
                NoteAtom::Rewrite(pack(&carrier)?)
            }
        }
        _ => return Err(invalid("not a NOTE carrier map")),
    })
}

/// The current rows of `doc`'s five NOTE carrier maps that change once the
/// NOTEs in `discarded` are gone, by map and key, each with its new bytes
/// or none for a row that goes. Beyond what [`project_atom`] takes from each
/// row, the attachments of the NOTEs the window still carries that only a
/// departed member bound go too, as a deletion prunes them, so the window
/// still validates. A window that holds no NOTE carrier changes nothing.
///
/// # Errors
///
/// A NOTE carrier that does not decode.
pub(crate) fn project_current(
    doc: &LoroDoc,
    discarded: &BTreeSet<EntityId>,
) -> Result<BTreeMap<(&'static str, String), Option<Vec<u8>>>> {
    let mut held = BTreeMap::new();
    for name in MAPS {
        held.insert(
            name,
            rows(doc, name)?.into_iter().collect::<BTreeMap<_, _>>(),
        );
    }
    let mut changes = BTreeMap::new();
    if held.values().all(BTreeMap::is_empty) {
        return Ok(changes);
    }
    let mut state = codec::read(doc)?;
    state.drop_deleted(discarded);
    let projected = state.carrier_rows()?;
    for (name, rows) in held {
        let kept = projected.get(name);
        for (key, bytes) in rows {
            match kept.and_then(|kept| kept.get(&key)) {
                Some(after) if *after == bytes => {}
                after => {
                    changes.insert((name, key), after.cloned());
                }
            }
        }
    }
    Ok(changes)
}
