//! Bind the temporary native read to the FINAL withheld-key capture.

use loro::LoroValue;
use loro::checkpoint::{Atom, AtomId, Parts, Payload, Site, SlotKind, placeholder_atom};

use super::{RecordDocumentSlot, RecordDocumentSlots};
use crate::store::checkpoint_payload::rows::Unresolved;
use crate::sync::carrier_parts::admit_part;
use crate::sync::skill_docs::SKILL_DOCS_MAP;
use crate::sync::skill_docs::checkpoint::capture::{
    CapturedPart, CapturedRecordDocument, CapturedSite,
};

pub(super) fn source(
    parts: &Parts,
    source: &CapturedRecordDocument,
) -> std::result::Result<RecordDocumentSlots, Unresolved> {
    let head = value(parts, SKILL_DOCS_MAP, &source.key, source.at)?;
    exact(parts, &head, &source.head)?;
    let rows = source
        .rows
        .iter()
        .map(|&at| {
            let slot = value(parts, "entities", &source.key, at)?;
            exact(parts, &slot, &source.split.row)?;
            Ok(slot)
        })
        .collect::<std::result::Result<Vec<_>, Unresolved>>()?;
    if rows.is_empty() {
        return Err(Unresolved::Undecodable);
    }
    let snapshot = leg(parts, &source.snapshot)?;
    let refinement = source
        .refinement
        .as_ref()
        .map(|positions| leg(parts, positions))
        .transpose()?;
    Ok(RecordDocumentSlots {
        head,
        rows,
        snapshot,
        refinement,
    })
}

fn leg(
    parts: &Parts,
    positions: &[CapturedPart],
) -> std::result::Result<Vec<Vec<RecordDocumentSlot>>, Unresolved> {
    positions
        .iter()
        .map(|position| {
            if position.sites.is_empty() {
                return Err(Unresolved::Undecodable);
            }
            position
                .sites
                .iter()
                .map(|&at| {
                    let slot = value(parts, SKILL_DOCS_MAP, &position.key, at)?;
                    if slot.key.is_none() {
                        return Err(Unresolved::Undecodable);
                    }
                    let payload = &atom(parts, slot.value, SlotKind::Value)?.payload;
                    let Payload::Value(value) = payload else {
                        return Err(Unresolved::Undecodable);
                    };
                    admit_part(&position.key, value).map_err(|_| Unresolved::Undecodable)?;
                    Ok(slot)
                })
                .collect()
        })
        .collect()
}

/// Native site identity selects the value. Callback encounter order and
/// temporary atom ordinals are deliberately never consulted.
fn value(
    parts: &Parts,
    root: &str,
    key: &str,
    at: CapturedSite,
) -> std::result::Result<RecordDocumentSlot, Unresolved> {
    let root = parts
        .skeleton
        .roots
        .iter()
        .position(|name| name == root)
        .and_then(|index| u32::try_from(index).ok())
        .ok_or(Unresolved::Undecodable)?;
    let mut found = None;
    match at.site {
        Site::Op(id) => {
            for change in &parts.skeleton.changes {
                if change.peer != id.peer {
                    continue;
                }
                let offset = i64::from(id.counter) - i64::from(change.counter);
                let Some(op) = usize::try_from(offset)
                    .ok()
                    .and_then(|offset| change.ops.get(offset))
                else {
                    continue;
                };
                if op.root != root {
                    return Err(Unresolved::Undecodable);
                }
                let key = key_slot(parts, &op.key, key)?;
                let slot = RecordDocumentSlot {
                    value: op.value.ok_or(Unresolved::Undecodable)?,
                    key,
                };
                unique(&mut found, slot)?;
            }
        }
        Site::Root => {
            // The vendor invokes Root only for a shallow winner whose op
            // is NOT retained. Latest-state references do not create atoms.
            for winner in parts.skeleton.shallow.iter().flat_map(|root| &root.winners) {
                if winner.root != root || !key_matches(parts, &winner.key, key)? {
                    continue;
                }
                let slot = RecordDocumentSlot {
                    value: winner.value.ok_or(Unresolved::Undecodable)?,
                    key: key_slot(parts, &winner.key, key)?,
                };
                unique(&mut found, slot)?;
            }
        }
    }
    let slot = found.ok_or(Unresolved::Undecodable)?;
    if !matches!(
        atom(parts, slot.value, SlotKind::Value)?.payload,
        Payload::Value(LoroValue::Binary(_))
    ) {
        return Err(Unresolved::Undecodable);
    }
    Ok(slot)
}

fn unique(
    found: &mut Option<RecordDocumentSlot>,
    slot: RecordDocumentSlot,
) -> std::result::Result<(), Unresolved> {
    if found.replace(slot).is_some() {
        return Err(Unresolved::Undecodable);
    }
    Ok(())
}

fn key_matches(parts: &Parts, spelled: &str, key: &str) -> std::result::Result<bool, Unresolved> {
    match placeholder_atom(spelled) {
        None => Ok(spelled == key),
        Some(Some(id)) => match &atom(parts, id, SlotKind::Key)?.payload {
            Payload::Key(opened) => Ok(opened == key),
            _ => Err(Unresolved::Undecodable),
        },
        Some(None) => Err(Unresolved::Undecodable),
    }
}

fn key_slot(
    parts: &Parts,
    spelled: &str,
    key: &str,
) -> std::result::Result<Option<AtomId>, Unresolved> {
    if !key_matches(parts, spelled, key)? {
        return Err(Unresolved::Undecodable);
    }
    match placeholder_atom(spelled) {
        None => Ok(None),
        Some(Some(id)) => Ok(Some(id)),
        Some(None) => Err(Unresolved::Undecodable),
    }
}

fn atom(parts: &Parts, id: AtomId, kind: SlotKind) -> std::result::Result<&Atom, Unresolved> {
    let index = usize::try_from(id).map_err(|_| Unresolved::Undecodable)?;
    let atom = parts.atoms.get(index).ok_or(Unresolved::Undecodable)?;
    let slot = parts
        .skeleton
        .slots
        .get(index)
        .ok_or(Unresolved::Undecodable)?;
    if atom.id != id
        || slot.kind != kind
        || atom.payload.kind() != kind
        || atom.holders != slot.holders
        || atom.holders.is_empty()
    {
        return Err(Unresolved::Undecodable);
    }
    Ok(atom)
}

fn exact(
    parts: &Parts,
    slot: &RecordDocumentSlot,
    expected: &[u8],
) -> std::result::Result<(), Unresolved> {
    match &atom(parts, slot.value, SlotKind::Value)?.payload {
        Payload::Value(LoroValue::Binary(bytes)) if bytes.as_slice() == expected => Ok(()),
        _ => Err(Unresolved::Undecodable),
    }
}
