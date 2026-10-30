//! The birth scope carriers of the rows a federation admission lands (FIX
//! 3656; Engine ruling 09:39 A).
//! The entry point is `copy_birth_scopes`.
//! Owned by `super`.
//!
//! Each row an admitted part carries keeps the birth scope its sender's
//! window holds beside it, under the id the row lands under. A verified
//! member's goes as it came: its rows are first-party here, as its CLAIMs'
//! worlds are. A guest's is moved as its CLAIMs are
//! (`record_scope::guest_birth_scope`): a TASK or SUMMARY to the foreign
//! WORLD its sender's world maps to, a WORLD row to its foreign id; a guest's
//! row of any other kind carries none and lands unstamped, as before. So do
//! the rows of an imported update no pact source names: no position is taken
//! from a sender this vault cannot place. The receiver's ingest judges each
//! carrier again before it stamps.

use std::collections::BTreeMap;

use loro::LoroDoc;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::sync::loro_support::{map_get_bytes, map_insert_bytes};
use crate::sync::window::birth_scope::BIRTH_SCOPES_MAP;

use super::ImportGrading;
use super::routing::GuestCopy;

/// Copies into `admitted` the birth scope `remote` carries for each row
/// `admitted` lands, under the id it lands under: a guest's (`guest`) as it
/// lands here, a first-party member's (`grading`) as it came, an imported
/// update's with no guest source none.
#[cfg(feature = "sync")]
pub(super) fn copy_birth_scopes(
    remote: &LoroDoc,
    admitted: &LoroDoc,
    guest: Option<GuestCopy<'_>>,
    grading: ImportGrading,
) -> Result<()> {
    let carried = remote.get_map(BIRTH_SCOPES_MAP);
    if carried.is_empty()
        || (guest.is_none() && matches!(grading, ImportGrading::Imported { .. }))
    {
        return Ok(());
    }
    // The sender's id of each row that lands under another id here, a
    // guest's WORLD (FIX 3657).
    let senders = guest.map_or_else(BTreeMap::new, |guest| {
        guest
            .worlds
            .iter()
            .map(|(sender, here)| (*here, *sender))
            .collect::<BTreeMap<EntityId, EntityId>>()
    });
    let landed = admitted
        .get_map("entities")
        .keys()
        .map(|key| key.to_string())
        .filter_map(|key| EntityId::from_hex(&key).ok().filter(|id| id.to_hex() == key))
        .collect::<Vec<_>>();
    let target = admitted.get_map(BIRTH_SCOPES_MAP);
    for here in landed {
        let sender = senders.get(&here).copied().unwrap_or(here);
        let Some(bytes) = map_get_bytes(&carried, &sender.to_hex()) else {
            continue;
        };
        let bytes = match guest {
            Some(guest) => match crate::federation::record_scope::guest_birth_scope(
                &bytes,
                guest.source,
                sender,
                here,
            )? {
                Some(bytes) => bytes,
                None => continue,
            },
            None => bytes,
        };
        map_insert_bytes(&target, &here.to_hex(), &bytes)?;
    }
    Ok(())
}
