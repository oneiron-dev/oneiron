//! `booking:emergency_uncertain_send:v1:` (FIX [BK-EMERGENCY-UNCERTAIN-SEND-NOT-SHOWN-TO-OWNER];
//! Engine ANSWER BK-EMERGENCY-UNCERTAIN-SEND-RECEIPT = A, 21 Nov 09:14): the owed effects of one
//! checkpoint whose send ended uncertain on an earlier home, as a home move carried them
//! (`super::home_rows`). The new home sends each again under the same idempotency key, so the
//! booker may receive it twice; each owner's run over the checkpoint once it is delivered says so
//! ([`super::execution::EmergencyRepeatNotice`]). The mark stays, and every later move carries
//! it, even once its send was delivered again (review round 1 of #10125): the answer replays, so
//! one that never reached the owner is given again (review round 2 of #10166).
//!
//! A side row beside the checkpoint, under the checkpoint's own key: the checkpoint's stored
//! shape stays as it was (stored change: keep).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use super::execution::{EMERGENCY_REPEAT_NOTICE, EmergencyRepeatNotice};
use super::planning::hex_suffix;
use super::*;
use crate::side_table::VersionedNamed;

/// The marks of each checkpoint, by its hex64 key (the key [`super::planning::ITEM`] holds it
/// under).
pub(super) const UNCERTAIN_SEND: SideTable<String, UncertainSends, VersionedNamed<1>> =
    SideTable::new(&side_table::EMERGENCY_UNCERTAIN_SEND);

/// One checkpoint's marked effects, each by its lane ([`owed_effects`] names the three).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UncertainSends {
    lanes: BTreeSet<String>,
}

/// The effects `item` still owes, each as its lane and the content hash its intent is keyed by
/// (`super::lookup`'s `index_item_in` spells the same three).
pub(super) fn owed_effects(item: &EmergencyItem) -> Vec<(&'static str, [u8; 32])> {
    let mut owed = Vec::new();
    if !item.calendar_delivered && item.plan.payload.is_some() {
        owed.push(("calendar", item.plan.content_hash));
    }
    if !item.apology_delivered {
        owed.push(("apology", item.plan.content_hash));
    }
    if let Some(picked) = item
        .picked
        .as_ref()
        .filter(|picked| !picked.calendar_delivered)
    {
        owed.push(("pick", picked.content_hash));
    }
    owed
}

/// The lanes among `lanes` that `item` still owes.
fn still_owed(lanes: impl IntoIterator<Item = String>, item: &EmergencyItem) -> BTreeSet<String> {
    let owed: BTreeSet<&str> = owed_effects(item)
        .into_iter()
        .map(|(lane, _)| lane)
        .collect();
    lanes
        .into_iter()
        .filter(|lane| owed.contains(lane.as_str()))
        .collect()
}

/// The lanes among `lanes` a move carries for `item`: a calendar or apology mark always,
/// delivered or not, since every owner's run over the checkpoint answers it ([`repeat_notices`];
/// review round 1 of #10125); a pick's mark, which no run answers, while the pick is owed.
fn carried_lanes(
    lanes: impl IntoIterator<Item = String>,
    item: &EmergencyItem,
) -> BTreeSet<String> {
    let pick_owed = owed_effects(item).iter().any(|(lane, _)| *lane == "pick");
    lanes
        .into_iter()
        .filter(|lane| match lane.as_str() {
            "calendar" | "apology" => true,
            "pick" => pick_owed,
            _ => false,
        })
        .collect()
}

/// The marked lanes of the checkpoint at `key` that the next move carries on
/// ([`carried_lanes`]). A row that does not decode marks nothing: the move is never held by it.
pub(super) fn carried_lanes_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    key: &str,
    item: &EmergencyItem,
) -> crate::error::Result<BTreeSet<String>> {
    Ok(UNCERTAIN_SEND
        .get_lenient(&vault.store, txn, &key.to_owned())?
        .map(|row| carried_lanes(row.lanes, item))
        .unwrap_or_default())
}

/// Lands the carried marks of the checkpoint at `key` ([`carried_lanes`]) in the adopting
/// writer, and answers how many it kept; with none the row goes, so a home that held the
/// checkpoint before keeps no older mark.
pub(super) fn land_in(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    key: &str,
    item: &EmergencyItem,
    carried: Vec<String>,
) -> crate::error::Result<usize> {
    let key = key.to_owned();
    let lanes = carried_lanes(carried, item);
    let kept = lanes.len();
    if lanes.is_empty() {
        UNCERTAIN_SEND.delete(&vault.store, txn, &key)?;
    } else {
        UNCERTAIN_SEND.put(&vault.store, txn, &key, &UncertainSends { lanes })?;
    }
    Ok(kept)
}

/// The owner's answer of a run over `item` (`super::execute_emergency_plan`): one notice for
/// each marked effect the checkpoint holds delivered, read with no writer. Every later run over
/// the checkpoint answers it again and its mark stays, so a run whose answer never reached the
/// owner (it stopped after its last delivery, or its reply was lost) loses no notice (review
/// round 2 of #10166); no act acknowledges one (BK-EMERGENCY-UNCERTAIN-SEND-RECEIPT = A: no
/// verb). A marked effect still owed is answered by the run that delivers it. A pick's mark is
/// not answered: the counterparty's press resends a pick, and that press is not the owner's
/// resume.
pub(super) fn repeat_notices(
    vault: &Vault,
    item: &EmergencyItem,
) -> Result<Vec<EmergencyRepeatNotice>, BookingError> {
    let key = item_key(&item.plan.request, item.calendar.event_ref)?;
    let hex = hex_suffix(&key, EMERGENCY_ITEM_META_PREFIX)
        .ok_or_else(|| refused("emergency checkpoint key is malformed"))?
        .to_owned();
    let txn = vault.store.env.read_txn().map_err(storage_failure)?;
    let Some(row) = UNCERTAIN_SEND
        .get_lenient(&vault.store, &txn, &hex)
        .map_err(storage_failure)?
    else {
        return Ok(Vec::new());
    };
    verify_owner_home_in(vault, &txn, item.plan.request.owner_ref)?;
    let owed = still_owed(row.lanes.iter().cloned(), item);
    Ok(row
        .lanes
        .iter()
        .filter(|lane| !owed.contains(*lane))
        .filter_map(|lane| match lane.as_str() {
            "calendar" => Some("calendar"),
            "apology" => Some("apology"),
            _ => None,
        })
        .map(|effect| EmergencyRepeatNotice {
            effect,
            message: EMERGENCY_REPEAT_NOTICE,
        })
        .collect())
}
