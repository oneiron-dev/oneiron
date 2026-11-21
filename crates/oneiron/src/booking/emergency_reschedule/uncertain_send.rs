//! `booking:emergency_uncertain_send:v1:` (FIX [BK-EMERGENCY-UNCERTAIN-SEND-NOT-SHOWN-TO-OWNER];
//! Engine ANSWER BK-EMERGENCY-UNCERTAIN-SEND-RECEIPT = A, 21 Nov 09:14): the owed effects of one
//! checkpoint whose send ended uncertain on an earlier home, as a home move carried them
//! (`super::home_rows`). The new home sends each again under the same idempotency key, so the
//! booker may receive it twice; the owner's run that has delivered it says so once
//! ([`super::execution::EmergencyRepeatNotice`]), and its mark goes.
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

/// The lanes among `lanes` that `item` still owes: a delivered effect's mark answers no later
/// move.
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

/// The marked lanes of the checkpoint at `key` that `item` still owes, which the next move
/// carries on. A row that does not decode marks nothing: the move is never held by it.
pub(super) fn carried_lanes_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    key: &str,
    item: &EmergencyItem,
) -> crate::error::Result<BTreeSet<String>> {
    Ok(UNCERTAIN_SEND
        .get_lenient(&vault.store, txn, &key.to_owned())?
        .map(|row| still_owed(row.lanes, item))
        .unwrap_or_default())
}

/// Lands the carried marks of the checkpoint at `key` that `item` still owes, in the adopting
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
    let lanes = still_owed(carried, item);
    let kept = lanes.len();
    if lanes.is_empty() {
        UNCERTAIN_SEND.delete(&vault.store, txn, &key)?;
    } else {
        UNCERTAIN_SEND.put(&vault.store, txn, &key, &UncertainSends { lanes })?;
    }
    Ok(kept)
}

/// The owner's answer of a run over `item` (`super::execute_emergency_plan`): one notice for
/// each marked effect delivered now, and its mark dropped, in one writer. A marked effect still
/// owed keeps its mark for the run that delivers it, so when a run sent it and then failed on a
/// later effect, the next run that succeeds still answers it. A pick's mark stays: the
/// counterparty's press resends a pick, and that press is not the owner's resume.
pub(super) fn answer_delivered(
    vault: &Vault,
    item: &EmergencyItem,
) -> Result<Vec<EmergencyRepeatNotice>, BookingError> {
    let key = item_key(&item.plan.request, item.calendar.event_ref)?;
    let hex = hex_suffix(&key, EMERGENCY_ITEM_META_PREFIX)
        .ok_or_else(|| refused("emergency checkpoint key is malformed"))?
        .to_owned();
    {
        // A run with no mark takes no writer.
        let txn = vault.store.env.read_txn().map_err(storage_failure)?;
        if !UNCERTAIN_SEND
            .contains(&vault.store, &txn, &hex)
            .map_err(storage_failure)?
        {
            return Ok(Vec::new());
        }
    }
    booking_writer(vault, |txn| {
        verify_owner_home_in(vault, txn, item.plan.request.owner_ref)?;
        let Some(mut row) = UNCERTAIN_SEND
            .get_lenient(&vault.store, txn, &hex)
            .map_err(storage_failure)?
        else {
            return Ok(Vec::new());
        };
        let owed = still_owed(row.lanes.iter().cloned(), item);
        let mut notices = Vec::new();
        row.lanes.retain(|lane| {
            let effect = match lane.as_str() {
                "calendar" => "calendar",
                "apology" => "apology",
                _ => return true,
            };
            if owed.contains(lane) {
                return true;
            }
            notices.push(EmergencyRepeatNotice {
                effect,
                message: EMERGENCY_REPEAT_NOTICE,
            });
            false
        });
        if row.lanes.is_empty() {
            UNCERTAIN_SEND
                .delete(&vault.store, txn, &hex)
                .map_err(storage_failure)?;
        } else {
            UNCERTAIN_SEND
                .put(&vault.store, txn, &hex, &row)
                .map_err(storage_failure)?;
        }
        Ok(notices)
    })
}
