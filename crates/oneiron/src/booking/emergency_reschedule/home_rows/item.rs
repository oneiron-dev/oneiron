//! `booking:emergency_item:v1:`, the committed checkpoints: the third emergency section a home
//! move carries (the parent module's doc).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{
    EmergencyRowContent, PayloadFacts, PlanFacts, booking_failure, check_key, event_erased_here,
    full_key, image_keys, invalid, join_plan, row_parts, split_plan, stored_keys,
};
use crate::Vault;
use crate::booking::CalendarRevision;
use crate::booking::emergency_reschedule::lookup::{self, EFFECT, PENDING_EVENT};
use crate::booking::emergency_reschedule::planning::{
    EMERGENCY_ITEM_META_PREFIX, EmergencyItem, ITEM,
};
use crate::booking::emergency_reschedule::{EmergencyLocalBasis, EmergencyPick, state};
use crate::error::Result;
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentResolution, read_intent_for_attempt_in_txn,
};
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    HomeFence, HomeMove, HomeTable, ImageRows, Partitioned, TableAdopt, froze_home_state_in_txn,
};

/// Every committed checkpoint's facts.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmergencyItemRows {
    items: Vec<CarriedItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedItem {
    key: String,
    plan: PlanFacts,
    calendar: CalendarRevision,
    basis: EmergencyLocalBasis,
    committed_at: u64,
    calendar_delivered: bool,
    apology_delivered: bool,
    picked: Option<PickFacts>,
}

/// A pick without the owner's address or the booker's.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PickFacts {
    proposal_index: usize,
    calendar: CalendarRevision,
    committed_at: u64,
    calendar_delivered: bool,
    payload: PayloadFacts,
    content_hash: [u8; 32],
}

/// The checkpoint table and the pending-event and effect lookups its rows rebuild.
const ITEM_DECLS: [&SideTableDecl; 3] = [
    &side_table::EMERGENCY_ITEM,
    &side_table::EMERGENCY_PENDING_EVENT_LOOKUP,
    &side_table::EMERGENCY_EFFECT_LOOKUP,
];

/// Whether this node's outbound ledger resolves `item`'s effect on `lane` as delivered.
fn ledger_delivered(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<bool> {
    let reference = state::effect_ref(item, lane, hash).map_err(booking_failure)?;
    let attempt = crate::outbound::outbound_dispatch_attempt_id(&reference)
        .map_err(|_| invalid("an emergency effect has no outbound attempt id"))?;
    match read_intent_for_attempt_in_txn(vault, txn, attempt, 0) {
        Ok(record) => Ok(record.is_some_and(|record| {
            matches!(
                IntentResolution::from_record(&record),
                Ok(IntentResolution::Delivered)
            )
        })),
        Err(IntentLedgerError::Engine(error)) => Err(error),
        Err(_) => Ok(false),
    }
}

/// `item` with each owed effect this node's outbound ledger resolves as delivered marked
/// delivered: the send went, and only its checkpoint write did not (an election that moved the
/// home between the two refuses that write here), so the new home must not send it again.
fn with_ledger_deliveries(
    vault: &Vault,
    txn: &RoTxn<'_>,
    mut item: EmergencyItem,
) -> Result<EmergencyItem> {
    let plan_hash = item.plan.content_hash;
    if !item.calendar_delivered
        && item.plan.payload.is_some()
        && ledger_delivered(vault, txn, &item, "calendar", plan_hash)?
    {
        item.calendar_delivered = true;
    }
    if !item.apology_delivered && ledger_delivered(vault, txn, &item, "apology", plan_hash)? {
        item.apology_delivered = true;
    }
    if let Some(hash) = item
        .picked
        .as_ref()
        .filter(|picked| !picked.calendar_delivered)
        .map(|picked| picked.content_hash)
        && ledger_delivered(vault, txn, &item, "pick", hash)?
        && let Some(picked) = item.picked.as_mut()
    {
        picked.calendar_delivered = true;
    }
    Ok(item)
}

impl HomeTable for EmergencyItemRows {
    type Rows = Self;
    type Actor = EmergencyRowContent;
    const TABLE: &'static SideTableDecl = &side_table::EMERGENCY_ITEM;
    const SCHEMA_VERSION: u16 = 1;

    /// The move waits for no delivery: an item whose delivery is owed travels owed, and the new
    /// home sends it (module doc; ASK BK-EMERGENCY-PENDING-ITEM-MOVE). Once its election names
    /// another node home this node can neither send an emergency effect nor mark one delivered,
    /// so a wait here would never end.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, EmergencyRowContent>> {
        let mut items = Vec::new();
        let mut actors = Vec::new();
        for (key, item) in ITEM.scan(&vault.store, txn)? {
            let EmergencyItem {
                plan,
                calendar,
                basis,
                committed_at,
                actions,
                calendar_delivered,
                apology_delivered,
                picked,
            } = with_ledger_deliveries(vault, txn, item)?;
            let (plan, mut owner, mut booker) = split_plan(&key, plan)?;
            booker.actions = actions;
            let picked = picked.map(|picked| {
                let EmergencyPick {
                    proposal_index,
                    calendar,
                    committed_at,
                    calendar_delivered,
                    payload,
                    organizer,
                    content_hash,
                } = picked;
                let (payload, recipient) = PayloadFacts::of(payload);
                owner.pick_organizer = Some(organizer);
                booker.pick_recipient = Some(recipient);
                PickFacts {
                    proposal_index,
                    calendar,
                    committed_at,
                    calendar_delivered,
                    payload,
                    content_hash,
                }
            });
            actors.push(EmergencyRowContent::Owner(owner));
            actors.push(EmergencyRowContent::Booker(booker));
            items.push(CarriedItem {
                key,
                plan,
                calendar,
                basis,
                committed_at,
                calendar_delivered,
                apology_delivered,
                picked,
            });
        }
        Ok(Partitioned {
            facts: Self { items },
            actors,
        })
    }

    /// Lands each whole item as the module doc says and indexes its pending event and its
    /// effects. On a node whose rows are history both lookups are rebuilt from the landed items
    /// alone.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, EmergencyRowContent>,
    ) -> Result<TableAdopt> {
        let history = froze_home_state_in_txn(vault, txn)?;
        if history {
            for key in PENDING_EVENT.scan_keys(&vault.store, txn, &[])? {
                PENDING_EVENT.delete(&vault.store, txn, &key)?;
            }
            for key in EFFECT.scan_keys(&vault.store, txn, &[])? {
                EFFECT.delete(&vault.store, txn, &key)?;
            }
        }
        let (mut owners, mut bookers) = row_parts(rows.actors);
        let mut landed = BTreeSet::new();
        for carried in rows.facts.items {
            let (Some(owner), Some(booker)) =
                (owners.remove(&carried.key), bookers.remove(&carried.key))
            else {
                continue;
            };
            if event_erased_here(vault, txn, &carried.calendar.event_ref)? {
                continue;
            }
            let CarriedItem {
                key,
                plan,
                calendar,
                basis,
                committed_at,
                calendar_delivered,
                apology_delivered,
                picked,
            } = carried;
            let plan = join_plan(plan, &owner, &booker)?;
            check_key(&key, &plan.request, calendar.event_ref)?;
            let picked = match (picked, &owner.pick_organizer, &booker.pick_recipient) {
                (Some(picked), Some(organizer), Some(recipient)) => Some(EmergencyPick {
                    proposal_index: picked.proposal_index,
                    calendar: picked.calendar,
                    committed_at: picked.committed_at,
                    calendar_delivered: picked.calendar_delivered,
                    payload: picked.payload.with(recipient.clone()),
                    organizer: organizer.clone(),
                    content_hash: picked.content_hash,
                }),
                (None, None, None) => None,
                _ => {
                    return Err(invalid("a carried emergency pick and its parties disagree"));
                }
            };
            let item = EmergencyItem {
                plan,
                calendar,
                basis,
                committed_at,
                actions: booker.actions,
                calendar_delivered,
                apology_delivered,
                picked,
            };
            match ITEM.get_lenient(&vault.store, txn, &key)? {
                Some(here) if here == item => {}
                Some(_) if !history => return Ok(TableAdopt::Conflict),
                _ => ITEM.put(&vault.store, txn, &key, &item)?,
            }
            lookup::index_item_in(
                vault,
                txn,
                &item,
                &full_key(EMERGENCY_ITEM_META_PREFIX, &key),
            )
            .map_err(booking_failure)?;
            landed.insert(key);
        }
        if history {
            for key in ITEM.scan_keys(&vault.store, txn, &[])? {
                if !landed.contains(&key) {
                    ITEM.delete(&vault.store, txn, &key)?;
                }
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        stored_keys(vault, txn, &ITEM_DECLS)
    }

    /// The items and the lookup rows they rebuild.
    fn manages(_vault: &Vault, _txn: &RoTxn<'_>, image: &ImageRows) -> Result<Vec<Vec<u8>>> {
        Ok(image_keys(image, &ITEM_DECLS))
    }

    /// Drops the raw action tokens of every item here (lead ruling
    /// BK-EMERGENCY-RAW-TOKENS-SEALED = A): the new home holds them now, and this node's items
    /// are history no pick reads, so no second live copy outlasts the move. A row that does
    /// not decode holds no token any reader takes.
    fn scrub_after_ack(vault: &Vault, txn: &mut RwTxn<'_>) -> Result<()> {
        for key in ITEM.scan_keys(&vault.store, txn, &[])? {
            let Some(mut item) = ITEM.get_lenient(&vault.store, txn, &key)? else {
                continue;
            };
            if item.actions.is_empty() {
                continue;
            }
            item.actions.clear();
            ITEM.put(&vault.store, txn, &key, &item)?;
        }
        Ok(())
    }
}
