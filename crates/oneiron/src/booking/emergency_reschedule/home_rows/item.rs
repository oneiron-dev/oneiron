//! `booking:emergency_item:v1:`, the committed checkpoints: the third emergency section a home
//! move carries (the parent module's doc).

use std::collections::{BTreeMap, BTreeSet};

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
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::outbound_intent_ledger::{
    IntentLedgerError, IntentLedgerRecord, IntentResolution, IntentState, UnconfirmedDelivery,
    read_intent_for_attempt_in_txn,
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
    /// The owed effects whose send ended uncertain on the old home: it may have reached the
    /// booker, so the new home's send may repeat it (Engine ANSWER
    /// BK-EMERGENCY-PENDING-ITEM-MOVE = A: the move names that case).
    uncertain_lanes: Vec<String>,
    /// Whether the old home's pending-event lookup names this item: the one whose revision its
    /// fence holds (`state::pending_effect_fences_in`), which the new home's lookup names again.
    pending_pointer: bool,
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

/// The longest one outbound transport call runs before its sink answers: the served sink's
/// client timeout (20 s, with a 5 s connect, `crate::outbound::served_sink`), rounded up to a
/// minute. A send the old home's ledger holds admitted with no outcome for longer than this
/// ended without one (a crash, a lost call): it ended uncertain, and the move waits no longer.
const MID_CALL_BOUND_MS: u64 = 60_000;

/// The effects `item` still owes, each as its lane and the content hash its intent is keyed by
/// (`super::super::lookup`'s `index_item_in` spells the same three).
fn owed_effects(item: &EmergencyItem) -> Vec<(&'static str, [u8; 32])> {
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

/// This node's outbound ledger row of `item`'s effect on `lane`, if any. A row that does not
/// read as a ledger row is none: only a store failure is an error.
fn ledger_record(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<Option<IntentLedgerRecord>> {
    let reference = state::effect_ref(item, lane, hash).map_err(booking_failure)?;
    let attempt = crate::outbound::outbound_dispatch_attempt_id(&reference)
        .map_err(|_| invalid("an emergency effect has no outbound attempt id"))?;
    match read_intent_for_attempt_in_txn(vault, txn, attempt, 0) {
        Ok(record) => Ok(record),
        Err(IntentLedgerError::Engine(error)) => Err(error),
        Err(_) => Ok(None),
    }
}

/// Whether `record` is a send whose transport call may still be running at `now_ms`: admitted,
/// no outcome recorded, and last written within [`MID_CALL_BOUND_MS`].
fn mid_call(record: &IntentLedgerRecord, now_ms: u64) -> bool {
    record.state == IntentState::Pending
        && record.recorded_outcome.is_none()
        && now_ms.saturating_sub(record.updated_ms) < MID_CALL_BOUND_MS
}

/// The owed effects of `item` whose send ended uncertain in this node's outbound ledger: no
/// longer mid-call, and neither delivered nor known undelivered.
fn uncertain_lanes(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &EmergencyItem,
    now_ms: u64,
) -> Result<Vec<String>> {
    let mut uncertain = Vec::new();
    for (lane, hash) in owed_effects(item) {
        let Some(record) = ledger_record(vault, txn, item, lane, hash)? else {
            continue;
        };
        if !mid_call(&record, now_ms)
            && matches!(
                IntentResolution::from_record(&record),
                Ok(IntentResolution::Pending {
                    delivery: UnconfirmedDelivery::Unresolved,
                    ..
                } | IntentResolution::Stopped {
                    delivery: UnconfirmedDelivery::Unresolved,
                    ..
                })
            )
        {
            uncertain.push(lane.to_owned());
        }
    }
    Ok(uncertain)
}

/// `item` with each owed effect this node's outbound ledger resolves as delivered marked
/// delivered: the send went, and only its checkpoint write did not (an election that moved the
/// home between the two refuses that write here), so the new home must not send it again.
fn with_ledger_deliveries(
    vault: &Vault,
    txn: &RoTxn<'_>,
    mut item: EmergencyItem,
) -> Result<EmergencyItem> {
    for (lane, hash) in owed_effects(&item) {
        let delivered = ledger_record(vault, txn, &item, lane, hash)?.is_some_and(|record| {
            matches!(
                IntentResolution::from_record(&record),
                Ok(IntentResolution::Delivered)
            )
        });
        if !delivered {
            continue;
        }
        match lane {
            "calendar" => item.calendar_delivered = true,
            "apology" => item.apology_delivered = true,
            _ => {
                if let Some(picked) = item.picked.as_mut() {
                    picked.calendar_delivered = true;
                }
            }
        }
    }
    Ok(item)
}

impl HomeTable for EmergencyItemRows {
    type Rows = Self;
    type Actor = EmergencyRowContent;
    const TABLE: &'static SideTableDecl = &side_table::EMERGENCY_ITEM;
    const SCHEMA_VERSION: u16 = 1;

    /// The move waits for no owed or approval-held delivery: such an item travels owed, and the
    /// new home sends it (module doc). Once its election names another node home this node can
    /// neither send an emergency effect nor mark one delivered, so a wait for delivery would
    /// never end. It waits only while an owed send is mid-call here ([`mid_call`]), bounded by
    /// the transport's call timeout (Engine ANSWER BK-EMERGENCY-PENDING-ITEM-MOVE = A, 21 Nov
    /// 08:52), so only a send that ended uncertain can reach the booker twice.
    fn quiescent(vault: &Vault, txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        let now_ms = vault.store.clock.now_recorded_at().saturating_mul(1_000);
        for key in ITEM.scan_keys(&vault.store, txn, &[])? {
            let Some(item) = ITEM.get_lenient(&vault.store, txn, &key)? else {
                continue;
            };
            for (lane, hash) in owed_effects(&item) {
                if ledger_record(vault, txn, &item, lane, hash)?
                    .is_some_and(|record| mid_call(&record, now_ms))
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, EmergencyRowContent>> {
        let now_ms = vault.store.clock.now_recorded_at().saturating_mul(1_000);
        let mut items = Vec::new();
        let mut actors = Vec::new();
        for (key, item) in ITEM.scan(&vault.store, txn)? {
            let item = with_ledger_deliveries(vault, txn, item)?;
            let uncertain = uncertain_lanes(vault, txn, &item, now_ms)?;
            let pending_pointer = PENDING_EVENT
                .get(&vault.store, txn, &item.calendar.event_ref)?
                .is_some_and(|target| target == full_key(EMERGENCY_ITEM_META_PREFIX, &key));
            let EmergencyItem {
                plan,
                calendar,
                basis,
                committed_at,
                actions,
                calendar_delivered,
                apology_delivered,
                picked,
            } = item;
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
                uncertain_lanes: uncertain,
                pending_pointer,
            });
        }
        Ok(Partitioned {
            facts: Self { items },
            actors,
        })
    }

    /// Lands each whole item as the module doc says and indexes its pending event and its
    /// effects. On a node whose rows are history both lookups are rebuilt from the landed items
    /// alone. Each EVENT's pending lookup names one landed item that still owes a delivery: the
    /// one the old home's names, else the one owed at the highest revision. Landing order
    /// never decides it, so an older owed item cannot take the fence from a later one (review
    /// round 1 of #10109).
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
        let mut pending: BTreeMap<EntityId, ((bool, u32), Vec<u8>)> = BTreeMap::new();
        let mut uncertain = 0_usize;
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
                uncertain_lanes,
                pending_pointer,
            } = carried;
            uncertain += uncertain_lanes.len();
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
            let item_key = full_key(EMERGENCY_ITEM_META_PREFIX, &key);
            lookup::index_item_in(vault, txn, &item, &item_key).map_err(booking_failure)?;
            if let Some(revision) = lookup::pending_revision(&item) {
                let rank = (pending_pointer, revision.sequence);
                let event = item.calendar.event_ref;
                if pending.get(&event).is_none_or(|(best, _)| rank > *best) {
                    pending.insert(event, (rank, item_key));
                }
            }
            landed.insert(key);
        }
        for (event, (_, item_key)) in pending {
            PENDING_EVENT.put(&vault.store, txn, &event, &item_key)?;
        }
        if history {
            for key in ITEM.scan_keys(&vault.store, txn, &[])? {
                if !landed.contains(&key) {
                    ITEM.delete(&vault.store, txn, &key)?;
                }
            }
        }
        if uncertain > 0 {
            tracing::warn!(
                uncertain,
                "emergency sends ended uncertain on the old home and may repeat"
            );
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
