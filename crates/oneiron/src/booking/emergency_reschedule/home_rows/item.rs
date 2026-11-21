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
use crate::booking::emergency_reschedule::uncertain_send::{self, UNCERTAIN_SEND, owed_effects};
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
    /// The effects whose send ended uncertain on the old home, or on a home before it, and that
    /// no run has answered the owner for yet, whether a later home sent them again or they are
    /// still owed (review round 1 of #10125): such a send may have reached the booker, so the
    /// next one may repeat it (Engine ANSWER BK-EMERGENCY-PENDING-ITEM-MOVE = A: the move names
    /// that case). The new home keeps them as the checkpoint's side row, and the owner's run
    /// that delivers one says so (`super::super::uncertain_send`; ANSWER
    /// BK-EMERGENCY-UNCERTAIN-SEND-RECEIPT = A).
    uncertain_lanes: Vec<String>,
    /// Whether the old home's pending-event lookup names this item: the one whose revision its
    /// fence holds (`state::pending_effect_fences_in`), which the new home's lookup names again.
    pending_pointer: bool,
    /// The ledger generation of each owed effect whose local ledger identity is not its
    /// idempotency key (`EmergencyItem::ledger_generations`), so every later home's ledger reads
    /// and sends follow that identity. Not written when there is none, so a section that
    /// carries none encodes as before and a section encoded before decodes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    ledger_generations: BTreeMap<String, u32>,
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

/// The checkpoint table, the pending-event and effect lookups its rows rebuild, and the
/// checkpoints' uncertain-send marks.
const ITEM_DECLS: [&SideTableDecl; 4] = [
    &side_table::EMERGENCY_ITEM,
    &side_table::EMERGENCY_PENDING_EVENT_LOOKUP,
    &side_table::EMERGENCY_EFFECT_LOOKUP,
    &side_table::EMERGENCY_UNCERTAIN_SEND,
];

/// The longest one outbound transport call runs before its sink answers: the served sink's
/// client timeout (20 s, with a 5 s connect, `crate::outbound::served_sink`), rounded up to a
/// minute. A send the old home's ledger holds admitted with no outcome for longer than this
/// ended without one (a crash, a lost call): it ended uncertain, and the move waits no longer.
///
/// In seconds, the clock an emergency send's ledger row is written on: `dispatch_item_effect`
/// passes its `now_utc` seconds as the dispatch's `occurred_at`, which the outbound ledger
/// keeps as the row's `updated_ms` (review round 2 of #10109).
const MID_CALL_BOUND_SECS: u64 = 60;

/// This node's outbound ledger row of `item`'s effect on `lane` at ledger `generation`
/// (`state::effect_generation_ref`), if any. A row that does not read as a ledger row is none:
/// only a store failure is an error.
fn ledger_record_at(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
    generation: u32,
) -> Result<Option<IntentLedgerRecord>> {
    let reference =
        state::effect_generation_ref(item, lane, hash, generation).map_err(booking_failure)?;
    let attempt = crate::outbound::outbound_dispatch_attempt_id(&reference)
        .map_err(|_| invalid("an emergency effect has no outbound attempt id"))?;
    match read_intent_for_attempt_in_txn(vault, txn, attempt, 0) {
        Ok(record) => Ok(record),
        Err(IntentLedgerError::Engine(error)) => Err(error),
        Err(_) => Ok(None),
    }
}

/// This node's outbound ledger rows of `item`'s effect on `lane` under every ledger generation
/// the effect has had, the earliest first. A send an earlier generation made can still settle
/// after this home took a fresh attempt (its remote task completes, FIX 7960), so the move's
/// reads take each one (review round 1 of #10220).
fn ledger_records(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<Vec<IntentLedgerRecord>> {
    let mut records = Vec::new();
    for generation in 0..=state::ledger_generation(item, lane) {
        records.extend(ledger_record_at(vault, txn, item, lane, hash, generation)?);
    }
    Ok(records)
}

/// This node's outbound ledger row of `item`'s effect on `lane` under the effect's current
/// ledger identity (`state::effect_ledger_ref`), if any. A row that does not read as a ledger
/// row is none: only a store failure is an error.
fn ledger_record(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &EmergencyItem,
    lane: &str,
    hash: [u8; 32],
) -> Result<Option<IntentLedgerRecord>> {
    let reference = state::effect_ledger_ref(item, lane, hash).map_err(booking_failure)?;
    let attempt = crate::outbound::outbound_dispatch_attempt_id(&reference)
        .map_err(|_| invalid("an emergency effect has no outbound attempt id"))?;
    match read_intent_for_attempt_in_txn(vault, txn, attempt, 0) {
        Ok(record) => Ok(record),
        Err(IntentLedgerError::Engine(error)) => Err(error),
        Err(_) => Ok(None),
    }
}

/// Whether `record` is a send whose transport call may still be running at `now`, in this
/// vault clock's seconds: admitted, no outcome recorded, and last written within
/// [`MID_CALL_BOUND_SECS`] before `now`. A row dated after `now` is on no clock this reads, and
/// never holds the move.
fn mid_call(record: &IntentLedgerRecord, now: u64) -> bool {
    record.state == IntentState::Pending
        && record.recorded_outcome.is_none()
        && record.updated_ms <= now
        && now - record.updated_ms < MID_CALL_BOUND_SECS
}

/// The owed effects of `item` whose send ended uncertain in this node's outbound ledger: no
/// longer mid-call, and neither delivered nor known undelivered. A send the provider accepted
/// as a remote task (`IntentResolution::Deferred`, never sent again here) is one: its delivery
/// is not known, and the new home's send may repeat it (review round 2 of #10109).
fn uncertain_lanes(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &EmergencyItem,
    now: u64,
) -> Result<BTreeSet<String>> {
    let mut uncertain = BTreeSet::new();
    for (lane, hash) in owed_effects(item) {
        let Some(record) = ledger_record(vault, txn, item, lane, hash)? else {
            continue;
        };
        if !mid_call(&record, now)
            && matches!(
                IntentResolution::from_record(&record),
                Ok(IntentResolution::Pending {
                    delivery: UnconfirmedDelivery::Unresolved,
                    ..
                } | IntentResolution::Stopped {
                    delivery: UnconfirmedDelivery::Unresolved,
                    ..
                } | IntentResolution::Deferred)
            )
        {
            uncertain.insert(lane.to_owned());
        }
    }
    Ok(uncertain)
}

/// Raises the ledger generation of each effect `item` owes while this node's outbound ledger
/// holds its send deferred or stopped under the effect's current identity: such a row's replay
/// never sends again (`outbound_chokepoint::replay`, FIX 7960), so every owner's resume here
/// would refuse, where any other new home sends it under the same idempotency key (Engine
/// ANSWER BK-EMERGENCY-PENDING-ITEM-MOVE = A; FIX
/// [BK-EMERGENCY-DEFERRED-SEND-STRANDED-ON-FORMER-HOME]). A send this ledger holds delivered
/// or still pending keeps its identity: its replay completes it or sends it again.
fn raise_stranded_generations(
    vault: &Vault,
    txn: &RoTxn<'_>,
    item: &mut EmergencyItem,
) -> Result<()> {
    for (lane, hash) in owed_effects(item) {
        while ledger_record(vault, txn, item, lane, hash)?.is_some_and(|record| {
            matches!(
                IntentResolution::from_record(&record),
                Ok(IntentResolution::Deferred | IntentResolution::Stopped { .. })
            )
        }) {
            let generation = item.ledger_generations.entry(lane.to_owned()).or_default();
            *generation = generation
                .checked_add(1)
                .ok_or_else(|| invalid("an emergency effect has no next ledger generation"))?;
        }
    }
    Ok(())
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

/// The ids of this node's outbound ledger rows for the `lane` effect (`"calendar"`,
/// `"apology"` or `"pick"`) of every emergency checkpoint it holds, under each ledger generation
/// the effect has had, the earliest first: the test door
/// `test_doors::booking_home_move::emergency_effect_ledger_rows` (review round 1 of #10220).
#[cfg(oneiron_test_support)]
pub(crate) fn effect_ledger_rows_for_doors(vault: &Vault, lane: &str) -> Result<Vec<[u8; 32]>> {
    let txn = vault.store.custody_snapshot()?;
    let mut rows = Vec::new();
    for (_, item) in ITEM.scan(&vault.store, &txn)? {
        let hash = match (lane, &item.picked) {
            ("pick", Some(picked)) => picked.content_hash,
            ("pick", None) => continue,
            _ => item.plan.content_hash,
        };
        rows.extend(
            ledger_records(vault, &txn, &item, lane, hash)?
                .into_iter()
                .map(|record| record.id),
        );
    }
    Ok(rows)
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
        let now = vault.store.clock.now_recorded_at();
        for key in ITEM.scan_keys(&vault.store, txn, &[])? {
            let Some(item) = ITEM.get_lenient(&vault.store, txn, &key)? else {
                continue;
            };
            for (lane, hash) in owed_effects(&item) {
                if ledger_record(vault, txn, &item, lane, hash)?
                    .is_some_and(|record| mid_call(&record, now))
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
        let now = vault.store.clock.now_recorded_at();
        let mut items = Vec::new();
        let mut actors = Vec::new();
        for (key, item) in ITEM.scan(&vault.store, txn)? {
            let item = with_ledger_deliveries(vault, txn, item)?;
            // This node's own uncertain sends, and the marks an earlier move carried here that no
            // run here has answered the owner for since, delivered or not (review round 1 of
            // #10125).
            let mut uncertain = uncertain_lanes(vault, txn, &item, now)?;
            uncertain.extend(uncertain_send::carried_lanes_in(vault, txn, &key, &item)?);
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
                ledger_generations,
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
                uncertain_lanes: uncertain.into_iter().collect(),
                pending_pointer,
                ledger_generations,
            });
        }
        Ok(Partitioned {
            facts: Self { items },
            actors,
        })
    }

    /// Lands each whole item as the module doc says and indexes its pending event and its
    /// effects, each owed effect this node's own ledger holds deferred or stopped under its next
    /// ledger generation ([`raise_stranded_generations`]). On a node whose rows are history both
    /// lookups are rebuilt from the landed items alone. Each EVENT's pending lookup names one
    /// landed item that still owes a delivery: the one the old home's names, else the one owed
    /// at the highest revision. Landing order never decides it, so an older owed item cannot
    /// take the fence from a later one (review round 1 of #10109).
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
                ledger_generations,
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
            let mut item = EmergencyItem {
                plan,
                calendar,
                basis,
                committed_at,
                actions: booker.actions,
                calendar_delivered,
                apology_delivered,
                picked,
                ledger_generations,
            };
            raise_stranded_generations(vault, txn, &mut item)?;
            match ITEM.get_lenient(&vault.store, txn, &key)? {
                Some(here) if here == item => {}
                Some(_) if !history => return Ok(TableAdopt::Conflict),
                _ => ITEM.put(&vault.store, txn, &key, &item)?,
            }
            let item_key = full_key(EMERGENCY_ITEM_META_PREFIX, &key);
            lookup::index_item_in(vault, txn, &item, &item_key).map_err(booking_failure)?;
            uncertain += uncertain_send::land_in(vault, txn, &key, &item, uncertain_lanes)?;
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
            for key in UNCERTAIN_SEND.scan_keys(&vault.store, txn, &[])? {
                if !landed.contains(&key) {
                    UNCERTAIN_SEND.delete(&vault.store, txn, &key)?;
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
