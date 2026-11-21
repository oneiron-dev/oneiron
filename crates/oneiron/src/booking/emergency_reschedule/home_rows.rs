//! FIX [BK-EMERGENCY-ROWS-NOT-CARRIED-BY-HOME-MOVE] (Engine ANSWER BK-EMERGENCY-ROWS-CARRY-SCOPE
//! = B, 21 Nov 07:38; lead ruling BK-HOME-MOVE-CARRIES-BOOKINGS = A, 06:2x: "a move must never
//! silently strand a visitor's link"): the emergency reschedule rows a home move carries, as
//! adapters on the home handoff carrier (`crate::sync::home_handoff`), beside the booking
//! lifecycle's (`crate::booking::lifecycle::home_rows`). Every emergency writer writes on the
//! home alone, and only while that node holds the booking rows (`super::state`'s
//! `verify_owner_home_in`), so the new home holds every emergency row the old home did:
//!
//! - `booking:emergency_instruction:v1:` ([`EmergencyInstructionRows`]): the owner's logged
//!   instructions, which every plan, commit and pick verifies again;
//! - `booking:emergency_plan:v1:` ([`EmergencyPlanRows`]): each booking's persisted plan, which
//!   a commit and a pick compare byte for byte (`super::verify_plan_in`);
//! - `booking:emergency_item:v1:` ([`EmergencyItemRows`]): each committed checkpoint, which a
//!   counterparty's pick resolves through its action token's digest (`booking.token.v1:`).
//!
//! The three lookups (pending event, effect attempt, request to plan) travel as no section: the
//! adopting writer rebuilds them from the rows it lands (`super::lookup`), so they never disagree
//! with those rows, and a restore keeps them live with their rows. The plans' and picks' ICS
//! bytes travel as no part either: they are blob artifact versions, which sync carries with
//! their bodies (`crate::sync::asset_body`).
//!
//! Each row's content travels sealed apart (FIX 8875): the owner's reason and sending address
//! under the owner's key; the booking's confirmation context (hosts, booker, the visitor's zone,
//! constraint and answers), the booker's delivery address and the item's raw action tokens
//! under the booker contact's key. The facts are keys, revisions, slots, proposals, flags and
//! content hashes. A row lands only whole: one whose owner or booker part does not open here
//! (an erased person), or whose EVENT this node holds erased, lands nothing, as a hold does, and
//! a pick of its action is then refused loudly ("emergency action has no durable checkpoint").
//! A plan lands only where it reassembles to its content hash.
//!
//! The raw action tokens are the one exception to "tokens travel as digests only" (lead ruling
//! BK-EMERGENCY-RAW-TOKENS-SEALED = A, 21 Nov 07:5x): the carried picks key them by digest and
//! the apology the booker holds names them, so none can be minted again. Only the adopting
//! writer opens them, a booker's erase leaves them unreadable wherever a copy went, and the old
//! home drops its copy once the new home acknowledged the move
//! ([`HomeTable::scrub_after_ack`]).
//!
//! An item whose delivery is still owed travels owed (ASK BK-EMERGENCY-PENDING-ITEM-MOVE): the
//! old home sends no emergency effect once its election names another node home (outbound's
//! gate and its last transport door verify the effect through `verify_owner_home_in`), so the
//! new home is the one node that sends it, under the same idempotency key. An effect the old
//! home's own outbound ledger resolves as delivered travels delivered.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::lookup::{self, REQUEST_PLAN_INDEX};
use super::planning::{
    EMERGENCY_ITEM_META_PREFIX, EMERGENCY_PLAN_META_PREFIX, EmergencyPlan, PLAN, item_key,
};
use super::{
    AffectedBooking, EmergencyActionPolicy, EmergencyRescheduleRequest, INSTRUCTION,
    OwnerInstructionRecord, entity_ref_serde, time_range_serde,
};
use crate::Vault;
use crate::booking::lifecycle::BookingConfirmationContext;
use crate::booking::{BookingError, CalendarRevision, EventTypeKey, OpaqueLifecycleToken};
use crate::calendar::{CalendarInviteMethod, CalendarInvitePayload, CalendarPassportValue};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, SideTableDecl};
use crate::sync::home_handoff::{
    ActorContent, HomeFence, HomeMove, HomeTable, ImageRows, Partitioned, TableAdopt,
    froze_home_state_in_txn,
};
use crate::temporal::TimeRange;

fn invalid(detail: &str) -> Error {
    Error::InvalidConfig(detail.to_owned())
}

fn booking_failure(error: BookingError) -> Error {
    Error::InvalidConfig(error.to_string())
}

/// Whether this node holds an erasure of `event`, pending or published (FIX 9636).
fn event_erased_here(vault: &Vault, txn: &RoTxn<'_>, event: &EntityId) -> Result<bool> {
    Ok(crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, txn, event)?.deleted)
}

/// The full stored keys of every row of `decls` here.
fn stored_keys(
    vault: &Vault,
    txn: &RoTxn<'_>,
    decls: &[&'static SideTableDecl],
) -> Result<Vec<Vec<u8>>> {
    let mut keys = Vec::new();
    for decl in decls {
        for row in decl.iter_raw(vault, txn)? {
            let (suffix, _) = row?;
            let mut key = decl.prefix.to_vec();
            key.extend_from_slice(&suffix);
            keys.push(key);
        }
    }
    Ok(keys)
}

/// The keys of `image` under any of `decls`.
fn image_keys(image: &ImageRows, decls: &[&'static SideTableDecl]) -> Vec<Vec<u8>> {
    image
        .iter()
        .filter(|(key, _)| decls.iter().any(|decl| key.starts_with(decl.prefix)))
        .map(|(key, _)| key.clone())
        .collect()
}

/// A row's full raw key, as the lookups store it: `prefix` and the hex key.
fn full_key(prefix: &[u8], key: &str) -> Vec<u8> {
    let mut full = prefix.to_vec();
    full.extend_from_slice(key.as_bytes());
    full
}

/// Refuses a carried row whose key is not the one its request and EVENT spell (`item_key`):
/// every lookup and every pick resolves a row through that key.
fn check_key(key: &str, request: &EmergencyRescheduleRequest, event: EntityId) -> Result<()> {
    let spelled = item_key(request, event).map_err(booking_failure)?;
    if spelled.strip_prefix(EMERGENCY_ITEM_META_PREFIX) != Some(key.as_bytes()) {
        return Err(invalid(
            "a carried emergency row's key is not the one its content spells",
        ));
    }
    Ok(())
}

// -------------------------------------------------------------------------
// The shared split: a plan's facts, the owner's words, the booking's parties
// -------------------------------------------------------------------------

/// An invite payload without its recipient.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadFacts {
    method: CalendarInviteMethod,
    uid: String,
    sequence: u32,
    ics_blob_ref: String,
    mention: Option<crate::outbound::MentionProvenance>,
}

impl PayloadFacts {
    fn of(payload: CalendarInvitePayload) -> (Self, String) {
        let CalendarInvitePayload {
            method,
            uid,
            sequence,
            ics_blob_ref,
            recipient,
            mention,
        } = payload;
        (
            Self {
                method,
                uid,
                sequence,
                ics_blob_ref,
                mention,
            },
            recipient,
        )
    }

    fn with(self, recipient: String) -> CalendarInvitePayload {
        CalendarInvitePayload {
            method: self.method,
            uid: self.uid,
            sequence: self.sequence,
            ics_blob_ref: self.ics_blob_ref,
            recipient,
            mention: self.mention,
        }
    }
}

/// One plan without the owner's words or the booking's parties.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanFacts {
    #[serde(with = "time_range_serde")]
    affected_window: TimeRange,
    action_policy: EmergencyActionPolicy,
    request_hash: [u8; 32],
    recorded_at: u64,
    calendar: CalendarRevision,
    #[serde(with = "entity_ref_serde")]
    page_ref: EntityId,
    event_type: EventTypeKey,
    #[serde(with = "time_range_serde")]
    occurrence: TimeRange,
    proposals: Vec<crate::booking::RankedSlot>,
    planned_at: u64,
    payload: Option<PayloadFacts>,
    invite_before: Option<CalendarPassportValue>,
    content_hash: [u8; 32],
}

/// The owner's part of one plan or item: the reason they logged and the address the
/// invitations go from, sealed under the owner's key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerWords {
    #[serde(with = "entity_ref_serde")]
    owner: EntityId,
    key: String,
    reason: String,
    organizer: String,
    pick_organizer: Option<String>,
}

/// The booking's part of one plan or item: the confirmation context (hosts, booker, the
/// visitor's zone, constraint and answers), the booker's delivery address and, for an item,
/// its raw action tokens, sealed under the booker contact's key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BookerContent {
    #[serde(with = "entity_ref_serde")]
    booker: EntityId,
    key: String,
    context: BookingConfirmationContext,
    recipient: String,
    payload_recipient: Option<String>,
    actions: Vec<OpaqueLifecycleToken>,
    pick_recipient: Option<String>,
}

/// One actor's part of an emergency plan or item.
#[derive(Serialize, Deserialize)]
pub(crate) enum EmergencyRowContent {
    Owner(OwnerWords),
    Booker(BookerContent),
}

impl ActorContent for EmergencyRowContent {
    fn actor(&self) -> EntityId {
        match self {
            Self::Owner(words) => words.owner,
            Self::Booker(content) => content.booker,
        }
    }
}

/// Splits `plan`, stored under `key`, into its facts and its two parts.
fn split_plan(key: &str, plan: EmergencyPlan) -> Result<(PlanFacts, OwnerWords, BookerContent)> {
    let EmergencyPlan {
        request,
        booking,
        proposals,
        planned_at,
        payload,
        recipient,
        organizer,
        invite_before,
        content_hash,
    } = plan;
    let EmergencyRescheduleRequest {
        owner_ref,
        affected_window,
        reason,
        action_policy,
        authority,
    } = request;
    // The instruction's writer binds both to one owner (`append_instruction_in_txn`).
    if authority.owner_ref != owner_ref {
        return Err(invalid(
            "an emergency plan's instruction names another owner",
        ));
    }
    let AffectedBooking {
        calendar,
        page_ref,
        event_type,
        occurrence,
        context,
    } = booking;
    let booker = EntityId::from_hex(&context.booker_ref)
        .map_err(|_| invalid("an emergency plan names no booker contact"))?;
    let (payload, payload_recipient) = payload.map(PayloadFacts::of).unzip();
    Ok((
        PlanFacts {
            affected_window,
            action_policy,
            request_hash: authority.request_hash,
            recorded_at: authority.recorded_at,
            calendar,
            page_ref,
            event_type,
            occurrence,
            proposals,
            planned_at,
            payload,
            invite_before,
            content_hash,
        },
        OwnerWords {
            owner: owner_ref,
            key: key.to_owned(),
            reason,
            organizer,
            pick_organizer: None,
        },
        BookerContent {
            booker,
            key: key.to_owned(),
            context,
            recipient,
            payload_recipient,
            actions: Vec::new(),
            pick_recipient: None,
        },
    ))
}

/// The plan `facts` and the two parts reassemble to, refused unless it hashes to its content
/// hash, the rule a commit and a pick verify it by (`super::verify_plan_in`).
fn join_plan(
    facts: PlanFacts,
    owner: &OwnerWords,
    booker: &BookerContent,
) -> Result<EmergencyPlan> {
    let payload = match (facts.payload, &booker.payload_recipient) {
        (Some(payload), Some(recipient)) => Some(payload.with(recipient.clone())),
        (None, None) => None,
        _ => {
            return Err(invalid(
                "a carried emergency plan's payload and its recipient disagree",
            ));
        }
    };
    let plan = EmergencyPlan {
        request: EmergencyRescheduleRequest {
            owner_ref: owner.owner,
            affected_window: facts.affected_window,
            reason: owner.reason.clone(),
            action_policy: facts.action_policy,
            authority: OwnerInstructionRecord {
                owner_ref: owner.owner,
                request_hash: facts.request_hash,
                recorded_at: facts.recorded_at,
            },
        },
        booking: AffectedBooking {
            calendar: facts.calendar,
            page_ref: facts.page_ref,
            event_type: facts.event_type,
            occurrence: facts.occurrence,
            context: booker.context.clone(),
        },
        proposals: facts.proposals,
        planned_at: facts.planned_at,
        payload,
        recipient: booker.recipient.clone(),
        organizer: owner.organizer.clone(),
        invite_before: facts.invite_before,
        content_hash: facts.content_hash,
    };
    if plan.hash().map_err(booking_failure)? != plan.content_hash {
        return Err(invalid(
            "a carried emergency plan does not reassemble to its content hash",
        ));
    }
    Ok(plan)
}

/// The owner's and the booker's parts of each row, by the row's key.
type RowParts = (
    BTreeMap<String, OwnerWords>,
    BTreeMap<String, BookerContent>,
);

fn row_parts(actors: Vec<EmergencyRowContent>) -> RowParts {
    let mut owners = BTreeMap::new();
    let mut bookers = BTreeMap::new();
    for part in actors {
        match part {
            EmergencyRowContent::Owner(words) => {
                owners.insert(words.key.clone(), words);
            }
            EmergencyRowContent::Booker(content) => {
                bookers.insert(content.key.clone(), content);
            }
        }
    }
    (owners, bookers)
}

// -------------------------------------------------------------------------
// booking:emergency_instruction:v1: the owner's logged instructions
// -------------------------------------------------------------------------

/// Every logged instruction's facts.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmergencyInstructionRows {
    instructions: Vec<InstructionFacts>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstructionFacts {
    key: String,
    request_hash: [u8; 32],
    recorded_at: u64,
}

/// The owner an instruction names, sealed under that owner's key.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstructionOwner {
    #[serde(with = "entity_ref_serde")]
    owner: EntityId,
    key: String,
}

impl ActorContent for InstructionOwner {
    fn actor(&self) -> EntityId {
        self.owner
    }
}

impl HomeTable for EmergencyInstructionRows {
    type Rows = Self;
    type Actor = InstructionOwner;
    const TABLE: &'static SideTableDecl = &side_table::EMERGENCY_INSTRUCTION;
    const SCHEMA_VERSION: u16 = 1;

    /// An instruction commits in one writer: none is in flight.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, InstructionOwner>> {
        let mut instructions = Vec::new();
        let mut actors = Vec::new();
        for (key, record) in INSTRUCTION.scan(&vault.store, txn)? {
            let OwnerInstructionRecord {
                owner_ref,
                request_hash,
                recorded_at,
            } = record;
            actors.push(InstructionOwner {
                owner: owner_ref,
                key: key.clone(),
            });
            instructions.push(InstructionFacts {
                key,
                request_hash,
                recorded_at,
            });
        }
        Ok(Partitioned {
            facts: Self { instructions },
            actors,
        })
    }

    /// Lands each instruction whose owner's part opened here, as the booking sections land
    /// theirs (`crate::booking::lifecycle::home_rows`).
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, InstructionOwner>,
    ) -> Result<TableAdopt> {
        let history = froze_home_state_in_txn(vault, txn)?;
        let mut owners: BTreeMap<String, InstructionOwner> = rows
            .actors
            .into_iter()
            .map(|owner| (owner.key.clone(), owner))
            .collect();
        let mut landed = BTreeSet::new();
        for facts in rows.facts.instructions {
            let Some(owner) = owners.remove(&facts.key) else {
                continue;
            };
            let record = OwnerInstructionRecord {
                owner_ref: owner.owner,
                request_hash: facts.request_hash,
                recorded_at: facts.recorded_at,
            };
            match INSTRUCTION.get_lenient(&vault.store, txn, &facts.key)? {
                Some(here) if here == record => {}
                Some(_) if !history => return Ok(TableAdopt::Conflict),
                _ => INSTRUCTION.put(&vault.store, txn, &facts.key, &record)?,
            }
            landed.insert(facts.key);
        }
        if history {
            for key in INSTRUCTION.scan_keys(&vault.store, txn, &[])? {
                if !landed.contains(&key) {
                    INSTRUCTION.delete(&vault.store, txn, &key)?;
                }
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        stored_keys(vault, txn, &[&side_table::EMERGENCY_INSTRUCTION])
    }
}

// -------------------------------------------------------------------------
// booking:emergency_plan:v1: the persisted plans
// -------------------------------------------------------------------------

/// Every persisted plan's facts.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmergencyPlanRows {
    plans: Vec<CarriedPlan>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CarriedPlan {
    key: String,
    facts: PlanFacts,
}

/// The plan table and the request-to-plan index its rows rebuild.
const PLAN_DECLS: [&SideTableDecl; 2] = [
    &side_table::EMERGENCY_PLAN,
    &side_table::EMERGENCY_REQUEST_PLAN_INDEX,
];

impl HomeTable for EmergencyPlanRows {
    type Rows = Self;
    type Actor = EmergencyRowContent;
    const TABLE: &'static SideTableDecl = &side_table::EMERGENCY_PLAN;
    const SCHEMA_VERSION: u16 = 1;

    /// A plan commits in one writer: none is in flight.
    fn quiescent(_vault: &Vault, _txn: &RoTxn<'_>, _movement: &HomeMove) -> Result<bool> {
        Ok(true)
    }

    fn export(
        vault: &Vault,
        txn: &RoTxn<'_>,
        _fence: &HomeFence,
    ) -> Result<Partitioned<Self, EmergencyRowContent>> {
        let mut plans = Vec::new();
        let mut actors = Vec::new();
        for (key, plan) in PLAN.scan(&vault.store, txn)? {
            let (facts, owner, booker) = split_plan(&key, plan)?;
            actors.push(EmergencyRowContent::Owner(owner));
            actors.push(EmergencyRowContent::Booker(booker));
            plans.push(CarriedPlan { key, facts });
        }
        Ok(Partitioned {
            facts: Self { plans },
            actors,
        })
    }

    /// Lands each whole plan as the module doc says and indexes it under its instruction. On a
    /// node whose rows are history the index is rebuilt from the landed plans alone.
    fn adopt(
        vault: &Vault,
        txn: &mut RwTxn<'_>,
        _fence: &HomeFence,
        rows: Partitioned<Self, EmergencyRowContent>,
    ) -> Result<TableAdopt> {
        let history = froze_home_state_in_txn(vault, txn)?;
        if history {
            for key in REQUEST_PLAN_INDEX.scan_keys(&vault.store, txn, &[])? {
                REQUEST_PLAN_INDEX.delete(&vault.store, txn, &key)?;
            }
        }
        let (mut owners, mut bookers) = row_parts(rows.actors);
        let mut landed = BTreeSet::new();
        for CarriedPlan { key, facts } in rows.facts.plans {
            let (Some(owner), Some(booker)) = (owners.remove(&key), bookers.remove(&key)) else {
                continue;
            };
            if event_erased_here(vault, txn, &facts.calendar.event_ref)? {
                continue;
            }
            let plan = join_plan(facts, &owner, &booker)?;
            check_key(&key, &plan.request, plan.booking.calendar.event_ref)?;
            match PLAN.get_lenient(&vault.store, txn, &key)? {
                Some(here) if here == plan => {}
                Some(_) if !history => return Ok(TableAdopt::Conflict),
                _ => PLAN.put(&vault.store, txn, &key, &plan)?,
            }
            lookup::index_plan_in(
                vault,
                txn,
                &plan,
                &full_key(EMERGENCY_PLAN_META_PREFIX, &key),
            )
            .map_err(booking_failure)?;
            landed.insert(key);
        }
        if history {
            for key in PLAN.scan_keys(&vault.store, txn, &[])? {
                if !landed.contains(&key) {
                    PLAN.delete(&vault.store, txn, &key)?;
                }
            }
        }
        Ok(TableAdopt::Applied)
    }

    fn live_keys(vault: &Vault, txn: &RoTxn<'_>) -> Result<Vec<Vec<u8>>> {
        stored_keys(vault, txn, &PLAN_DECLS)
    }

    /// The plans and the index rows they rebuild.
    fn manages(_vault: &Vault, _txn: &RoTxn<'_>, image: &ImageRows) -> Result<Vec<Vec<u8>>> {
        Ok(image_keys(image, &PLAN_DECLS))
    }
}

mod item;
pub(crate) use item::EmergencyItemRows;
