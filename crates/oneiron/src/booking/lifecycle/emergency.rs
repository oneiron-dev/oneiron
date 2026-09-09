//! BK-09's emergency-reschedule transitions: the home-node guard, the durable
//! pick row, and the commit that joins the lifecycle and CAL transactions.

use serde::{Deserialize, Serialize};

use super::claim::{
    calendar_status_value, encode_event_body, read_booking_facts, supersede_exact_claim,
};
use super::door::BookingLifecycleConsumerInput;
use super::occurrence::{inclusive_occurrence, offers_slot};
use super::passport::supersede_outbound_passport;
use super::storage::{
    booking_writer, delete_meta, encode_claim_value, encode_row, engine_failure, meta_key,
    put_meta, read_meta, read_txn, revision_receipt_key, write_receipt,
};
use super::token::{OpaqueLifecycleToken, mint_raw_token, token_digest};
use super::types::{
    BOOKING_PASSPORT_SYSTEM, BOOKING_RECEIPT_META_PREFIX, BOOKING_STATUS_PREDICATE,
    BOOKING_TOKEN_META_PREFIX, BookingStatus, BookingStatusValue, CalendarRevision,
};
use super::{BookingContent, LifecycleReceiptRow};
use crate::booking::BookingError;
use crate::calendar::claims::{
    CalendarStatus, PREDICATE_CALENDAR_PASSPORT, PREDICATE_CALENDAR_STATUS,
};
use crate::claim::ClaimLifecycleStatus;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

fn emergency_refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConfig(detail.into())
}

// BK-09 extends this same home-node writer, not the ordinary token scopes.
// The item checkpoint joins the lifecycle and CAL transactions here; no
// outbound call may run while this writer is held.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EmergencyPickRow {
    emergency_item_key: Vec<u8>,
    proposal_index: usize,
}

fn require_emergency_home(
    vault: &Vault,
    input: &BookingLifecycleConsumerInput,
) -> Result<(), BookingError> {
    let txn = read_txn(vault)?;
    let home = DreamerRunnerStore::new(vault)
        .home_node_designation_in_txn(&txn)
        .map_err(|error| engine_failure("home node designation read", error))?;
    let local = crate::identity::read_client_id_in_txn(vault, &txn)
        .map_err(|error| engine_failure("local node identity read", error))?;
    if local != Some(input.local_node_id) || home.is_none_or(|home| Some(home.node_id) != local) {
        return Err(BookingError::InvalidConfig(
            "emergency transition requires the lifecycle home node".to_owned(),
        ));
    }
    Ok(())
}

pub(in crate::booking) fn emergency_current_revision_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> Result<CalendarRevision, BookingError> {
    let mut values = Vec::new();
    for id in vault
        .claims_for_subject_in_txn(txn, &event)
        .map_err(|error| engine_failure("booking passport scan", error))?
    {
        if let Some(body) = vault
            .get_claim_in_txn(txn, &id)
            .map_err(|error| engine_failure("booking passport read", error))?
            && body.lifecycle == ClaimLifecycleStatus::Active
            && body.predicate == PREDICATE_CALENDAR_PASSPORT
        {
            let value =
                crate::calendar::claims::decode_passport_value(&body.value).map_err(|_| {
                    emergency_refused("booking has malformed calendar passport metadata")
                })?;
            if value.system == BOOKING_PASSPORT_SYSTEM {
                values.push((id, value));
            }
        }
    }
    let mut passports = values.into_iter();
    let (_, current) = passports
        .next()
        .ok_or_else(|| emergency_refused("booking carries no outbound calendar passport"))?;
    if passports.next().is_some() {
        return Err(emergency_refused(
            "booking has competing outbound passports",
        ));
    }
    Ok(CalendarRevision {
        event_ref: event,
        uid: current.uid,
        sequence: current.last_sequence,
    })
}

pub(in crate::booking) fn commit_emergency_item(
    vault: &Vault,
    plan: &crate::booking::emergency_reschedule::EmergencyPlan,
    calendars: &[(EntityId, Vec<crate::calendar::query::CalendarSel>)],
    input: &BookingLifecycleConsumerInput,
) -> Result<crate::booking::emergency_reschedule::EmergencyItem, BookingError> {
    use crate::booking::emergency_reschedule::{
        self as emergency, EmergencyActionPolicy, EmergencyItem, EmergencyLocalBasis,
    };
    require_emergency_home(vault, input)?;
    booking_writer(vault, |txn| {
        if crate::identity::read_client_id_in_txn(vault, &*txn)
            .map_err(|error| engine_failure("local identity read", error))?
            != Some(input.local_node_id)
        {
            return Err(BookingError::InvalidConfig(
                "wrong lifecycle home node".to_owned(),
            ));
        }
        emergency::verify_plan_in(vault, &*txn, plan)?;
        emergency::verify_plan_blob(vault, plan)?;
        crate::memory::verify_deletion_authority_in_txn(
            vault,
            &*txn,
            plan.request.owner_ref,
            crate::edge::EdgeActorClass::Human,
        )
        .map_err(|error| BookingError::Boundary(Box::new(error)))?;
        let key = emergency::item_key(&plan.request, plan.booking.calendar.event_ref)?;
        if let Some(item) = emergency::read_item_in(vault, &*txn, &key)? {
            if item.plan != *plan {
                return Err(emergency_refused(
                    "same emergency sequence has conflicting content",
                ));
            }
            if (!item.calendar_delivered || !item.apology_delivered)
                && emergency_current_revision_in(vault, &*txn, item.calendar.event_ref)?
                    != item.calendar
            {
                return Err(emergency_refused(
                    "a newer lifecycle revision supersedes this pending emergency effect",
                ));
            }
            return Ok(item);
        }
        let event = plan.booking.calendar.event_ref;
        let booking = read_booking_facts(vault, &*txn, &event)?;
        if booking.status != BookingStatus::Confirmed
            || booking.slot != plan.booking.occurrence
            || booking.page_ref != plan.booking.page_ref
            || booking.event_type != plan.booking.event_type
            || booking.context.as_ref() != Some(&plan.booking.context)
            || !plan
                .booking
                .context
                .owner_refs
                .contains(&plan.request.owner_ref.to_hex())
            || plan.planned_at >= booking.slot.start
            || emergency_current_revision_in(vault, &*txn, event)? != plan.booking.calendar
        {
            return Err(emergency_refused(
                "emergency booking snapshot is stale or does not belong to this owner",
            ));
        }
        if !(2..=3).contains(&plan.proposals.len()) {
            return Err(emergency_refused(
                "emergency requires two or three genuine proposals",
            ));
        }
        for slot in &plan.proposals {
            let target = TimeRange {
                start: slot.start_utc,
                end: slot.end_utc,
            };
            let solved = emergency::solve_live(
                vault,
                &plan.booking,
                calendars,
                inclusive_occurrence(target)?,
                input.now_utc,
            )?;
            if slot.start_utc <= input.now_utc || !offers_slot(&solved.slots, target) {
                return Err(emergency_refused(
                    "an emergency proposal is no longer available",
                ));
            }
        }
        emergency::verify_initial_invite_in(vault, txn, plan)?;
        let admission = plan
            .payload
            .as_ref()
            .map(|payload| {
                crate::calendar::admit_calendar_invite(
                    vault,
                    plan.request.owner_ref,
                    payload,
                    input.now_utc,
                )
                .map_err(crate::booking::emergency_reschedule::calendar_failure)
            })
            .transpose()?;
        if admission
            .as_ref()
            .is_some_and(|admission| admission.event_ref() != event)
        {
            return Err(emergency_refused(
                "calendar admission names another booking",
            ));
        }
        let cancel = plan.request.action_policy == EmergencyActionPolicy::Cancel;
        let status = if cancel {
            BookingStatus::Cancelled
        } else {
            BookingStatus::Confirmed
        };
        let slot = if cancel {
            booking.slot
        } else {
            TimeRange {
                start: plan.proposals[0].start_utc,
                end: plan.proposals[0].end_utc,
            }
        };
        if !cancel {
            vault
                .batch_in()
                .put(
                    &event,
                    ENTITY_TYPE_EVENT,
                    inclusive_occurrence(slot)?,
                    input.now_utc,
                    &encode_event_body(&booking.event_type)?,
                )
                .apply(txn)
                .map_err(|error| engine_failure("emergency event rewrite", error))?;
        }
        supersede_exact_claim(
            vault,
            txn,
            &event,
            BOOKING_STATUS_PREDICATE,
            encode_claim_value(&BookingStatusValue {
                status,
                recorded_at: input.now_utc,
            })?,
            input.now_utc,
        )?;
        supersede_exact_claim(
            vault,
            txn,
            &event,
            PREDICATE_CALENDAR_STATUS,
            calendar_status_value(
                if cancel {
                    CalendarStatus::Cancelled
                } else {
                    CalendarStatus::Confirmed
                },
                input.now_utc,
            ),
            input.now_utc,
        )?;
        let calendar = supersede_outbound_passport(
            vault,
            txn,
            &event,
            &BookingContent {
                page_ref: booking.page_ref,
                event_type: booking.event_type,
                slot,
                status,
                emergency_content_hash: Some(plan.content_hash),
            },
            input.now_utc,
        )?;
        if calendar.uid != plan.booking.calendar.uid
            || Some(calendar.sequence) != plan.booking.calendar.sequence.checked_add(1)
        {
            return Err(emergency_refused(
                "emergency calendar sequence conflicts with the lifecycle revision",
            ));
        }
        if let Some(admission) = admission {
            admission
                .commit_in_txn(vault, txn, input.now_utc)
                .map_err(crate::booking::emergency_reschedule::calendar_failure)?;
        }
        if cancel {
            write_receipt(
                vault,
                txn,
                &revision_receipt_key(&event, None),
                &LifecycleReceiptRow {
                    event_ref: event,
                    uid: calendar.uid.clone(),
                    sequence: calendar.sequence,
                    session_hash: None,
                    confirmation: None,
                    invite_identity: None,
                },
            )?;
        }
        let mut actions = Vec::new();
        for proposal_index in 0..plan.proposals.len() {
            let token = OpaqueLifecycleToken(mint_raw_token());
            put_meta(
                vault,
                txn,
                &meta_key(BOOKING_TOKEN_META_PREFIX, &token_digest(&token)),
                &encode_row(&EmergencyPickRow {
                    emergency_item_key: key.clone(),
                    proposal_index,
                })?,
            )?;
            actions.push(token);
        }
        let item = EmergencyItem {
            plan: plan.clone(),
            calendar,
            basis: if !cancel {
                EmergencyLocalBasis::RequestUpdate
            } else if input.now_utc < booking.slot.start {
                EmergencyLocalBasis::PreStartCancellation
            } else {
                EmergencyLocalBasis::EmergencyAtOrAfterStart
            },
            committed_at: input.now_utc,
            actions,
            // No initial invitation means no CANCEL effect is owed.
            calendar_delivered: plan.payload.is_none(),
            apology_delivered: false,
            picked: None,
        };
        if item.basis == EmergencyLocalBasis::PreStartCancellation {
            use crate::calendar::outcome::{
                EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue,
            };
            crate::calendar::outcome::record_lifecycle_outcome_in_txn(
                vault,
                txn,
                event,
                &EventOutcomeClaimValue {
                    outcome: EventOutcome::CancelledPreStart,
                    basis: EventOutcomeBasis::OwnerAttested,
                    recorded_at: item.committed_at,
                },
                None,
            )
            .map_err(|error| BookingError::Boundary(Box::new(error.into())))?;
        }
        emergency::write_item_in(vault, txn, &item)?;
        Ok(item)
    })
}

/// Resolves only a released proposal action, with its instruction and owner
/// still valid. Shared by preparation and the serialized transition.
fn emergency_pick_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    token: &OpaqueLifecycleToken,
) -> Result<(crate::booking::emergency_reschedule::EmergencyItem, usize), BookingError> {
    use crate::booking::emergency_reschedule as emergency;
    let action: EmergencyPickRow =
        read_meta(vault, txn, BOOKING_TOKEN_META_PREFIX, &token_digest(token))?
            .ok_or_else(|| emergency_refused("unknown emergency lifecycle action"))?;
    let item = emergency::read_item_in(vault, txn, &action.emergency_item_key)?
        .ok_or_else(|| emergency_refused("emergency action has no durable checkpoint"))?;
    emergency::verify_plan_in(vault, txn, &item.plan)?;
    crate::memory::verify_deletion_authority_in_txn(
        vault,
        txn,
        item.plan.request.owner_ref,
        crate::edge::EdgeActorClass::Human,
    )
    .map_err(|error| BookingError::Boundary(Box::new(error)))?;
    if !item.calendar_delivered || !item.apology_delivered {
        return Err(emergency_refused(
            "emergency actions are not released until both deliveries complete",
        ));
    }
    if item.actions.get(action.proposal_index) != Some(token) {
        return Err(emergency_refused(
            "emergency action does not bind this proposal",
        ));
    }
    Ok((item, action.proposal_index))
}

pub(in crate::booking) fn read_emergency_pick(
    vault: &Vault,
    token: &OpaqueLifecycleToken,
    input: &BookingLifecycleConsumerInput,
) -> Result<(crate::booking::emergency_reschedule::EmergencyItem, usize), BookingError> {
    require_emergency_home(vault, input)?;
    let txn = read_txn(vault)?;
    emergency_pick_in(vault, &txn, token)
}

/// Only this proposal-bound instruction transition may reopen the exact
/// emergency-cancelled revision. Its REQUEST content checkpoint commits with
/// the booking; CAL admission follows against that now-confirmed booking.
pub(in crate::booking) fn pick_emergency_item(
    vault: &Vault,
    token: &OpaqueLifecycleToken,
    calendars: &[(EntityId, Vec<crate::calendar::query::CalendarSel>)],
    input: &BookingLifecycleConsumerInput,
    prepared: &crate::booking::emergency_reschedule::EmergencyPick,
) -> Result<crate::booking::emergency_reschedule::EmergencyItem, BookingError> {
    use crate::booking::emergency_reschedule as emergency;
    require_emergency_home(vault, input)?;
    booking_writer(vault, |txn| {
        if crate::identity::read_client_id_in_txn(vault, &*txn)
            .map_err(|error| engine_failure("local identity read", error))?
            != Some(input.local_node_id)
        {
            return Err(BookingError::InvalidConfig(
                "wrong lifecycle home node".to_owned(),
            ));
        }
        let (mut item, proposal_index) = emergency_pick_in(vault, &*txn, token)?;
        let proposal = item
            .plan
            .proposals
            .get(proposal_index)
            .ok_or_else(|| emergency_refused("missing genuine proposal"))?;
        let target = TimeRange {
            start: proposal.start_utc,
            end: proposal.end_utc,
        };
        let event = item.calendar.event_ref;
        let booking = read_booking_facts(vault, &*txn, &event)?;
        let current = emergency_current_revision_in(vault, &*txn, event)?;
        if let Some(picked) = &item.picked {
            return if picked.proposal_index == proposal_index
                && booking.status == BookingStatus::Confirmed
                && booking.slot == target
                && current == picked.calendar
            {
                Ok(item)
            } else {
                Err(emergency_refused(
                    "this emergency action has already been consumed",
                ))
            };
        }
        let expected_status =
            if item.plan.request.action_policy == emergency::EmergencyActionPolicy::Cancel {
                BookingStatus::Cancelled
            } else {
                BookingStatus::Confirmed
            };
        if current != item.calendar
            || booking.status != expected_status
            || booking.context.as_ref() != Some(&item.plan.booking.context)
        {
            return Err(emergency_refused(
                "only this exact emergency revision may accept its proposal",
            ));
        }
        if prepared.proposal_index != proposal_index
            || prepared.committed_at != input.now_utc
            || prepared.calendar_delivered
        {
            return Err(emergency_refused(
                "prepared REQUEST does not bind this pick",
            ));
        }
        emergency::verify_pick_blob(vault, &item, prepared)?;
        emergency::verify_pick_invite_in(vault, txn, &item)?;
        if target.start <= input.now_utc {
            return Err(emergency_refused("the picked proposal is no longer future"));
        }
        // A RequestUpdate already occupies its first proposal. Retaining that
        // exact slot is not a new allocation and must not collide with itself.
        if booking.status != BookingStatus::Confirmed || booking.slot != target {
            let solved = emergency::solve_live(
                vault,
                &item.plan.booking,
                calendars,
                inclusive_occurrence(target)?,
                input.now_utc,
            )?;
            if !offers_slot(&solved.slots, target) {
                return Err(emergency_refused("the picked proposal is now busy"));
            }
        }
        vault
            .batch_in()
            .put(
                &event,
                ENTITY_TYPE_EVENT,
                inclusive_occurrence(target)?,
                input.now_utc,
                &encode_event_body(&booking.event_type)?,
            )
            .apply(txn)
            .map_err(|error| engine_failure("emergency picked event rewrite", error))?;
        supersede_exact_claim(
            vault,
            txn,
            &event,
            BOOKING_STATUS_PREDICATE,
            encode_claim_value(&BookingStatusValue {
                status: BookingStatus::Confirmed,
                recorded_at: input.now_utc,
            })?,
            input.now_utc,
        )?;
        supersede_exact_claim(
            vault,
            txn,
            &event,
            PREDICATE_CALENDAR_STATUS,
            calendar_status_value(CalendarStatus::Confirmed, input.now_utc),
            input.now_utc,
        )?;
        let revision = supersede_outbound_passport(
            vault,
            txn,
            &event,
            &BookingContent {
                page_ref: booking.page_ref,
                event_type: booking.event_type,
                slot: target,
                status: BookingStatus::Confirmed,
                emergency_content_hash: Some(prepared.content_hash),
            },
            input.now_utc,
        )?;
        if revision != prepared.calendar {
            return Err(emergency_refused(
                "picked REQUEST sequence conflicts with the lifecycle revision",
            ));
        }
        if expected_status == BookingStatus::Cancelled {
            delete_meta(
                vault,
                txn,
                &meta_key(
                    BOOKING_RECEIPT_META_PREFIX,
                    &revision_receipt_key(&event, None),
                ),
            )?;
        }
        if item.basis == emergency::EmergencyLocalBasis::PreStartCancellation {
            use crate::calendar::outcome::{
                EventOutcome, EventOutcomeBasis, EventOutcomeClaimValue,
            };
            crate::calendar::outcome::record_lifecycle_outcome_in_txn(
                vault,
                txn,
                event,
                &EventOutcomeClaimValue {
                    outcome: EventOutcome::Unknown,
                    basis: EventOutcomeBasis::OwnerAttested,
                    recorded_at: prepared.committed_at,
                },
                Some(EventOutcomeClaimValue {
                    outcome: EventOutcome::CancelledPreStart,
                    basis: EventOutcomeBasis::OwnerAttested,
                    recorded_at: item.committed_at,
                }),
            )
            .map_err(|error| BookingError::Boundary(Box::new(error.into())))?;
        }
        item.picked = Some(prepared.clone());
        emergency::write_item_in(vault, txn, &item)?;
        Ok(item)
    })
}

/// CAL reads the committed confirmed booking to verify its existing invite
/// grant. Commit its passport before dispatch, guarded by the same home writer
/// and exact pick checkpoint. A refusal leaves the pick pending, not unbound.
pub(in crate::booking) fn admit_emergency_pick(
    vault: &Vault,
    item: &crate::booking::emergency_reschedule::EmergencyItem,
    input: &BookingLifecycleConsumerInput,
) -> Result<(), BookingError> {
    use crate::booking::emergency_reschedule as emergency;
    require_emergency_home(vault, input)?;
    booking_writer(vault, |txn| {
        if crate::identity::read_client_id_in_txn(vault, &*txn)
            .map_err(|error| engine_failure("local identity read", error))?
            != Some(input.local_node_id)
        {
            return Err(BookingError::InvalidConfig(
                "wrong lifecycle home node".to_owned(),
            ));
        }
        emergency::verify_plan_in(vault, &*txn, &item.plan)?;
        crate::memory::verify_deletion_authority_in_txn(
            vault,
            &*txn,
            item.plan.request.owner_ref,
            crate::edge::EdgeActorClass::Human,
        )
        .map_err(|error| BookingError::Boundary(Box::new(error)))?;
        let current = emergency::read_item_in(
            vault,
            &*txn,
            &emergency::item_key(&item.plan.request, item.calendar.event_ref)?,
        )?
        .ok_or_else(|| emergency_refused("pick checkpoint disappeared"))?;
        let picked = item
            .picked
            .as_ref()
            .ok_or_else(|| emergency_refused("missing picked REQUEST"))?;
        if current.plan != item.plan
            || current
                .picked
                .as_ref()
                .is_none_or(|saved| saved.content_hash != picked.content_hash)
            || emergency_current_revision_in(vault, &*txn, item.calendar.event_ref)?
                != picked.calendar
        {
            return Err(emergency_refused(
                "a newer revision supersedes this picked REQUEST",
            ));
        }
        emergency::verify_pick_blob(vault, item, picked)?;
        let admission = crate::calendar::admit_calendar_invite(
            vault,
            item.plan.request.owner_ref,
            &picked.payload,
            input.now_utc,
        )
        .map_err(crate::booking::emergency_reschedule::calendar_failure)?;
        if admission.event_ref() != picked.calendar.event_ref {
            return Err(emergency_refused("picked REQUEST names another booking"));
        }
        admission
            .commit_in_txn(vault, txn, input.now_utc)
            .map_err(crate::booking::emergency_reschedule::calendar_failure)
    })
}
