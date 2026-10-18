//! Typed meeting prep, outcome observation and the owner's check-in policy.
use serde::{Deserialize, Serialize};

use crate::calendar::outcome::{
    self, CheckInAnswer, CheckInResolution, DEFAULT_OUTCOME_GRACE_SECS, DueOutcomeCheckIn,
    EventOutcome, EventOutcomeClaimValue, MeetingClassSignals,
};
use crate::calendar::prep::{PrepBuildRequest, PrepPack, PrepPolicy, build_prep_pack_scoped};
use crate::claim::{
    ClaimApprovalStatus, ClaimReadStatus, ClaimSource, PointRead, ScopedReadResult,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, WriteActor, WriteEnvelope, WriteProvenance};

mod facts;
pub(in crate::calendar) use facts::meeting_event_in_txn;

const POLICY: SideTable<(), CalendarOutcomePolicy, Named> =
    SideTable::new(&side_table::CALENDAR_OUTCOME_POLICY);

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarMeetingRequest {
    pub event_ref: String,
}

/// Vault-side grace, never a caller-supplied clock or evidence signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarOutcomePolicy {
    pub grace_secs: u64,
}

impl Default for CalendarOutcomePolicy {
    fn default() -> Self {
        Self {
            grace_secs: DEFAULT_OUTCOME_GRACE_SECS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarEventOutcome {
    pub event_ref: String,
    pub outcome: EventOutcome,
    pub claim: Option<EventOutcomeClaimValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarCheckInDue {
    pub event_ref: String,
    pub observed_at: u64,
    pub grace_secs: u64,
    pub due_at: Option<u64>,
    pub due: bool,
    pub outcome: Option<EventOutcomeClaimValue>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CalendarCheckInAnswer {
    Held,
    NoShow,
    Rescheduled,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarCheckInRequest {
    pub event_ref: String,
    pub answer: CalendarCheckInAnswer,
}

/// A reschedule disposition routes the consumer to scheduling; it is not an outcome.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum CalendarCheckInReceipt {
    Outcome {
        event_ref: String,
        claim_ref: String,
        value: EventOutcomeClaimValue,
    },
    RescheduleRequested {
        event_ref: String,
        claim_ref: String,
        value: EventOutcomeClaimValue,
    },
}

fn event_id(reference: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(reference)
        .map_err(|_| MemoryError::bad_request("event_ref is not an entity id"))
}

fn check_owner(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    txn: &heed::RoTxn<'_>,
) -> MemoryResult<()> {
    if owner.revalidate_in_txn(memory.vault(), txn)? != memory.actor()
        || memory.actor_class() != EdgeActorClass::Human
    {
        return Err(MemoryError::bad_request(
            "calendar check-in must act as its authenticated owner",
        ));
    }
    Ok(())
}

pub fn outcome_policy_get(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
) -> MemoryResult<CalendarOutcomePolicy> {
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    check_owner(memory, owner, &txn)?;
    Ok(POLICY
        .get(&memory.vault().store, &txn, &())?
        .unwrap_or_default())
}

pub fn outcome_policy_set(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarOutcomePolicy,
) -> MemoryResult<CalendarOutcomePolicy> {
    memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        POLICY.put(&memory.vault().store, txn, &(), input)?;
        Ok(input.clone())
    })
}

fn signals(event: &crate::calendar::PrepEvent) -> MeetingClassSignals {
    MeetingClassSignals {
        external_attendee_count: event.external_attendee_count,
        has_campaign_linkage: event.has_campaign_linkage,
        has_commitment_linkage: event.has_commitment_linkage,
        internal_meeting_opt_in: event.internal_meeting_opt_in,
    }
}

fn trace_event(memory: &Memory<'_>, txn: &heed::RoTxn<'_>, event: EntityId) -> crate::Result<()> {
    memory.produced_from([event]);
    for id in memory.vault().claims_for_subject_in_txn(txn, &event)? {
        if memory
            .vault()
            .get_claim_in_txn(txn, &id)?
            .is_some_and(|body| body.lifecycle == crate::claim::ClaimLifecycleStatus::Active)
        {
            memory.produced_from([id]);
        }
    }
    Ok(())
}

fn due_in_txn(
    memory: &Memory<'_>,
    lane: &crate::claim::ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    event: EntityId,
) -> crate::Result<CalendarCheckInDue> {
    let vault = memory.vault();
    trace_event(memory, txn, event)?;
    let observed_at = vault.instant_in_txn(txn)?.secs();
    let grace_secs = POLICY
        .get(&vault.store, txn, &())?
        .unwrap_or_default()
        .grace_secs;
    let outcome = outcome::current_outcome_in(vault, txn, &event)?;
    let mut result = CalendarCheckInDue {
        event_ref: event.to_hex(),
        observed_at,
        grace_secs,
        due_at: None,
        due: false,
        outcome,
    };
    if let Some(meeting) = meeting_event_in_txn(vault, txn, lane, event)? {
        let signals = signals(&meeting);
        if outcome::is_meeting_class(signals) {
            let due_at = meeting.end_utc.saturating_add(grace_secs);
            result.due_at = Some(due_at);
            result.due = observed_at >= due_at
                && outcome::check_in_is_still_due_in_txn(
                    vault,
                    txn,
                    &DueOutcomeCheckIn {
                        wake_id: format!(
                            "{}:{}",
                            outcome::OUTCOME_CHECK_IN_REASON_TAG,
                            event.to_hex()
                        ),
                        event_ref: event,
                        scheduled_start_utc: meeting.start_utc,
                        signals,
                    },
                )?;
        }
    }
    Ok(result)
}

pub fn check_in_due(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarMeetingRequest,
) -> MemoryResult<ScopedReadResult<Option<CalendarCheckInDue>>> {
    let event = event_id(&input.event_ref)?;
    let lane = memory.read_lane(ClaimReadStatus::Surfaceable)?;
    lane.read_projected(&[PointRead::id(event)], None, |txn, _| {
        check_owner(memory, owner, txn)?;
        if !facts::readable_event_in_txn(memory.vault(), txn, &lane, event)? {
            return Ok(None);
        }
        Ok(Some(due_in_txn(memory, &lane, txn, event)?))
    })
}

pub fn check_in_answer(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: &CalendarCheckInRequest,
) -> MemoryResult<CalendarCheckInReceipt> {
    let event = event_id(&input.event_ref)?;
    let lane = memory.read_lane(ClaimReadStatus::Surfaceable)?;
    let receipt = memory.with_verified_actor_write_txn(|txn| {
        check_owner(memory, owner, txn)?;
        if !facts::readable_event_in_txn(memory.vault(), txn, &lane, event)? {
            return Err(MemoryError::not_found(
                "calendar EVENT is absent or withheld",
            ));
        }
        let due = due_in_txn(memory, &lane, txn, event)?;
        if !due.due {
            return Err(MemoryError::bad_request(
                "calendar check-in is not due or already has evidence",
            ));
        }
        let answer = match input.answer {
            CalendarCheckInAnswer::Held => CheckInAnswer::Held,
            CalendarCheckInAnswer::NoShow => CheckInAnswer::NoShow,
            CalendarCheckInAnswer::Rescheduled => CheckInAnswer::Rescheduled,
        };
        let resolution = outcome::resolve_owner_check_in(event, answer, due.observed_at);
        let value = resolution.recorded_value();
        let envelope = WriteEnvelope::new(
            WriteActor::new(memory.actor(), memory.actor_class()),
            ClaimSource::UserStated,
            WriteProvenance::new(rmpv::Value::from("vault.calendar.check_in.answer"))?,
            ClaimApprovalStatus::Auto,
        );
        let claim = outcome::record_event_outcome_as_in_txn(
            memory.vault(),
            txn,
            event,
            &value,
            &envelope,
            None,
        )?;
        memory.produced_from([claim]);
        match resolution {
            CheckInResolution::Outcome(_) => Ok(CalendarCheckInReceipt::Outcome {
                event_ref: event.to_hex(),
                claim_ref: claim.to_hex(),
                value,
            }),
            CheckInResolution::RescheduleRequested { .. } => {
                Ok(CalendarCheckInReceipt::RescheduleRequested {
                    event_ref: event.to_hex(),
                    claim_ref: claim.to_hex(),
                    value,
                })
            }
        }
    })?;
    memory.produced_from([event]);
    Ok(receipt)
}

impl Memory<'_> {
    pub fn calendar_prep(
        &self,
        input: &CalendarMeetingRequest,
    ) -> MemoryResult<ScopedReadResult<Option<PrepPack>>> {
        let event = event_id(&input.event_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        let scoped = lane.read_projected(
            &[PointRead::id(event)],
            None,
            |txn, _| -> crate::Result<_> {
                let meeting = meeting_event_in_txn(self.vault(), txn, &lane, event)?;
                if meeting.is_some() {
                    trace_event(self, txn, event)?;
                }
                Ok(meeting)
            },
        )?;
        let mut receipt = scoped.receipt;
        let Some(event) = scoped.value else {
            return Ok(ScopedReadResult {
                value: None,
                receipt,
            });
        };
        let pack = build_prep_pack_scoped(
            &lane,
            &PrepBuildRequest {
                event,
                fired_at: self.vault().now_recorded_at(),
                policy: PrepPolicy::default(),
            },
        )?;
        receipt.restrict_with(&pack.receipt);
        if let Some(pack) = &pack.value {
            self.produced_from(
                pack.sections
                    .iter()
                    .flat_map(|section| &section.items)
                    .flat_map(|item| &item.source_refs)
                    .filter_map(|reference| EntityId::from_hex(reference).ok()),
            );
        }
        Ok(ScopedReadResult {
            value: pack.value,
            receipt,
        })
    }

    pub fn calendar_event_outcome(
        &self,
        input: &CalendarMeetingRequest,
    ) -> MemoryResult<ScopedReadResult<Option<CalendarEventOutcome>>> {
        let event = event_id(&input.event_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Surfaceable)?;
        Ok(lane.read_projected(
            &[PointRead::id(event)],
            None,
            |txn, _| -> crate::Result<_> {
                if !facts::readable_event_in_txn(self.vault(), txn, &lane, event)? {
                    return Ok(None);
                }
                trace_event(self, txn, event)?;
                let claim = outcome::current_outcome_in(self.vault(), txn, &event)?;
                Ok(Some(CalendarEventOutcome {
                    event_ref: event.to_hex(),
                    outcome: outcome::project_event_outcome(claim),
                    claim,
                }))
            },
        )?)
    }
}
