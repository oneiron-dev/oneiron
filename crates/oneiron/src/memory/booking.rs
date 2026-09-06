//! Owner-authenticated booking operations on the existing Memory surface.

use super::{Memory, MemoryError, MemoryResult};
use crate::EntityId;
use crate::booking::emergency_reschedule::{
    self as emergency, EmergencyActionPolicy, EmergencyBatchPlan, EmergencyItem, EmergencyPlan,
    EmergencyRescheduleRequest, OwnerInstructionRecord,
};
use crate::booking::{BookingLifecycleConsumerInput, CalendarRevision, OpaqueLifecycleToken};
use crate::calendar::query::{CalendarRangeDto, CalendarSel};
use crate::outbound::OutboundExecutionSink;

/// The bound Memory actor is the owner; an input never names a replacement actor.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmergencyInstructionInput {
    pub affected_window: CalendarRangeDto,
    pub reason: String,
    pub action_policy: EmergencyActionPolicy,
    pub recorded_at: u64,
}

pub(crate) fn booking_error(error: crate::booking::BookingError) -> MemoryError {
    use crate::booking::BookingError;
    if let BookingError::Boundary(error) = error {
        return *error;
    }
    let code = match &error {
        BookingError::Boundary(_) => unreachable!(),
        BookingError::InvalidConstraint(_) | BookingError::ConstraintParse(_) => {
            super::MEMORY_CODE_BAD_REQUEST
        }
        BookingError::InvalidConfig(_) | BookingError::SessionCapExhausted => {
            super::MEMORY_CODE_INVALID_STATE
        }
        BookingError::SlotOracle(_) | BookingError::Surface(_) => super::MEMORY_CODE_INTERNAL,
    };
    MemoryError::new(
        code,
        error.to_string(),
        &["Check current booking state and local storage before retrying."],
    )
}

impl Memory<'_> {
    /// Logs the single lane-owned stamp under the existing owner-verb checks.
    /// Actor validity and owner authority are checked in the stamp transaction.
    pub fn record_emergency_instruction(
        &self,
        input: &EmergencyInstructionInput,
    ) -> MemoryResult<OwnerInstructionRecord> {
        let window = input.affected_window.to_time_range();
        let record = OwnerInstructionRecord {
            owner_ref: self.actor,
            request_hash: emergency::canonical_emergency_request_hash(
                window,
                &input.reason,
                input.action_policy,
            )
            .map_err(booking_error)?,
            recorded_at: input.recorded_at,
        };
        let request = EmergencyRescheduleRequest {
            owner_ref: self.actor,
            affected_window: window,
            reason: input.reason.clone(),
            action_policy: input.action_policy,
            authority: record.clone(),
        };
        self.with_verified_actor_write_txn(|txn| {
            super::support::verify_deletion_authority_in_txn(
                self.vault,
                &*txn,
                self.actor,
                self.actor_class,
            )?;
            emergency::append_instruction_in_txn(self.vault, txn, &request).map_err(booking_error)
        })?;
        emergency::verify_logged_owner_instruction(self.vault, &request).map_err(booking_error)?;
        Ok(record)
    }

    fn verify_emergency_owner(&self, request: &EmergencyRescheduleRequest) -> MemoryResult<()> {
        if request.owner_ref != self.actor {
            return Err(MemoryError::bad_request(
                "emergency request names another owner",
            ));
        }
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        super::support::verify_deletion_authority_in_txn(
            self.vault,
            &txn,
            self.actor,
            self.actor_class,
        )
    }

    pub fn plan_emergency_reschedule(
        &self,
        request: &EmergencyRescheduleRequest,
        calendars: &[(EntityId, Vec<CalendarSel>)],
        now_utc: u64,
    ) -> MemoryResult<EmergencyBatchPlan> {
        self.verify_emergency_owner(request)?;
        emergency::plan_emergency_reschedule(self.vault, request, calendars, now_utc)
            .map_err(booking_error)
    }

    pub fn execute_emergency_reschedule(
        &self,
        request: &EmergencyRescheduleRequest,
        plan: &EmergencyPlan,
        calendars: &[(EntityId, Vec<CalendarSel>)],
        input: &BookingLifecycleConsumerInput,
        sink: &mut impl OutboundExecutionSink,
    ) -> MemoryResult<EmergencyItem> {
        self.verify_emergency_owner(request)?;
        emergency::execute_emergency_plan(self.vault, request, plan, calendars, input, sink)
            .map_err(booking_error)
    }

    /// The action itself is counterparty authority for one persisted proposal.
    /// It is never converted into an owner cancel/reschedule token.
    pub fn pick_emergency_reschedule(
        &self,
        token: &OpaqueLifecycleToken,
        calendars: &[(EntityId, Vec<CalendarSel>)],
        input: &BookingLifecycleConsumerInput,
        sink: &mut impl OutboundExecutionSink,
    ) -> MemoryResult<CalendarRevision> {
        self.verified_actor_class()?;
        emergency::counterparty_pick(self.vault, token, calendars, input, sink)
            .map_err(booking_error)
    }
}
