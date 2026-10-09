//! Pure execute-time admission: one decision consumed by freeze and gate paths.
use crate::delivery_window::DeliveryWindowResolution;
use crate::outbound::OutboundDeliveryWindowDecision;
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::dispatch_types::{OutboundDispatchOutcome, OutboundDispatchRequest};

use super::seat_policy::{SeatPolicyAction, SeatPolicyDecision, evaluate_seat_policy};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DispatchAdmission {
    Execute,
    Park { outcome: OutboundDispatchOutcome },
}

pub(in crate::outbound) struct AdmissionStage {
    pub(super) decision: DispatchAdmission,
    pub(in crate::outbound) window_resolution: DeliveryWindowResolution,
    pub(in crate::outbound) window_decision: OutboundDeliveryWindowDecision,
    pub(in crate::outbound) seat: Option<SeatPolicyDecision>,
}

impl AdmissionStage {
    pub(super) fn evaluate(
        request: &OutboundDispatchRequest,
        contract: &OutboundVerbContract,
        window_resolution: DeliveryWindowResolution,
        window_decision: OutboundDeliveryWindowDecision,
    ) -> Self {
        let parked = match &window_decision {
            OutboundDeliveryWindowDecision::Hold { .. } => Some(OutboundDispatchOutcome::Held),
            OutboundDeliveryWindowDecision::Degrade { .. } => {
                Some(OutboundDispatchOutcome::Degraded)
            }
            OutboundDeliveryWindowDecision::LetGo { .. } => Some(OutboundDispatchOutcome::LetGo),
            OutboundDeliveryWindowDecision::DeliverNow
            | OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { .. } => None,
        };
        // A window that parks a send never evaluates the connector's seat policy.
        let seat = if parked.is_none() {
            evaluate_seat_policy(request, contract)
        } else {
            None
        };
        let decision = match parked {
            Some(outcome) => DispatchAdmission::Park { outcome },
            None => match seat.as_ref().map(|seat| seat.action) {
                Some(SeatPolicyAction::Hold) => DispatchAdmission::Park {
                    outcome: OutboundDispatchOutcome::Held,
                },
                Some(SeatPolicyAction::Suppress) => DispatchAdmission::Park {
                    outcome: OutboundDispatchOutcome::Suppressed,
                },
                Some(SeatPolicyAction::Allow) | None => DispatchAdmission::Execute,
            },
        };
        Self {
            decision,
            window_resolution,
            window_decision,
            seat,
        }
    }
}
