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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linkedin_connector::{
        LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB, LinkedInSandboxHostConfig,
        LinkedInSeatSandboxPolicy,
    };
    use crate::outbound::capability::outbound_verb_contract;
    use crate::outbound::dispatch_types::{OutboundDispatchActor, OutboundDispatchGate};
    use crate::outbound::intent::{OutboundIntent, OutboundIntentDraft, OutboundIntentTrigger};

    fn seat_applicable_request(
        window_decision: OutboundDeliveryWindowDecision,
    ) -> OutboundDispatchRequest {
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new(
                "agent:dispatch",
                LINKEDIN_SEND_DM_VERB,
                LINKEDIN_CHANNEL,
                "linkedin:member:jane-doe",
            ),
            OutboundIntentTrigger::agent_immediate("session:admission"),
        );
        let policy = LinkedInSeatSandboxPolicy::new(
            LinkedInSandboxHostConfig::new(
                "seat:jane",
                "sandbox:jane",
                "profile:jane",
                "vault-secret:linkedin-cookie",
            )
            .expect("host config"),
        );
        OutboundDispatchRequest::new(
            "receipt:admission",
            "intent:admission",
            intent,
            OutboundDispatchActor::agent(crate::test_util::entity(0xD1)),
            OutboundDispatchGate::allow_when_policy_grants(),
            1_060,
            window_decision,
        )
        .linkedin_sandbox_policy(policy)
    }

    #[test]
    fn admission_carries_the_park_reason_without_a_second_window_or_seat_check() {
        let contract = outbound_verb_contract(LINKEDIN_CHANNEL, LINKEDIN_SEND_DM_VERB)
            .expect("registered DM contract");
        // An inactive seat holds an unparked send, so the parked cases below
        // cannot pass merely because the request has no applicable seat policy.
        let request = seat_applicable_request(OutboundDeliveryWindowDecision::DeliverNow);
        let unparked = AdmissionStage::evaluate(
            &request,
            contract,
            DeliveryWindowResolution::missing_local_minute(Vec::new()),
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        assert_eq!(
            unparked.seat.as_ref().expect("seat evaluated").action,
            SeatPolicyAction::Hold
        );
        assert_eq!(
            unparked.decision,
            DispatchAdmission::Park {
                outcome: OutboundDispatchOutcome::Held
            }
        );

        for (window_decision, expected) in [
            (
                OutboundDeliveryWindowDecision::Hold {
                    reason: "quiet".to_owned(),
                    retry_at: None,
                },
                OutboundDispatchOutcome::Held,
            ),
            (
                OutboundDeliveryWindowDecision::Degrade {
                    reason: "quiet".to_owned(),
                    from: "interrupt".to_owned(),
                    to: "ambient".to_owned(),
                },
                OutboundDispatchOutcome::Degraded,
            ),
            (
                OutboundDeliveryWindowDecision::LetGo {
                    reason: "expired".to_owned(),
                },
                OutboundDispatchOutcome::LetGo,
            ),
        ] {
            let request = seat_applicable_request(window_decision.clone());
            let stage = AdmissionStage::evaluate(
                &request,
                contract,
                DeliveryWindowResolution::missing_local_minute(Vec::new()),
                window_decision.clone(),
            );
            assert_eq!(
                stage.decision,
                DispatchAdmission::Park { outcome: expected }
            );
            assert!(
                stage.seat.is_none(),
                "{window_decision:?} must skip the seat policy"
            );
        }
    }
}
