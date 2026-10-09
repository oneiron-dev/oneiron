//! Connector-neutral seat wall and its host-supplied LinkedIn policy adapter.
use std::collections::BTreeMap;

use crate::linkedin_connector::{
    LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB, LinkedInSeatPolicyAction,
    LinkedInSeatPolicyDecision,
};
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::dispatch_types::OutboundDispatchRequest;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SeatPolicyAction {
    Allow,
    Hold,
    Suppress,
}

/// The dispatch wall consumes this value, not a connector-specific decision.
pub(in crate::outbound) struct SeatPolicyDecision {
    pub(super) action: SeatPolicyAction,
    pub(in crate::outbound) receipt_fields: BTreeMap<String, String>,
    pub(in crate::outbound) policy_trace: Vec<String>,
}

impl From<LinkedInSeatPolicyDecision> for SeatPolicyDecision {
    fn from(value: LinkedInSeatPolicyDecision) -> Self {
        let action = match value.action {
            LinkedInSeatPolicyAction::Allow => SeatPolicyAction::Allow,
            LinkedInSeatPolicyAction::Hold => SeatPolicyAction::Hold,
            LinkedInSeatPolicyAction::Suppress => SeatPolicyAction::Suppress,
        };
        Self {
            action,
            receipt_fields: value.receipt_fields,
            policy_trace: value.policy_trace,
        }
    }
}

pub(super) fn evaluate_seat_policy(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
) -> Option<SeatPolicyDecision> {
    request.linkedin_sandbox_policy.as_ref().map(|policy| {
        let send_decision = policy.evaluate_outbound(
            &request.intent.channel,
            &verb_contract.kind,
            request.occurred_at,
        );
        if request.intent.channel == LINKEDIN_CHANNEL
            && verb_contract.kind == LINKEDIN_CONNECT_REQUEST_VERB
            && matches!(send_decision.action, LinkedInSeatPolicyAction::Allow)
        {
            let read_decision = policy.evaluate_profile_read();
            if !matches!(read_decision.action, LinkedInSeatPolicyAction::Allow) {
                return read_decision.into();
            }
        }
        send_decision.into()
    })
}
