//! Connector-neutral seat wall and its host-supplied LinkedIn policy adapter.
use std::collections::BTreeMap;

use crate::linkedin_connector::{
    LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB, LINKEDIN_SEND_DM_VERB,
    LinkedInSeatPolicyAction, LinkedInSeatPolicyDecision, LinkedInSeatSandboxPolicy,
};
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::dispatch_types::OutboundDispatchRequest;
use crate::outbound_chokepoint::AdmissionCeiling;

/// The window a seat's daily caps count over. Admission anchors it, and
/// stamps the ledger, at the vault's own clock in seconds (FIX 5992), so the
/// window is in seconds too. A rolling day holds every send of the host's
/// calendar day and possibly a few more, so it never counts fewer.
const SEAT_CAP_WINDOW_SECS: u64 = 24 * 60 * 60;

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

/// This vault's own count of a seat's capped sends: the LinkedIn connects or
/// DMs the outbound intent ledger admitted in the last day, settled or not.
/// The host's count stays a floor; admission reads the larger of the two.
///
/// The count is read once, by the admission writer lock through
/// [`Self::ceiling`], after an exact retry has replayed and a semantic
/// duplicate has been suppressed. The seat wall before it sees only the
/// host's count, so a duplicate at a full cap is still suppressed, never
/// held; a send the ceiling holds raises this count to what the lock read
/// ([`Self::held_at`]) for its typed reason.
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::outbound) struct SeatLedgerCount {
    connect_requests: u16,
    dm_sends: u16,
    pub(super) ceiling: Option<AdmissionCeiling>,
}

impl SeatLedgerCount {
    /// The admission ceiling for a request whose seat policy caps its verb;
    /// every other request has none.
    pub(super) fn for_request(
        request: &OutboundDispatchRequest,
        verb_contract: &OutboundVerbContract,
    ) -> Self {
        let Some(policy) = request.linkedin_sandbox_policy.as_ref() else {
            return Self::default();
        };
        // The channel as the seat wall reads it.
        if crate::outbound::capability::normalize_key(&request.intent.channel) != LINKEDIN_CHANNEL {
            return Self::default();
        }
        let (host_count, cap) = match verb_contract.kind.as_str() {
            LINKEDIN_CONNECT_REQUEST_VERB => (
                policy.state.connect_requests_today,
                policy.limits.daily_connect_request_cap,
            ),
            LINKEDIN_SEND_DM_VERB => (policy.state.dm_sends_today, policy.limits.daily_dm_cap),
            _ => return Self::default(),
        };
        Self {
            connect_requests: 0,
            dm_sends: 0,
            ceiling: Some(AdmissionCeiling {
                window_secs: SEAT_CAP_WINDOW_SECS,
                prior: u32::from(host_count),
                cap: u32::from(cap),
            }),
        }
    }

    /// This count raised to what the admission writer lock read for a send
    /// its ceiling held.
    pub(super) fn held_at(mut self, verb_contract: &OutboundVerbContract, count: u32) -> Self {
        let count = u16::try_from(count).unwrap_or(u16::MAX);
        if verb_contract.kind == LINKEDIN_CONNECT_REQUEST_VERB {
            self.connect_requests = self.connect_requests.max(count);
        } else {
            self.dm_sends = self.dm_sends.max(count);
        }
        self
    }

    /// The policy with each capped count raised to this vault's own count.
    fn raise(self, policy: &LinkedInSeatSandboxPolicy) -> LinkedInSeatSandboxPolicy {
        let mut policy = policy.clone();
        let state = &mut policy.state;
        state.connect_requests_today = state.connect_requests_today.max(self.connect_requests);
        state.dm_sends_today = state.dm_sends_today.max(self.dm_sends);
        policy
    }
}

pub(super) fn evaluate_seat_policy(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
    ledger: SeatLedgerCount,
) -> Option<SeatPolicyDecision> {
    // The channel as the capability lookup read it: a spelling that lookup
    // accepts cannot step around the seat wall.
    let channel = crate::outbound::capability::normalize_key(&request.intent.channel);
    let Some(policy) = request.linkedin_sandbox_policy.as_ref() else {
        // A LinkedIn effect with no seat verdict is held, never executed.
        return (channel == LINKEDIN_CHANNEL)
            .then(|| LinkedInSeatPolicyDecision::seat_policy_missing().into());
    };
    let policy = &ledger.raise(policy);
    let send_decision =
        policy.evaluate_outbound(&channel, &verb_contract.kind, request.occurred_at);
    if channel == LINKEDIN_CHANNEL
        && verb_contract.kind == LINKEDIN_CONNECT_REQUEST_VERB
        && matches!(send_decision.action, LinkedInSeatPolicyAction::Allow)
    {
        let read_decision = policy.evaluate_profile_read();
        if !matches!(read_decision.action, LinkedInSeatPolicyAction::Allow) {
            return Some(read_decision.into());
        }
    }
    Some(send_decision.into())
}
