//! Connector-neutral seat wall and its host-supplied LinkedIn policy adapter.
use std::collections::BTreeMap;

use crate::Vault;
use crate::linkedin_connector::{
    LINKEDIN_CHANNEL, LINKEDIN_CONNECT_REQUEST_VERB, LINKEDIN_SEND_DM_VERB,
    LinkedInSeatPolicyAction, LinkedInSeatPolicyDecision, LinkedInSeatSandboxPolicy,
};
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::dispatch_types::{OutboundDispatchError, OutboundDispatchRequest};
use crate::outbound_chokepoint::AdmissionCeiling;

/// The window a seat's daily caps count over. Dispatch stamps the ledger with
/// the request's `occurred_at`, which is engine-clock seconds, so the window
/// is in seconds too. A rolling day holds every send of the host's calendar
/// day and possibly a few more, so it never counts fewer.
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
#[derive(Clone, Copy, Debug, Default)]
pub(in crate::outbound) struct SeatLedgerCount {
    connect_requests: u16,
    dm_sends: u16,
    pub(super) ceiling: Option<AdmissionCeiling>,
}

impl SeatLedgerCount {
    /// Reads the count for a request whose seat policy caps its verb; every
    /// other request counts nothing.
    pub(super) fn read(
        vault: &Vault,
        request: &OutboundDispatchRequest,
        verb_contract: &OutboundVerbContract,
    ) -> Result<Self, OutboundDispatchError> {
        let Some(policy) = request.linkedin_sandbox_policy.as_ref() else {
            return Ok(Self::default());
        };
        if !request
            .intent
            .channel
            .trim()
            .eq_ignore_ascii_case(LINKEDIN_CHANNEL)
        {
            return Ok(Self::default());
        }
        let (host_count, cap) = match verb_contract.kind.as_str() {
            LINKEDIN_CONNECT_REQUEST_VERB => (
                policy.state.connect_requests_today,
                policy.limits.daily_connect_request_cap,
            ),
            LINKEDIN_SEND_DM_VERB => (policy.state.dm_sends_today, policy.limits.daily_dm_cap),
            _ => return Ok(Self::default()),
        };
        let since_ms = request.occurred_at.saturating_sub(SEAT_CAP_WINDOW_SECS);
        // An exact retry of this logical send already holds its admission;
        // its own Pending row is not a second one.
        let own_attempt = crate::outbound::dispatch_attempt_id::outbound_dispatch_attempt_id(
            request
                .ledger_identity_ref
                .as_deref()
                .unwrap_or(&request.intent_ref),
        )?;
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let admitted = crate::outbound_intent_ledger::admitted_calls_since_in_txn(
            vault,
            &txn,
            LINKEDIN_CHANNEL,
            &verb_contract.kind,
            since_ms,
            Some(own_attempt),
        )
        .map_err(OutboundDispatchError::Chokepoint)?;
        let admitted = u16::try_from(admitted).unwrap_or(u16::MAX);
        let connect = verb_contract.kind == LINKEDIN_CONNECT_REQUEST_VERB;
        Ok(Self {
            connect_requests: if connect { admitted } else { 0 },
            dm_sends: if connect { 0 } else { admitted },
            ceiling: Some(AdmissionCeiling {
                since_ms,
                prior: u32::from(host_count),
                cap: u32::from(cap),
            }),
        })
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
    request.linkedin_sandbox_policy.as_ref().map(|policy| {
        let policy = &ledger.raise(policy);
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
