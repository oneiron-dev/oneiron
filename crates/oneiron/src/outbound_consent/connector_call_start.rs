//! The connector-call entry doors: a call, its secret-presenting forms and its
//! listing, and the start that matches a held row to its request.
//! Entry: `Vault::call_connector`. Defines its own items; the rows stay in `connector_call`.

use serde_json::Value;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::Memory;
use crate::outbound_intent_ledger::IntentLedgerError;
use crate::secret_custody::SentPresentation;
use crate::secret_lease::SecretGrantRef;

use super::connector_call::{
    ConnectorCallHost, ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest,
    PENDING_CALLS, PendingConnectorCall, connector_call_ref, now_ms,
};

/// The reason a call gets when its host identity already names a held call
/// with another request.
const CONNECTOR_CALL_INVOCATION_CONFLICT: &str = "connector_call_invocation_conflict";

impl PendingConnectorCall {
    /// Whether `other` asks for exactly this call: the same caller, tool,
    /// arguments and mutation.
    fn same_call(&self, other: &Self) -> bool {
        let arguments = |text: &str| serde_json::from_str::<Value>(text).ok();
        self.name == other.name
            && self.tool == other.tool
            && self.mutation == other.mutation
            && self.principal_ref == other.principal_ref
            && self.credential == other.credential
            && self.grant == other.grant
            && arguments(&self.arguments).is_some()
            && arguments(&self.arguments) == arguments(&other.arguments)
    }
}

impl Vault {
    /// Calls one tool on one catalogued connector for the caller `memory`
    /// is bound to. The principal is the verified actor of that scope; the
    /// grant, schema, endpoint and credential are never the guest's.
    pub fn call_connector<H: ConnectorCallHost>(
        &self,
        memory: &Memory<'_>,
        request: ConnectorCallRequest,
        invocation: Option<ConnectorCallInvocation>,
        host: &mut H,
    ) -> Result<ConnectorCallOutcome, IntentLedgerError> {
        self.call_connector_listing(memory, request, invocation, host)
            .map(|(outcome, _)| outcome)
    }

    /// [`Self::call_connector`] with the value of the custody record
    /// `credential` as the call's credential, in place of the route's own
    /// secret: the call `self.use` makes for a handle (OF-560). The call's
    /// row keeps the record, so a resume presents the same one; the
    /// credential door rechecks its binding at each send, and a delivered
    /// reply comes back cleared of the value. The caller checked the binding
    /// before, and wrote the use's record. Beside the outcome, or the engine
    /// error that ended the call, the custody presentation the call's send
    /// made, if it sent (FIX 7647): an error after the send hands it out
    /// exactly as an outcome does (FIX 8053).
    pub(crate) fn call_connector_with_secret<H: ConnectorCallHost>(
        &self,
        memory: &Memory<'_>,
        request: ConnectorCallRequest,
        invocation: Option<ConnectorCallInvocation>,
        host: &mut H,
        credential: EntityId,
    ) -> (
        Result<ConnectorCallOutcome, IntentLedgerError>,
        Option<SentPresentation>,
    ) {
        let _ = host.take_sent_presentation();
        let outcome = self
            .start_connector_call(memory, request, invocation, Some(credential), None, host)
            .map(|(outcome, _)| outcome);
        (outcome, host.take_sent_presentation())
    }

    /// [`Self::call_connector_with_secret`] under the secret grant `grant`
    /// (FIX 4313): the call's row keeps the grant beside the record, and the
    /// host redeems it at every send, a held send resumed later included, so
    /// a grant gone stale, expired or torn down since sends nothing.
    pub(crate) fn call_connector_with_secret_grant<H: ConnectorCallHost>(
        &self,
        memory: &Memory<'_>,
        request: ConnectorCallRequest,
        invocation: Option<ConnectorCallInvocation>,
        host: &mut H,
        credential: EntityId,
        grant: SecretGrantRef,
    ) -> (
        Result<ConnectorCallOutcome, IntentLedgerError>,
        Option<SentPresentation>,
    ) {
        let (credential, grant) = (Some(credential), Some(grant));
        let _ = host.take_sent_presentation();
        let outcome = self
            .start_connector_call(memory, request, invocation, credential, grant, host)
            .map(|(outcome, _)| outcome);
        (outcome, host.take_sent_presentation())
    }

    /// The body of every call: `credential` is the record a `self.use` call
    /// presents, if any, and `grant` the secret grant it redeems.
    fn start_connector_call<H: ConnectorCallHost>(
        &self,
        memory: &Memory<'_>,
        request: ConnectorCallRequest,
        invocation: Option<ConnectorCallInvocation>,
        credential: Option<EntityId>,
        grant: Option<SecretGrantRef>,
        host: &mut H,
    ) -> Result<(ConnectorCallOutcome, Option<Vec<EntityId>>), IntentLedgerError> {
        if !std::ptr::eq(memory.vault(), self) {
            return Err(IntentLedgerError::InvalidInput(
                "the caller's scope is bound to another vault",
            ));
        }
        let named = invocation;
        let invocation = invocation.unwrap_or_else(|| ConnectorCallInvocation {
            attempt_id: AttemptId::now(),
            call_seq: 0,
        });
        let arguments = serde_json::to_string(&request.arguments).map_err(|_| {
            IntentLedgerError::InvalidInput("connector call arguments are not JSON")
        })?;
        let pending = PendingConnectorCall {
            name: request.name,
            tool: request.tool,
            arguments,
            mutation: request.mutation,
            grant_id: None,
            attempt_id: invocation.attempt_id,
            call_seq: invocation.call_seq,
            principal_ref: memory.actor().to_hex(),
            held_at_ms: now_ms(),
            settled: None,
            held_reasons: Vec::new(),
            owner_ask_seq: None,
            credential,
            grant,
            code_consent_wait: None,
            source_rows: Some(Vec::new()),
            approval: None,
            input: None,
            code: None,
            sealed_arguments: None,
            off_record: memory.keeps_no_record(),
        };
        let Some(named) = named else {
            return self.drive_connector_call(None, None, pending, host);
        };
        // The host's identity names one logical call: run again, it finds
        // the call it held instead of holding a second one.
        let call_ref = connector_call_ref(&pending.principal_ref, named)?;
        let held = {
            let txn = self.store.env.read_txn().map_err(Error::from)?;
            PENDING_CALLS.get(&self.store, &txn, &call_ref)?
        };
        // An off-record caller's held arguments open for the comparison and
        // the resume (FIX 9159).
        let held = held
            .map(|held| held.opened(&self.store, &call_ref))
            .transpose()?;
        match held {
            None => {
                let pending = super::connector_call_code::with_code_pass(memory, pending);
                let (outcome, rows) =
                    self.drive_connector_call(None, Some(call_ref), pending, host)?;
                Ok((self.ask_code_consent_for_hold(memory, outcome), rows))
            }
            // It read only the held row, which names no row of its own.
            Some(held) if !held.same_call(&pending) => Ok((
                ConnectorCallOutcome::Refused {
                    decision_ref: None,
                    reasons: vec![CONNECTOR_CALL_INVOCATION_CONFLICT.to_owned()],
                },
                Some(Vec::new()),
            )),
            // A call whose connector asked for input answers from its row:
            // its send was delivered, and nothing is sent again (FIX 3837).
            Some(held) if held.input.is_some() => Ok((
                held.input_outcome(call_ref)
                    .unwrap_or(ConnectorCallOutcome::Delivered {
                        intent: None,
                        result: None,
                    }),
                held.source_rows,
            )),
            Some(held) if held.code_consent_wait.is_some() => {
                self.resume_code_owned_connector_call(&call_ref, held, host, false)
            }
            Some(held) => {
                // A settled or expiring row answers with the rows its passes
                // kept.
                if let Some(settled) = &held.settled {
                    return Ok((settled.outcome(), held.source_rows));
                }
                if let Some(expired) =
                    self.expire_connector_call_if_due(&call_ref, &held, now_ms())?
                {
                    return Ok((expired, held.source_rows));
                }
                self.drive_connector_call(Some(call_ref), None, held, host)
            }
        }
    }

    /// [`Self::call_connector`], beside the rows its passes picked
    /// (FIX 5455): the catalog route key, each standing grant read, the
    /// governing key, each slate read and the custody record a send
    /// presented. Ids only; `None` when they are not known.
    pub fn call_connector_listing<H: ConnectorCallHost>(
        &self,
        memory: &Memory<'_>,
        request: ConnectorCallRequest,
        invocation: Option<ConnectorCallInvocation>,
        host: &mut H,
    ) -> Result<(ConnectorCallOutcome, Option<Vec<EntityId>>), IntentLedgerError> {
        self.start_connector_call(memory, request, invocation, None, None, host)
    }
}
