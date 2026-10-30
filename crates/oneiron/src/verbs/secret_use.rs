//! `self.use`: an agent hands a secret to one trusted operation by its
//! handle, and reads the operation's result, never the value (OF-560;
//! ARCH-0069 "One use(handle) call"). The door is [`crate::Vault`]'s use door
//! under the caller's own verified actor; the operations are its table,
//! [`crate::secret_custody::SECRET_USE_OPERATIONS`].
//!
//! The custody binding is the only grant: a handle whose record holds no
//! binding for the operation's effector is refused with the owner door that
//! adds one. The answer, its failure text and its receipt hold the handle
//! where the value would have been.
//!
//! `connector.call` ([`SECRET_USE_CONNECTOR_CALL`]) is a server's: its host
//! door sends one connector call with the handle's secret as the call's
//! credential ([`use_secret_for_connector_call`]), and an embedded vault,
//! which installs no connector transport, refuses it.
//!
//! The lease-aware twins ([`use_secret_grant_as_caller`],
//! [`use_secret_grant_for_connector_call`], FIX 4313) take a secret grant the
//! caller holds in place of a handle, and answer the same way.
use serde::{Deserialize, Serialize};

use super::connector_call::ConnectorCallReply;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, SecretError};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_MODEL_UNAVAILABLE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
    verify_actor_binding,
};
use crate::outbound_consent::{
    ConnectorCallHost, ConnectorCallInvocation, ConnectorCallRequest, connector_call_effector,
};
use crate::secret_custody::{
    SECRET_BIND_DOOR, SECRET_USE_CONNECTOR_CALL, SECRET_USE_OPERATIONS, SecretUseConsumed,
    SecretUseOutcome, SecretUseSend, SecretUser,
};
use crate::secret_lease::{SecretGrantCaller, SecretGrantTarget};

/// `self.use`'s input: the handle, the operation, and its arguments.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretUseRequest {
    /// The secret's handle, such as `sc12`, as the text or field holds it.
    pub handle: String,
    /// The operation, such as `slack.auth_test`.
    pub operation: String,
    /// The operation's arguments, a JSON object; `{}` for one that takes
    /// none.
    #[serde(default = "no_arguments")]
    pub arguments: serde_json::Value,
}

fn no_arguments() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// How an operation's send went.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretUseStatus {
    /// The provider answered; `result` is its answer.
    Answered,
    /// The operation failed; `failure` says why.
    Failed,
    /// It ran, but its result could not be cleared of the value, so none
    /// comes back.
    Withheld,
}

/// `self.use`'s answer. It never holds the value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretUseAnswer {
    pub status: SecretUseStatus,
    /// The operation's answer, when it answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Why it failed, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
    pub receipt: SecretUseRecord,
}

/// One use's receipt: what was used, by what, and how it went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecretUseRecord {
    pub handle: String,
    /// The secret's rotation generation when it was used.
    pub generation: u32,
    /// The custody record whose value the send actually presented, as its
    /// door released it (FIX 8052); distinct from the admitted handle.
    /// `None` when nothing was sent, or nothing said what was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_custody: Option<EntityId>,
    /// The generation the send actually presented; distinct from the
    /// admitted generation. `None` when nothing said what was presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presented_generation: Option<u32>,
    /// The effector the binding names, such as `connector:slack`.
    pub effector: String,
    pub operation: String,
    /// The Gate record that keeps it, `gate:<hex>`.
    pub decision: String,
    pub used_at: u64,
}

/// `self.use` on a handle, for the calling actor. `connector.call` is
/// refused here: a server's host door sends it.
pub fn use_secret_as_caller(
    memory: &Memory<'_>,
    input: SecretUseRequest,
) -> MemoryResult<SecretUseAnswer> {
    let user = secret_user(memory)?;
    if input.operation == SECRET_USE_CONNECTOR_CALL {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "self.use's connector.call sends through a server's installed connector transports; \
             an embedded vault has none",
            &[super::host::SERVED_CLIENT_HINT],
        ));
    }
    let outcome = memory
        .vault()
        .use_secret_handle(&user, &input.handle, &input.operation, &input.arguments)
        .map_err(|error| use_refusal(error, &input.operation))?;
    Ok(answer(outcome))
}

/// `self.use` of `connector.call` on a host that sends connector calls: one
/// call, named by `input.arguments` as `connector.call` names it, under the
/// caller's own grant and gate, with the handle's secret as its credential
/// in place of the route's own. The record's binding must name the route's
/// effector, `connector:<connector>`. A call the gate holds keeps the record
/// on its row, and the settler sends it with the same one once the hold
/// clears. The tool's reply comes back as `result`, foreign data, cleared of
/// the value.
pub fn use_secret_for_connector_call<H: ConnectorCallHost>(
    memory: &Memory<'_>,
    input: SecretUseRequest,
    invocation: Option<ConnectorCallInvocation>,
    host: &mut H,
) -> MemoryResult<SecretUseAnswer> {
    if input.operation != SECRET_USE_CONNECTOR_CALL {
        return use_secret_as_caller(memory, input);
    }
    let user = secret_user(memory)?;
    let request: ConnectorCallRequest = serde_json::from_value(input.arguments).map_err(|_| {
        MemoryError::bad_request_with(
            "connector.call's arguments are one connector call",
            &[
                "Name the connector's catalog name, its tool, the tool's arguments and, for a \
                   change, its mutation, as connector.call takes them.",
            ],
        )
    })?;
    let vault = memory.vault();
    let route = vault.route_connector_call(&request.name)?.ok_or_else(|| {
        MemoryError::bad_request(format!(
            "{} is not a catalogued connector a call can route to",
            request.name
        ))
    })?;
    let effector = connector_call_effector(&route);
    let (name, tool) = (request.name.clone(), request.tool.clone());
    let mut request = Some(request);
    let outcome = vault
        .use_secret_with(
            &user,
            &input.handle,
            SECRET_USE_CONNECTOR_CALL,
            &effector,
            &mut |target| {
                let Some(request) = request.take() else {
                    return SecretUseConsumed::failed("the call was already made".to_owned());
                };
                let (outcome, sent) = vault.call_connector_with_secret(
                    memory,
                    request,
                    invocation,
                    &mut *host,
                    target.custody,
                );
                // Its host cleared the reply inside the send's door (FIX
                // 7647); what the send presented is noted on an engine error
                // after it as on an outcome (FIX 8053).
                target.note_sent(sent);
                match outcome {
                    Ok(outcome) => {
                        connector_consumed(&ConnectorCallReply::project(&name, &tool, outcome))
                    }
                    Err(error) => SecretUseConsumed::failed(error.to_string()),
                }
            },
        )
        .map_err(|error| use_refusal(error, SECRET_USE_CONNECTOR_CALL))?;
    Ok(answer(outcome))
}

/// `self.use` under the secret grant `grant` the caller holds, acting in
/// `run` when its host attached one (FIX 4313): the grant is redeemed for
/// `operation`, one of the table's, and the use answers as
/// [`use_secret_as_caller`] does. `connector.call` is refused here: a
/// server's host door sends it ([`use_secret_grant_for_connector_call`]).
pub fn use_secret_grant_as_caller(
    memory: &Memory<'_>,
    run: Option<AttemptId>,
    grant: &EntityId,
    operation: &str,
    arguments: &serde_json::Value,
) -> MemoryResult<SecretUseAnswer> {
    if operation == SECRET_USE_CONNECTOR_CALL {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "self.use's connector.call sends through a server's installed connector transports; \
             an embedded vault has none",
            &[super::host::SERVED_CLIENT_HINT],
        ));
    }
    let caller = SecretGrantCaller::of(memory, run)?;
    let outcome = memory
        .vault()
        .use_secret_grant(&caller, grant, operation, arguments)
        .map_err(|error| grant_refusal(error, operation))?;
    Ok(answer(outcome))
}

/// [`use_secret_for_connector_call`] under the secret grant `grant` the
/// caller holds, acting in `run` when its host attached one (FIX 4313): the
/// grant must be a connector grant for the route `request` names. The call's
/// row keeps the grant, and the host redeems it again at every real send, a
/// held send resumed later included; the caller's own standing grant, gate
/// and invocation govern the call as before, and the reply comes back
/// cleared of the value.
pub fn use_secret_grant_for_connector_call<H: ConnectorCallHost>(
    memory: &Memory<'_>,
    run: Option<AttemptId>,
    grant: &EntityId,
    request: ConnectorCallRequest,
    invocation: Option<ConnectorCallInvocation>,
    host: &mut H,
) -> MemoryResult<SecretUseAnswer> {
    let caller = SecretGrantCaller::of(memory, run)?;
    let vault = memory.vault();
    let route = vault.route_connector_call(&request.name)?.ok_or_else(|| {
        MemoryError::bad_request(format!(
            "{} is not a catalogued connector a call can route to",
            request.name
        ))
    })?;
    let target = SecretGrantTarget::Connector { name: route.name };
    let (name, tool) = (request.name.clone(), request.tool.clone());
    let mut request = Some(request);
    let outcome = vault
        .use_secret_grant_with(
            &caller,
            grant,
            &target,
            SECRET_USE_CONNECTOR_CALL,
            &mut |used, presented| {
                let Some(request) = request.take() else {
                    return SecretUseConsumed::failed("the call was already made".to_owned());
                };
                let (outcome, sent) = vault.call_connector_with_secret_grant(
                    memory,
                    request,
                    invocation,
                    &mut *host,
                    used.custody,
                    *presented,
                );
                // Noted on an engine error after the send too (FIX 8053).
                used.note_sent(sent);
                match outcome {
                    Ok(outcome) => {
                        connector_consumed(&ConnectorCallReply::project(&name, &tool, outcome))
                    }
                    Err(error) => SecretUseConsumed::failed(error.to_string()),
                }
            },
        )
        .map_err(|error| grant_refusal(error, SECRET_USE_CONNECTOR_CALL))?;
    Ok(answer(outcome))
}

/// A grant's refusal in words its holder can act on: a stale grant renews,
/// an ended one is minted again, another's reads as unknown; the rest reads
/// as the handle use's refusal.
pub(super) fn grant_refusal(error: Error, operation: &str) -> MemoryError {
    match error {
        Error::Secret(SecretError::SecretGrantStale { .. }) => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            error.to_string(),
            &["Renew the grant: a renewal mints a fresh one at the secret's current generation."],
        ),
        Error::Secret(SecretError::SecretLeaseNotActive { .. }) => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            error.to_string(),
            &["Mint a fresh grant: an expired, torn down or replaced grant does not come back."],
        ),
        Error::Secret(SecretError::SecretLeaseNotFound { .. }) => MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            error.to_string(),
            &["Name a grant this caller holds, in the run it was minted for."],
        ),
        Error::Secret(
            SecretError::SecretGrantTargetMismatch { .. } | SecretError::SecretGrantSpent { .. },
        ) => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            error.to_string(),
            &["Mint a grant for this operation or connector."],
        ),
        other => use_refusal(other, operation),
    }
}

/// The caller as a secret's user: a verified actor of a session that keeps
/// a record.
fn secret_user(memory: &Memory<'_>) -> MemoryResult<SecretUser> {
    verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    if memory.keeps_no_record() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a use writes its receipt, and an anonymous off-record session keeps none",
            &["Use the secret outside the anonymous session."],
        ));
    }
    Ok(SecretUser::new(memory.actor(), memory.actor_class()))
}

/// A connector call's reply as the use's answer: delivered is answered; a
/// hold or a refusal sent nothing; an unsettled delivery failed. The reply
/// rides along in each, so a hold's `call_ref` is the caller's. A connector
/// that asked for input mid-call received the call, but its questions are
/// withheld: a send that presented a record's value serves no questions.
fn connector_consumed(reply: &ConnectorCallReply) -> SecretUseConsumed {
    let (send, failure) = match reply {
        ConnectorCallReply::Delivered { .. } => (SecretUseSend::Answered, None),
        ConnectorCallReply::Held { .. } => (
            SecretUseSend::NotSent,
            Some(
                "the connector call is held for consent or governance: nothing was sent, and \
                 the settler sends it with the same secret once the hold clears",
            ),
        ),
        ConnectorCallReply::Refused { .. } => (
            SecretUseSend::NotSent,
            Some("the connector call was refused: nothing was sent"),
        ),
        ConnectorCallReply::PendingDelivery { .. } => (
            SecretUseSend::Failed,
            Some("the connector call's delivery is not settled"),
        ),
        ConnectorCallReply::AwaitingInput { .. } => {
            return SecretUseConsumed {
                result: None,
                failure: Some(
                    "the connector asked for input mid-call; a call made with a secret's \
                     handle answers no connector questions"
                        .to_owned(),
                ),
                send: SecretUseSend::Withheld,
            };
        }
    };
    match serde_json::to_value(reply) {
        Ok(result) => SecretUseConsumed {
            result: Some(result),
            failure: failure.map(str::to_owned),
            send,
        },
        Err(_) => SecretUseConsumed::failed("the connector call's reply could not be read".into()),
    }
}

fn answer(outcome: SecretUseOutcome) -> SecretUseAnswer {
    let receipt = outcome.receipt;
    let presented = receipt.presented;
    SecretUseAnswer {
        status: match receipt.send {
            SecretUseSend::Answered => SecretUseStatus::Answered,
            SecretUseSend::Withheld => SecretUseStatus::Withheld,
            SecretUseSend::Failed | SecretUseSend::NotSent => SecretUseStatus::Failed,
        },
        result: outcome.result,
        failure: outcome.failure,
        receipt: SecretUseRecord {
            handle: receipt.handle,
            generation: receipt.generation,
            presented_custody: presented.map(|presented| presented.custody),
            presented_generation: presented.map(|presented| presented.generation),
            effector: receipt.effector,
            operation: receipt.operation,
            decision: format!("gate:{}", receipt.receipt.to_hex()),
            used_at: receipt.used_at,
        },
    }
}

/// A refusal in words the agent can act on: a missing binding names the
/// owner door that adds one, an unknown operation lists the table.
fn use_refusal(error: Error, operation: &str) -> MemoryError {
    match error {
        Error::Secret(SecretError::SecretBindingDenied {
            effector,
            secret_ref,
        }) => {
            let bind = format!(
                "The owner binds it at {SECRET_BIND_DOOR} with {{\"handle\": \"{secret_ref}\", \
                 \"effector\": \"{effector}\"}}."
            );
            MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "{secret_ref} holds no binding for {effector} that grants read, so \
                     {operation} cannot use it"
                ),
                &[bind.as_str(), "A reveal's grant does not reach self.use."],
            )
        }
        Error::Gate(GateError::InvalidConsentBound(reason))
            if operation != SECRET_USE_CONNECTOR_CALL
                && !SECRET_USE_OPERATIONS.iter().any(|op| op.name == operation) =>
        {
            let names = SECRET_USE_OPERATIONS
                .iter()
                .map(|op| format!("{} ({})", op.name, op.what))
                .collect::<Vec<_>>()
                .join("; ");
            let list = format!(
                "The operations are: {names}; and, on a server, {SECRET_USE_CONNECTOR_CALL} \
                 (one connector call with the secret as its credential)."
            );
            MemoryError::new(MEMORY_CODE_BAD_REQUEST, reason, &[list.as_str()])
        }
        other => other.into(),
    }
}
