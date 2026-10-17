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
use serde::{Deserialize, Serialize};

use crate::error::{Error, GateError, SecretError};
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult,
    verify_actor_binding,
};
use crate::secret_custody::{
    SECRET_BIND_DOOR, SECRET_USE_OPERATIONS, SecretUseOutcome, SecretUseSend, SecretUser,
};

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
    /// The effector the binding names, such as `connector:slack`.
    pub effector: String,
    pub operation: String,
    /// The Gate record that keeps it, `gate:<hex>`.
    pub decision: String,
    pub used_at: u64,
}

/// `self.use` on a handle, for the calling actor.
pub fn use_secret_as_caller(
    memory: &Memory<'_>,
    input: SecretUseRequest,
) -> MemoryResult<SecretUseAnswer> {
    verify_actor_binding(memory.vault(), memory.actor(), memory.actor_class())?;
    if memory.keeps_no_record() {
        return Err(MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "a use writes its receipt, and an anonymous off-record session keeps none",
            &["Use the secret outside the anonymous session."],
        ));
    }
    let user = SecretUser::new(memory.actor(), memory.actor_class());
    let outcome = memory
        .vault()
        .use_secret_handle(&user, &input.handle, &input.operation, &input.arguments)
        .map_err(|error| use_refusal(error, &input.operation))?;
    Ok(answer(outcome))
}

fn answer(outcome: SecretUseOutcome) -> SecretUseAnswer {
    let receipt = outcome.receipt;
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
            if !SECRET_USE_OPERATIONS.iter().any(|op| op.name == operation) =>
        {
            let names = SECRET_USE_OPERATIONS
                .iter()
                .map(|op| format!("{} ({})", op.name, op.what))
                .collect::<Vec<_>>()
                .join("; ");
            let list = format!("The operations are: {names}.");
            MemoryError::new(MEMORY_CODE_BAD_REQUEST, reason, &[list.as_str()])
        }
        other => other.into(),
    }
}
