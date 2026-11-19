//! Receipts for the named memory verbs on the caller's facade row.

use super::{CoreMemoryVerbDeleteReason, facade};
use crate::api::{DagWriteError, scoped_auth};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::task_verb::sdk::SafeDeleteRequest;
use serde_json::Value;

/// The core retract of `id` by a token that is not owner-grade, through
/// the facade row `vault.claims.retract` (FIX-LIST 25699). The generated
/// dispatch runs the row's verb-hook boundary, admits `/claim_ref`
/// through the caller's scoped read, and only then calls
/// `Memory::claim_retract`, which judges the resolved actor's authorship.
/// Calling a judged door directly here would skip the hooks and the
/// admission, and the door would answer for claims the caller cannot
/// read. The actor is resolved as the delete below resolves it, an
/// account key judged as its person; a token that names no actor is
/// refused `unresolved_actor`.
pub(super) fn core_memory_retract_by_facade(
    server: &SyncServer,
    auth: &CoreAuth,
    id: &oneiron::EntityId,
) -> Result<(Option<String>, Value), DagWriteError> {
    let (actor, class) = match facade::facade_actor(server, auth) {
        Ok((actor, class)) => (actor, class),
        Err(_) => match auth.account_key_principal() {
            Some(person) => (person, oneiron::EdgeActorClass::Human),
            None => {
                return Err(oneiron::memory::MemoryError::new(
                    oneiron::memory::MEMORY_CODE_FORBIDDEN,
                    "unresolved_actor: this token names no actor the retract authority can judge",
                    &[
                        "Present a slip paired with --principal-ref and --actor-class, an account key that names its person, or the owner's own credential.",
                    ],
                )
                .into());
            }
        },
    };
    let memory = scoped_auth::credential_memory(server.vault(), Some(auth), actor, class);
    // Use only the post-hook claim ref: a redacted target must not be restored.
    let receipt = oneiron::task_verb::sdk::invoke(
        &memory,
        "vault.claims.retract",
        serde_json::json!({ "claim_ref": id.to_hex() }),
    )?;
    let id = receipt
        .pointer("/claim/id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok((id, receipt))
}

/// The core delete of `id` by a token that is not owner-grade (DEL-2,
/// ARCH-0043; Engine ruling 13 Nov 02:51 = A). Its actor is resolved as the
/// facade resolves a writer, and the facade row `vault.delete` runs on
/// that actor's handle, the credential's proof bound: its verb hooks and
/// its `/entity_ref` reference admission first (FIX-LIST 25699), then
/// `Memory::safe_delete`'s judge: the owner path when the
/// actor is the vault's owner, else the role table (a Member's own item, an
/// Admin's in-scope item, an agent under a Grant that names `delete`), each
/// refusal FORBIDDEN and naming its reason. A token that names no actor is
/// refused `unresolved_actor`.
///
/// An account API key (OF-448) names its person and no actor class: it is
/// judged as that person, a human (Engine rulings 13 Nov 08:20 and 08:30 =
/// C). The owner's own key deletes on the owner's path, within its scopes.
/// The key carries no vault slip, so on a rooted vault no other person
/// stands by it: the engine's owner refusal there answers
/// `account_key_unbound`. On a rootless vault the role table judges it.
pub(super) fn core_memory_delete_by_role(
    server: &SyncServer,
    auth: &CoreAuth,
    id: &oneiron::EntityId,
    reason: CoreMemoryVerbDeleteReason,
) -> Result<(Option<String>, Value), DagWriteError> {
    let (actor, class, by_account_key) = match facade::facade_actor(server, auth) {
        Ok((actor, class)) => (actor, class, false),
        Err(_) => match auth.account_key_principal() {
            Some(person) => (person, oneiron::EdgeActorClass::Human, true),
            None => {
                return Err(oneiron::memory::MemoryError::new(
                    oneiron::memory::MEMORY_CODE_FORBIDDEN,
                    "unresolved_actor: this token names no actor the delete authority can judge",
                    &[
                        "Present a slip paired with --principal-ref and --actor-class, an account key that names its person, or the owner's own credential.",
                    ],
                )
                .into());
            }
        },
    };
    let memory = scoped_auth::credential_memory(server.vault(), Some(auth), actor, class);
    let reason = match reason {
        CoreMemoryVerbDeleteReason::User => oneiron::memory::SafeDeleteReason::UserDelete,
        CoreMemoryVerbDeleteReason::UserHard => oneiron::memory::SafeDeleteReason::UserHardDelete,
        CoreMemoryVerbDeleteReason::Gdpr => oneiron::memory::SafeDeleteReason::GdprDelete,
        CoreMemoryVerbDeleteReason::Policy => oneiron::memory::SafeDeleteReason::PolicyDelete,
    };
    let mut committed = None;
    let deleted = oneiron::task_verb::verb_hook_boundary::row(
        &memory,
        &oneiron::task_verb::sdk::VERB_TABLE,
        "vault.delete",
        serde_json::json!({ "entity_ref": id.to_hex(), "reason": reason.as_str() }),
        |value| {
            let input: SafeDeleteRequest = serde_json::from_value(value).map_err(|error| {
                oneiron::memory::MemoryError::bad_request(format!("invalid SDK request: {error}"))
            })?;
            let entity_ref = input.entity_ref.clone();
            // The generated typed row still admits /entity_ref and judges delete authority.
            let receipt = oneiron::task_verb::sdk::vault_delete(&memory, input)?;
            let mut value = serde_json::to_value(&receipt).map_err(|_| {
                oneiron::memory::MemoryError::bad_request("SDK result encoding failed")
            })?;
            // Carry the executed target through post hooks so they can redact it too.
            value["entity_ref"] = Value::String(entity_ref);
            // Capture the typed result before the post chain removes caller-visible fields.
            committed = Some(receipt);
            Ok(value)
        },
    );
    match deleted {
        Err(refusal)
            if by_account_key
                && refusal.code == oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED
                && server
                    .vault()
                    .authority_vault_id()
                    .is_ok_and(|root| root.is_some()) =>
        {
            Err(oneiron::memory::MemoryError::new(
                oneiron::memory::MEMORY_CODE_FORBIDDEN,
                "account_key_unbound: this key can't delete in this vault; use your app login or ask the owner",
                &[
                    "Present the person's own paired slip (--principal-ref, --actor-class human) to delete as that person.",
                ],
            )
            .into())
        }
        outcome => Ok(delete_receipt_view(outcome?, committed.as_ref())),
    }
}

/// Map the executed receipt to the core response without restoring any redacted fields.
/// A saved completion may skip the call body; its retained view already carries the
/// executed reason and must likewise never be decoded as a complete receipt.
fn delete_receipt_view(
    mut view: Value,
    committed: Option<&oneiron::memory::DeleteReceipt>,
) -> (Option<String>, Value) {
    let Some(fields) = view.as_object_mut() else {
        return (None, view);
    };
    let id = fields
        .remove("entity_ref")
        .and_then(|target| target.as_str().map(str::to_owned));
    if let Some(reason) = fields.get("reason").and_then(Value::as_str) {
        let reason = committed.map_or(reason, |receipt| receipt.reason.as_str());
        let hard = matches!(reason, "user_hard_delete" | "gdpr_delete" | "policy_delete");
        let reason = reason.to_owned();
        fields.insert("reason".to_owned(), Value::String(reason));
        fields.insert("hard".to_owned(), Value::Bool(hard));
    }
    if let Some(receipt) = fields.remove("receipt_ref")
        && let Some(receipt) = receipt.as_str()
    {
        fields.insert(
            "receipt_id".to_owned(),
            Value::String(
                receipt
                    .strip_prefix("redaction:")
                    .unwrap_or(receipt)
                    .to_owned(),
            ),
        );
    }
    (id, view)
}

pub(crate) fn core_memory_delete_reason(
    verb: oneiron::NamedMemoryVerb,
    requested: Option<CoreMemoryVerbDeleteReason>,
) -> Result<(oneiron::DeleteReason, CoreMemoryVerbDeleteReason), ApiError> {
    let response_reason = requested.unwrap_or(match verb {
        oneiron::NamedMemoryVerb::HardDelete => CoreMemoryVerbDeleteReason::UserHard,
        _ => CoreMemoryVerbDeleteReason::User,
    });
    let reason = match response_reason {
        CoreMemoryVerbDeleteReason::User => oneiron::DeleteReason::UserDelete,
        CoreMemoryVerbDeleteReason::UserHard => oneiron::DeleteReason::UserHardDelete,
        CoreMemoryVerbDeleteReason::Gdpr => oneiron::DeleteReason::GdprDelete,
        CoreMemoryVerbDeleteReason::Policy => oneiron::DeleteReason::PolicyDelete,
    };
    match (verb, response_reason) {
        (oneiron::NamedMemoryVerb::Delete, CoreMemoryVerbDeleteReason::User) => {}
        (oneiron::NamedMemoryVerb::Delete, _) => {
            return Err(ApiError::bad_request(
                "delete only accepts user_delete; use hard_delete for hard-delete reasons",
                Some("reason"),
            ));
        }
        (
            oneiron::NamedMemoryVerb::HardDelete,
            CoreMemoryVerbDeleteReason::UserHard
            | CoreMemoryVerbDeleteReason::Gdpr
            | CoreMemoryVerbDeleteReason::Policy,
        ) => {}
        (oneiron::NamedMemoryVerb::HardDelete, CoreMemoryVerbDeleteReason::User) => {
            return Err(ApiError::bad_request(
                "hard_delete requires user_hard_delete, gdpr_delete, or policy_delete",
                Some("reason"),
            ));
        }
        _ => {}
    }
    Ok((reason, response_reason))
}
