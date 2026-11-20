//! Receipts for the named memory verbs on the caller's facade row.

use super::{CoreMemoryVerbDeleteReason, facade};
use crate::api::{DagWriteError, scoped_auth};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::task_verb::sdk::SafeDeleteRequest;
use serde_json::Value;

/// The core retract of `id` by a caller that is not the vault owner: the
/// claim door `vault.claims.retract` runs ([`oneiron::Memory::claim_retract`]),
/// on the caller's own actor ([`core_memory_caller`]) with the credential's
/// proof bound. A human the authority log binds retracts any claim, recorded
/// as the owner's explicit retraction (the door takes that binding for
/// ownership: FIX-LIST CLAIM-RETRACT-HUMAN-BINDING-IS-NOT-OWNERSHIP); anyone
/// else only a claim it wrote, and an agent's retract the gate holds parks
/// for the holder's consent. An account key on a rooted vault retracting a
/// claim its person did not write answers `account_key_unbound`, as delete
/// does. The vault's clock dates it.
/// The facade row runs its verb hooks and `/claim_ref` reference admission
/// before the claim door (FIX-LIST 25699). Its post-hook view alone supplies
/// the executed target and receipt fields; redactions are never restored.
pub(super) fn core_memory_retract_by_facade(
    server: &SyncServer,
    auth: &CoreAuth,
    id: &oneiron::EntityId,
) -> Result<(Option<String>, Value), DagWriteError> {
    let (actor, class, by_account_key) = core_memory_caller(server, auth, "retract")?;
    let memory = scoped_auth::credential_memory(server.vault(), Some(auth), actor, class)
        .at(auth.locality());
    // Use only the post-hook claim ref: a redacted target must not be restored.
    let receipt = oneiron::task_verb::sdk::invoke(
        &memory,
        "vault.claims.retract",
        serde_json::json!({ "claim_ref": id.to_hex() }),
    )
    .map_err(|refusal| {
        account_key_unbound(server, by_account_key, refusal, "retract another's claim")
    })?;
    let id = receipt
        .pointer("/claim/id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok((id, receipt))
}

/// The core delete of `id` by a caller that holds no proof of the vault
/// owner, a full-vault slip someone else holds included (DEL-2, ARCH-0043;
/// Engine ruling 13 Nov 02:51 = A; OWNER-GRADE-IS-NOT-OWNERSHIP). Its actor
/// is resolved as the facade resolves a writer, and the facade row
/// `vault.delete` runs on that actor's handle, the credential's proof
/// bound: its verb hooks and its `/entity_ref` reference admission first
/// (FIX-LIST 25699), then
/// `Memory::safe_delete`'s judge: the owner path when the
/// actor is the vault's owner, else the role table (a Member's own item, an
/// Admin's in-scope item, an agent under a Grant that names `delete`), each
/// refusal FORBIDDEN and naming its reason. A token that names no actor is
/// refused `unresolved_actor`.
///
/// A person whose role makes the delete wait (a Steward's delete of
/// another's item in scope) gets `CHECK_IN_PENDING` naming the check-in;
/// once the Owner approves it, the same call naming it as `check_in_ref`
/// deletes and spends it, and the receipt's `check_in` names it
/// (ROLES-CHECKIN 2k5; FIX-LIST CHECK-IN-CORE-DELETE-ROUTE-NO-CHECK-IN-REF).
/// A delete that goes at once spends none, so a check-in it names is refused
/// `BAD_REQUEST` and nothing is deleted.
///
/// An account API key (OF-448) names its person and no actor class: it is
/// judged as that person, a human (Engine rulings 13 Nov 08:20 and 08:30 =
/// C). The owner's own key deletes on the owner's path, within its scopes.
/// The key carries no vault slip, so on a rooted vault no other person
/// stands by it: the engine's owner refusal there answers
/// `account_key_unbound`, and so does the reference admission's refusal of a
/// target that key cannot read ([`account_key_target_unreadable`]). On a
/// rootless vault the role table judges a target the key reads.
pub(super) fn core_memory_delete_by_role(
    server: &SyncServer,
    auth: &CoreAuth,
    id: &oneiron::EntityId,
    reason: CoreMemoryVerbDeleteReason,
    check_in_ref: Option<&str>,
) -> Result<(Option<String>, Value), DagWriteError> {
    let (actor, class, by_account_key) = core_memory_caller(server, auth, "delete")?;
    let memory = scoped_auth::credential_memory(server.vault(), Some(auth), actor, class);
    let reason = match reason {
        CoreMemoryVerbDeleteReason::User => oneiron::memory::SafeDeleteReason::UserDelete,
        CoreMemoryVerbDeleteReason::UserHard => oneiron::memory::SafeDeleteReason::UserHardDelete,
        CoreMemoryVerbDeleteReason::Gdpr => oneiron::memory::SafeDeleteReason::GdprDelete,
        CoreMemoryVerbDeleteReason::Policy => oneiron::memory::SafeDeleteReason::PolicyDelete,
    };
    let mut input = serde_json::json!({ "entity_ref": id.to_hex(), "reason": reason.as_str() });
    if let Some(check_in_ref) = check_in_ref {
        input["check_in_ref"] = Value::String(check_in_ref.to_owned());
    }
    let mut committed = None;
    let deleted = oneiron::task_verb::verb_hook_boundary::row(
        &memory,
        &oneiron::task_verb::sdk::VERB_TABLE,
        "vault.delete",
        input,
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
    let view = deleted.map_err(|refusal| {
        if account_key_target_unreadable(server, &memory, by_account_key, &refusal) {
            return account_key_unbound_refusal("delete");
        }
        account_key_unbound(server, by_account_key, refusal, "delete")
    })?;
    Ok(delete_receipt_view(view, committed.as_ref()))
}

/// Whether `refusal` is `vault.delete`'s `/entity_ref` reference admission
/// (FIX-LIST 25699) refusing a target to an account key that is not the
/// owner's, on a rooted vault. The key carries no vault slip, so its read
/// lane holds no Scope and reads no row the vault's policy does not grant its
/// person; the admission then refuses the target before the delete judge,
/// which on a rooted vault stands no person but the owner by a slip-less key
/// (FIX-LIST DEL2-DOOR-MEMBER-ACCOUNT-KEY-INVENTED-REFERENCE). The owner's
/// key reads every row, so its refusal passes unchanged, as does every
/// refusal on a rootless vault.
fn account_key_target_unreadable(
    server: &SyncServer,
    memory: &oneiron::memory::Memory<'_>,
    by_account_key: bool,
    refusal: &oneiron::memory::MemoryError,
) -> bool {
    by_account_key
        && refusal.code == oneiron::memory::MEMORY_CODE_INVENTED_REFERENCE
        && vault_is_rooted(server)
        && matches!(memory.is_vault_owner(), Ok(false))
}

/// An account key's refusal of `act`: the key carries no vault slip, so on a
/// rooted vault no person but the owner stands by it, and the engine's owner
/// refusal there answers `account_key_unbound` with the remedy (Engine rulings
/// 13 Nov 08:20 and 08:30 = C). Any other refusal passes unchanged.
fn account_key_unbound(
    server: &SyncServer,
    by_account_key: bool,
    refusal: oneiron::memory::MemoryError,
    act: &str,
) -> oneiron::memory::MemoryError {
    if by_account_key
        && refusal.code == oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED
        && vault_is_rooted(server)
    {
        return account_key_unbound_refusal(act);
    }
    refusal
}

/// The `account_key_unbound` refusal of `act`, naming the person's own slip
/// as the remedy.
fn account_key_unbound_refusal(act: &str) -> oneiron::memory::MemoryError {
    let remedy = format!(
        "Present the person's own paired slip (--principal-ref, --actor-class human) to {act} as that person."
    );
    oneiron::memory::MemoryError::new(
        oneiron::memory::MEMORY_CODE_FORBIDDEN,
        format!(
            "account_key_unbound: this key can't {act} in this vault; use your app login or ask the owner"
        ),
        &[remedy.as_str()],
    )
}

/// Whether the served vault has an authority root.
fn vault_is_rooted(server: &SyncServer) -> bool {
    server
        .vault()
        .authority_vault_id()
        .is_ok_and(|root| root.is_some())
}

/// The actor a memory verb judges a caller that is not the vault owner on:
/// the writer the facade resolves, or the person an account API key names, as
/// a human (Engine rulings 13 Nov 08:20 and 08:30 = C). The flag says it came
/// from an account key. A token that names neither is refused
/// `unresolved_actor`, naming `authority`.
fn core_memory_caller(
    server: &SyncServer,
    auth: &CoreAuth,
    authority: &str,
) -> Result<(oneiron::EntityId, oneiron::EdgeActorClass, bool), DagWriteError> {
    match facade::facade_actor(server, auth) {
        Ok((actor, class)) => Ok((actor, class, false)),
        Err(_) => match auth.account_key_principal() {
            Some(person) => Ok((person, oneiron::EdgeActorClass::Human, true)),
            None => Err(oneiron::memory::MemoryError::new(
                oneiron::memory::MEMORY_CODE_FORBIDDEN,
                format!("unresolved_actor: this token names no actor the {authority} authority can judge"),
                &[
                    "Present a slip paired with --principal-ref and --actor-class, an account key that names its person, or the owner's own credential.",
                ],
            )
            .into()),
        },
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
