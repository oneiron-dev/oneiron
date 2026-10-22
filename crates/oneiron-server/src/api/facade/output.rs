//! A facade row's input and output: its decoded JSON and the rows its answer reads.
//! `facade_input`, `facade_output` and the `facade_admit_*` fns are its call surface.
//! The engine DTOs of `oneiron::task_verb::sdk` define the records forwarded here.

use super::*;

/// Decodes a facade request body, reporting a malformed one in the FACADE
/// error vocabulary rather than the server's closed one.
pub(super) fn facade_json<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, FacadeApiError> {
    payload.map(|Json(payload)| payload).map_err(|_| {
        FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            "invalid JSON request body",
            ["Send a JSON body matching this verb's documented input."],
        )
    })
}

/// Decodes a request `validate_input` already admitted into the verb's typed
/// input, for a route that works on the typed result before encoding it.
pub(super) fn facade_input<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<T, FacadeApiError> {
    serde_json::from_value(value).map_err(|_| {
        FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            "invalid typed SDK arguments",
            ["Send a JSON body matching this verb's documented input."],
        )
    })
}

/// [`facade_input`] for a host door, on the args its pre chain left: a
/// restrictive call's args that do not decode as the door's own typed input
/// give way to the caller's, and the owner hears of it (FIX 5076).
pub(super) fn facade_door_input<T: serde::de::DeserializeOwned>(
    hooks: &mut VerbHookPre,
) -> Result<T, FacadeApiError> {
    oneiron::task_verb::revoke_lands::settle(
        hooks,
        &oneiron::task_verb::revoke_lands::decodes::<T>,
    );
    facade_input(hooks.args.clone())
}

/// Encodes a typed verb result in the facade's vocabulary.
pub(super) fn facade_output<T: Serialize>(output: T) -> Result<serde_json::Value, FacadeApiError> {
    serde_json::to_value(output).map_err(|_| {
        FacadeApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            MEMORY_CODE_INTERNAL,
            "result encoding failed",
            ["Report this SDK response mismatch."],
        )
    })
}

/// Refuses a caller-named entity this credential cannot read, with the
/// NOT_FOUND a missing one gets, so the route never confirms that the id
/// exists. A ref that is not an entity id is left for the engine to refuse.
pub(super) fn facade_admit_readable_ref(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    value: &serde_json::Value,
    field: &str,
) -> Result<(), FacadeApiError> {
    let Some(id) = value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .and_then(|id| EntityId::from_hex(id).ok())
    else {
        return Ok(());
    };
    if auth
        .can_read_entity(vault, &id)
        .map_err(MemoryError::from)?
    {
        Ok(())
    } else {
        Err(MemoryError::from(oneiron::Error::EntityNotFound).into())
    }
}

/// Re-admits each top-level `*_ref` field a hook's rewrite changed, as the
/// route admitted the caller's own refs ([`facade_admit_readable_ref`]): a
/// rewrite may not point the verb at an entity this credential cannot read.
/// The reason refuses the rewrite.
pub(super) fn facade_admit_rewritten(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    original: &serde_json::Value,
    rewritten: &serde_json::Value,
) -> Result<(), String> {
    let Some(fields) = rewritten.as_object() else {
        return Ok(());
    };
    for (field, value) in fields {
        if field.ends_with("_ref") && original.get(field) != Some(value) {
            facade_admit_readable_ref(vault, auth, rewritten, field)
                .map_err(|refusal| refusal.body.error.message)?;
        }
    }
    Ok(())
}

/// [`facade_admit_rewritten`] against the caller's `original` args, as a
/// row's rewrite admission.
pub(super) fn facade_rewrite_admit(
    server: &SyncServer,
    auth: &CoreAuth,
    original: &serde_json::Value,
) -> RewriteAdmit {
    let (vault, auth, original) = (Arc::clone(&server.vault), auth.clone(), original.clone());
    Arc::new(move |verb: &str, rewritten: &serde_json::Value| {
        facade_admit_rewritten(&vault, &auth, &original, rewritten)?;
        // A courtesy answer's rewritten reply_to meets its door's own check
        // here, so a bad one gives way to the caller's (FIX 5140).
        crate::owner::courtesy_delete::check_rewritten_reply_to(verb, rewritten)
    })
}

/// `memory` bound to re-admit a hook's rewritten refs, on every call: a
/// binding installed meanwhile still meets it.
pub(super) fn facade_rewrites_admitted<'v>(
    server: &SyncServer,
    auth: &CoreAuth,
    original: &serde_json::Value,
    memory: oneiron::Memory<'v>,
) -> oneiron::Memory<'v> {
    memory.with_rewrite_admit(facade_rewrite_admit(server, auth, original))
}

/// Drops every TASKS row this credential cannot read from a described
/// section, as MCP's board does, then encodes the description. A row id that
/// is not an entity id cannot be proven readable, so only a credential without
/// a slip, which reads every entity, keeps it. A card passes unchanged: its
/// task ref was admitted before the engine call.
pub(super) fn facade_readable_task_rows(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    mut description: oneiron::task_verb::TaskDescription,
) -> Result<serde_json::Value, FacadeApiError> {
    if let oneiron::task_verb::TaskDescription::Section(section) = &mut description {
        let mut rows = Vec::with_capacity(section.rows.len());
        for row in std::mem::take(&mut section.rows) {
            let readable = match EntityId::from_hex(&row.id) {
                Ok(id) => auth
                    .can_read_entity(vault, &id)
                    .map_err(MemoryError::from)?,
                Err(_) => auth.verified_slip().is_none(),
            };
            if readable {
                rows.push(row);
            }
        }
        section.rows = rows;
    }
    serde_json::to_value(description).map_err(|_| {
        FacadeApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            MEMORY_CODE_INTERNAL,
            "SDK result encoding failed",
            ["Report this SDK response mismatch."],
        )
    })
}
