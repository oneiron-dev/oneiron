//! The positively bound Anonymous caller selects a session-owned claim first.

use super::*;
use oneiron::memory::SessionWitnessBinding;

pub(super) async fn claim(
    server: &SyncServer,
    auth: &CoreAuth,
    locality: oneiron::claim::CallerLocality,
    invocation: InvocationId,
    body: [u8; 32],
) -> Result<(DoorClaim, Option<SessionWitnessBinding>), Refused> {
    let Some(binding) = caller_binding(server, auth, locality)? else {
        return Ok((
            facade::claim_door_invocation(server, invocation, body, auth.principal_entity()).await,
            None,
        ));
    };
    let entry = binding
        .claim_invocation(server.vault(), invocation, body)
        .map_err(native_refusal)?;
    let claimed = DoorClaim::from_session(entry).await;
    binding.revalidate(server.vault()).map_err(native_refusal)?;
    Ok((claimed, Some(binding)))
}

/// Captures a positively bound private route. Ordinary OnRecord and unmatched
/// session headers retain their existing recorded path.
pub(super) fn caller_binding(
    server: &SyncServer,
    auth: &CoreAuth,
    locality: oneiron::claim::CallerLocality,
) -> Result<Option<SessionWitnessBinding>, Refused> {
    let vault = server.vault();
    if !vault.model_call_keeps_no_record_for(
        auth.off_record_session(),
        crate::api::call_receipt::request_principal(auth),
    ) {
        return Ok(None);
    }
    let (actor, class) = principal(auth, vault)?;
    let mut caller = credential_memory(vault, Some(auth), actor, class).at(locality);
    if let Some(holder) = crate::api::scoped_auth::attested_owner_holder(auth)
        && auth.principal_entity() == Some(holder)
        && actor == holder
        && class == EdgeActorClass::Human
        && auth.actor_class() == Some("human")
    {
        let owner = crate::api::owner_routes::managed_owner_proof(server, holder)
            .map_err(|error| Box::new(facade::FacadeApiError::from(error).into_response()))?
            .ok_or_else(|| {
                Box::new(
                    facade::FacadeApiError::from(crate::error::ApiError::managed_owner_not_live())
                        .into_response(),
                )
            })?;
        // Only the requester's Human caller handle receives this proof.
        // The independently selected assistant author is never changed.
        caller = caller.with_owner_authorship(&owner);
    }
    let Some(context) = caller.session_witness_context().map_err(native_refusal)? else {
        return Ok(None);
    };
    context.into_binding().map(Some).map_err(native_refusal)
}

pub(super) fn replay(
    vault: &Vault,
    auth: &CoreAuth,
    binding: Option<&SessionWitnessBinding>,
    mut outcome: oneiron::runtime_hooks::verb::InvocationOutcome,
) -> Response {
    if let Some(binding) = binding {
        if let Some(release) = &mut outcome.release
            && let Some(rows) = release.rows.as_deref()
        {
            release.rows = match binding.base_replay_rows(vault, rows, &auth.destination()) {
                Ok(Some(rows)) => Some(rows),
                Ok(None) => {
                    let status = StatusCode::from_u16(outcome.status)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    return (status, Json(facade::details_on_device())).into_response();
                }
                Err(error) => return *native_refusal(error),
            };
        }
        for value in std::iter::once(&mut outcome.body)
            .chain(outcome.release.iter_mut().map(|release| &mut release.value))
        {
            if let Some(text) = value.get_mut("text")
                && let Some(original) = text.as_str()
            {
                let projected = match binding.project_completed_text(vault, original) {
                    Ok(text) => text,
                    Err(error) => return *native_refusal(error),
                };
                *text = Value::String(projected);
            }
        }
    }
    let response = facade::door_replay_for(vault, auth, "chat", outcome);
    if let Some(binding) = binding
        && let Err(error) = binding.revalidate(vault)
    {
        return *native_refusal(error);
    }
    response
}

fn native_refusal(error: MemoryError) -> Refused {
    Box::new(facade::FacadeApiError::from(error).into_response())
}
