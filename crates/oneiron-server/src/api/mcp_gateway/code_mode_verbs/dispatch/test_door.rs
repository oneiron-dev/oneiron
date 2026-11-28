//! The integration tests' door to one run call's credential lane (FIX-LIST 25102).

use super::*;

/// Whether one call a run serves itself reads on its connector's credential
/// lane: `effect` admitted as the door of a vault-wide connector presenting
/// `token` with its holder proof (`timestamp`, `nonce`, hex `signature`)
/// admits it. `Ok(true)` is a key, `Ok(false)` the actor's own key, and
/// `Err` the refusal or the proof failure. A door for the integration tests
/// (FIX-LIST 25102); the connector is unregistered, so no bound-verb
/// ceiling narrows it.
#[cfg(oneiron_test_support)]
pub(crate) fn admit_run_call_for_test(
    server: &Arc<SyncServer>,
    token: &str,
    timestamp: u64,
    nonce: &str,
    signature: &str,
    effect: SelfEffect,
) -> Result<bool, String> {
    let proof = crate::auth::BindingProof {
        timestamp,
        nonce: nonce.to_owned(),
        signature: signature.to_owned(),
    };
    let auth = crate::auth::CoreAuth::from_slip_token(token, &proof, server.vault().as_ref())
        .map_err(|error| format!("the holder proof does not verify: {error:?}"))?;
    let verified = auth
        .verified_slip()
        .ok_or_else(|| "the auth carries no verified slip".to_owned())?;
    let actor_ref = oneiron::EntityId::from_hex(&verified.claims().holder_ref)
        .map_err(|_| "the slip names no entity holder".to_owned())?;
    let actor_class = match verified.claims().actor_class.as_deref() {
        Some("human") => oneiron::EdgeActorClass::Human,
        Some("agent") => oneiron::EdgeActorClass::Agent,
        Some("system") => oneiron::EdgeActorClass::System,
        _ => return Err("the slip names no actor class".to_owned()),
    };
    let actor = crate::mcp::McpResolvedActor {
        auth: Some(auth),
        actor_ref,
        actor_class,
        gate_actor_class: actor_class.gate_actor_class(),
        gate_actor_ref: actor_ref.to_hex(),
        scope: crate::mcp::McpConnectorScope::vault_wide(),
        stream_connection: oneiron::context_board::StreamConnectionId(
            "mcp-test:run-claim-lane".to_owned(),
        ),
        bound_verbs: None,
        subscription_ceiling: std::collections::BTreeSet::new(),
    };
    let context = McpCallContext {
        actor,
        mode: crate::mcp::McpSurfaceMode::Primary,
        request_id: "run-claim-lane".to_owned(),
        landing: Ok(None),
        invocation: None,
        hook_ask: None,
        off_record_session: None,
        room_turn: None,
        drain: None,
        forwarded: None,
        client_surface: None,
        session_workspace: None,
        signing_request_transport: None,
    };
    let door = McpCodeModeVerbs::new(server, &context, oneiron::EntityId::now())
        .authored_by_engine_model();
    door.admit_run_call(RunCall::Bridge(effect))
        .map(|key| key.is_some())
        .map_err(|refusal| refusal.code)
}

#[cfg(test)]
pub(crate) fn admit_run_row_for_test(
    door: &McpCodeModeVerbs,
    row: &'static str,
) -> Result<(), AgentVerbRefusal> {
    door.admit_run_row(row)
}

#[cfg(test)]
pub(crate) fn admit_run_call_on_door_for_test(
    door: &McpCodeModeVerbs,
    call: RunCall,
) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
    door.admit_run_call(call)
}

#[cfg(test)]
pub(crate) fn admit_outer_skill_call_for_test(
    door: &McpCodeModeVerbs,
) -> Result<Option<ScopedReadActorKey>, AgentVerbRefusal> {
    door.admit_outer_skill_call()
}

#[cfg(test)]
pub(crate) fn admit_recorded_verb_for_test(
    door: &McpCodeModeVerbs,
    verb: AgentVerb,
) -> Result<(), AgentVerbRefusal> {
    door.admit_recorded_verb(verb)
}

#[cfg(test)]
pub(crate) fn admit_session_read_for_test(
    door: &McpCodeModeVerbs,
    verb: AgentVerb,
) -> Result<ScopedReadActorKey, AgentVerbRefusal> {
    door.admit_session_read(verb)
}
