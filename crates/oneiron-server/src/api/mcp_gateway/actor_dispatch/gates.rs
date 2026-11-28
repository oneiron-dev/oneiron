//! The gates an MCP call passes before it executes: proof, verb, credential, a code run's
//! session and each operation a run makes.
//! `mcp_proof_admits`, `mcp_verb_gate`, `mcp_execute_code_gate`, `mcp_run_call_gate` and
//! `mcp_host_verb_gate` are its call surface.
//! The actor_dispatch root defines `McpCallEffect` and `McpRecordBounds`.

use super::super::static_admission::{GrantBounds, StaticCaller, StaticCheck, static_admission};
use super::*;

/// Whether `auth`, the exact instrument a connector call verified, may act
/// through the registration `actor` resolved: its holder and class, Read or
/// its live two-renderer share, no organization, and a registered world/facet
/// Scope that narrows the proof's. A call settlement meets it under its credential as it
/// verified again then (ARCH-0080 §3 Ask).
pub(in crate::api::mcp_gateway) fn mcp_proof_admits(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
    auth: &crate::auth::CoreAuth,
) -> Result<(), McpGatewayError> {
    let proof = auth.verified_slip().ok_or_else(mcp_proof_error)?;
    // The host's own root acts only as the owner its host action names, and
    // only through that owner's registration; a hosted operator's root gets
    // the typed refusal before any tool runs (FIX 2222). Every client is
    // bound to the paired holder and verified class.
    if let Some(action) = crate::api::host_action::host_action_of(server.vault(), auth) {
        let owner = action
            .map_err(|error| super::mcp_engine_error("host action failed", error))?
            .actor();
        if actor.actor_ref != owner.entity_ref() || actor.actor_class != owner.actor_class() {
            return Err(mcp_proof_error());
        }
    } else if auth.principal_ref() != Some(actor.gate_actor_ref.as_str())
        || auth.actor_class() != Some(actor.gate_actor_class)
    {
        return Err(mcp_proof_error());
    }
    let share_view =
        mcp_share_view_holder_admits(server, auth, actor.gate_actor_class, &actor.gate_actor_ref)
            && actor.bound_verbs.as_ref().is_some_and(|verbs| {
                verbs.len() == 2
                    && verbs.contains("vault.shares.view")
                    && verbs.contains("vault.notes.follow_citation")
            });
    if auth.org_ref().is_some() || (!auth.has_scope(crate::auth::CoreScope::Read) && !share_view) {
        return Err(mcp_proof_error());
    }
    // The registry holds all or one world, and all or a set of facets: as a
    // world/facet Scope it must narrow the proof's. Refuse a wider
    // registration instead of silently projecting away verifier bounds. A
    // facet bound the owner's own credential carries binds nothing (owner
    // ruling FACET-READ), so it refuses no facet set.
    let axis = |id: Option<oneiron::EntityId>| {
        id.map_or(ScopeAxis::All, |id| {
            ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(id)]))
        })
    };
    let facets_owner_exempt = || {
        server
            .vault
            .credential_facets_owner_exempt(proof)
            .unwrap_or(false)
    };
    let proof_facets =
        if actor.scope.facets.is_narrowing_of(&proof.scope().facets) || !facets_owner_exempt() {
            proof.scope().facets.clone()
        } else {
            ScopeAxis::All
        };
    let projection = |worlds, facets| oneiron::federation::Scope {
        worlds,
        facets,
        ..oneiron::federation::Scope::top()
    };
    if !projection(axis(actor.scope.world_ref), actor.scope.facets.clone())
        .is_narrowing_of(&projection(proof.scope().worlds.clone(), proof_facets))
    {
        return Err(mcp_proof_error());
    }
    Ok(())
}

/// A share recipient needs no general write-ceiling row merely to reach
/// the two renderers. Only the live proof's own holder and class qualify.
pub(super) fn mcp_share_view_holder_admits(
    server: &SyncServer,
    auth: &crate::auth::CoreAuth,
    class: &str,
    actor_ref: &str,
) -> bool {
    auth.principal_ref() == Some(actor_ref)
        && auth.actor_class() == Some(class)
        && auth.org_ref().is_none()
        && ["vault.shares.view", "vault.notes.follow_citation"]
            .into_iter()
            .any(|verb| auth.allows_share_view_verb(verb))
        && auth.credential_is_live(server.vault())
}

/// Resolves the ordinary actor ceiling, or the live share recipient's own
/// registration. The registry's two-tool bound and proof gate still apply.
pub(in crate::api::mcp_gateway) fn mcp_actor_ceiling_admits(
    server: &SyncServer,
    auth: &crate::auth::CoreAuth,
    class: &str,
    actor_ref: &str,
) -> bool {
    server
        .vault()
        .gate_actor_ceiling_exists(class, actor_ref)
        .unwrap_or(false)
        || mcp_share_view_holder_admits(server, auth, class, actor_ref)
}

/// The same request, with Read only for its actual share-rendering verb.
pub(in crate::api::mcp_gateway) fn mcp_share_view_context(
    actor: &McpCallContext,
    verb: &str,
) -> Option<McpCallContext> {
    let auth = actor.auth.as_ref()?;
    if !auth.allows_share_view_verb(verb) {
        return None;
    }
    let mut context = actor.clone();
    context.actor.auth = Some(auth.clone().at_share_view_door(verb));
    Some(context)
}

/// A write whose session names a facet the connector does not read, or a
/// session that does not read, is refused before anything is written, alike.
pub(super) fn mcp_landing_refusal(_: crate::api::write_facet::LandingRefused) -> McpGatewayError {
    McpGatewayError::new(
        -32020,
        "mcp_scope_refused",
        "the session this request names does not place this connector's writes",
    )
}

pub(in crate::api::mcp_gateway) fn mcp_proof_error() -> McpGatewayError {
    McpGatewayError::new(
        -32001,
        "mcp_auth_required",
        "the registered connector requires its live paired holder proof",
    )
}

/// A live connector credential, matched to its registration, that lacks the
/// grant a call needs: its tier holds less (read-only: no Propose or Write;
/// propose-only: no Write). It names the grant, as the HTTP door's
/// `forbidden_scope` does, and is not the proof refusal: nothing about the
/// credential needs presenting again or renewing (FIX
/// MCP-READONLY-WRITE-REFUSAL-NAMES-AUTH).
pub(in crate::api::mcp_gateway) fn mcp_grant_refusal(
    scope: crate::auth::CoreScope,
) -> McpGatewayError {
    McpGatewayError::new(
        -32020,
        "mcp_grant_missing",
        format!(
            "this connector's credential does not hold the {} grant this call needs",
            scope.as_str()
        ),
    )
    .with_required_scope(scope.as_str())
}

/// The verb a call needs on this door: Read; for a write, Write — or Propose
/// when the write waits for review: it proposes and the actor's live ceiling
/// is `proposed`. So a propose-only credential (ARCH-0028: write capability
/// at `proposed`) drafts here and nowhere else, and nothing it does here takes
/// effect without review: acknowledging a task, claiming a room turn, speech,
/// a key-value write, an ask, a wait or an answer all need Write, as every
/// unbound door does.
pub(super) fn mcp_call_scope(
    server: &SyncServer,
    actor: &McpResolvedActor,
    auth: &crate::auth::CoreAuth,
    effect: McpCallEffect,
) -> crate::auth::CoreScope {
    use crate::auth::CoreScope;
    match effect {
        McpCallEffect::Reads => CoreScope::Read,
        McpCallEffect::Proposes
            if !auth.has_scope(CoreScope::Write)
                && server
                    .vault
                    .gate_actor_ceiling_is_proposed(actor.gate_actor_class, &actor.gate_actor_ref)
                    .unwrap_or(false) =>
        {
            CoreScope::Propose
        }
        McpCallEffect::Proposes | McpCallEffect::Commits => CoreScope::Write,
    }
}

/// `execute` and `resume`'s session gate: the native run this credential
/// starts or enters again, at that call and at each later check of it
/// (after an await, at a replay, at the answer's release). Its holder,
/// class and organization were judged where the call resolved
/// (`mcp_proof_admits`). Here the credential is live now, holds Read, and
/// carries no record bound, since no proof projection reaches a run. The
/// host records the run for every tier (ARCH-0028: read-only, propose-only,
/// full-access; ONE-1183-D2), and that record grants nothing: each operation
/// the run makes is judged by its own effect (`mcp_run_call_gate`,
/// `mcp_host_verb_gate`, and each verb's own `mcp_verb_gate`).
pub(in crate::api::mcp_gateway) fn mcp_execute_code_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    mcp_credential_gate(
        server,
        actor,
        McpRecordBounds::Unrestricted,
        McpCallEffect::Reads,
    )
}

/// The refusal a connector's run meets when it sets a world's privacy
/// (CODE-MODE-LENDING-WORLD-PRIVACY = A): a world's privacy is set by its
/// holder directly, not by a connector's run, for both run authors (caller
/// code and engine model), until a direct row exists. Native agent runs keep
/// the act: the engine's own dispatcher
/// (`crates/oneiron/src/code_run/dispatcher/world_privacy_set.rs`) is unchanged.
pub(crate) const MCP_WORLD_PRIVACY_REFUSED: &str = "mcp_world_privacy_refused";

/// One call a run serves itself (`RunCall`): the live session, then what
/// the call does (`McpCallEffect::of_run_call`). A read needs the session's
/// Read alone; every write takes effect at once, so it needs Write.
pub(in crate::api::mcp_gateway) fn mcp_run_call_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    call: oneiron::code_run::RunCall,
) -> Result<(), McpGatewayError> {
    if static_admission(
        StaticCaller::connector(actor),
        StaticCheck::ConnectorRunCall(call),
    )
    .is_err()
    {
        let mut refused = McpGatewayError::new(
            -32020,
            MCP_WORLD_PRIVACY_REFUSED,
            "a world's privacy is set by its holder directly, not by a connector's run",
        );
        refused.reason_codes = vec!["world_privacy.set_by_holder_directly".to_owned()];
        return Err(refused);
    }
    mcp_session_operation_gate(server, actor, McpCallEffect::of_run_call(call))
}

#[cfg(test)]
pub(crate) fn mcp_run_call_gate_for_test(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    call: oneiron::code_run::RunCall,
) -> Result<(), McpGatewayError> {
    mcp_run_call_gate(server, actor, call)
}

/// One speech call of a run, at `destination`, where its storage lands it:
/// the live session, then Write in the run's own derived conversation as
/// anywhere else (`McpCallEffect::of_run_speech`, FIX CODE-MODE-LENDING-W7).
pub(in crate::api::mcp_gateway) fn mcp_run_speech_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    destination: oneiron::code_run::RunSpeechDestination,
) -> Result<(), McpGatewayError> {
    mcp_session_operation_gate(server, actor, McpCallEffect::of_run_speech(destination))
}

/// One speech call of a run whose program its caller wrote (FIX
/// EXECUTE-CALLER-CODE): the live session, then Write wherever it lands.
/// No direct call writes a MESSAGE under a Read grant, so the caller's own
/// code does not either.
pub(in crate::api::mcp_gateway) fn mcp_caller_code_speech_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    mcp_session_operation_gate(server, actor, McpCallEffect::Commits)
}

/// One row a run's door serves itself, not through a tool: a browser or
/// desktop row, a session-bound run's room read or write, or a program
/// admission job's call. The live session, then the row's own effect
/// (`McpCallEffect::of_host_verb`): none of them waits for review, so a
/// writing row needs Write.
pub(crate) fn mcp_host_verb_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    verb: oneiron::task_verb::sdk::AgentVerb,
) -> Result<(), McpGatewayError> {
    mcp_session_operation_gate(server, actor, McpCallEffect::of_host_verb(verb))
}

/// One browser row of a run, whatever it reads: the live session, then
/// Write. The row drives the host's browser guest, which a direct call
/// reaches only through the caller's attached live run, and attaching needs
/// Write (FIX CODE-MODE-LENDING-W2).
pub(in crate::api::mcp_gateway) fn mcp_browser_guest_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    mcp_session_operation_gate(server, actor, McpCallEffect::Commits)
}

#[cfg(test)]
pub(crate) fn mcp_browser_guest_gate_for_test(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    mcp_browser_guest_gate(server, actor)
}

/// The live session, then one operation's own effect: a read needs only the
/// session's Read; a write needs the grant `mcp_call_scope` names for it,
/// over the whole record scope.
fn mcp_session_operation_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    effect: McpCallEffect,
) -> Result<(), McpGatewayError> {
    mcp_execute_code_gate(server, actor)?;
    match effect {
        McpCallEffect::Reads => Ok(()),
        McpCallEffect::Proposes | McpCallEffect::Commits => {
            let auth = actor.auth.as_ref().ok_or_else(mcp_proof_error)?;
            // The session gate above held the credential live and its record
            // scope unrestricted, so only the grant is left to miss.
            let scope = mcp_call_scope(server, actor, auth, effect);
            static_admission(
                StaticCaller::connector(actor),
                StaticCheck::Grant {
                    scope,
                    bounds: GrantBounds::Checked,
                },
            )
            .map_err(|_| mcp_grant_refusal(scope))
        }
    }
}

/// One generated verb's credential gate, whichever door the call arrived at.
///
/// Board/task lists are explicitly filtered row by row. Task detail/write
/// facades have no recursive proof projection, so they require an unrestricted
/// record scope instead of dropping caveats. A filtered read that names one
/// task reads that task's card, which is task detail too. `describe(self)`
/// renders the whole run brief, not filtered rows, so it takes the same guard.
/// A `born` write (`tasks.create`) from a narrowed connector carries its world
/// and facet into the records it mints, so only those two axes may be
/// narrowed, and it needs a Write grant. From a vault-wide connector it is
/// unrestricted, as before.
pub(crate) fn mcp_verb_gate(
    server: &Arc<SyncServer>,
    tool: crate::mcp::McpGeneratedVerbTool,
    arguments: &crate::mcp::McpVerbArguments,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    let bounds = if tool.filtered_read()
        && arguments.task_ref.is_none()
        && arguments.self_target != Some(true)
    {
        McpRecordBounds::Filtered
    } else if tool.born_in_scope() && actor.scope.is_narrow() {
        McpRecordBounds::Born
    } else {
        McpRecordBounds::Unrestricted
    };
    // A host door runs outside the engine's scoped read, which applies a
    // channel caveat row by row, so the filtered bounds cannot carry one to
    // it: refused here, before the call's hooks, as the door's HTTP
    // admission `lane_record_scope` refuses it before its hooks
    // (`self.actor`, review of #9533; every other such door, FIX
    // MCP-FILTERED-HOST-DOOR-CHANNEL-CAVEAT-PARITY).
    if tool.lane_record_scope_host_door() {
        actor.auth.as_ref().ok_or_else(mcp_proof_error)?;
        static_admission(StaticCaller::connector(actor), StaticCheck::LaneRecordScope).map_err(
            |_| {
                McpGatewayError::new(
                    -32020,
                    "mcp_scope_unprojectable",
                    "this facade cannot project the credential's record bounds",
                )
            },
        )?;
    }
    mcp_credential_gate(server, actor, bounds, McpCallEffect::of(tool, arguments))
}

/// The connector credential is live, inside the record bounds the call can
/// carry, and holds the verb for what the call does.
pub(super) fn mcp_credential_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    bounds: McpRecordBounds,
    effect: McpCallEffect,
) -> Result<(), McpGatewayError> {
    let auth = actor.auth.as_ref().ok_or_else(mcp_proof_error)?;
    if !auth.credential_is_live(server.vault().as_ref()) {
        return Err(mcp_proof_error());
    }
    let axis = |id: Option<oneiron::EntityId>| {
        id.map_or(ScopeAxis::All, |id| {
            ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(id)]))
        })
    };
    let carried = match bounds {
        McpRecordBounds::Filtered => Ok(()),
        McpRecordBounds::Born => {
            let landing = actor.landing.map_err(mcp_landing_refusal)?;
            auth.require_record_scope_carried(axis(actor.scope.world_ref), axis(landing))
                .map_err(drop)
        }
        McpRecordBounds::Unrestricted => static_admission(
            StaticCaller::connector(actor),
            StaticCheck::UnrestrictedRecordScope,
        )
        .map_err(drop),
    };
    carried.map_err(|_| {
        McpGatewayError::new(
            -32020,
            "mcp_scope_unprojectable",
            "this facade cannot project the credential's record bounds",
        )
    })?;
    // The credential is live and its record bounds were judged just above,
    // so what is left to miss is the grant itself. Read is part of the proof
    // a connector registers with (`mcp_proof_admits`), so its miss stays the
    // proof refusal; a missing Propose or Write is the tier's.
    let scope = match bounds {
        // The world and facet it carries were judged just above. The birth
        // takes Write: a Propose-only grant would rest on a ceiling read
        // outside the transaction that commits the TASK.
        McpRecordBounds::Born => crate::auth::CoreScope::Write,
        McpRecordBounds::Filtered | McpRecordBounds::Unrestricted => {
            mcp_call_scope(server, actor, auth, effect)
        }
    };
    let bounds = match bounds {
        McpRecordBounds::Born | McpRecordBounds::Filtered => GrantBounds::Carried,
        McpRecordBounds::Unrestricted => GrantBounds::Checked,
    };
    static_admission(
        StaticCaller::connector(actor),
        StaticCheck::Grant { scope, bounds },
    )
    .map_err(|_| match scope {
        crate::auth::CoreScope::Read => mcp_proof_error(),
        _ => mcp_grant_refusal(scope),
    })
}
