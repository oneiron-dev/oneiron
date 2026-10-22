//! The gates an MCP call passes before it executes: proof, verb, credential and execute_code.
//! `mcp_proof_admits`, `mcp_verb_gate` and `mcp_execute_code_gate` are its call surface.
//! The actor_dispatch root defines `McpCallEffect` and `McpRecordBounds`.

use super::*;

/// Whether `auth`, the exact instrument a connector call verified, may act
/// through the registration `actor` resolved: its holder and class, Read and
/// no organization, and a registered world/facet Scope that narrows the
/// proof's. A call settlement runs again meets it under its credential as it
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
    if auth.org_ref().is_some() || !auth.has_scope(crate::auth::CoreScope::Read) {
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

/// `execute_code`'s credential gate: a run commits at once, so it needs the
/// whole record scope and Write.
pub(in crate::api::mcp_gateway) fn mcp_execute_code_gate(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
) -> Result<(), McpGatewayError> {
    mcp_credential_gate(
        server,
        actor,
        McpRecordBounds::Unrestricted,
        McpCallEffect::Commits,
    )
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
        }
        McpRecordBounds::Unrestricted => auth.require_unrestricted_record_scope(),
    };
    carried.map_err(|_| {
        McpGatewayError::new(
            -32020,
            "mcp_scope_unprojectable",
            "this facade cannot project the credential's record bounds",
        )
    })?;
    match bounds {
        // The world and facet it carries were judged just above. The birth
        // takes Write: a Propose-only grant would rest on a ceiling read
        // outside the transaction that commits the TASK.
        McpRecordBounds::Born => auth.require_granted(crate::auth::CoreScope::Write),
        McpRecordBounds::Filtered => {
            auth.require_granted(mcp_call_scope(server, actor, auth, effect))
        }
        McpRecordBounds::Unrestricted => auth.require(mcp_call_scope(server, actor, auth, effect)),
    }
    .map_err(|_| mcp_proof_error())
}
