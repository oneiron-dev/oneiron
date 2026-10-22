//! How a facade row invokes its door: in the caller's room turn, on a scoped credential.
//! `facade_invoke`, `facade_invoke_in_turn` and `facade_invoke_born` are its call surface.
//! The engine's `Memory` and scoped read keys (`oneiron::claim`) define the records forwarded here.

use super::*;

/// Runs one SDK verb as the caller's credential reads, inside the named room
/// turn when the call names one. Its reads list the rows they pick in
/// `producers`.
pub(super) fn facade_invoke(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    value: serde_json::Value,
    producers: &oneiron::memory::ProducerRows,
) -> Result<serde_json::Value, FacadeApiError> {
    facade_invoke_in_turn(server, call, actor, class, verb, value, producers, None)
}

/// [`facade_invoke`] on the task-work turn the dispatch awaited for the call
/// (Rule 5), bound on the surface the verb runs on: the engine's task work,
/// a verb hook's ask among it, runs on that turn and waits for no other.
///
/// The row runs off the async runtime ([`crate::server::blocking`]): its
/// work blocks, and a hook's ask may wait in the task-work line. The
/// surface, its room turn and the drain's scope are built on the thread that
/// runs it.
#[expect(
    clippy::too_many_arguments,
    reason = "the generated dispatch passes facade_invoke's inputs plus the turn it awaited"
)]
pub(super) fn facade_invoke_in_turn(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    value: serde_json::Value,
    producers: &oneiron::memory::ProducerRows,
    turn: Option<Arc<oneiron::work_line::TaskWorkTurn>>,
) -> Result<serde_json::Value, FacadeApiError> {
    crate::server::blocking(move || -> Result<serde_json::Value, FacadeApiError> {
        let auth = call.auth();
        let memory = facade_invocation(
            credential_memory(&server.vault, Some(auth), actor, class)
                .at(auth.locality())
                .listing_producers(producers),
            call,
        )?;
        let memory = match turn {
            Some(turn) => memory.with_task_work_turn(turn),
            None => memory,
        };
        let memory = facade_task_decisions(server, verb, memory)?;
        let memory = facade_rewrites_admitted(server, auth, &value, memory);
        // Settlement's run of the call enters its boundary here as the drain's.
        let _drain = call.drain().map(VerbAskDrainPermit::enter);
        Ok(match call.room_turn()? {
            Some(room) => memory.for_room_turn(room)?.invoke(verb, value)?,
            None => {
                // The owner's own request on the owner's own full credential:
                // owner-authored writes carry their own confirmation. Any other
                // caller writes as itself; the owner's credential that no longer
                // holds is refused. The work-companion setting takes the
                // person's own proof instead (OF-417). His acts record where
                // the request reached this install, as its headers proved it
                // (`FacadeCall::surface`, audit only, FIX 4650).
                let memory = match direct_authorship(auth, server, verb)? {
                    Some(owner) => memory
                        .with_owner_authorship(&owner)
                        .with_owner_surface(call.surface()),
                    None => memory,
                };
                if verb == GUEST_REVOKING_DELETE_VERB {
                    // With no host key the delete runs as before (FIX 3875).
                    super::pairing::with_host_issuer(server, |issuer| match issuer {
                        Some(issuer) => oneiron::task_verb::sdk::invoke(
                            &memory.with_host_slip_issuer(issuer),
                            verb,
                            value,
                        ),
                        None => oneiron::task_verb::sdk::invoke(&memory, verb, value),
                    })?
                } else {
                    oneiron::task_verb::sdk::invoke(&memory, verb, value)?
                }
            }
        })
    })
}

/// These doors act only on the caller's presented proof, never on host-root fallback authority.
pub(super) fn facade_scoped_credential(auth: &CoreAuth) -> Result<(), FacadeApiError> {
    if auth.verified_slip().is_none() {
        return Err(FacadeApiError::forbidden(
            "a verified caller credential is required",
            ["Present the paired caller credential."],
        ));
    }
    Ok(())
}

pub(super) fn facade_scoped_export_credential(auth: &CoreAuth) -> Result<(), FacadeApiError> {
    facade_scoped_credential(auth)?;
    if !auth
        .verified_slip()
        .is_some_and(|proof| proof.allows_verb("export"))
    {
        return Err(FacadeApiError::forbidden(
            "the credential does not grant export",
            ["Use a credential with the export verb class."],
        ));
    }
    Ok(())
}

/// Explicit claim admission carries the credential into the committing engine writer.
/// A named sitting still binds its current facet; its name cannot authorize another position.
pub(super) fn facade_claim_position(
    server: &SyncServer,
    call: &FacadeCall<'_>,
) -> Result<BirthPosition, FacadeApiError> {
    let facet = call
        .session()?
        .map(|session| {
            server
                .vault
                .session_facet(session)
                .map_err(MemoryError::from)?
                .ok_or_else(|| {
                    FacadeApiError::forbidden(
                        "the named session has no write facet",
                        ["Name a session with a facet."],
                    )
                })
        })
        .transpose()?;
    Ok(BirthPosition { world: None, facet })
}

/// Where the records this credential births land (owner ruling FACET-READ;
/// placement stays derived, ARCH-0028). A credential never narrowed to facets
/// keeps the derived birth, under the same strict door as before. A narrowed
/// one lands in its landing facet, which it must carry; any other narrowing
/// still fails closed.
pub(super) fn facade_landing(
    server: &SyncServer,
    call: &FacadeCall<'_>,
) -> Result<BirthPosition, FacadeApiError> {
    let auth = call.auth();
    let Some(proof) = auth.verified_slip() else {
        return Ok(BirthPosition::default());
    };
    if matches!(proof.scope().facets, ScopeAxis::All) {
        auth.require_unrestricted_record_scope()?;
        return Ok(BirthPosition::default());
    }
    let session = call.session()?;
    let write_facet = server
        .vault
        .paired_write_facet(&proof.claims().slip_id)
        .map_err(MemoryError::from)?;
    let landing = landing_facet(&server.vault, session, &proof.scope().facets, write_facet)
        .map_err(|_| {
            FacadeApiError::forbidden(
                "the session this request names does not place this credential's writes",
                ["Name a session whose facet this credential reads, or none."],
            )
        })?;
    auth.require_record_scope_carried(
        ScopeAxis::All,
        landing.map_or(ScopeAxis::All, |facet| {
            ScopeAxis::Some(std::collections::BTreeSet::from([ScopeId(facet)]))
        }),
    )?;
    Ok(BirthPosition {
        world: None,
        facet: landing,
    })
}

/// [`facade_invoke`] for a verb that births records at `position`, off the
/// async runtime as [`facade_invoke_in_turn`] runs.
#[expect(
    clippy::too_many_arguments,
    reason = "the generated dispatch passes facade_invoke's inputs plus the birth position"
)]
pub(super) fn facade_invoke_born(
    server: &SyncServer,
    call: &FacadeCall<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    value: serde_json::Value,
    position: BirthPosition,
    producers: &oneiron::memory::ProducerRows,
) -> Result<serde_json::Value, FacadeApiError> {
    crate::server::blocking(move || -> Result<serde_json::Value, FacadeApiError> {
        let auth = call.auth();
        let memory = facade_invocation(
            credential_memory(&server.vault, Some(auth), actor, class)
                .at(auth.locality())
                .with_birth_position(position)
                .listing_producers(producers),
            call,
        )?;
        let memory = facade_task_decisions(server, verb, memory)?;
        let memory = facade_rewrites_admitted(server, auth, &value, memory);
        let _drain = call.drain().map(VerbAskDrainPermit::enter);
        Ok(match call.room_turn()? {
            Some(room) => memory.for_room_turn(room)?.invoke(verb, value)?,
            None => {
                let memory = match direct_authorship(auth, server, verb)? {
                    Some(owner) => memory
                        .with_owner_authorship(&owner)
                        .with_owner_surface(call.surface()),
                    None => memory,
                };
                oneiron::task_verb::sdk::invoke(&memory, verb, value)?
            }
        })
    })
}

/// `memory` with the host's task decisions bound, on a task row that asks
/// them (OF-533): a post's take question and a report's done and ask-up
/// questions then go through the host's ladder instead of asking up. A
/// model rung may block on the server's runtime, so the dispatch runs these
/// rows on a blocking thread; every other row's surface stays unbound. The
/// row's `task_decisions` flag picks both (FIX 2762). A ladder the host
/// cannot build refuses the row.
pub(super) fn facade_task_decisions<'v>(
    server: &'v SyncServer,
    verb: &str,
    memory: oneiron::Memory<'v>,
) -> Result<oneiron::Memory<'v>, FacadeApiError> {
    if !oneiron::task_verb::sdk::AgentVerb::from_name(verb)
        .is_some_and(oneiron::task_verb::sdk::AgentVerb::takes_task_decisions)
    {
        return Ok(memory);
    }
    let decisions = server
        .decision_host()
        .task_decisions()
        .map_err(MemoryError::from)?;
    Ok(memory.with_task_decisions(decisions))
}

/// A verb that reads around the read lane is not served inside a room turn.
pub(super) fn facade_outside_room_turn(
    call: &FacadeCall<'_>,
    verb: &str,
) -> Result<(), FacadeApiError> {
    facade_room_turn_serves(call, verb, false)
}

/// Refuses, before any lookup the verb would make, a verb the named room
/// turn does not serve, so the refusal says nothing about the verb's target.
pub(super) fn facade_room_turn_serves(
    call: &FacadeCall<'_>,
    verb: &str,
    served: bool,
) -> Result<(), FacadeApiError> {
    if !served && call.room_turn()?.is_some() {
        return Err(FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            format!("{verb} is not served inside a room turn"),
            ["Call it without the room turn header."],
        ));
    }
    Ok(())
}
