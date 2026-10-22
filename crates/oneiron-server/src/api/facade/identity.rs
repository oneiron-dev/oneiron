//! Who a facade call acts as: its actor, its invocation id and the owner's authorship.
//! `facade_actor`, `facade_invocation` and the two authorship fns are its call surface.
//! `crate::auth::CoreAuth` and the engine's `EdgeActorClass` define the records forwarded here.

use super::*;

/// Resolves the write identity every facade verb runs as, from the CREDENTIAL
/// and from nowhere else.
///
/// BOTH claims are required, and their absence is a `FORBIDDEN` the handler
/// raises rather than a `401` the extractor raises. The split is the contract:
/// a malformed claim value never reaches here (the MAC-verified parse already
/// 401'd it), so everything this function can see is a well-formed credential
/// that simply is not actor-bound — an owner-grade secret, or a scoped slip
/// minted without `--actor-class`. Those callers keep every non-facade route
/// they have today; they only cannot write as somebody.
///
/// Nothing here is authority. The engine re-checks, per write, that the named
/// principal exists and that its stored entity type admits the asserted class.
///
/// A host credential binds no principal of its own (FIX 2222): a self-hosted
/// root, or the explicit local dev mode, writes as the owner the one
/// resolver names ([`crate::api::host_action::facade_host_action`]), and a
/// hosted operator's root gets the typed refusal. No other owner-grade
/// credential chooses whom it writes as.
pub(super) fn facade_actor(
    server: &SyncServer,
    auth: &CoreAuth,
) -> Result<(EntityId, EdgeActorClass), FacadeApiError> {
    if let Some(action) = super::host_action::facade_host_action(server, auth)? {
        let actor = action.actor();
        return Ok((actor.entity_ref(), actor.actor_class()));
    }
    let principal_ref = auth.principal_ref().ok_or_else(|| {
        FacadeApiError::forbidden(
            "facade routes bind writes to an authenticated principal",
            [
                "Present a slip paired from a link created with --principal-ref <32-hex person id>.",
                "An owner-grade credential names no principal and cannot write here.",
            ],
        )
    })?;
    let actor = EntityId::from_hex(principal_ref).map_err(|_| {
        // Unreachable through the extractor, which canonicalizes the claim
        // through `EntityId::from_hex` before it ever builds a `CoreAuth`.
        // Kept as a typed refusal anyway: this function must not be the place
        // that assumes an upstream check ran.
        FacadeApiError::forbidden(
            "principal_ref is not a 32-hex entity id",
            ["Re-mint the slip with a 32-character lowercase hex principal ref."],
        )
    })?;
    let actor_class = match auth.actor_class() {
        Some("human") => EdgeActorClass::Human,
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        // `None` is the well-formed-but-unbound credential above. `Some(_)`
        // outside the enum cannot occur — `parse_actor_class` 401s it — and is
        // folded in here so the match stays total and fails CLOSED either way.
        None | Some(_) => {
            return Err(FacadeApiError::forbidden(
                "facade routes bind writes to a declared actor class",
                [
                    "Present a slip paired from a link created with --actor-class <human|agent|system>.",
                    "Reconnect with a differently scoped slip to act as another actor.",
                ],
            ));
        }
    };
    Ok((actor, actor_class))
}

/// Names the room whose turn a request runs in (ARCH-0067 §8). It names only
/// the room: the engine reads the roster and its Scope from the vault.
pub(crate) const ROOM_TURN_HEADER: &str = "x-oneiron-room-turn";

/// Names the logical verb a request runs (ARCH-0080 §3), as 32 hex digits:
/// its verb hooks fire once for it, and a retry of a pending call names the
/// same one to find its ask.
pub(crate) const INVOCATION_HEADER: &str = "x-oneiron-invocation";

/// `memory` bound to the invocation the call names, if it names one, the
/// hook pause it resumes beside it (L13 PR-D), and the off-record session
/// it names (OF-063: inside an anonymous one a reference refusal writes no
/// receipt, as its call writes none, OF-538).
/// The facade, in the room turn the call names, is the door a credential
/// caller's call came in by: a verb hook's ask saves it, so settlement runs
/// the call again here (ARCH-0080 §3 Ask).
pub(super) fn facade_invocation<'v>(
    memory: oneiron::Memory<'v>,
    call: &FacadeCall<'_>,
) -> Result<oneiron::Memory<'v>, FacadeApiError> {
    let memory = match call.session_ref() {
        Some(session_ref) => memory.in_off_record_session(session_ref),
        None => memory,
    };
    let memory = memory.with_credential_door(VerbAskDoor::Facade {
        room: call.room_turn()?,
    });
    let memory = match call.hook_ask()? {
        Some(ask) => memory.with_hook_ask(ask),
        None => memory,
    };
    Ok(match call.invocation()? {
        Some(invocation) => memory.with_invocation(invocation),
        None => memory,
    })
}

/// The proof a write carries when the vault's owner makes it in person, on the
/// owner's own undelegated full slip: owner-authored writes carry their own
/// confirmation. `None` for any other credential, which writes as itself. The
/// owner's own credential that no longer holds (revoked, or its PERSON
/// deleted, merged or split) is refused, never downgraded to an ordinary
/// write.
pub(in crate::api) fn owner_authorship(
    auth: &CoreAuth,
    server: &SyncServer,
) -> Result<Option<oneiron::consent::AuthenticatedOwner>, ApiError> {
    // A managed vault's owner, whom its supervisor attested for this one
    // request (`ManagedOwnerAction`): no slip to bind, so the proof holds
    // only while the person is the vault's live recorded owner.
    if let Some(holder) = auth.managed_owner() {
        return super::owner_routes::managed_owner_proof(server, holder);
    }
    // A self-hosted root, or the dev mode, acting as the owner (FIX 2222):
    // the owner's proof carries the host action, which every acting
    // transaction proves again. A hosted operator's root gets the refusal.
    if let Some(action) = super::host_action::host_action_of(server.vault(), auth) {
        let action = action.map_err(super::host_action::host_action_refusal)?;
        return server
            .vault()
            .authenticate_host_action_owner(&action, oneiron::store::GateDecisionId::now())
            .map(Some)
            .map_err(|_| ApiError::forbidden_scope("owner"));
    }
    let Some((principal, actor)) = auth
        .principal_ref()
        .and_then(|principal| Some((principal, oneiron::EntityId::from_hex(principal).ok()?)))
    else {
        return Ok(None);
    };
    let Some(slip) = auth.verified_slip().filter(|slip| {
        let claims = slip.claims();
        slip.is_full_vault_owner_grade()
            && claims.parent_id.is_none()
            && claims.holder_ref == actor.to_hex()
            && claims.actor_class.as_deref() == Some("human")
    }) else {
        return Ok(None);
    };
    // The owner's own forwarded slip carries his authorship on a managed
    // vault too (FIX 5121): it is his say-so, on his own proof.
    if !auth.is_owner_grade() {
        return Ok(None);
    }
    let refused = || ApiError::forbidden_scope("owner");
    let Some(owner) = server
        .vault()
        .authenticate_recorded_owner(actor, principal, oneiron::store::GateDecisionId::now())
        .map_err(|_| refused())?
    else {
        return Ok(None);
    };
    if !server
        .vault()
        .is_live_vault_owner(&owner)
        .map_err(|_| refused())?
    {
        return Ok(None);
    }
    server
        .vault()
        .bind_owner_credential(owner, slip.clone())
        .map(Some)
        .map_err(|_| refused())
}

/// The one verb whose direct request binds the requesting person's own
/// proof rather than only the owner's (OF-417).
pub(super) const PERSON_PROOF_VERB: &str = "vault.workspace.work_companion.set";

/// The delete whose direct owner request also binds the host's own slip
/// issuer: deleting a Connect guest's PERSON withdraws its grants and
/// disconnects their pacts first (FIX 3875).
pub(super) const GUEST_REVOKING_DELETE_VERB: &str = "vault.delete";

/// The proof a direct request (outside any room turn) binds onto its
/// caller's surface for `verb`. `vault.workspace.work_companion.set` takes
/// the person's own proof ([`shared_act_doors::person`]): the owner's, or a
/// live person's on their own verified human credential, whose
/// workspace-settings power the engine then checks; any other caller binds
/// none and the engine refuses it. Every other verb binds the owner's own
/// authorship ([`owner_authorship`]), or none.
pub(in crate::api) fn direct_authorship(
    auth: &CoreAuth,
    server: &SyncServer,
    verb: &str,
) -> Result<Option<oneiron::consent::AuthenticatedOwner>, ApiError> {
    if verb == PERSON_PROOF_VERB {
        return Ok(shared_act_doors::person(server, auth, verb).ok());
    }
    owner_authorship(auth, server)
}
