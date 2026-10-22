//! A facade row's verb hooks: the pre chain before its door runs and the post chain after it.
//! `facade_hooks_pre`, `row_hooks_pre_with` and `facade_hooks_post` are its call surface.
//! The engine's verb hook types (`oneiron::runtime_hooks`) define the records forwarded here.

use super::*;

/// What a row's pre chain carries for settlement (ARCH-0080 §3 Ask): the
/// credential a caller's call can run again on through its door, and the
/// drain's permit when settlement runs it again. The default carries
/// neither. A call that keeps no record carries its session instead
/// (FIX 4283): its hooks' records stay there, and only its caller's retry in
/// that session resumes it.
#[derive(Default)]
pub(crate) struct RowHookResume {
    pub(crate) credential: Option<VerbAskCredential>,
    pub(crate) drain: Option<VerbAskDrainPermit>,
    pub(crate) session: Option<verb_hook_boundary::HookSession>,
}

/// The pre chain of row `verb` for `actor` over `args`, off the async
/// runtime (ARCH-0080 §3): a hook may write, open an ask and run its
/// sandbox. Every server door that runs a row itself, not through `invoke`,
/// crosses it here. The hooks read under `reader`, capped by their grant,
/// and as `actor` when it is `None`. A rewrite must pass the row's input
/// check, then `check`, as if the caller sent it. An ask saves `resume`'s
/// credential, and its drain permit marks the chain's thread as the drain's
/// run of the call. A hook's ask runs on `turn`, the task-work turn the
/// calling operation already holds, if any.
#[expect(
    clippy::too_many_arguments,
    reason = "the row's call plus the caller's key, rewrite admission, resume and turn"
)]
pub(crate) async fn row_hooks_pre_with(
    server: &Arc<SyncServer>,
    reader: Option<ScopedReadActorKey>,
    check: Option<RewriteAdmit>,
    actor: EntityId,
    class: EdgeActorClass,
    invocation: Option<InvocationId>,
    verb: &str,
    args: serde_json::Value,
    resume: RowHookResume,
    turn: Option<Arc<oneiron::work_line::TaskWorkTurn>>,
) -> Result<VerbHookPre, MemoryError> {
    let (pre, _) = row_hooks_pre_decided(
        server, reader, check, actor, class, invocation, verb, args, resume, turn,
    )
    .await?;
    Ok(pre)
}

/// [`row_hooks_pre_with`], beside each hook `ai.verdict` decision its chain
/// answered (FIX 10425): the chain runs on a blocking thread, where only
/// this collection sees them. Record only: no ceiling is set and no
/// verdict changes.
#[expect(
    clippy::too_many_arguments,
    reason = "row_hooks_pre_with's inputs, unchanged"
)]
async fn row_hooks_pre_decided(
    server: &Arc<SyncServer>,
    reader: Option<ScopedReadActorKey>,
    check: Option<RewriteAdmit>,
    actor: EntityId,
    class: EdgeActorClass,
    invocation: Option<InvocationId>,
    verb: &str,
    args: serde_json::Value,
    resume: RowHookResume,
    turn: Option<Arc<oneiron::work_line::TaskWorkTurn>>,
) -> Result<(VerbHookPre, Vec<serde_json::Value>), MemoryError> {
    let server = Arc::clone(server);
    let verb = verb.to_owned();
    let chain = move || -> Result<VerbHookPre, MemoryError> {
        let _drain = resume.drain.as_ref().map(VerbAskDrainPermit::enter);
        let call = VerbCall {
            verb: verb.clone(),
            invocation: invocation.unwrap_or_else(InvocationId::mint),
            actor,
            class: hook_class(class),
            scope: None,
            board_epoch: None,
            domain: verb_hook_boundary::row_domain(&verb),
            reader,
        };
        oneiron::runtime_hooks::host_doors::admit_trigger(&server.vault, &verb, &args)?;
        let admit = |args: &serde_json::Value| {
            oneiron::task_verb::sdk::validate_input(&verb, args)
                .map_err(|error| error.to_string())?;
            check
                .as_ref()
                .map_or(Ok(()), |check| check(verb.as_str(), args))
        };
        let session = resume.session;
        let ended = match &session {
            Some(session) => {
                verb_hook_boundary::session_pre(&server.vault, call, args, &admit, session, turn)?
            }
            None => server.vault.pre_verb_hooks_for_credential(
                call,
                args,
                &admit,
                resume.credential,
                turn,
            )?,
        };
        let mut pre =
            ended.map_err(|stop| verb_hook_boundary::stop_refusal(stop, session.as_ref()))?;
        // A restrictive call's args that fail the row's input check give way
        // to the caller's own (FIX 5076).
        oneiron::task_verb::revoke_lands::settle(&mut pre, &|args| {
            oneiron::task_verb::sdk::validate_input(&verb, args).is_ok()
        });
        Ok(pre)
    };
    tokio::task::spawn_blocking(move || {
        let (ended, decided) = crate::hook_verdict::collect_hook_decisions(chain);
        ended.map(|pre| (pre, decided))
    })
    .await
    .map_err(|_| hooks_did_not_finish())?
}

/// The post chain over that row's result, off the async runtime: the
/// caller's view of it.
pub(crate) async fn row_hooks_post(
    server: &Arc<SyncServer>,
    pre: VerbHookPre,
    result: serde_json::Value,
) -> Result<serde_json::Value, MemoryError> {
    let (output, _) = row_hooks_post_decided(server, pre, result).await?;
    Ok(output)
}

/// [`row_hooks_post`], beside each hook `ai.verdict` decision its chain
/// answered (FIX 10425), as [`row_hooks_pre_decided`] collects them.
async fn row_hooks_post_decided(
    server: &Arc<SyncServer>,
    pre: VerbHookPre,
    result: serde_json::Value,
) -> Result<(serde_json::Value, Vec<serde_json::Value>), MemoryError> {
    let server = Arc::clone(server);
    tokio::task::spawn_blocking(move || {
        let (output, decided) = crate::hook_verdict::collect_hook_decisions(move || {
            verb_hook_boundary::row_post(&server.vault, pre, result)
        });
        output.map(|output| (output, decided))
    })
    .await
    .map_err(|_| hooks_did_not_finish())?
}

/// A row that failed after its pre chain ran (the door, its input's decode
/// or its answer's encoding): a session-only call keeps that chain's records,
/// best effort and off the async runtime, and no post chain runs (FIX 5527).
/// The caller returns its own error.
pub(crate) async fn row_hooks_abort(server: &Arc<SyncServer>, pre: VerbHookPre) {
    let server = Arc::clone(server);
    let kept = tokio::task::spawn_blocking(move || verb_hook_boundary::abort(&server.vault, pre));
    if let Err(error) = kept.await {
        tracing::warn!(%error, "a failed row's pre hook records were not kept");
    }
}

pub(super) fn hooks_did_not_finish() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        "the verb's hooks did not finish on this server",
        &["Retry; if the failure persists, report it with this request's id."],
    )
}

/// The pre chain of a row this route runs itself (ARCH-0080 §3): the args to
/// run it with. Its caller is the credential's actor; a credential bound to
/// none calls as the host, the vault's owner in person when it is
/// owner-grade. The row's door checks its own authority first, so a hook
/// never fires on a call the door refuses.
pub(super) async fn facade_hooks_pre(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    verb: &str,
    value: serde_json::Value,
) -> Result<VerbHookPre, FacadeApiError> {
    let (pre, _) = facade_hooks_pre_counted(server, call, verb, value).await?;
    Ok(pre)
}

/// [`facade_hooks_pre`], beside each hook `ai.verdict` decision the chain
/// answered (FIX 10425), for a row whose answer counts its hooks' decisions
/// among its own ([`facade_hooks_post_counted`]).
pub(super) async fn facade_hooks_pre_counted(
    server: &Arc<SyncServer>,
    call: &FacadeCall<'_>,
    verb: &str,
    value: serde_json::Value,
) -> Result<(VerbHookPre, Vec<serde_json::Value>), FacadeApiError> {
    let auth = call.auth();
    // A hosted operator's root acts as nobody (FIX 2222): no hook runs for
    // it, and its typed refusal comes before any row door's own (FIX 4371).
    super::host_action::facade_host_action(server, auth)?;
    if verb == "vault.export" {
        export_admits(server, auth)?;
    } else {
        host_doors::door_admits(server, auth, verb)?;
    }
    let bound = facade_actor(server, auth).ok();
    let (actor, class) = match bound {
        Some(actor) => actor,
        None => (
            verb_hook_boundary::host_actor().map_err(MemoryError::from)?,
            if auth.is_owner_grade() {
                EdgeActorClass::Human
            } else {
                EdgeActorClass::System
            },
        ),
    };
    let invocation = call.invocation()?;
    // A credential caller's own call can run again through this door once
    // its hook's ask settles, on the drain's permit when it does. A context
    // the row refuses saves none.
    let credential = match bound {
        Some(_) => facade_invocation(
            credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality()),
            call,
        )
        .ok()
        .and_then(|memory| memory.verb_ask_credential()),
        _ => None,
    };
    let resume = RowHookResume {
        credential,
        drain: call.drain().cloned(),
        session: hook_session::facade_hook_session(server, call, bound, verb, &value)?,
    };
    // What a hook reads, built on every call so a binding installed after
    // this door looked still finds it: the caller's read key, its
    // credential's where its connection sits (an owner-grade credential that
    // calls as the host reads as the host, its owner), and the re-admission
    // of a rewritten ref. A key that does not build fails the call only when
    // a hook may run; otherwise the call carries a key that reads nothing, so
    // a binding installed meanwhile never reads as the host.
    let reader = match bound {
        Some(_) => VerbCall::reader_of(
            &credential_memory(&server.vault, Some(auth), actor, class).at(auth.locality()),
            verb,
        )?,
        None if auth.is_owner_grade() => None,
        None => match super::scoped_read_for_core_auth(&server.vault, auth) {
            Ok(read) => Some(read.actor_key().clone()),
            Err(error) if VerbCall::may_run(&server.vault, verb) => return Err(error.into()),
            Err(error) => Some(
                ScopedReadActorKey::read_nothing(actor.to_hex(), class.gate_actor_class())
                    .ok_or(error)?
                    .at(auth.locality()),
            ),
        },
    };
    let check = Some(facade_rewrite_admit(server, auth, &value));
    // A host-door row holds no task-work turn before its pre chain.
    Ok(row_hooks_pre_decided(
        server, reader, check, actor, class, invocation, verb, value, resume, None,
    )
    .await?)
}

/// What the facade admits before a host-door row's pre chain, for a door
/// that runs the chain itself: the row door's own authority check, and
/// whole-vault export's owner admission. A hook never fires on a call the
/// row's door refuses.
pub(crate) fn row_door_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> Result<(), MemoryError> {
    if verb == "vault.export" {
        export_admits(server, auth).map_err(FacadeApiError::into_memory_error)
    } else {
        host_doors::door_admits(server, auth, verb)
    }
}

/// Whole-vault export's owner admission, as the export runs it in its own
/// snapshot: the host's root, the owner's own live slip, or a managed
/// vault's attested owner's request proof. The route has already refused a
/// credential short of owner-grade or with none of those.
pub(super) fn export_admits(server: &SyncServer, auth: &CoreAuth) -> Result<(), FacadeApiError> {
    let Some(proof) = auth.verified_slip() else {
        // The attested owner carries no slip: its request's own owner
        // proof, as the export revalidates it in its snapshot.
        if auth.managed_owner().is_some() {
            let owner = host_doors::owner_proof(auth, server, "vault.export")?;
            server.vault.admit_authenticated_owner_export(&owner)?;
        }
        return Ok(());
    };
    if proof.claims().holder_ref == "host" {
        server.vault.admit_host_owner_export(proof)?;
    } else {
        let (actor, class) = facade_actor(server, auth)?;
        server
            .vault
            .memory(actor, class)
            .at(auth.locality())
            .admit_export(Some(proof))?;
    }
    Ok(())
}

/// The post chain over that row's result: the caller's view of it.
pub(super) async fn facade_hooks_post(
    server: &Arc<SyncServer>,
    pre: VerbHookPre,
    output: serde_json::Value,
) -> Result<serde_json::Value, FacadeApiError> {
    Ok(row_hooks_post(server, pre, output).await?)
}

/// [`facade_hooks_post`] for a browser batch or library run (FIX 10425):
/// the hook decisions its pre chain answered (`decided`) and its post
/// chain's join the answer's own decisions, so a library run's
/// `model_free` reads them as its code-mode door's does (FIX 8042). Record
/// only: nothing is capped and no verdict changes.
pub(super) async fn facade_hooks_post_counted(
    server: &Arc<SyncServer>,
    pre: VerbHookPre,
    verb: &str,
    output: serde_json::Value,
    mut decided: Vec<serde_json::Value>,
) -> Result<serde_json::Value, FacadeApiError> {
    let (mut output, mut after) = row_hooks_post_decided(server, pre, output).await?;
    decided.append(&mut after);
    crate::api::mcp_gateway::count_hook_decisions(verb, &mut output, decided);
    Ok(output)
}
