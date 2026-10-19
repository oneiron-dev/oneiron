//! How one action runs (OF-181): the principal its call reads as, and the
//! blocking thread it runs on with its host binding, under the live run it
//! acts for, held.
use std::sync::Arc;

use axum::http::{Extensions, HeaderMap};
use oneiron::code_run::AgentVerbDoor;
use oneiron::code_run::actions::{ActionDispatch, ActionHostBinding, AgentActionCall};
use oneiron::lens::LensPrincipalBinding;
use oneiron::{EdgeActorClass, WriteActor};

use super::super::FacadeApiError;
use super::row_door::FacadeRowDoor;
use super::{ActionBound, app, engine, internal, refused};
use crate::actions::SharedActionExecutor;
use crate::api::call_receipt::CallStamp;
use crate::auth::CoreAuth;
use crate::server::{HeldLiveRun, ResolvedLiveRun, SyncServer, seated_planner};

/// Runs `call` from the app's table under `bound`, its verb-table rows
/// through their own routes under this request's headers and connection,
/// or, given `credential`, as that caller, for an action no request carries
/// (a fold door's, as a held card's event runs).
pub(super) async fn execute(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
    credential: Option<CoreAuth>,
    call: AgentActionCall,
) -> Result<ActionDispatch, FacadeApiError> {
    let ActionBound {
        actor, class, key, ..
    } = &bound;
    let principal = match class {
        EdgeActorClass::Agent => {
            LensPrincipalBinding::agent_task(actor.to_hex(), key.clone(), vec![key.clone()])
        }
        EdgeActorClass::System => {
            LensPrincipalBinding::system_job(actor.to_hex(), key.clone(), vec![key.clone()])
        }
        EdgeActorClass::Human => {
            LensPrincipalBinding::human_view(actor.to_hex(), key.clone(), vec![key.clone()])
        }
    }
    .map_err(engine)?;
    run_bound(
        server,
        headers,
        extensions,
        bound,
        credential,
        move |executor, vault, writer, binding| {
            executor.execute_call(vault, writer, &principal, &call, binding)
        },
    )
    .await
}

/// Runs `run` on a blocking thread with the app's table, the vault, the
/// actor `bound` writes as, and its host binding: the verb door over this
/// request and the credential's read key, and the owner's proof.
pub(super) async fn run_bound<F>(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
    credential: Option<CoreAuth>,
    run: F,
) -> Result<ActionDispatch, FacadeApiError>
where
    F: FnOnce(
            &SharedActionExecutor,
            &oneiron::Vault,
            WriteActor,
            ActionHostBinding<'_>,
        ) -> oneiron::Result<ActionDispatch>
        + Send
        + 'static,
{
    run_bound_stamped(server, headers, extensions, bound, credential, run)
        .await
        .0
}

/// [`run_bound`], and beside its dispatch what its verb-table row's reply
/// stated of its call receipt (FIX 2887): recorded, no-record or
/// unrecorded, on the row's success and its refusal alike. Unrecorded when
/// no row ran through the door's route: a typed action, a run row, a
/// refusal before the row, or a row the credential's own facade call ran.
pub(super) async fn run_bound_stamped<F>(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
    credential: Option<CoreAuth>,
    run: F,
) -> (Result<ActionDispatch, FacadeApiError>, CallStamp)
where
    F: FnOnce(
            &SharedActionExecutor,
            &oneiron::Vault,
            WriteActor,
            ActionHostBinding<'_>,
        ) -> oneiron::Result<ActionDispatch>
        + Send
        + 'static,
{
    let ActionBound {
        actor,
        class,
        key,
        owner,
        surface,
        live_run,
    } = bound;
    let door = Arc::new(FacadeRowDoor::new(
        server, headers, extensions, key, credential,
    ));
    let verb_door: Arc<dyn AgentVerbDoor> = Arc::clone(&door) as Arc<dyn AgentVerbDoor>;
    let bound = Unbound {
        actor,
        class,
        owner,
        surface,
        live_run,
    };
    let ran = run_with_door(server, verb_door, bound, run).await;
    (ran, door.stamp())
}

/// What an action runs under once its read key went to its verb door.
struct Unbound {
    actor: oneiron::EntityId,
    class: EdgeActorClass,
    owner: Option<oneiron::consent::AuthenticatedOwner>,
    surface: Option<oneiron::authority::ActSurface>,
    live_run: Option<ResolvedLiveRun>,
}

async fn run_with_door<F>(
    server: &Arc<SyncServer>,
    door: Arc<dyn AgentVerbDoor>,
    bound: Unbound,
    run: F,
) -> Result<ActionDispatch, FacadeApiError>
where
    F: FnOnce(
            &SharedActionExecutor,
            &oneiron::Vault,
            WriteActor,
            ActionHostBinding<'_>,
        ) -> oneiron::Result<ActionDispatch>
        + Send
        + 'static,
{
    let Unbound {
        actor,
        class,
        owner,
        surface,
        live_run,
    } = bound;
    let executor = app()?;
    // OF-181: the live run's guard, waited for briefly while an entry or
    // another action holds it, taken before the action and held through it,
    // with the run's lease read again under it.
    let held = match &live_run {
        Some(run) => Some(
            run.hold(&server.live_runs, &server.vault)
                .await
                .map_err(engine)?
                .map_err(refused)?,
        ),
        None => None,
    };
    let host = Arc::clone(server);
    let vault = Arc::clone(&server.vault);
    tokio::task::spawn_blocking(move || {
        // OF-181: an action for a live run plans its leader rows as the
        // run's own entries do, on the host's ladder.
        let mut planner = match live_run.as_ref().map(ResolvedLiveRun::planner) {
            Some((Some(settings), model)) => seated_planner(
                &vault,
                settings,
                model,
                host.decision_host().host_planner_decisions(actor),
            )
            .map_err(oneiron::Error::InvalidConfig)?,
            _ => None,
        };
        // DOOR-111 S4c-4: its planned team's start is written on the run's
        // own seat and line, as its entries' are.
        if let (Some(planner), Some(live)) = (&mut planner, &live_run) {
            planner.pattern_runner = live.pattern_runner(&host);
        }
        let binding = ActionHostBinding {
            verb_door: Some(door),
            owner: owner.as_ref(),
            owner_surface: surface,
            live_run: held.as_ref().map(HeldLiveRun::proof),
            planner,
        };
        run(executor, &vault, WriteActor::new(actor, class), binding)
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)
}
