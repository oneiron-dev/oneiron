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
use super::{ActionBound, FacadeRowDoor, app, engine, internal, refused};
use crate::actions::SharedActionExecutor;
use crate::auth::CoreAuth;
use crate::server::{HeldLiveRun, ResolvedLiveRun, SyncServer, seated_planner};

/// Runs `call` from the app's table under `bound`, its verb-table rows
/// through their own routes under this request's headers and connection.
pub(super) async fn execute(
    server: &Arc<SyncServer>,
    headers: HeaderMap,
    extensions: Extensions,
    bound: ActionBound,
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
        None,
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
    let ActionBound {
        actor,
        class,
        key,
        owner,
        surface,
        live_run,
    } = bound;
    let door: Arc<dyn AgentVerbDoor> = Arc::new(FacadeRowDoor::new(
        server, headers, extensions, key, credential,
    ));
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
