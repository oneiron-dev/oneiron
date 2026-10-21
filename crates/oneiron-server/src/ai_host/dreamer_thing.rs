//! The served thing-child host (FIX 7508): what this server lends a thing
//! branch's scoped code-mode agent.
//!
//! It lends the agent this server's code host (its verified runtime, its
//! provider and the reader runner that runs every reader child) and one
//! profile per child: its own generation on the Dreamer's extraction route,
//! admitted on the parent attempt's own wake guard (never the code-mode
//! meter), counted so its parent charges it once, and two ports served on
//! its parent's own wake. The loan, the lent clock and the borrowed lease
//! are the substrate's (`ScopedChildLoan::from_parent`,
//! `reader_parent_for_wake`, `ReaderSeats::seat_with_parent`); nothing here
//! makes a second clock, queue or store.

mod ports;
mod profile;

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Weak};

use oneiron::claim::CallerLocality;
use oneiron::code_run::{
    HostSelfDispatcher, ReaderJobs, ScopedChildLoan, ScopedChildProfile, ScopedChildSpec,
    ScopedChildStop, scoped_child_task,
};
use oneiron::dreamer_consolidation::{
    THING_CHILD_LOAN_REFUSED, THING_CHILD_RUNTIME_UNBOUND, THING_CHILD_SPAWN_REFUSED,
    ThingChildHost, ThingChildLaunch, ThingChildStart,
};
use oneiron::{ModelId, ModelLocality, Vault};

use self::ports::ThingChildPorts;
use self::profile::{CountedBackend, ThingSession};
use super::dreamer::QuestionTimer;
use super::scoped_child::{enqueue_scoped_child, reader_parent_for_wake};
use crate::mcp::McpCodeModeProvider;
use crate::models::{ModelRuntime, OfferLadder, RunBackend};
use crate::server::SyncServer;

/// The run an agent's own generation is admitted under, on its parent's
/// guard.
const THING_CHILD_RUN: &str = "dreamer-pass/thing-child";

/// The extraction route an agent generates on: its ladder, model, locality
/// and input window.
pub(super) struct ThingRoute {
    pub(super) ladder: Arc<OfferLadder>,
    pub(super) model: ModelId,
    pub(super) locality: ModelLocality,
    pub(super) window: Option<u64>,
}

/// The host a Dreamer pass lends its thing branches.
pub(super) struct ServedThingChildHost {
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
    server: QuestionTimer,
    route: ThingRoute,
}

impl ServedThingChildHost {
    pub(super) fn new(
        vault: Arc<Vault>,
        runtime: Arc<ModelRuntime>,
        server: QuestionTimer,
        route: ThingRoute,
    ) -> Self {
        Self {
            vault,
            runtime,
            server,
            route,
        }
    }

    /// The bound server and its code host's provider, when the server runs
    /// a verified runtime whose provider keeps scoped profiles.
    fn bound(&self) -> Result<(Arc<SyncServer>, Arc<dyn McpCodeModeProvider>), &'static str> {
        let server = self
            .server
            .get()
            .and_then(Weak::upgrade)
            .ok_or(THING_CHILD_RUNTIME_UNBOUND)?;
        let provider = server
            .mcp_code_host
            .as_ref()
            .and_then(|host| host.engine_native())
            .map(|native| Arc::clone(native.provider()))
            .filter(|provider| {
                provider.production_runtime_available() && provider.scoped_child_hosts().is_some()
            })
            .ok_or(THING_CHILD_RUNTIME_UNBOUND)?;
        Ok((server, provider))
    }
}

impl ThingChildHost for ServedThingChildHost {
    fn window_tokens(&self) -> Option<u64> {
        self.route.window
    }

    fn unavailable(&self) -> Option<&'static str> {
        self.bound().err()
    }

    fn launch(&self, launch: ThingChildLaunch<'_, '_>) -> oneiron::Result<ThingChildStart> {
        let (server, provider) = match self.bound() {
            Ok(bound) => bound,
            Err(reason) => return Ok(ThingChildStart::Unavailable(reason)),
        };
        let ThingChildLaunch {
            ctx,
            leased,
            guard,
            actor,
            parent_run,
            inputs,
            bound,
            scope,
            ports,
            intent_key,
            ask,
        } = launch;
        let vault = ctx.vault;
        let Some(hosts) = provider
            .scoped_child_hosts()
            .filter(|_| std::ptr::eq(self.vault.as_ref(), vault))
        else {
            return Ok(ThingChildStart::Unavailable(THING_CHILD_RUNTIME_UNBOUND));
        };
        let dispatcher = HostSelfDispatcher::new(vault, actor, parent_run.to_hex())?;
        let spec = ScopedChildSpec {
            inputs,
            scope,
            ports: ports.clone(),
        };
        let loan = match ScopedChildLoan::from_parent(
            vault,
            &dispatcher,
            parent_run,
            &bound,
            &ports,
            spec,
        )? {
            Ok(loan) => loan,
            Err(code) => return Ok(not_launched(THING_CHILD_LOAN_REFUSED, code)),
        };
        // The wake's live clock and the attempt's lease, lent once (FIX 8231,
        // 8506); the lent ports are the two the parent itself serves (8232).
        let parent = match reader_parent_for_wake(ctx, leased, parent_run, loan, &ports)? {
            Ok(parent) => parent,
            Err(code) => return Ok(not_launched(THING_CHILD_LOAN_REFUSED, code)),
        };
        let Some(loan) = parent.loan() else {
            return Ok(ThingChildStart::Unavailable(THING_CHILD_LOAN_REFUSED));
        };
        let seat = server.reader_runner.seats().seat_with_parent(
            parent_run,
            None,
            CallerLocality::OnDevice,
            self.route.window,
            Some(&parent),
        );
        let task = scoped_child_task(parent_run, &intent_key)?;
        let (calls, received) = tokio::sync::mpsc::unbounded_channel();
        let stop = ScopedChildStop::default();
        let units = Arc::new(AtomicU64::new(0));
        let run = self.runtime.undeclared_run(THING_CHILD_RUN, guard.clone());
        let backend = CountedBackend::new(
            RunBackend::new(Arc::clone(&self.route.ladder), run),
            Arc::clone(&units),
            stop.clone(),
        );
        // Registered before the child is queued: the runner may claim it at
        // once, and a child it claims runs on this profile.
        hosts.register(
            task,
            ScopedChildProfile {
                backend: Arc::new(backend),
                guard: guard.clone(),
                model: self.route.model.clone(),
                locality: self.route.locality,
                ports: Arc::new(ThingChildPorts::new(
                    calls,
                    stop.clone(),
                    seat.deadline.child_cutoff(),
                )),
                stop: stop.clone(),
            },
        );
        let mut session = ThingSession::new(
            Arc::clone(&self.vault),
            Arc::clone(&provider),
            task,
            parent_run,
            received,
            stop,
            units,
        );
        let queued = enqueue_scoped_child(
            &ReaderJobs::canonical(vault),
            &seat,
            loan,
            &intent_key,
            ask,
            unix_millis_now(),
        )?;
        match queued {
            Ok(receipt) => {
                session.bind_run(receipt.run);
                Ok(ThingChildStart::Launched(Box::new(session)))
            }
            // The session's drop forgets the profile.
            Err(code) => Ok(not_launched(THING_CHILD_SPAWN_REFUSED, code)),
        }
    }
}

/// A launch the substrate refused with `code`: the branch stays on today's
/// path for `reason`.
fn not_launched(reason: &'static str, code: &'static str) -> ThingChildStart {
    tracing::info!(reason, code, "a thing branch's agent was not launched");
    ThingChildStart::Unavailable(reason)
}

/// The wall clock in unix milliseconds, as reader rows keep their times.
fn unix_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
