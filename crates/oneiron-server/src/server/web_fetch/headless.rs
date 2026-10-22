//! The host's headless browser rung (FIX 7122): one fresh browser guest per
//! render, from the host's `[browser]` guest, with every request and every
//! connection of the render in the host's custody. On a managed node a
//! render checks each request its pages make, every redirect hop and
//! subresource included ([`handler`], FIX 7332), and each connection and
//! datagram its guest opens off its own session, a page WebSocket's and a
//! worker's included ([`relay`], FIX 7333), by the address it goes to, with
//! the hosted egress guard the fetch hands the render. It refuses only what
//! that guard refuses, by the guard's own reason: hosted infrastructure, or
//! a private network (FIX 7657), which a page's request may reach at an
//! operator's private origin and a relayed connection never does, as the
//! relay knows only an address. The guest's own loopback (the Lightpanda
//! debugger's socket among it) never reaches the relay, and the guest's DNS
//! goes to the host's resolvers, which are no page's destination.
//!
//! A render ends its guest before it answers: once the page is read it
//! stops taking new work, cancels the requests still in flight, drops the
//! session, which removes the guest, and waits until every piece of its work
//! has returned. No request of a render runs after its answer. A refusal any
//! of its work gave answers the render, whatever the page showed, and so
//! ends the fetch's ladder.
//!
//! A render's guest start moves the server's browser readiness (FIX 7670):
//! a start that stops, by the phase it stopped at, and a guest whose driver
//! attached. What the page does after that moves nothing.

mod handler;
mod relay;

use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use oneiron::Vault;
use oneiron::code_sandbox::SandboxGuestTier;
use oneiron::code_sandbox::egress::EgressConfig;
use oneiron::code_sandbox::microvm::select_backend_for_session;
use oneiron::web_fetch::{
    HeadlessDocument, HeadlessRenderer, HostedEgressGuard, HostedEgressRefusal, RendererError,
    RendererResult,
};
use oneiron_browser::{
    BrowserDriver as _, BrowserError, BrowserGuest, BrowserRequestHandler, BrowserSession,
    DestinationRefusal, HandleRetention, OpenInput, RenderedDocument,
};
use oneiron_container::{EgressRelay, GuestSeccomp, GuestSpec, ImageRef};
use oneiron_vault_contract::BrowserUnavailableReason;
use reqwest::Url;
use tokio::sync::watch;

use self::handler::PageRequests;
use self::relay::HeadlessRelay;
use crate::config::browser::BrowserReadinessCell;
use crate::server::HandleLine;

/// The host's headless browser for the fetch ladder's second rung: each
/// render starts its own guest from `guest`, charges its live handles to
/// `handles`, and charges its guest's network work to the floor `vault`'s
/// host lent. Each guest start moves `readiness`.
pub(super) struct GuestHeadless {
    guest: BrowserGuest,
    handles: HandleLine,
    vault: Arc<Vault>,
    readiness: BrowserReadinessCell,
}

impl GuestHeadless {
    pub(super) fn new(
        guest: BrowserGuest,
        handles: HandleLine,
        vault: Arc<Vault>,
        readiness: BrowserReadinessCell,
    ) -> Self {
        Self {
            guest,
            handles,
            vault,
            readiness,
        }
    }

    /// One render of `url`, checked with `guard` where the fetch gave one.
    fn render(
        &self,
        url: &str,
        guard: Option<Arc<HostedEgressGuard>>,
    ) -> RendererResult<HeadlessDocument> {
        let operation = Arc::new(Operation::new(guard));
        let read = self.read(url, &operation);
        // The guest is gone: nothing of the render starts again, and what
        // it had in flight returns before the render answers.
        operation.end();
        operation.settle();
        if let Err(BrowserError::DestinationRefused(refused)) = &read {
            operation.refuse(destination_refusal(refused));
        }
        if let Some(refused) = operation.refusal() {
            return Err(refused);
        }
        let document = read.map_err(|error| {
            RendererError::transport(format!("the headless browser failed: {error}"))
        })?;
        // The browser names no status where it knows none; none is invented.
        let status = document.status.ok_or_else(|| {
            RendererError::invalid_response("the headless browser knows no status for the page")
        })?;
        Ok(HeadlessDocument {
            html: document.html,
            final_url: document.final_url,
            status,
        })
    }

    /// Reads `url` on a fresh guest whose network `operation` keeps, then
    /// ends that guest: the page is opened, then read as it renders, and a
    /// refusal the session still holds is kept for the render.
    fn read(
        &self,
        url: &str,
        operation: &Arc<Operation>,
    ) -> Result<RenderedDocument, BrowserError> {
        // The server's runtime drives the render's requests; every fetch
        // door renders on its blocking pool, which carries it.
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            BrowserError::Unavailable("the headless browser runs on the server's runtime".into())
        })?;
        let requests = PageRequests::new(Arc::clone(operation), runtime).map_err(|error| {
            BrowserError::Unavailable(format!("the page request client did not build: {error}"))
        })?;
        let requests = Arc::new(requests);
        let relay: Arc<dyn EgressRelay> = Arc::new(HeadlessRelay::new(
            Arc::clone(operation),
            Arc::clone(&requests),
            Arc::clone(&self.vault),
            self.guest.wait_cap,
        ));
        // A guarded render's pages take its handler; an unguarded one's take
        // the relay, which performs them the same way, unchecked.
        let handler: Option<Arc<dyn BrowserRequestHandler>> = if operation.guard.is_some() {
            Some(requests)
        } else {
            None
        };
        let mut session = start_guest(
            &self.guest,
            relay,
            self.handles.charge(),
            handler,
            &self.readiness,
        )?;
        let read = session
            .open(OpenInput {
                url: url.to_owned(),
            })
            .and_then(|_| session.document());
        if let Some(refused) = session.take_destination_refusal() {
            operation.refuse(destination_refusal(&refused));
        }
        // The page is read: nothing new of the render starts from here, its
        // requests in flight are cancelled, and dropping the session removes
        // its guest.
        operation.end();
        drop(session);
        read
    }
}

impl HeadlessRenderer for GuestHeadless {
    /// Unchecked: the guest's requests and connections go where they ask.
    /// Only a managed node installs this rung, and its fetch renders guarded.
    fn render_html(&self, url: &str) -> RendererResult<HeadlessDocument> {
        self.render(url, None)
    }

    /// Checked with the managed node's `guard`, as the fetch handed it.
    fn render_html_guarded(
        &self,
        url: &str,
        guard: &HostedEgressGuard,
    ) -> RendererResult<HeadlessDocument> {
        self.render(url, Some(Arc::new(guard.clone())))
    }
}

/// The rung error a browser's destination refusal stands for: the guard
/// refusal its reason names exactly (FIX 7657); a reason that names neither
/// stays the hosted-infrastructure refusal every one was before.
fn destination_refusal(refused: &DestinationRefusal) -> RendererError {
    let reason = HostedEgressRefusal::from_reason(&refused.reason)
        .unwrap_or(HostedEgressRefusal::Infrastructure);
    RendererError::hosted(reason, refused.message.clone())
}

/// Starts one render's guest from the host's pinned image through the
/// engine's tier selector, as a code run's guest starts, behind `relay`,
/// and attaches it: with no starter, as one render switches no engine, and
/// with `requests` where the render is guarded. The guest mounts no fixture.
/// Each phase's outcome moves `readiness`.
fn start_guest(
    guest: &BrowserGuest,
    relay: Arc<dyn EgressRelay>,
    retention: Box<dyn HandleRetention>,
    requests: Option<Arc<dyn BrowserRequestHandler>>,
    readiness: &BrowserReadinessCell,
) -> Result<BrowserSession, BrowserError> {
    let backend = select_backend_for_session(
        SandboxGuestTier::Untrusted,
        guest.runtime.clone(),
        &guest.image,
    )
    .inspect_err(|_| readiness.unavailable(BrowserUnavailableReason::SandboxUnavailable))
    .map_err(|error| BrowserError::Unavailable(error.to_string()))?;
    let spec = GuestSpec {
        image: ImageRef::pinned(&guest.image)
            .inspect_err(|_| readiness.unavailable(BrowserUnavailableReason::GuestStartFailed))
            .map_err(|error| BrowserError::Unavailable(error.to_string()))?,
        user: (10001, 10001),
        limits: guest.limits,
        seccomp: GuestSeccomp::EngineFence,
        read_only_mounts: Vec::new(),
    };
    // The guest's browser takes the CDP messages a run's egress door would
    // hand it (FIX 6815). A render's requests cross no such door, so an
    // unreadable egress file costs it nothing: the door's default stands.
    let egress = EgressConfig::from_env().unwrap_or_default();
    let command = guest.engine.guest_argv(egress.max_response_bytes);
    let transport = backend
        .start_session(&spec, &command, Arc::clone(&relay))
        .inspect_err(|_| readiness.unavailable(BrowserUnavailableReason::GuestStartFailed))
        .map_err(|error| BrowserError::Unavailable(error.to_string()))?;
    BrowserSession::attach(guest, transport, relay, retention, None, requests)
        .inspect(|session| readiness.started(session.manifest()))
        .inspect_err(|_| readiness.unavailable(BrowserUnavailableReason::DriverAttachFailed))
}

/// One render's custody of its guest's network, shared by its request
/// handler and its relay: the managed node's guard (none on an unguarded
/// render), the first refusal either gave, and the work they have in flight.
struct Operation {
    guard: Option<Arc<HostedEgressGuard>>,
    refused: Mutex<Option<RendererError>>,
    work: Mutex<Work>,
    settled: Condvar,
    /// Turns true when the render ends, which cancels its requests in flight.
    stop: watch::Sender<bool>,
}

/// How much of a render's work is in flight, and whether the render ended.
#[derive(Default)]
struct Work {
    running: usize,
    ended: bool,
}

/// One piece of a render's work in flight; it has returned once dropped.
#[must_use = "the work counts as in flight only while this is held"]
struct Running<'a>(&'a Operation);

impl Operation {
    fn new(guard: Option<Arc<HostedEgressGuard>>) -> Self {
        Self {
            guard,
            refused: Mutex::default(),
            work: Mutex::default(),
            settled: Condvar::new(),
            stop: watch::Sender::new(false),
        }
    }

    /// Starts one piece of the render's work; none once the render ended.
    fn begin(&self) -> Option<Running<'_>> {
        let mut work = lock(&self.work);
        if work.ended {
            return None;
        }
        work.running += 1;
        Some(Running(self))
    }

    /// Whether the render ended.
    fn ended(&self) -> bool {
        lock(&self.work).ended
    }

    /// What turns true when the render ends.
    fn stopped(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// Refuses the request or connection `destination` names, about to go
    /// to `ip`, when the render's guard refuses that address, and keeps the
    /// refusal for the render first. No operator origin admits an address
    /// here. An unguarded render refuses nothing.
    fn check(&self, destination: &str, ip: IpAddr) -> Result<(), HostedEgressRefusal> {
        self.judge(destination, |guard| guard.refuses(ip))
    }

    /// Refuses a request to `url`, a named host, when its host is an
    /// operator's private origin name at a scheme and port no origin lists
    /// (FIX 7657), as [`Self::check`] refuses; its resolver judges the
    /// addresses.
    fn check_origin(&self, url: &Url) -> Result<(), HostedEgressRefusal> {
        self.judge(url.as_str(), |guard| guard.refuses_origin(url))
    }

    /// The render's guard's verdict on `destination`, `refuses` asked of it,
    /// with a refusal kept for the render first.
    fn judge(
        &self,
        destination: &str,
        refuses: impl FnOnce(&HostedEgressGuard) -> Option<HostedEgressRefusal>,
    ) -> Result<(), HostedEgressRefusal> {
        let Some(refused) = self.guard.as_deref().and_then(refuses) else {
            return Ok(());
        };
        self.refuse(refused.request_error(destination));
        Err(refused)
    }

    /// Keeps `refused` for the render, unless it keeps one already.
    fn refuse(&self, refused: RendererError) {
        lock(&self.refused).get_or_insert(refused);
    }

    /// Ends the render: no new work starts, and its requests in flight are
    /// cancelled.
    fn end(&self) {
        lock(&self.work).ended = true;
        self.stop.send_modify(|stop| *stop = true);
    }

    /// Waits until every piece of the render's work in flight has returned.
    fn settle(&self) {
        let mut work = lock(&self.work);
        while work.running > 0 {
            work = self
                .settled
                .wait(work)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// The first refusal the render's work gave, taken.
    fn refusal(&self) -> Option<RendererError> {
        lock(&self.refused).take()
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut work = lock(&self.0.work);
        work.running -= 1;
        if work.running == 0 {
            self.0.settled.notify_all();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
