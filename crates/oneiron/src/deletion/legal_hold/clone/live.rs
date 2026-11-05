//! Exact HOST order standing for a live entry, independent of any one socket.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

use oneiron_crypto::{HybridPublicKey, legal_clone::SourceComponent};
use oneiron_vault_contract::host_legal::{
    CaptureExtent, CaptureRequest, CaptureScope, CaptureSource, FrameHeader, FrameKind,
    LiveSessionTarget, ReleaseLiveOrder,
};

use crate::error::Result;
use crate::off_record::PublishedSessionSpill;
use crate::{EntityId, Vault};

use super::collector::Collector;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OrderKey {
    order: [u8; 16],
    generation: u64,
    target: LiveSessionTarget,
}

#[derive(Default)]
struct Registry {
    orders: BTreeMap<OrderKey, Arc<LiveOrder>>,
    released: BTreeSet<([u8; 16], u64)>,
}

/// In memory only, owned by this Vault's managed legal service. No raw source
/// bytes, private key, ordinary hold or process-global state is kept here.
#[derive(Default)]
pub(crate) struct HostLegalCaptures {
    registry: Mutex<Registry>,
    stopped: AtomicBool,
}

struct LiveOrder {
    key: OrderKey,
    ends_at: u64,
    recipient: Vec<u8>,
    attempts: Mutex<Vec<Weak<Attempt>>>,
}

struct Attempt {
    request: CaptureRequest,
    public: HybridPublicKey,
    shutdown: UnixStream,
    cancelled: AtomicBool,
    state: Mutex<AttemptState>,
    changed: Condvar,
}

struct AttemptState {
    stream: Option<UnixStream>,
    ready: bool,
    capturing: bool,
    outcome: Option<std::result::Result<(), io::ErrorKind>>,
}

impl Attempt {
    fn new(request: CaptureRequest, public: HybridPublicKey, stream: UnixStream) -> Result<Self> {
        Ok(Self {
            request,
            public,
            shutdown: stream.try_clone()?,
            cancelled: AtomicBool::new(false),
            state: Mutex::new(AttemptState {
                stream: Some(stream),
                ready: false,
                capturing: false,
                outcome: None,
            }),
            changed: Condvar::new(),
        })
    }

    fn pending(&self) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        if self.cancelled.load(Ordering::Acquire) {
            return Err(interrupted().into());
        }
        let digest = self.request.digest()?;
        let stream = state.stream.as_mut().ok_or_else(interrupted)?;
        let outcome = (|| -> io::Result<()> {
            stream.write_all(
                &FrameHeader {
                    kind: FrameKind::Pending,
                    member: 0,
                    part: 0,
                    len: digest.len() as u64,
                }
                .bytes(),
            )?;
            stream.write_all(&digest)?;
            stream.flush()
        })();
        state.ready = true;
        if let Err(error) = outcome {
            state.stream.take();
            state.outcome = Some(Err(error.kind()));
            self.changed.notify_all();
            return Err(error.into());
        }
        self.changed.notify_all();
        Ok(())
    }

    fn check(&self, vault: &Vault) -> Result<()> {
        super::check(vault, &self.request, &self.cancelled)
    }

    fn wait(&self, vault: &Vault) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        loop {
            if let Some(outcome) = state.outcome {
                return outcome.map_err(|kind| {
                    io::Error::new(kind, "live legal capture did not finish").into()
                });
            }
            let remaining = self
                .request
                .ends_at
                .saturating_sub(vault.store.clock.now_recorded_at());
            if remaining == 0 {
                drop(state);
                self.cancel(io::ErrorKind::TimedOut)?;
                state = self.state.lock().map_err(|_| poisoned())?;
                // A capturing caller owns the source pin. Cancellation interrupts
                // its socket, but only its completion releases this worker.
                while state.capturing && state.outcome.is_none() {
                    state = self.changed.wait(state).map_err(|_| poisoned())?;
                }
                continue;
            }
            state = self
                .changed
                .wait_timeout(state, Duration::from_secs(remaining))
                .map_err(|_| poisoned())?
                .0;
        }
    }

    fn start(self: &Arc<Self>, vault: &Vault) -> Result<CaptureAttempt> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        while !state.ready && state.outcome.is_none() {
            self.check(vault)?;
            let remaining = self
                .request
                .ends_at
                .saturating_sub(vault.store.clock.now_recorded_at());
            state = self
                .changed
                .wait_timeout(state, Duration::from_secs(remaining))
                .map_err(|_| poisoned())?
                .0;
        }
        self.check(vault)?;
        if state.outcome.is_some() || state.capturing {
            return Err(interrupted().into());
        }
        let stream = state.stream.take().ok_or_else(interrupted)?;
        state.capturing = true;
        Ok(CaptureAttempt {
            attempt: Arc::clone(self),
            stream,
            finished: false,
        })
    }

    fn cancel(&self, kind: io::ErrorKind) -> Result<()> {
        self.cancelled.store(true, Ordering::Release);
        let _ = self.shutdown.shutdown(Shutdown::Both);
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        if !state.capturing && state.outcome.is_none() {
            state.stream.take();
            state.outcome = Some(Err(kind));
        }
        self.changed.notify_all();
        Ok(())
    }
}

struct CaptureAttempt {
    attempt: Arc<Attempt>,
    stream: UnixStream,
    finished: bool,
}

impl CaptureAttempt {
    fn finish(&mut self, outcome: &Result<()>) -> Result<()> {
        let mut state = self.attempt.state.lock().map_err(|_| poisoned())?;
        state.capturing = false;
        state.outcome = Some(if outcome.is_ok() {
            Ok(())
        } else {
            Err(io::ErrorKind::Other)
        });
        self.finished = true;
        self.attempt.changed.notify_all();
        Ok(())
    }
}

impl Drop for CaptureAttempt {
    fn drop(&mut self) {
        if !self.finished
            && let Ok(mut state) = self.attempt.state.lock()
        {
            state.capturing = false;
            state.outcome = Some(Err(io::ErrorKind::Interrupted));
            self.attempt.changed.notify_all();
        }
    }
}

impl LiveOrder {
    fn attach(&self, attempt: &Arc<Attempt>) -> Result<()> {
        if self.ends_at != attempt.request.ends_at || self.recipient != attempt.request.recipient {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "live legal order standing changed",
            )
            .into());
        }
        let mut attempts = self.attempts.lock().map_err(|_| poisoned())?;
        for previous in attempts.iter().filter_map(Weak::upgrade) {
            previous.cancel(io::ErrorKind::Interrupted)?;
        }
        attempts.retain(|previous| previous.strong_count() != 0);
        attempts.push(Arc::downgrade(attempt));
        Ok(())
    }

    fn attempts(&self) -> Result<Vec<Arc<Attempt>>> {
        Ok(self
            .attempts
            .lock()
            .map_err(|_| poisoned())?
            .iter()
            .filter_map(Weak::upgrade)
            .collect())
    }

    fn current_attempt(&self) -> Result<Arc<Attempt>> {
        for attempt in self.attempts()?.into_iter().rev() {
            if !attempt.cancelled.load(Ordering::Acquire)
                && attempt
                    .state
                    .lock()
                    .map_err(|_| poisoned())?
                    .outcome
                    .is_none()
            {
                return Ok(attempt);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "live legal order awaits HOST retry",
        )
        .into())
    }
}

impl HostLegalCaptures {
    fn register(&self, vault: &Vault, attempt: &Arc<Attempt>) -> Result<()> {
        let CaptureScope::LiveSession(target) = &attempt.request.scope else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "live legal target").into());
        };
        let key = OrderKey {
            order: attempt.request.order,
            generation: attempt.request.generation,
            target: target.clone(),
        };
        let attach = || -> Result<()> {
            let mut registry = self.registry.lock().map_err(|_| poisoned())?;
            if self.stopped.load(Ordering::Acquire)
                || registry.released.contains(&(key.order, key.generation))
            {
                return Err(interrupted().into());
            }
            let order = registry.orders.entry(key.clone()).or_insert_with(|| {
                Arc::new(LiveOrder {
                    key: key.clone(),
                    ends_at: attempt.request.ends_at,
                    recipient: attempt.request.recipient.clone(),
                    attempts: Mutex::new(Vec::new()),
                })
            });
            order.attach(attempt)
        };
        // An already admitted exact standing may reconnect to its closing,
        // retained source. A new order must linearize with closing publication.
        {
            let registry = self.registry.lock().map_err(|_| poisoned())?;
            if let Some(order) = registry.orders.get(&key) {
                if self.stopped.load(Ordering::Acquire) {
                    return Err(interrupted().into());
                }
                return order.attach(attempt);
            }
        }
        vault.with_live_spill_target(
            &target.session_ref,
            EntityId::from_bytes(target.instance)?,
            attach,
        )
    }

    fn release(&self, vault: &Vault, release: &ReleaseLiveOrder) -> Result<()> {
        let orders = {
            let mut registry = self.registry.lock().map_err(|_| poisoned())?;
            registry
                .released
                .insert((release.order, release.generation));
            let keys: Vec<_> = registry
                .orders
                .keys()
                .filter(|key| key.order == release.order && key.generation == release.generation)
                .cloned()
                .collect();
            keys.into_iter()
                .filter_map(|key| registry.orders.remove(&key))
                .collect::<Vec<_>>()
        };
        let mut attempts = Vec::new();
        for order in orders {
            attempts.extend(order.attempts()?);
        }
        for attempt in &attempts {
            attempt.cancel(io::ErrorKind::Interrupted)?;
        }
        for attempt in &attempts {
            let _ = attempt.wait(vault);
        }
        Ok(())
    }

    fn stop(&self) -> Result<()> {
        self.stopped.store(true, Ordering::Release);
        let orders: Vec<_> = self
            .registry
            .lock()
            .map_err(|_| poisoned())?
            .orders
            .values()
            .cloned()
            .collect();
        let mut attempts = Vec::new();
        for order in orders {
            attempts.extend(order.attempts()?);
        }
        for attempt in attempts {
            attempt.cancel(io::ErrorKind::Interrupted)?;
        }
        Ok(())
    }
}

impl super::HostLegalConnection {
    pub(super) fn run_live(
        self,
        vault: &Vault,
        request: CaptureRequest,
        public: HybridPublicKey,
    ) -> Result<()> {
        let attempt = Arc::new(Attempt::new(request, public, self.stream)?);
        vault.host_legal_captures.register(vault, &attempt)?;
        attempt.pending()?;
        attempt.wait(vault)
    }

    pub(super) fn release_live(mut self, vault: &Vault, release: ReleaseLiveOrder) -> Result<()> {
        EntityId::from_bytes(release.order)?;
        if release.source_vault != *vault.vault_id().as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "legal release source identity",
            )
            .into());
        }
        vault.host_legal_captures.release(vault, &release)?;
        let digest = release.digest()?;
        self.stream.write_all(
            &FrameHeader {
                kind: FrameKind::Released,
                member: 0,
                part: 0,
                len: digest.len() as u64,
            }
            .bytes(),
        )?;
        self.stream.write_all(&digest)?;
        self.stream.flush()?;
        Ok(())
    }
}

/// Only the authenticated native registry constructs this close-side handle.
/// A failed socket does not remove its actual order standing.
pub(crate) struct LiveSpillCaptures {
    orders: Vec<Arc<LiveOrder>>,
}

impl Vault {
    pub(crate) fn pending_live_spill_captures(
        &self,
        session_ref: &str,
        instance: EntityId,
    ) -> Result<Option<LiveSpillCaptures>> {
        let target = LiveSessionTarget {
            session_ref: session_ref.to_owned(),
            instance: instance.as_bytes(),
        };
        let now = self.store.clock.now_recorded_at();
        let mut registry = self
            .host_legal_captures
            .registry
            .lock()
            .map_err(|_| poisoned())?;
        registry.orders.retain(|_, order| order.ends_at > now);
        let orders: Vec<_> = registry
            .orders
            .values()
            .filter(|order| order.key.target == target)
            .cloned()
            .collect();
        Ok((!orders.is_empty()).then_some(LiveSpillCaptures { orders }))
    }

    /// Managed teardown calls this before shutting down ALL accepted sockets
    /// and joining ALL workers. Stop is not legal release or key destruction.
    pub fn stop_pending_host_legal_captures(&self) -> Result<()> {
        self.host_legal_captures.stop()
    }
}

impl LiveSpillCaptures {
    pub(crate) fn capture(&self, vault: &Vault, source: &PublishedSessionSpill) -> Result<()> {
        let identity = source.identity();
        for order in &self.orders {
            if order.ends_at <= vault.store.clock.now_recorded_at() {
                continue;
            }
            if identity.source_vault() != vault.vault_id()
                || identity.session_ref() != order.key.target.session_ref
                || identity.instance().as_bytes() != order.key.target.instance
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "live legal source identity",
                )
                .into());
            }
            let attempt = order.current_attempt()?;
            let mut capture = attempt.start(vault)?;
            let outcome = (|| -> Result<()> {
                attempt.check(vault)?;
                let mut collector =
                    Collector::pinned(&mut capture.stream, &attempt.public, &attempt.request)?;
                source.for_each_published_body(|key, file_row, reference, reader| {
                    attempt.check(vault)?;
                    let source = CaptureSource::LiveSession(order.key.target.clone());
                    let revision = *blake3::hash(file_row).as_bytes();
                    collector.component(
                        SourceComponent::LiveSessionMetadata,
                        source.clone(),
                        "off-record.raw-output.file",
                        key,
                        revision,
                        file_row.len() as u64,
                        revision,
                        &mut &file_row[..],
                        || attempt.check(vault),
                    )?;
                    collector.component(
                        SourceComponent::LiveSessionBody,
                        source,
                        "off-record.raw-output.body",
                        key,
                        revision,
                        reference.raw_len,
                        reference.raw_blake3,
                        reader,
                        || attempt.check(vault),
                    )
                })?;
                collector.finish(0, 1, CaptureExtent::PublishedLiveSessionBodies, || {
                    attempt.check(vault)
                })
            })();
            capture.finish(&outcome)?;
            outcome?;
        }
        if self
            .orders
            .iter()
            .all(|order| order.ends_at <= vault.store.clock.now_recorded_at())
        {
            return Ok(());
        }
        // This supplier covers published bodies only. It does not prove that
        // an in-progress written spill is absent or captured. An extent ACK
        // must not authorize normal close/wipe of an unqualified extent.
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "live legal unpublished spill extent unqualified",
        )
        .into())
    }

    pub(crate) fn no_published_spill(&self) -> Result<()> {
        // Empty published rows are not proof that a written .tmp is absent.
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "live legal written spill extent unqualified",
        )
        .into())
    }
}

fn poisoned() -> io::Error {
    io::Error::other("live legal capture state poisoned")
}
fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "live legal capture stopped")
}
