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
    LiveSessionTarget, LiveSpillMetadata, ReleaseLiveOrder,
};

use crate::error::Result;
use crate::off_record::{WrittenSessionSpill, WrittenSpillMetadata};
use crate::store::LiveSpillRetention;
use crate::{EntityId, Vault};
use zeroize::Zeroizing;

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
    /// Set once managed stop closes every off-record session: a live order
    /// whose HOST has no working attempt then ends interrupted instead of
    /// keeping its session open for a retry.
    closing_at_stop: AtomicBool,
    /// Live prospective-capture connections (FIX 13866).
    pub(super) prospective: super::outbox::ProspectiveAttempts,
}

struct LiveOrder {
    key: OrderKey,
    ends_at: u64,
    recipient: Vec<u8>,
    _retention: LiveSpillRetention,
    completed: AtomicBool,
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
            let _ = self.shutdown.shutdown(Shutdown::Both);
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

    /// A failed connection still owns an admitted standing. Keep this SAME
    /// managed worker until retry, release, stop or its actual order term, so
    /// the original native source guard never outlives an unobserved expiry.
    fn wait_standing(&self, vault: &Vault) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        while !self.cancelled.load(Ordering::Acquire) {
            let remaining = self
                .request
                .ends_at
                .saturating_sub(vault.store.clock.now_recorded_at());
            if remaining == 0 {
                break;
            }
            state = self
                .changed
                .wait_timeout(state, Duration::from_secs(remaining))
                .map_err(|_| poisoned())?
                .0;
        }
        Ok(())
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
        if outcome.is_err() {
            let _ = self.attempt.shutdown.shutdown(Shutdown::Both);
        }
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
        if !self.finished {
            let _ = self.attempt.shutdown.shutdown(Shutdown::Both);
        }
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
        if self.completed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "live legal capture complete",
            )
            .into());
        }
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
        let attach = |retention| -> Result<()> {
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
                    _retention: retention,
                    completed: AtomicBool::new(false),
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
                if self.stopped.load(Ordering::Acquire)
                    || registry.released.contains(&(key.order, key.generation))
                {
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

    fn complete(&self, vault: &Vault, order: &Arc<LiveOrder>) -> Result<()> {
        {
            let _registry = self.registry.lock().map_err(|_| poisoned())?;
            order.completed.store(true, Ordering::Release);
        }
        self.prune_ended(vault)
    }

    fn release(&self, vault: &Vault, release: &ReleaseLiveOrder) -> Result<()> {
        let orders = {
            let mut registry = self.registry.lock().map_err(|_| poisoned())?;
            registry
                .released
                .insert((release.order, release.generation));
            // Overlapping releases must see the SAME draining orders. The
            // tombstone stops new attempts, but removal waits for the drain.
            registry
                .orders
                .values()
                .filter(|order| {
                    order.key.order == release.order && order.key.generation == release.generation
                })
                .cloned()
                .collect::<Vec<_>>()
        };
        let mut attempts = Vec::new();
        for order in &orders {
            attempts.extend(order.attempts()?);
        }
        for attempt in &attempts {
            attempt.cancel(io::ErrorKind::Interrupted)?;
        }
        for attempt in &attempts {
            let _ = attempt.wait(vault);
        }
        let mut registry = self.registry.lock().map_err(|_| poisoned())?;
        for order in &orders {
            if registry
                .orders
                .get(&order.key)
                .is_some_and(|current| Arc::ptr_eq(current, order))
            {
                registry.orders.remove(&order.key);
            }
        }
        Ok(())
    }

    fn prune_ended(&self, vault: &Vault) -> Result<()> {
        let mut registry = self.registry.lock().map_err(|_| poisoned())?;
        let now = vault.store.clock.now_recorded_at();
        let ended: Vec<_> = registry
            .orders
            .values()
            .filter(|order| order.completed.load(Ordering::Acquire) || order.ends_at <= now)
            .cloned()
            .collect();
        for order in ended {
            let attempts = order.attempts()?;
            // Cancel before inspecting capturing: no attempt may start after
            // this cut. Keep an aborting capture discoverable by Release,
            // whose receipt promises that its collectors have returned.
            for attempt in &attempts {
                attempt.cancel(if order.completed.load(Ordering::Acquire) {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                })?;
            }
            let mut capturing = false;
            for attempt in &attempts {
                capturing |= attempt.state.lock().map_err(|_| poisoned())?.capturing;
            }
            if !capturing {
                registry.orders.remove(&order.key);
            }
        }
        Ok(())
    }

    /// Stops live-session captures; prospective connections keep draining.
    fn stop_live(&self) -> Result<()> {
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
        let outcome = attempt.pending().and_then(|()| attempt.wait(vault));
        if outcome.is_err() {
            attempt.wait_standing(vault)?;
        }
        vault.host_legal_captures.prune_ended(vault)?;
        outcome
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
        // The same generation's prospective capture ends with it: standing
        // and outbox destroyed, never standing again (FIX 13867).
        super::outbox::release(vault, (release.order, release.generation))?;
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
            instance: *instance.as_bytes(),
        };
        self.host_legal_captures.prune_ended(self)?;
        let now = self.store.clock.now_recorded_at();
        let registry = self
            .host_legal_captures
            .registry
            .lock()
            .map_err(|_| poisoned())?;
        let orders: Vec<_> = registry
            .orders
            .values()
            .filter(|order| {
                !order.completed.load(Ordering::Acquire)
                    && order.ends_at > now
                    && order.key.target == target
            })
            .cloned()
            .collect();
        Ok((!orders.is_empty()).then_some(LiveSpillCaptures { orders }))
    }

    /// Managed teardown calls this before shutting down ALL accepted sockets
    /// and joining ALL workers: it stops live-session captures and cancels
    /// every prospective connection. Stop is not legal release or key
    /// destruction.
    pub fn stop_pending_host_legal_captures(&self) -> Result<()> {
        self.host_legal_captures.prospective.cancel(None);
        // A prospective worker waiting for new messages wakes to see stop.
        self.store.host_legal_prospective.bump();
        self.host_legal_captures.stop_live()
    }

    /// Managed stop's off-record session close starts: from here a live
    /// order whose capture cannot run ends interrupted, never captured, and
    /// its session's close proceeds.
    pub(crate) fn begin_live_capture_close_at_stop(&self) {
        self.host_legal_captures
            .closing_at_stop
            .store(true, Ordering::Release);
    }

    /// Managed teardown calls this once every writer of this process stopped,
    /// before the Vault closes: each attached prospective connection drains
    /// its outbox to empty, sends its final batch (`final_next_ordinal`) and
    /// ends, and this waits for them. It does not wait for a HOST that is
    /// not connected: that order's outbox stays for the next start. Not
    /// release, expiry or key destruction.
    pub fn finish_host_legal_prospective(&self) {
        let attempts = self.host_legal_captures.prospective.finish();
        self.store.host_legal_prospective.bump();
        for attempt in attempts {
            attempt.wait_ended();
        }
    }
}

impl LiveSpillCaptures {
    pub(crate) fn capture_written(
        &self,
        vault: &Vault,
        source: &WrittenSessionSpill,
    ) -> Result<()> {
        let identity = source.identity();
        for order in &self.orders {
            if identity.source_vault() != vault.vault_id()
                || identity.session_ref() != order.key.target.session_ref
                || *identity.instance().as_bytes() != order.key.target.instance
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "live legal source identity",
                )
                .into());
            }
        }
        self.capture(vault, Some(source))
    }

    /// Called only after the native final snapshot and frozen writer inventory
    /// jointly prove that this exact instance has no written spill.
    pub(crate) fn no_written_spill(&self, vault: &Vault) -> Result<()> {
        self.capture(vault, None)
    }

    fn capture(&self, vault: &Vault, source: Option<&WrittenSessionSpill>) -> Result<()> {
        let at_stop = vault
            .host_legal_captures
            .closing_at_stop
            .load(Ordering::Acquire);
        for order in &self.orders {
            if order.completed.load(Ordering::Acquire)
                || order.ends_at <= vault.store.clock.now_recorded_at()
            {
                continue;
            }
            match Self::capture_order(vault, order, source) {
                Ok(()) => {}
                // Managed stop: no HOST retry can come. The order's capture of
                // this session ends interrupted, never claimed, and the other
                // orders and the session's close go on.
                Err(error) if at_stop => {
                    tracing::warn!(
                        %error,
                        "a live legal capture ended interrupted at managed stop; its spill was not captured"
                    );
                    for attempt in order.attempts()? {
                        attempt.cancel(io::ErrorKind::Interrupted)?;
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn capture_order(
        vault: &Vault,
        order: &Arc<LiveOrder>,
        source: Option<&WrittenSessionSpill>,
    ) -> Result<()> {
        let bodies = u64::try_from(source.map_or(0, WrittenSessionSpill::body_count))
            .map_err(|_| io::Error::other("live legal body count overflow"))?;
        let attempt = order.current_attempt()?;
        let mut capture = attempt.start(vault)?;
        let outcome = (|| -> Result<()> {
            attempt.check(vault)?;
            let mut collector =
                Collector::pinned(&mut capture.stream, &attempt.public, &attempt.request)?;
            let mut copied = 0u64;
            if let Some(source) = source {
                source.for_each_written_body(|metadata, reference, reader| {
                    attempt.check(vault)?;
                    let metadata = match metadata {
                        WrittenSpillMetadata::Published {
                            raw_key,
                            raw_file_row,
                        } => LiveSpillMetadata::Published {
                            raw_key: raw_key.to_vec(),
                            raw_file_row: raw_file_row.to_vec(),
                        },
                        WrittenSpillMetadata::NativeFile {
                            name,
                            finished,
                            physical_len,
                        } => LiveSpillMetadata::NativeFile {
                            name: name.to_owned(),
                            finished,
                            physical_len,
                        },
                    };
                    let encoded =
                        Zeroizing::new(serde_json::to_vec(&metadata).map_err(io::Error::other)?);
                    let source = CaptureSource::LiveSession(order.key.target.clone());
                    let revision = *blake3::hash(&encoded).as_bytes();
                    collector.component(
                        SourceComponent::LiveSessionMetadata,
                        source.clone(),
                        metadata.metadata_family(),
                        metadata.source_key(),
                        revision,
                        encoded.len() as u64,
                        revision,
                        &mut &encoded[..],
                        || attempt.check(vault),
                    )?;
                    collector.component(
                        SourceComponent::LiveSessionBody,
                        source,
                        metadata.body_family(),
                        metadata.source_key(),
                        revision,
                        reference.raw_len,
                        reference.raw_blake3,
                        reader,
                        || attempt.check(vault),
                    )?;
                    copied = copied
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("live legal body count overflow"))?;
                    Ok(())
                })?;
            }
            if copied != bodies {
                return Err(
                    io::Error::new(io::ErrorKind::InvalidData, "live legal body count").into(),
                );
            }
            collector.finish(
                0,
                1,
                copied,
                0,
                CaptureExtent::WrittenLiveSessionSpill,
                || attempt.check(vault),
            )
        })();
        capture.finish(&outcome)?;
        outcome?;
        vault.host_legal_captures.complete(vault, order)?;
        Ok(())
    }
}

fn poisoned() -> io::Error {
    io::Error::other("live legal capture state poisoned")
}
fn interrupted() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "live legal capture stopped")
}
