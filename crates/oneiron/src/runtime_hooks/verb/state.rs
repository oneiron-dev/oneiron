//! What a vault holds in memory for verb hooks: the process switch, the
//! cached binding list, the sandbox, the loaded bodies, the invocations in
//! flight and the ids the doors claimed for their clients. Nothing here is
//! stored.

use std::cell::Cell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::skill_hub::pack_catalog::{HookPhase, PackHookBinding};
use crate::{EntityId, Result, Vault};

use super::InvocationId;
use crate::runtime_hooks::HookBodyRuntime;

/// How long a cached binding list stands without a change notice: a binding
/// claim written outside the binding doors shows within this.
const BINDINGS_STALE: Duration = Duration::from_secs(2);
/// Bodies one vault keeps loaded.
const MAX_BODIES: usize = 256;

thread_local! {
    /// This thread's hook depth: 1 while a chain runs or an outcome applies.
    static DEPTH: Cell<u8> = const { Cell::new(0) };
    /// The invocation this thread's drain runs again, while it runs.
    static DRAINING: Cell<Option<InvocationId>> = const { Cell::new(None) };
}

type InFlight = Arc<Mutex<HashMap<InvocationId, Holder>>>;
type Claims = Arc<Mutex<HashMap<InvocationId, Arc<ClaimSlot>>>>;

/// The vault's verb-hook state.
#[derive(Default)]
pub(crate) struct VerbHookState {
    /// `serve --no-hooks`: every boundary passes through.
    suppressed: AtomicBool,
    /// Bumped by the binding doors and the switch.
    generation: AtomicU64,
    bindings: RwLock<Option<Arc<Bindings>>>,
    /// Bodies by their BLAKE3; `pack_hook_body` checked each against it.
    bodies: Mutex<HashMap<String, Arc<str>>>,
    /// Invocations whose chain is running, with who holds each.
    in_flight: InFlight,
    /// Client-named invocations a door is serving, each with its call.
    claims: Claims,
    /// The process's one sandbox: the host's, when it installed one before
    /// the first hooked call, else built on that call.
    runtime: OnceLock<std::result::Result<Arc<dyn HookBodyRuntime>, String>>,
}

/// The enabled verb bindings as of one read, in run order: priority
/// descending, then body hash. Empty while `hooks.enabled` is off.
pub(super) struct Bindings {
    loaded: Instant,
    generation: u64,
    pub(super) verb: Vec<(EntityId, PackHookBinding)>,
}

/// Who holds an invocation in flight.
#[derive(Debug)]
struct Holder {
    actor: EntityId,
    /// Set while the drain runs a settled call again: the ask it resumes,
    /// and whether the drain's own boundary entered yet.
    drain: Option<(EntityId, bool)>,
}

/// How a call enters the in-flight set.
pub(super) enum Entered {
    /// The same actor's invocation is in flight: a nested boundary.
    Nested,
    /// The drain runs this call again, resumed on ask `.0`: a retry waits
    /// for what it returns.
    Draining(EntityId),
    /// The call holds the mark until it drops; `None` when another actor
    /// holds this id, whose own call keeps it, or when the drain's hold
    /// keeps it.
    Fresh(Option<InFlightMark>),
}

/// Holds an invocation in the in-flight set until dropped.
#[derive(Debug)]
pub(crate) struct InFlightMark {
    set: InFlight,
    invocation: InvocationId,
}

impl Drop for InFlightMark {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.invocation);
    }
}

/// What the pre chain hands the post chain.
#[derive(Debug)]
pub(crate) struct Carry {
    pub(super) mark: Option<InFlightMark>,
    /// Unix milliseconds from the vault clock at dispatch.
    pub(super) now: u64,
}

impl VerbHookState {
    pub(super) fn suppressed(&self) -> bool {
        self.suppressed.load(Ordering::Acquire)
    }

    /// The binding list, read again after a binding door wrote or once it
    /// is stale. A fresh one costs no read transaction.
    pub(super) fn bindings(&self, vault: &Vault) -> Result<Arc<Bindings>> {
        let generation = self.generation.load(Ordering::Acquire);
        let cached = self
            .bindings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(cached) = cached
            && cached.generation == generation
            && cached.loaded.elapsed() < BINDINGS_STALE
        {
            return Ok(cached);
        }
        let mut verb = Vec::new();
        if vault.hooks_enabled()? {
            verb = vault
                .pack_hook_bindings()?
                .into_iter()
                .filter(|(_, binding)| {
                    binding.enabled
                        && matches!(binding.selector.phase, HookPhase::Pre | HookPhase::Post)
                })
                .collect();
            verb.sort_by(|(_, a), (_, b)| {
                b.selector
                    .priority
                    .cmp(&a.selector.priority)
                    .then_with(|| a.body_hash.cmp(&b.body_hash))
            });
        }
        let fresh = Arc::new(Bindings {
            loaded: Instant::now(),
            generation,
            verb,
        });
        *self
            .bindings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&fresh));
        Ok(fresh)
    }

    /// A binding's body, loaded once per body hash.
    pub(super) fn body(
        &self,
        vault: &Vault,
        binding: &PackHookBinding,
    ) -> std::result::Result<Arc<str>, String> {
        if let Some(body) = self
            .bodies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&binding.body_hash)
        {
            return Ok(Arc::clone(body));
        }
        let bytes = vault
            .pack_hook_body(binding)
            .map_err(|error| error.to_string())?;
        let body: Arc<str> = String::from_utf8(bytes)
            .map_err(|_| "hook body is not UTF-8".to_owned())?
            .into();
        let mut bodies = self.bodies.lock().unwrap_or_else(PoisonError::into_inner);
        if bodies.len() >= MAX_BODIES {
            bodies.clear();
        }
        bodies.insert(binding.body_hash.clone(), Arc::clone(&body));
        Ok(body)
    }

    /// The vault's one sandbox: the one the host installed, or one built on
    /// first use. `None` without the sandbox feature and none installed:
    /// verb hooks then pass through. A sandbox that did not build fails each
    /// run, so blocking hooks still fail safe.
    pub(super) fn runtime(&self) -> Option<std::result::Result<&dyn HookBodyRuntime, &str>> {
        #[cfg(feature = "code-sandbox-wasmtime")]
        let runtime = Some(self.runtime.get_or_init(build_sandbox));
        #[cfg(not(feature = "code-sandbox-wasmtime"))]
        let runtime = self.runtime.get();
        runtime.map(|runtime| runtime.as_deref().map_err(String::as_str))
    }

    /// Marks `invocation` in flight for `actor`. The same actor's id in
    /// flight is a nested boundary of one call: a concurrent request naming
    /// it never reaches here, since each door that takes a client's id claims
    /// it first ([`Vault::claim_invocation`]), and an id the engine mints is
    /// its own. The one other holder is the drain ([`Self::hold_for_drain`]):
    /// its own first boundary enters fresh, and the caller's retry meanwhile
    /// waits on it.
    pub(super) fn enter(&self, invocation: InvocationId, actor: EntityId) -> Entered {
        let mut set = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match set.get_mut(&invocation) {
            Some(holder) if holder.actor == actor => match &mut holder.drain {
                None => Entered::Nested,
                Some((_, entered)) if draining() == Some(invocation) => {
                    if *entered {
                        Entered::Nested
                    } else {
                        *entered = true;
                        Entered::Fresh(None)
                    }
                }
                Some((ask, _)) => Entered::Draining(*ask),
            },
            Some(_) => Entered::Fresh(None),
            None => {
                set.insert(invocation, Holder { actor, drain: None });
                Entered::Fresh(Some(self.mark(invocation)))
            }
        }
    }

    /// Holds `invocation` for the drain's run of `actor`'s call stopped on
    /// `ask`, until the mark drops: from before the call to after its
    /// outcome is saved. `None` when a call of it is in flight already: the
    /// check and the hold are one step, so no retry starts between them.
    pub(super) fn hold_for_drain(
        &self,
        invocation: InvocationId,
        actor: EntityId,
        ask: EntityId,
    ) -> Option<InFlightMark> {
        let mut set = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if set.contains_key(&invocation) {
            return None;
        }
        set.insert(
            invocation,
            Holder {
                actor,
                drain: Some((ask, false)),
            },
        );
        Some(self.mark(invocation))
    }

    fn mark(&self, invocation: InvocationId) -> InFlightMark {
        InFlightMark {
            set: Arc::clone(&self.in_flight),
            invocation,
        }
    }
}

/// What a door saved of a call its client named: its reply's status and
/// body, sent again to a duplicate of the call. The engine never reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct InvocationOutcome {
    pub status: u16,
    pub body: serde_json::Value,
}

/// One claimed invocation: the call it names, and its reply once it ends.
struct ClaimSlot {
    /// BLAKE3 of the call: its caller and its canonical body.
    body: [u8; 32],
    /// `None` while the call runs; `Some(None)` once it ended with no reply
    /// to share.
    ended: Mutex<Option<Option<InvocationOutcome>>>,
    woken: Condvar,
}

impl ClaimSlot {
    /// Ends the call once, with `outcome`, and wakes every waiter.
    fn end(&self, outcome: Option<InvocationOutcome>) {
        let mut ended = self.ended.lock().unwrap_or_else(PoisonError::into_inner);
        if ended.is_none() {
            *ended = Some(outcome);
        }
        drop(ended);
        self.woken.notify_all();
    }
}

/// How a request naming an invocation meets the door's claims.
pub enum InvocationEntry {
    /// No request holds the id: this one runs the call.
    Claimed(InvocationClaim),
    /// Another request runs the same call: wait for its reply.
    Busy(InvocationWait),
    /// Another request holds the id for a different call.
    Conflict,
}

/// Holds a client-named invocation for the request that runs it, until
/// dropped. A drop without [`Self::finish`] tells each waiter the call left
/// no reply.
pub struct InvocationClaim {
    claims: Claims,
    invocation: InvocationId,
    slot: Arc<ClaimSlot>,
}

impl InvocationClaim {
    /// Saves the reply the door is about to send, a refusal included, and
    /// wakes every request waiting on it.
    pub fn finish(self, outcome: InvocationOutcome) {
        self.slot.end(Some(outcome));
    }
}

impl Drop for InvocationClaim {
    fn drop(&mut self) {
        self.claims
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.invocation);
        self.slot.end(None);
    }
}

/// A request waiting on another's run of the same call.
pub struct InvocationWait(Arc<ClaimSlot>);

impl InvocationWait {
    /// The first call's reply, once it ends within `deadline`, blocking until
    /// then. `None` when the deadline passes first, or the call ended with no
    /// reply to share.
    #[must_use]
    pub fn outcome(self, deadline: Duration) -> Option<InvocationOutcome> {
        let ended = self.0.ended.lock().unwrap_or_else(PoisonError::into_inner);
        let (ended, _) = self
            .0
            .woken
            .wait_timeout_while(ended, deadline, |ended| ended.is_none())
            .unwrap_or_else(PoisonError::into_inner);
        ended.clone().flatten()
    }
}

#[cfg(feature = "code-sandbox-wasmtime")]
fn build_sandbox() -> std::result::Result<Arc<dyn HookBodyRuntime>, String> {
    use crate::runtime_hooks::sandbox::{HookSandbox, hook_component_bytes};
    let (bytes, pin) = hook_component_bytes();
    match HookSandbox::from_component(bytes, pin) {
        Ok(sandbox) => Ok(Arc::new(sandbox)),
        Err(error) => {
            tracing::warn!(%error, "hook sandbox did not load; verb hooks fail");
            Err(format!("hook sandbox did not load: {error}"))
        }
    }
}

/// This thread's hook depth.
pub(super) fn depth() -> u8 {
    DEPTH.with(Cell::get)
}

/// The invocation this thread's drain runs again, if any.
pub(super) fn draining() -> Option<InvocationId> {
    DRAINING.with(Cell::get)
}

/// Marks this thread as the drain's run of one invocation while held.
pub(super) struct DrainScope(Option<InvocationId>, PhantomData<*const ()>);

impl DrainScope {
    pub(super) fn enter(invocation: InvocationId) -> Self {
        Self(
            DRAINING.with(|draining| draining.replace(Some(invocation))),
            PhantomData,
        )
    }
}

impl Drop for DrainScope {
    fn drop(&mut self) {
        DRAINING.with(|draining| draining.set(self.0));
    }
}

/// Raises this thread's hook depth while held: no verb hook runs under it,
/// and a door an outcome reaches still runs its own gate.
pub(crate) struct HookDepth(PhantomData<*const ()>);

impl HookDepth {
    pub(crate) fn enter() -> Self {
        DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self(PhantomData)
    }
}

impl Drop for HookDepth {
    fn drop(&mut self) {
        DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

impl Vault {
    /// Turns verb hooks off for this process: every boundary passes through.
    /// Serve calls it for `--no-hooks`; fact hooks keep their own switch.
    pub fn suppress_verb_hooks(&self) {
        self.verb_hook_state
            .suppressed
            .store(true, Ordering::Release);
    }

    /// Hands verb hooks the host's sandbox, so the process runs one. Serve
    /// installs its fact-hook runner's before any call; once a hooked call
    /// has built its own, this does nothing.
    pub fn install_hook_runtime(&self, runtime: Arc<dyn HookBodyRuntime>) {
        let _ = self.verb_hook_state.runtime.set(Ok(runtime));
    }

    /// Claims `invocation`, which a client named, for the request that
    /// carries it. `body` is the BLAKE3 of the call: its caller and its
    /// canonical args. A door claims once, at its outermost point, and holds
    /// the claim until it replies: the vault's in-flight set cannot tell a
    /// concurrent request from a nested boundary, so the doors close it.
    #[must_use]
    pub fn claim_invocation(&self, invocation: InvocationId, body: [u8; 32]) -> InvocationEntry {
        let claims = &self.verb_hook_state.claims;
        let mut held = claims.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(slot) = held.get(&invocation) {
            return if slot.body == body {
                InvocationEntry::Busy(InvocationWait(Arc::clone(slot)))
            } else {
                InvocationEntry::Conflict
            };
        }
        let slot = Arc::new(ClaimSlot {
            body,
            ended: Mutex::new(None),
            woken: Condvar::new(),
        });
        held.insert(invocation, Arc::clone(&slot));
        InvocationEntry::Claimed(InvocationClaim {
            claims: Arc::clone(claims),
            invocation,
            slot,
        })
    }

    /// Tells the verb hooks a binding or the switch changed, so the next
    /// call reads the binding list again.
    pub(crate) fn verb_hook_bindings_changed(&self) {
        self.verb_hook_state
            .generation
            .fetch_add(1, Ordering::AcqRel);
    }
}
