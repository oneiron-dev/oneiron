//! What a vault holds in memory for verb hooks: the process switch, the
//! cached binding list, the sandbox, the loaded bodies and the invocations in
//! flight. Nothing here is stored.

use std::cell::Cell;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
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
}

type InFlight = Arc<Mutex<HashMap<InvocationId, EntityId>>>;

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
    /// Invocations whose chain is running, with the actor that holds each.
    in_flight: InFlight,
    #[cfg(feature = "code-sandbox-wasmtime")]
    runtime: std::sync::OnceLock<std::result::Result<Box<dyn HookBodyRuntime>, String>>,
}

/// The enabled verb bindings as of one read, in run order: priority
/// descending, then body hash. Empty while `hooks.enabled` is off.
pub(super) struct Bindings {
    loaded: Instant,
    generation: u64,
    pub(super) verb: Vec<(EntityId, PackHookBinding)>,
}

/// How a call enters the in-flight set.
pub(super) enum Entered {
    /// The same actor's invocation is in flight: a nested boundary.
    Nested,
    /// The call holds the mark until it drops; `None` when another actor
    /// holds this id, whose own call keeps it.
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

    /// The vault's one sandbox, built on first use. `None` without the
    /// sandbox feature: verb hooks then pass through. A sandbox that did not
    /// build fails each run, so blocking hooks still fail safe.
    pub(super) fn runtime(&self) -> Option<std::result::Result<&dyn HookBodyRuntime, &str>> {
        #[cfg(feature = "code-sandbox-wasmtime")]
        {
            Some(
                self.runtime
                    .get_or_init(build_sandbox)
                    .as_deref()
                    .map_err(String::as_str),
            )
        }
        #[cfg(not(feature = "code-sandbox-wasmtime"))]
        {
            None
        }
    }

    /// Marks `invocation` in flight for `actor`.
    pub(super) fn enter(&self, invocation: InvocationId, actor: EntityId) -> Entered {
        let mut set = self.in_flight.lock().unwrap_or_else(PoisonError::into_inner);
        match set.get(&invocation) {
            Some(holder) if *holder == actor => Entered::Nested,
            Some(_) => Entered::Fresh(None),
            None => {
                set.insert(invocation, actor);
                Entered::Fresh(Some(InFlightMark {
                    set: Arc::clone(&self.in_flight),
                    invocation,
                }))
            }
        }
    }
}

#[cfg(feature = "code-sandbox-wasmtime")]
fn build_sandbox() -> std::result::Result<Box<dyn HookBodyRuntime>, String> {
    use crate::runtime_hooks::sandbox::{HookSandbox, hook_component_bytes};
    let (bytes, pin) = hook_component_bytes();
    match HookSandbox::from_component(bytes, pin) {
        Ok(sandbox) => Ok(Box::new(sandbox)),
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
        self.verb_hook_state.suppressed.store(true, Ordering::Release);
    }

    /// Tells the verb hooks a binding or the switch changed, so the next
    /// call reads the binding list again.
    pub(crate) fn verb_hook_bindings_changed(&self) {
        self.verb_hook_state
            .generation
            .fetch_add(1, Ordering::AcqRel);
    }
}
