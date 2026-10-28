//! Sandboxed, read-only lens authoring. Guest components emit atoms, never effects.
//!
//! The component ABI has three string-based host imports: `scoped-read(handle)`
//! returns displayed text, `resolve-backing-ref(handle)` returns the opaque
//! host-issued reference name, and `emit-atom(json)` accepts a closed LensAtom.
//! Handles must already be bound in the render frame. No WASI is linked.
//!
//! A run is paced, not rationed (FIX 9898): every host call is a yield that
//! refills one step of fuel, so a lens that keeps reading and emitting runs
//! to its end, and only a loop that never calls the host runs dry. No call
//! count, output total or read total ends a run. The guest's memory stays
//! bounded: it isolates untrusted code ([`LensGuestPolicy`]).

use std::collections::BTreeMap;

use wasmtime::component::{Component, InstancePre, Linker};
use wasmtime::{Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder};

use super::instrument::display_body;
use super::{
    InstrumentAtoms, InstrumentView, LensAtom, LensExecutionBoundary, LensHostImport,
    LensRenderFrame, render_instrument,
};
use crate::claim::{ScopedRead, ScopedReadReceipt};
use crate::{Error, Result};

const MAX_COMPONENT_BYTES: usize = 1024 * 1024;
/// The largest single atom message one `emit-atom` call carries: a frame
/// bound of the codec, not a total.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// The linear memory one guest instance may grow to. It isolates untrusted
/// lens code from the host; the owner raises it through [`LensGuestPolicy`].
pub const LENS_GUEST_MEMORY_BYTES: usize = 32 * 1024 * 1024;
/// The fuel one step of guest work gets: what a run may spend between two
/// host calls, refilled at each (FIX 9898). It paces a run; it never ends one
/// that keeps yielding to the host.
pub const LENS_GUEST_STEP_FUEL: u64 = 2_000_000;

/// How a lens guest runs: the one hook a ruling on its memory or its step
/// changes. The defaults are [`LENS_GUEST_MEMORY_BYTES`] and
/// [`LENS_GUEST_STEP_FUEL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LensGuestPolicy {
    /// The linear memory one guest instance may grow to, in bytes.
    pub memory_bytes: usize,
    /// The fuel each step between two host calls gets.
    pub step_fuel: u64,
}

impl Default for LensGuestPolicy {
    fn default() -> Self {
        Self {
            memory_bytes: LENS_GUEST_MEMORY_BYTES,
            step_fuel: LENS_GUEST_STEP_FUEL,
        }
    }
}

struct GuestState {
    // Resolved through the acting principal's ScopedRead just before each run.
    // The guest sees only the host-bound handle, never a caller-supplied ID.
    bindings: BTreeMap<String, (String, String)>,
    atoms: Vec<LensAtom>,
    step_fuel: u64,
    limits: StoreLimits,
}

/// Compiled Component Model lens code. Each run owns fresh guest memory and a
/// fresh ScopedRead-admitted handle table. Component construction links ONLY
/// the three read-only imports; any write, WASI or unknown import fails here.
pub struct LensExecutionRuntime {
    engine: Engine,
    instance: InstancePre<GuestState>,
    boundary: LensExecutionBoundary,
    policy: LensGuestPolicy,
}

impl LensExecutionRuntime {
    pub fn from_component(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_COMPONENT_BYTES {
            return Err(failure("lens component exceeds byte limit"));
        }
        let boundary = LensExecutionBoundary::read_only(vec![
            LensHostImport::ScopedRead,
            LensHostImport::ResolveBackingRef,
            LensHostImport::EmitAtom,
        ])?;
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            .consume_fuel(true)
            .max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config).map_err(|_| failure("lens engine creation failed"))?;
        let component =
            Component::new(&engine, bytes).map_err(|_| failure("invalid lens component"))?;
        let mut linker = Linker::<GuestState>::new(&engine);
        {
            let mut root = linker.root();
            root.func_wrap("scoped-read", |mut cx, (handle,): (String,)| {
                next_step(&mut cx)?;
                let state = cx.data_mut();
                let (text, _) = state.bindings.get(&handle).ok_or_else(|| {
                    wasmtime::Error::msg("lens handle is not scoped and host-bound")
                })?;
                Ok((text.clone(),))
            })
            .map_err(|_| failure("lens scoped-read link failed"))?;
            root.func_wrap("resolve-backing-ref", |mut cx, (handle,): (String,)| {
                next_step(&mut cx)?;
                let state = cx.data_mut();
                let (_, token) = state
                    .bindings
                    .get(&handle)
                    .ok_or_else(|| wasmtime::Error::msg("lens backing ref is not host-bound"))?;
                Ok((token.clone(),))
            })
            .map_err(|_| failure("lens backing-ref link failed"))?;
            root.func_wrap("emit-atom", |mut cx, (json,): (String,)| {
                next_step(&mut cx)?;
                if json.len() > MAX_MESSAGE_BYTES {
                    return Err(wasmtime::Error::msg("lens atom message exceeds its frame"));
                }
                let atom: LensAtom = serde_json::from_str(&json)
                    .map_err(|_| wasmtime::Error::msg("invalid lens atom"))?;
                atom.validate().map_err(wasmtime::Error::msg)?;
                cx.data_mut().atoms.push(atom);
                Ok(())
            })
            .map_err(|_| failure("lens emit-atom link failed"))?;
        }
        // Import and type checks happen here, not on the first render. In
        // particular a write import cannot be satisfied by this linker.
        let instance = linker
            .instantiate_pre(&component)
            .map_err(|_| failure("lens component imports refused"))?;
        Ok(Self {
            engine,
            instance,
            boundary,
            policy: LensGuestPolicy::default(),
        })
    }

    /// This runtime under `policy` instead of [`LensGuestPolicy::default`].
    #[must_use]
    pub fn with_policy(mut self, policy: LensGuestPolicy) -> Self {
        self.policy = policy;
        self
    }

    #[must_use]
    pub fn imports(&self) -> &[LensHostImport] {
        self.boundary.imports()
    }

    pub fn run(&self, frame: &LensRenderFrame, read: &ScopedRead<'_>) -> Result<InstrumentView> {
        if !matches!(
            frame.world_scope(),
            crate::pipeline::WorldScope::WorldSet(_) | crate::pipeline::WorldScope::CodebaseSet(_)
        ) {
            return Err(failure("lens execution requires a WorldSet frame"));
        }
        // Admission is performed before invoking any guest instruction. Every
        // row is resolved from the frame's host table, then checked against the
        // acting principal and WorldSet. A stale or inaccessible row refuses
        // the entire run instead of silently broadening its view.
        let mut bindings = BTreeMap::new();
        let mut admission_receipt: Option<ScopedReadReceipt> = None;
        for row in frame.backing_refs() {
            let bound = frame.resolve_backing_ref_token(read, row.token())?;
            let admitted = frame.scoped_body(read, bound.target().entity_id())?;
            match &mut admission_receipt {
                Some(receipt) => receipt.restrict_with(&admitted.receipt),
                None => admission_receipt = Some(admitted.receipt),
            }
            let body = admitted
                .value
                .ok_or_else(|| failure("lens backing ref outside read scope"))?;
            let text = display_body(&body);
            bindings.insert(
                bound.handle().as_str().to_owned(),
                (text, bound.token().ref_id().as_str().to_owned()),
            );
        }
        // Even an empty frame must use its principal's key, not merely have a
        // WorldSet label. ScopedRead performs the authoritative actor check.
        frame.ensure_scoped_read_actor(read)?;
        let mut store = Store::new(
            &self.engine,
            GuestState {
                bindings,
                atoms: Vec::new(),
                step_fuel: self.policy.step_fuel,
                limits: StoreLimitsBuilder::new()
                    .memory_size(self.policy.memory_bytes)
                    .memories(1)
                    .tables(4)
                    .instances(16)
                    .table_elements(10_000)
                    .trap_on_grow_failure(true)
                    .build(),
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.policy.step_fuel)
            .map_err(|_| failure("lens fuel setup failed"))?;
        let instance = self
            .instance
            .instantiate(&mut store)
            .map_err(|_| failure("lens component instantiation failed"))?;
        let run = instance
            .get_typed_func::<(), ()>(&mut store, "run")
            .map_err(|_| failure("lens run export missing"))?;
        run.call(&mut store, ())
            .map_err(|_| failure("lens component execution refused"))?;
        let atoms = InstrumentAtoms::new(std::mem::take(&mut store.data_mut().atoms))?;
        let mut view = render_instrument(&atoms, frame, read)?;
        if let Some(admission) = admission_receipt {
            match &mut view.receipt {
                Some(receipt) => receipt.restrict_with(&admission),
                None => view.receipt = Some(admission),
            }
        }
        Ok(view)
    }
}

/// A host call is a yield: the guest's next step starts with a full step of
/// fuel, however much the step before it spent (FIX 9898).
fn next_step(cx: &mut StoreContextMut<'_, GuestState>) -> wasmtime::Result<()> {
    let step_fuel = cx.data().step_fuel;
    cx.set_fuel(step_fuel)
}

fn failure(reason: &'static str) -> Error {
    Error::InvalidConfig(reason.into())
}
