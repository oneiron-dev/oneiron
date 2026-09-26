//! Sandboxed, read-only lens authoring. Guest components emit atoms, never effects.
//!
//! The component ABI has three string-based host imports: `scoped-read(handle)`
//! returns displayed text, `resolve-backing-ref(handle)` returns the opaque
//! host-issued reference name, and `emit-atom(json)` accepts a closed LensAtom.
//! Handles must already be bound in the render frame. No WASI is linked.

use std::collections::BTreeMap;

use wasmtime::component::{Component, InstancePre, Linker};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};

use super::instrument::display_body;
use super::{
    InstrumentAtoms, InstrumentView, LensAtom, LensExecutionBoundary, LensHostImport,
    LensRenderFrame, render_instrument,
};
use crate::claim::ScopedRead;
use crate::{Error, Result};

const MAX_COMPONENT_BYTES: usize = 1024 * 1024;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_ATOMS: usize = 4096;

struct GuestState {
    // Resolved through the acting principal's ScopedRead just before each run.
    // The guest sees only the host-bound handle, never a caller-supplied ID.
    bindings: BTreeMap<String, (String, String)>,
    atoms: Vec<LensAtom>,
    emitted_bytes: usize,
    remaining_calls: usize,
    limits: StoreLimits,
}

/// Compiled Component Model lens code. Each run owns fresh guest memory and a
/// fresh ScopedRead-admitted handle table. Component construction links ONLY
/// the three read-only imports; any write, WASI or unknown import fails here.
pub struct LensExecutionRuntime {
    engine: Engine,
    instance: InstancePre<GuestState>,
    boundary: LensExecutionBoundary,
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
                let state = cx.data_mut();
                state.charge()?;
                let (text, _) = state.bindings.get(&handle).ok_or_else(|| {
                    wasmtime::Error::msg("lens handle is not scoped and host-bound")
                })?;
                Ok((text.clone(),))
            })
            .map_err(|_| failure("lens scoped-read link failed"))?;
            root.func_wrap("resolve-backing-ref", |mut cx, (handle,): (String,)| {
                let state = cx.data_mut();
                state.charge()?;
                let (_, token) = state
                    .bindings
                    .get(&handle)
                    .ok_or_else(|| wasmtime::Error::msg("lens backing ref is not host-bound"))?;
                Ok((token.clone(),))
            })
            .map_err(|_| failure("lens backing-ref link failed"))?;
            root.func_wrap("emit-atom", |mut cx, (json,): (String,)| {
                let state = cx.data_mut();
                state.charge()?;
                if json.len() > MAX_MESSAGE_BYTES
                    || state.emitted_bytes.saturating_add(json.len()) > MAX_MESSAGE_BYTES
                    || state.atoms.len() >= MAX_ATOMS
                {
                    return Err(wasmtime::Error::msg("lens atom output limit"));
                }
                let atom: LensAtom = serde_json::from_str(&json)
                    .map_err(|_| wasmtime::Error::msg("invalid lens atom"))?;
                atom.validate().map_err(wasmtime::Error::msg)?;
                state.emitted_bytes += json.len();
                state.atoms.push(atom);
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
        })
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
        let mut admitted_bytes = 0usize;
        for row in frame.backing_refs() {
            let bound = frame.resolve_backing_ref_token(read, row.token())?;
            let body = frame
                .scoped_body(read, bound.target().entity_id())?
                .ok_or_else(|| failure("lens backing ref outside read scope"))?;
            admitted_bytes = admitted_bytes.saturating_add(body.len());
            if admitted_bytes > MAX_MESSAGE_BYTES {
                return Err(failure("lens read budget exceeded"));
            }
            let text = display_body(&body);
            if text.len() > MAX_MESSAGE_BYTES {
                return Err(failure("lens read budget exceeded"));
            }
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
                emitted_bytes: 0,
                remaining_calls: 256,
                limits: StoreLimitsBuilder::new()
                    .memory_size(32 * 1024 * 1024)
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
            .set_fuel(2_000_000)
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
        render_instrument(&atoms, frame, read)
    }
}

impl GuestState {
    fn charge(&mut self) -> wasmtime::Result<()> {
        self.remaining_calls = self
            .remaining_calls
            .checked_sub(1)
            .ok_or_else(|| wasmtime::Error::msg("lens host call budget exceeded"))?;
        Ok(())
    }
}

fn failure(reason: &'static str) -> Error {
    Error::InvalidConfig(reason.into())
}
