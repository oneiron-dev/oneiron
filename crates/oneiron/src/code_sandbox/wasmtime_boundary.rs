//! Real Component Model boundary. Each request owns a fresh, fuel-limited Store.
//!
//! No WASI linker, process environment, clock or random capability is installed.
//! These capabilities are only the typed imports supplied by the request host.

use super::{SandboxBoundaryContract, SandboxGuestTier};
use wasmtime::component::{Component, ComponentNamedList, Instance, Lift, Linker, Lower};
use wasmtime::{Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder};

/// Types and host traits generated from the same WIT used by the guest SDK.
pub mod bindings {
    wasmtime::component::bindgen!({ path: "wit", world: "guest" });
}

const IMPORTS: &[(&str, &str)] = include!("../../wit/generated/imports.rs");

/// Compiled component cache owner; no guest memory or request state is shared.
pub struct WasmtimeBoundary {
    engine: Engine,
}

/// A request's private host state and resource limiter.
struct RequestState<H> {
    host: H,
    limits: StoreLimits,
}

/// One instantiated request. Dropping it drops all guest globals and memory.
pub struct WasmtimeRequest<H: 'static> {
    store: Store<RequestState<H>>,
    instance: Instance,
}

impl WasmtimeBoundary {
    pub fn new() -> wasmtime::Result<Self> {
        let mut config = Config::new();
        config
            .consume_fuel(true)
            .wasm_component_model(true)
            .max_wasm_stack(512 * 1024);
        Ok(Self {
            engine: Engine::new(&config)?,
        })
    }

    /// Compile a host-selected component, not user-supplied source in another
    /// authoring language. The production authoring door remains plain JS.
    pub fn compile(&self, bytes: &[u8]) -> wasmtime::Result<Component> {
        Component::new(&self.engine, bytes)
    }

    /// Instantiate only the tier's imports. Unknown and write imports in a
    /// foreign component fail construction, before any guest instruction runs.
    pub fn request<H: bindings::GuestImports + 'static>(
        &self,
        component: &Component,
        tier: SandboxGuestTier,
        host: H,
    ) -> wasmtime::Result<WasmtimeRequest<H>> {
        let mut linker = Linker::new(&self.engine);
        link(&mut linker, tier)?;
        let state = RequestState {
            host,
            limits: StoreLimitsBuilder::new()
                .memory_size(32 * 1024 * 1024)
                .table_elements(10_000)
                .instances(16)
                .tables(4)
                .memories(1)
                .trap_on_grow_failure(true)
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store.set_fuel(20_000_000)?;
        let instance = linker.instantiate(&mut store, component)?;
        Ok(WasmtimeRequest { store, instance })
    }
}

impl<H: 'static> WasmtimeRequest<H> {
    /// Call one typed export, including canonical ABI post-return cleanup.
    pub fn call<P, R>(&mut self, export: &str, params: P) -> wasmtime::Result<R>
    where
        P: ComponentNamedList + Lower,
        R: ComponentNamedList + Lift,
    {
        let function = self
            .instance
            .get_typed_func::<P, R>(&mut self.store, export)?;
        let value = function.call(&mut self.store, params)?;
        function.post_return(&mut self.store)?;
        Ok(value)
    }

    /// Read the host's durable receipt/continuation state after the guest step.
    pub fn host(&self) -> &H {
        &self.store.data().host
    }
}

/// Exact WIT-to-public-name inventory installed by the linker for this tier.
/// It includes both pinned ask-human spellings as separate typed imports.
pub fn linked_imports(tier: SandboxGuestTier) -> Vec<(&'static str, &'static str)> {
    let contract = SandboxBoundaryContract::for_tier(tier);
    IMPORTS
        .iter()
        .copied()
        .filter(|(_, public)| {
            contract
                .linked_imports()
                .iter()
                .any(|import| import.name() == *public)
        })
        .collect()
}

fn link<H: bindings::GuestImports + 'static>(
    linker: &mut Linker<RequestState<H>>,
    tier: SandboxGuestTier,
) -> wasmtime::Result<()> {
    use bindings::*;
    // The generated world trait is the implementation contract. Link its
    // individual methods, not Guest::add_to_linker (which links the superset).
    macro_rules! unary {
        ($root:expr, $name:expr, $method:ident, $param:ty) => {
            $root.func_wrap(
                $name,
                |mut cx: StoreContextMut<'_, RequestState<H>>, (value,): ($param,)| {
                    Ok((cx.data_mut().host.$method(value),))
                },
            )?
        };
    }
    let imports = linked_imports(tier);
    let contract = SandboxBoundaryContract::for_tier(tier);
    if imports.len() != contract.linked_imports().len()
        || !contract
            .linked_imports()
            .iter()
            .all(|expected| imports.iter().any(|(_, name)| *name == expected.name()))
    {
        return Err(wasmtime::Error::msg(
            "sandbox WIT capability inventory mismatch",
        ));
    }
    let mut root = linker.root();
    for (wit, public) in imports {
        match public {
            "sandbox.fs.read_file" => unary!(root, wit, read_file, String),
            "sandbox.credential.call" => unary!(root, wit, credential_call, CredentialInput),
            "oneiron.clock.now_unix_ms" => root.func_wrap(
                wit,
                |mut cx: StoreContextMut<'_, RequestState<H>>, (): ()| {
                    Ok((cx.data_mut().host.clock_now_unix_ms(),))
                },
            )?,
            "oneiron.random.bytes" => unary!(root, wit, random_bytes, u32),
            "self.memory.search" => unary!(root, wit, memory_search, SearchInput),
            "self.memory.put_claim" => unary!(root, wit, memory_put_claim, ClaimInput),
            "self.memory.supersede_claim" => {
                unary!(root, wit, memory_supersede_claim, SupersedeInput);
            }
            "self.memory.put_edge" => unary!(root, wit, memory_put_edge, EdgeInput),
            "self.ask_human" => unary!(root, wit, ask_human, PromptInput),
            "self.askHuman" => unary!(root, wit, ask_human_camel, PromptInput),
            "self.speak" => unary!(root, wit, speak, TextInput),
            "self.think" => unary!(root, wit, think, TextInput),
            "self.express" => unary!(root, wit, express, TextInput),
            _ => {
                return Err(wasmtime::Error::msg(
                    "WIT import is not a sandbox capability",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
