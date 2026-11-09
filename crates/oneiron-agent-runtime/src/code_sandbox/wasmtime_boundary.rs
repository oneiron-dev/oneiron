//! Real Component Model boundary. Each request owns a fresh, fuel-limited Store.
//!
//! No WASI linker, process environment, clock or random capability is installed.
//! These capabilities are only the typed imports supplied by the request host.
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::wasmtime_boundary::*;

