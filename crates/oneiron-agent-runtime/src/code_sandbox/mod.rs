//! The code sandbox backends, beside core's sandbox contract (re-exported
//! whole, so the moved code's `crate::code_sandbox::` and `super::` paths
//! resolve as they did in core).

pub use oneiron::code_sandbox::*;

/// The isolating backends this build carries, behind `microvm::SandboxBackends`.
mod compiled_backends;
/// Firecracker-backed microVM lane (Linux; feature-gated).
#[cfg(feature = "microvm-firecracker")]
pub mod firecracker;
/// The microVM lane: core's contract, and the OCI fenced container backend.
pub mod microvm;
/// Host-pinned production QuickJS artifact loader and runtime factory.
#[cfg(feature = "code-sandbox-wasmtime")]
pub mod quickjs;
/// Fuel-limited Component Model request boundary (no WASI).
#[cfg(feature = "code-sandbox-wasmtime")]
pub mod wasmtime_boundary;
/// Typed Component Model adapter shared with the canonical CODE host boundary.
#[cfg(feature = "code-sandbox-wasmtime")]
pub mod wasmtime_runtime;

pub use self::compiled_backends::{CompiledSandboxBackends, SANDBOX_BACKENDS};
