//! Sandbox boundary contract for code-mode execution.
//!
//! The optional `code-sandbox-wasmtime` boundary instantiates a fresh sandbox. It pins
//! the host/guest ABI that future runners must obey: plain JavaScript runs
//! inside a QuickJS-class interpreter embedded as a WASM component in the
//! existing Wasmtime/WIT boundary, guests target stable `/mnt` virtual paths,
//! clock/random are deterministic host imports, credential use is handle-only,
//! first-party writes are linked as typed traps, and foreign writes leave the
//! sandbox as reviewable proposal deltas rather than commit authority.
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::*;

#[doc(hidden)]
pub mod adapter;
mod contract;
mod credential;
/// A guest program's own error text, masked before it leaves the host (FIX 9209).
pub mod guest_error;
mod paths;

pub use self::adapter::FakeSandboxAdapter;
pub use self::contract::SandboxLinkedImportEffects;
pub use guest_error::CodeSandboxGuestErrorGuestProgramErrorExt;
