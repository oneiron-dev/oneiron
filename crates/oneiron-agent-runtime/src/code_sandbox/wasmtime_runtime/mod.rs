//! Pinned, in-process Component Model execution for host-trusted code.
//!
//! The host supplies a QuickJS component implementing the canonical `wit/code-run.wit`, not guest
//! machine code. `from_component` also accepts a compatible bounded component
//! (for example an ABI conformance fixture); it makes no QuickJS provenance
//! claim. No WASI, environment, filesystem or network imports are linked.
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::wasmtime_runtime::*;

mod isolated;
mod typed;

use super::guest_error::guest_failure;
