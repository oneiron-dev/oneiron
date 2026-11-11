//! `oneiron-agent-runtime`: the sandbox backends above the `oneiron` core
//! crate (core split slice 5b.1). Core keeps the sandbox contract and the
//! selection law, and reaches these backends only through its traits:
//! `oneiron::code_sandbox::microvm::SandboxBackends` (implemented here by
//! [`code_sandbox::CompiledSandboxBackends`], which a host installs on each
//! vault it builds), `MicroVmBackend` and
//! `oneiron::engine_executor::JsCodeModeRuntime`.
//!
//! Every `crate::x` path in the moved code resolves through the glob below to
//! `oneiron::x`, unless this crate defines `x`; `crate::code_sandbox` is this
//! crate's own module, which re-exports core's `code_sandbox` beside the
//! backends.
#![deny(ambiguous_glob_reexports, hidden_glob_reexports)]

#[allow(unused_imports)]
pub(crate) use oneiron::*;

pub mod code_sandbox;
