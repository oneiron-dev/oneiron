//! A proposed file's bytes, spooled to an anonymous host temp file as they
//! arrive. A foreign guest streams a file of any size in frames; the host
//! never holds it whole, and review reads only the ranges it needs.
//!
//! A body spooled on a host's measured spool ([`SandboxProposalBody::spool_floored`])
//! admits each append on the shared disk floor before writing it (FIX 7650).
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::proposal::body::*;

#[doc(hidden)]
pub mod text;

pub use text::CodeSandboxProposalBodyTextSandboxProposalTextExt;
