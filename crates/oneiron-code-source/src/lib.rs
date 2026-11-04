//! Host-side preparation of a code-mode program in the oneiron engine:
//! TypeScript stripped by Oxc in process, JavaScript passed through byte for
//! byte. The `oneiron` crate re-exports `source` at its old
//! `oneiron::code_sandbox::source` path; the sandbox runtimes stay there.

pub mod source;

// The engine error type, as `crate::{Error, Result}` names it in `source`.
pub(crate) use oneiron_base::error::{Error, Result};
