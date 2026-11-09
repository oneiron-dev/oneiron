//! The proposal-delta channel a guest write becomes instead of a direct mutation.
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::proposal::*;

mod spool;
mod spooled_edit;

