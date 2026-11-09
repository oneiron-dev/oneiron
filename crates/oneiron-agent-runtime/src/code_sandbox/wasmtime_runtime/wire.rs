//! Internal bounded JSON bridge between typed WIT and the borrowed engine host.
//!
//! Lifted half (core split, `oneiron-agent-runtime`): the modules and re-exports below moved out of
//! `oneiron`; everything that stays there is re-exported by the glob.

pub use oneiron::code_sandbox::wasmtime_runtime::wire::*;

mod describe;
mod reply;
mod search;

use describe::names_one_target;
use describe::result_ref;
use describe::secret_handle;
use reply::guest_reply;
