//! What each verb hook bound to a read did in an off-record room, as the
//! read's answer says it (WILL L11-01 S01-2c, FIX 5160; CALLS-9
//! `session_hook_meta_shape`).
//!
//! A hook bound to a read runs in a room as it runs on base. Its receipt
//! stages in the room's own store, and its outcome applies whether the room
//! keeps that receipt or not: the read answers either way, and the answer
//! names each hook's disposition, so a hook the room could not keep a record
//! for is never silent. The run's search with no key also answers when the
//! hooks bound to it could not be read, and says so (Engine 10-19 17:1x).
//! Outside a room the list is empty.

use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_records::code_run::types::session_hooks::{
    SessionHookDisposition, SessionHookNotKept, SessionHookPhase, SessionHookReceipt,
    SessionHookState,
};
