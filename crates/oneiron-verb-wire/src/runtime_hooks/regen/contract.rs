//! Moved from `crates/oneiron/src/runtime_hooks/regen/contract.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::pack_hook_proposal::HookPhase;
use crate::store::pack_hook_proposal::HookSelector;
use std::collections::BTreeSet;
use std::collections::VecDeque;

/// The code-mode declarations a hook body's verb shapes come from: the verb
/// table half of [`super::HookContractStamp`].
pub const VERB_TABLE: &str = include_str!(concat!(env!("OUT_DIR"), "/code-mode.d.ts"));

/// The hook world: the sandbox half of [`super::HookContractStamp`].
pub const HOOK_WORLD: &str = include_str!("../../../wit/hook/hook.wit");
