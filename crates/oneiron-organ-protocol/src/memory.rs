//! The `memory.grow` ask (FIX 7654): an organ reserves the memory its own
//! buffers are about to take, before it allocates them.
//!
//! The engine's host takes the bytes from the machine's memory floor and
//! holds them in the call's room, apart from the bytes its answers hold, until
//! the call ends. Nothing gives them back earlier: the protocol has no
//! release, so what an organ reserved stays reserved while its call lives.
//! The answer is typed: granted, the machine's floor, or the call's deadline.
//! No count or size of the organ's own refuses an ask (Rule 5).
//!
//! It is an ask, not a frame kind: it rides the 1.1 asks as `net.fetch` does,
//! and the install grant names it.

use serde::{Deserialize, Serialize};

/// The memory ask: an organ's own buffers, reserved before it allocates them.
pub const ASK_MEMORY_GROW: &str = "memory.grow";

/// The value of a `memory.grow` ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryAsk {
    /// The bytes the organ is about to allocate, past what it has reserved.
    pub bytes: u64,
}

/// The value of a `memory.grow` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAnswer {
    /// Reserved until the call ends.
    Granted,
    /// The machine cannot hold `needed` bytes: past the memory it keeps
    /// free, it has `available` for them at most.
    Floor { needed: u64, available: u64 },
    /// The bytes did not fit before the call's deadline.
    Deadline,
}
