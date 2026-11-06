//! Per-vault admission state for speculative retrieval passes.

use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;

use oneiron_base::work_line::WorkLine;

/// The speculative passes running on threads of their own in one vault. A
/// pass past its deadline keeps its read snapshot, and with it a reader
/// slot, until its next checkpoint, so fires that keep missing a stalled
/// stage would otherwise take every slot the vault has.
#[derive(Default)]
pub struct SpeculativePasses {
    pub line: OnceLock<WorkLine<[u8; 32]>>,
    pub last_cap: AtomicUsize,
}
