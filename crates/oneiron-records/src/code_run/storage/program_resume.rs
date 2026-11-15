//! Moved from `crates/oneiron/src/code_run/storage/program_resume.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How a later entry answers one listed call (FIX 5878).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramResumeKind {
    /// Its row answers it whole: a call, or a callable whose body ended
    /// before the entry parked. A callable's own calls are not listed: its
    /// row's answer stands for them.
    #[default]
    Settled,
    /// A callable whose body unwound on the wait the entry parked on: it
    /// had not returned. Its own calls follow it, up to that wait. A later
    /// entry runs its body again, its own calls answered from those rows,
    /// the wait's from its delivered reply.
    OpenCallable,
    /// A callable a later entry cannot answer from its row, nor run again:
    /// its body returned past the entry's wait, the bridge halted inside it,
    /// or its own calls stored outputs. A later entry holds on it.
    HeldCallable,
}
