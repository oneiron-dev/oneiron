//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/code_fix.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::dreamer_runner::maintenance::code_fix::publisher::EngineAdmission;
pub use crate::dreamer_runner::maintenance::code_fix::publisher::EngineArm;
pub use crate::dreamer_runner::maintenance::code_fix::publisher::EngineCallUsage;
pub use crate::dreamer_runner::maintenance::code_fix::publisher::PublisherCandidateKind;
pub use crate::dreamer_runner::maintenance::code_fix::publisher_refs::PublisherCandidateInput;
pub use crate::dreamer_runner::maintenance::code_fix::publisher_refs::PublisherCandidateRef;
pub use crate::dreamer_runner::maintenance::code_fix::publisher_refs::publisher_candidates_with_refs;

/// A candidate fix the deployment's publisher supplied and its operator
/// pinned: an instruction the replay adds to the failing agent's own, or an
/// engine build or patch the host's shadow runner runs in a sandboxed arm
/// (FIX 1661, 2144). It is tried in the vault only; nothing fetches or
/// installs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherCandidate {
    /// The token its result exports under, naming the pinned artifact by its
    /// whole digest.
    pub id: String,
    /// What it is.
    pub kind: PublisherCandidateKind,
}
pub mod publisher;
pub mod publisher_refs;
