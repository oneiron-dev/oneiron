//! OF-366 tournament claim-authoring runner primitives.
//!
//! The tournament is modeled as extra Dreamer run-tree steps. This module
//! keeps the steps deterministic and fixture-friendly: callers supply an
//! explicit OF-267 author fork artifact, MC-1 critique artifacts, typed
//! synthesis outputs, optional LMX weave output, and blind Borda ballots. The
//! winner is persisted through the normal claim-candidate write path.

mod evidence;
mod run;
mod types;
mod validate;

pub use self::evidence::DreamerTournamentEvidenceStore;
pub use self::run::run_dreamer_claim_tournament;
pub use self::types::{
    DREAMER_TOURNAMENT_BRANCH_EVIDENCE_SCHEMA_VERSION, DREAMER_TOURNAMENT_MAX_FANOUT_M,
    DREAMER_TOURNAMENT_MAX_ROUNDS_K, DREAMER_TOURNAMENT_MIN_FANOUT_M, DreamerTournamentAuthorFork,
    DreamerTournamentBlindJudgeContext, DreamerTournamentBordaBallot, DreamerTournamentBranch,
    DreamerTournamentBranchEvidence, DreamerTournamentBranchVerdict, DreamerTournamentCandidate,
    DreamerTournamentCandidateIdentity, DreamerTournamentJudgeClaim, DreamerTournamentRound,
    DreamerTournamentRun, DreamerTournamentRunResult, DreamerTournamentStopReason,
    DreamerTournamentSynthesisArtifact, DreamerTournamentSynthesisVerdict,
    DreamerTournamentWeaveArtifact, DreamerTournamentWinner,
};

#[cfg(test)]
mod tests;

// The flat dreamer_tournament.rs module used to provide these names to the
// sibling test module through `use super::*`: its own private crate import
// header. Every dreamer_tournament-internal item the tests name bare is
// already re-exported above, so only the crate names need re-importing for
// `tests.rs` to resolve exactly as it did before.
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::attempt_queue::AttemptId;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::Result;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::{ClaimCandidate, WriteEnvelope};
