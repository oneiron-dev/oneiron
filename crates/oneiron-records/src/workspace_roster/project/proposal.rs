//! Moved from `crates/oneiron/src/workspace_roster/project/proposal.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::workspace_roster::project::proposal::ProjectCardConfirmRequest;
pub use oneiron_verb_wire::workspace_roster::project::proposal::ProjectProposalRequest;
use serde::Deserialize;
use serde::Serialize;

/// What the project question answered on one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectDetectionAnswer {
    /// Yes: the house mind drafts a card.
    Yes,
    /// The ladder asked a person; the source stays pending. A person's yes to
    /// the question is not the mint tap.
    AskedPerson,
}

/// Where a host-held card stands. A dismissed card never mints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectCardState {
    Proposed,
    Minted { project: EntityId },
    Dismissed,
}
