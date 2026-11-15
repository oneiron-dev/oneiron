//! Moved from `crates/oneiron/src/memory/repo_doors/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoMergeQueueEnqueueInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoMergeQueueObserveInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoMergeQueueObserveOutput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoProposalResolveInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoProposalSubmitInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoProposalSubmitOutput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoQueueEntryView;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoQueueSuccessor;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSnapshotView;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSnapshotsReadOutput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSymbolDeclarationView;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSymbolsDeclareInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSymbolsDefinitionsOutput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSymbolsObserveInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSymbolsReleaseInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSymbolsReleaseOutput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoSymbolsRenewInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoViewsGetInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoViewsReadInput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoViewsReadOutput;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoWorkFile;
pub use oneiron_verb_wire::memory::repo_doors::types::RepoWorkView;
use serde::Deserialize;
use serde::Serialize;

/// The run a work belongs to, bound in the receipt's first write (PREMISE
/// 2): the leased try, the executor run, the TASK, the repo and ref the
/// Grant admitted, and the pinned base. Evidence a later door compares with
/// its own binding, never a lease: no door rebuilds a host binding from it.
/// The actor is the receipt's own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoRunStamp {
    pub attempt: AttemptId,
    pub lease_owner: String,
    pub generation: u32,
    pub executor_run: EntityId,
    pub task: EntityId,
    pub project: EntityId,
    pub repo: EntityId,
    pub grant: EntityId,
    #[serde(rename = "ref")]
    pub git_ref: String,
    pub base_green: String,
    /// The pinned base snapshot's hash.
    pub base_snapshot: [u8; 32],
    /// The work id: the view id the stamp was bound with.
    pub work: EntityId,
    /// The run's symbol declaration a proposal was made under (FIX 6867,
    /// G1 PR2b): `None` on a work's own stamp and on a proposal made with
    /// none.
    pub symbol_fence: Option<EntityId>,
}
