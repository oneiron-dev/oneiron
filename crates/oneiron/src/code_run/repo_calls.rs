//! The run repo rows as typed calls (FIX 6867, L11 G1 PR2a, PR2b): one
//! variant a row, carrying that row's closed input exactly as the guest gave it. The
//! actor, the lease, the TASK, the executor run and the read lane are the
//! host's, bound at dispatch; none rides the call, its replay row or a verb
//! hook's rewrite.

use serde_json::Value;

use super::SelfEffect;
use crate::EntityId;
use crate::error::{Error, Result};
use crate::memory::repo_doors::{
    RepoMergeQueueEnqueueInput, RepoMergeQueueObserveInput, RepoProposalSubmitInput,
    RepoSnapshotsGetInput, RepoSnapshotsIngestInput, RepoSnapshotsReadInput,
    RepoSymbolsDeclareInput, RepoSymbolsDefinitionsInput, RepoSymbolsReleaseInput,
    RepoSymbolsRenewInput, RepoViewsGetInput, RepoViewsReadInput, RepoWorkOpenInput,
};
use crate::task_verb::sdk::RunVerb;

/// One run repo row's call. It serializes as its input alone: the row is
/// its effect's label.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(untagged)]
pub enum RepoRunCall {
    /// `self.code.snapshots.get`.
    SnapshotsGet(RepoSnapshotsGetInput),
    /// `self.code.snapshots.read`.
    SnapshotsRead(RepoSnapshotsReadInput),
    /// `self.code.symbols.definitions`.
    SymbolsDefinitions(RepoSymbolsDefinitionsInput),
    /// `self.code.views.get`.
    ViewsGet(RepoViewsGetInput),
    /// `self.code.views.read`.
    ViewsRead(RepoViewsReadInput),
    /// `self.code.merge_queue.observe`.
    MergeQueueObserve(RepoMergeQueueObserveInput),
    /// `self.code.snapshots.ingest`.
    SnapshotsIngest(RepoSnapshotsIngestInput),
    /// `self.code.work.open`.
    WorkOpen(RepoWorkOpenInput),
    /// `self.code.symbols.declare`.
    SymbolsDeclare(RepoSymbolsDeclareInput),
    /// `self.code.symbols.renew`.
    SymbolsRenew(RepoSymbolsRenewInput),
    /// `self.code.symbols.release`.
    SymbolsRelease(RepoSymbolsReleaseInput),
    /// `self.code.proposal_submit`.
    ProposalSubmit(RepoProposalSubmitInput),
    /// `self.code.merge_queue.enqueue`.
    MergeQueueEnqueue(RepoMergeQueueEnqueueInput),
}

impl RepoRunCall {
    /// The effect, one a row, whose label is the row's name.
    #[must_use]
    pub const fn effect(&self) -> SelfEffect {
        match self {
            Self::SnapshotsGet(_) => SelfEffect::RepoSnapshotsGet,
            Self::SnapshotsRead(_) => SelfEffect::RepoSnapshotsRead,
            Self::SymbolsDefinitions(_) => SelfEffect::RepoSymbolsDefinitions,
            Self::ViewsGet(_) => SelfEffect::RepoViewsGet,
            Self::ViewsRead(_) => SelfEffect::RepoViewsRead,
            Self::MergeQueueObserve(_) => SelfEffect::RepoMergeQueueObserve,
            Self::SnapshotsIngest(_) => SelfEffect::RepoSnapshotsIngest,
            Self::WorkOpen(_) => SelfEffect::RepoWorkOpen,
            Self::SymbolsDeclare(_) => SelfEffect::RepoSymbolsDeclare,
            Self::SymbolsRenew(_) => SelfEffect::RepoSymbolsRenew,
            Self::SymbolsRelease(_) => SelfEffect::RepoSymbolsRelease,
            Self::ProposalSubmit(_) => SelfEffect::RepoProposalSubmit,
            Self::MergeQueueEnqueue(_) => SelfEffect::RepoMergeQueueEnqueue,
        }
    }

    /// Whether the call writes: its row's transport scope, which confers no
    /// repo edit of its own.
    #[must_use]
    pub const fn writes(&self) -> bool {
        self.effect().repo_writes()
    }

    /// The run's own work the call names, for a row on one.
    #[must_use]
    pub(crate) const fn work(&self) -> Option<EntityId> {
        match self {
            Self::ViewsGet(RepoViewsGetInput { work })
            | Self::ViewsRead(RepoViewsReadInput { work, .. })
            | Self::MergeQueueObserve(RepoMergeQueueObserveInput { work })
            | Self::SymbolsDeclare(RepoSymbolsDeclareInput { work, .. })
            | Self::SymbolsRenew(RepoSymbolsRenewInput { work, .. })
            | Self::SymbolsRelease(RepoSymbolsReleaseInput { work, .. })
            | Self::ProposalSubmit(RepoProposalSubmitInput { work, .. })
            | Self::MergeQueueEnqueue(RepoMergeQueueEnqueueInput { work, .. }) => Some(*work),
            Self::SnapshotsGet(_)
            | Self::SnapshotsRead(_)
            | Self::SymbolsDefinitions(_)
            | Self::SnapshotsIngest(_)
            | Self::WorkOpen(_) => None,
        }
    }

    /// The call a run repo row's JSON input makes; `None` for a row that is
    /// none of them.
    pub(crate) fn decode(verb: RunVerb, input: Value) -> Result<Option<Self>> {
        Ok(Some(match verb {
            RunVerb::SelfCodeSnapshotsGet => Self::SnapshotsGet(typed(input)?),
            RunVerb::SelfCodeSnapshotsRead => Self::SnapshotsRead(typed(input)?),
            RunVerb::SelfCodeSymbolsDefinitions => Self::SymbolsDefinitions(typed(input)?),
            RunVerb::SelfCodeViewsGet => Self::ViewsGet(typed(input)?),
            RunVerb::SelfCodeViewsRead => Self::ViewsRead(typed(input)?),
            RunVerb::SelfCodeMergeQueueObserve => Self::MergeQueueObserve(typed(input)?),
            RunVerb::SelfCodeSnapshotsIngest => Self::SnapshotsIngest(typed(input)?),
            RunVerb::SelfCodeWorkOpen => Self::WorkOpen(typed(input)?),
            RunVerb::SelfCodeSymbolsDeclare => Self::SymbolsDeclare(typed(input)?),
            RunVerb::SelfCodeSymbolsRenew => Self::SymbolsRenew(typed(input)?),
            RunVerb::SelfCodeSymbolsRelease => Self::SymbolsRelease(typed(input)?),
            RunVerb::SelfCodeProposalSubmit => Self::ProposalSubmit(typed(input)?),
            RunVerb::SelfCodeMergeQueueEnqueue => Self::MergeQueueEnqueue(typed(input)?),
            _ => return Ok(None),
        }))
    }

    /// A verb hook's rewrite of this call, decoded as the guest's input is
    /// and only into the same row: a hook cannot turn a read into a write
    /// or name a binding.
    pub(crate) fn rewrite(&self, args: &Value) -> std::result::Result<Self, String> {
        Ok(match self {
            Self::SnapshotsGet(_) => Self::SnapshotsGet(retyped(args)?),
            Self::SnapshotsRead(_) => Self::SnapshotsRead(retyped(args)?),
            Self::SymbolsDefinitions(_) => Self::SymbolsDefinitions(retyped(args)?),
            Self::ViewsGet(_) => Self::ViewsGet(retyped(args)?),
            Self::ViewsRead(_) => Self::ViewsRead(retyped(args)?),
            Self::MergeQueueObserve(_) => Self::MergeQueueObserve(retyped(args)?),
            Self::SnapshotsIngest(_) => Self::SnapshotsIngest(retyped(args)?),
            Self::WorkOpen(_) => Self::WorkOpen(retyped(args)?),
            Self::SymbolsDeclare(_) => Self::SymbolsDeclare(retyped(args)?),
            Self::SymbolsRenew(_) => Self::SymbolsRenew(retyped(args)?),
            Self::SymbolsRelease(_) => Self::SymbolsRelease(retyped(args)?),
            Self::ProposalSubmit(_) => Self::ProposalSubmit(retyped(args)?),
            Self::MergeQueueEnqueue(_) => Self::MergeQueueEnqueue(retyped(args)?),
        })
    }
}

/// Every run repo effect, in row order.
const REPO_EFFECTS: [SelfEffect; 13] = [
    SelfEffect::RepoSnapshotsGet,
    SelfEffect::RepoSnapshotsRead,
    SelfEffect::RepoSymbolsDefinitions,
    SelfEffect::RepoViewsGet,
    SelfEffect::RepoViewsRead,
    SelfEffect::RepoMergeQueueObserve,
    SelfEffect::RepoSnapshotsIngest,
    SelfEffect::RepoWorkOpen,
    SelfEffect::RepoSymbolsDeclare,
    SelfEffect::RepoSymbolsRenew,
    SelfEffect::RepoSymbolsRelease,
    SelfEffect::RepoProposalSubmit,
    SelfEffect::RepoMergeQueueEnqueue,
];

impl SelfEffect {
    /// Whether this is a run repo row's effect (FIX 6867).
    #[must_use]
    pub const fn is_repo(self) -> bool {
        matches!(
            self,
            Self::RepoSnapshotsGet
                | Self::RepoSnapshotsRead
                | Self::RepoSymbolsDefinitions
                | Self::RepoViewsGet
                | Self::RepoViewsRead
                | Self::RepoMergeQueueObserve
                | Self::RepoSnapshotsIngest
                | Self::RepoWorkOpen
                | Self::RepoSymbolsDeclare
                | Self::RepoSymbolsRenew
                | Self::RepoSymbolsRelease
                | Self::RepoProposalSubmit
                | Self::RepoMergeQueueEnqueue
        )
    }

    /// Whether this is a run repo row that writes: the import, the open,
    /// the symbol declarations, the proposal and the queue entry.
    #[must_use]
    pub const fn repo_writes(self) -> bool {
        matches!(
            self,
            Self::RepoSnapshotsIngest
                | Self::RepoWorkOpen
                | Self::RepoSymbolsDeclare
                | Self::RepoSymbolsRenew
                | Self::RepoSymbolsRelease
                | Self::RepoProposalSubmit
                | Self::RepoMergeQueueEnqueue
        )
    }

    /// The run repo effect a replay row's label names.
    pub(crate) fn repo_from_label(label: &str) -> Option<Self> {
        REPO_EFFECTS
            .iter()
            .copied()
            .find(|effect| effect.as_str() == label)
    }
}

/// A run repo row's closed input from its JSON.
fn typed<T: serde::de::DeserializeOwned>(input: Value) -> Result<T> {
    serde_json::from_value(input)
        .map_err(|_| Error::InvalidConfig("invalid typed component arguments".to_owned()))
}

/// A verb hook's rewrite of one row's input, decoded as the guest's is.
fn retyped<T: serde::de::DeserializeOwned>(args: &Value) -> std::result::Result<T, String> {
    serde_json::from_value(args.clone()).map_err(|error| error.to_string())
}
