//! The run repo rows as typed calls (FIX 6867, L11 G1 PR2a): one variant a
//! row, carrying that row's closed input exactly as the guest gave it. The
//! actor, the lease, the TASK, the executor run and the read lane are the
//! host's, bound at dispatch; none rides the call, its replay row or a verb
//! hook's rewrite.

use serde_json::Value;

use super::SelfEffect;
use crate::error::{Error, Result};
use crate::memory::repo_doors::{
    RepoMergeQueueObserveInput, RepoSnapshotsGetInput, RepoSnapshotsIngestInput,
    RepoSnapshotsReadInput, RepoSymbolsDefinitionsInput, RepoViewsGetInput, RepoViewsReadInput,
    RepoWorkOpenInput,
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
        }
    }

    /// Whether the call writes: its row's transport scope, which confers no
    /// repo edit of its own.
    #[must_use]
    pub const fn writes(&self) -> bool {
        self.effect().repo_writes()
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
        })
    }
}

/// Every run repo effect, in row order.
const REPO_EFFECTS: [SelfEffect; 8] = [
    SelfEffect::RepoSnapshotsGet,
    SelfEffect::RepoSnapshotsRead,
    SelfEffect::RepoSymbolsDefinitions,
    SelfEffect::RepoViewsGet,
    SelfEffect::RepoViewsRead,
    SelfEffect::RepoMergeQueueObserve,
    SelfEffect::RepoSnapshotsIngest,
    SelfEffect::RepoWorkOpen,
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
        )
    }

    /// Whether this is a run repo row that writes: the import and the open.
    #[must_use]
    pub const fn repo_writes(self) -> bool {
        matches!(self, Self::RepoSnapshotsIngest | Self::RepoWorkOpen)
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
