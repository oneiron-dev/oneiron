//! Candidate results and the native origin each replay carries.

use serde::{Deserialize, Serialize};

use super::{
    EngineCandidateRun, PublisherCandidate, PublisherCandidateKind, PublisherCandidateRef,
};
use crate::EntityId;
use crate::failure_signals::{CodeFixVerdict, FixOutcome, ReplayFidelity};

/// One candidate's shadow replay: its outcome and its export's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRun {
    pub candidate_id: String,
    /// True only for the candidate this run's Coach drafted, not a publisher pin.
    pub coach_own: bool,
    /// The actual publisher input occurrence, not an external identity.
    /// `None` only for the candidate this run's Coach drafted.
    #[serde(deserialize_with = "Option::deserialize")]
    pub publisher_ref: Option<PublisherCandidateRef>,
    /// `None` when the replay could not run, or did not fail before the fix.
    pub outcome: Option<FixOutcome>,
    pub export: CodeFixVerdict,
    /// How the replay ran the real failure (FIX 1662): the request the
    /// failing call sent, or a call rebuilt from its text. `None` when it
    /// could not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay: Option<ReplayFidelity>,
    /// An engine candidate's matched pair (FIX 1661, 2144), content-free:
    /// its pin, each arm's summary, and whether it was judged or why not.
    /// `None` for an instruction, and for a candidate whose failure no
    /// longer stood.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineCandidateRun>,
    /// The Grant an instruction's exact replay read the kept request under
    /// (FIX 9448): its keep is rechecked against that Grant alone. `None`
    /// for an engine pair, which holds its own, and for any other run.
    pub grant: Option<EntityId>,
}

impl CandidateRun {
    pub(super) fn matches_publisher(
        &self,
        id: &str,
        publisher_ref: Option<&PublisherCandidateRef>,
    ) -> bool {
        !self.coach_own
            && self.candidate_id == id
            && publisher_ref.is_some()
            && self.publisher_ref.as_ref() == publisher_ref
    }

    /// Whether this run stands for its candidate: every run does but an
    /// engine pair kept not run at another shadow protocol, or kept for want
    /// of the Coach's Grant when `read_granted` says that Grant now reads
    /// the run's scope; each is tried once more (FIX 1661, 2144, 7031).
    pub(super) fn tried(&self, read_granted: bool) -> bool {
        self.engine
            .as_ref()
            .is_none_or(|engine| !engine.retries(read_granted))
    }
}

/// One actual candidate, before its replay: identity is not inferred from its id.
#[derive(Clone)]
pub(super) struct ReplayCandidate {
    pub(super) id: String,
    pub(super) kind: PublisherCandidateKind,
    pub(super) coach_own: bool,
    pub(super) publisher_ref: Option<PublisherCandidateRef>,
}

impl ReplayCandidate {
    pub(super) fn publisher(
        candidate: &PublisherCandidate,
        publisher_ref: PublisherCandidateRef,
    ) -> Self {
        Self {
            id: candidate.id.clone(),
            kind: candidate.kind.clone(),
            coach_own: false,
            publisher_ref: Some(publisher_ref),
        }
    }
}
