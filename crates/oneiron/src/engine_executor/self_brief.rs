//! The host's self-brief port for a native run (FIX 17594, delivery slice D2).
//! Entry trait: `SelfBriefPort`; the executor binds it with
//! `EngineNativeExecutor::with_self_brief`.
//!
//! A host that keeps a run's self brief lends the executor this port. The
//! executor asks it for the brief's prefix at the run's birth, its first
//! model request in this executor's life, and again past each fold batch
//! the run commits (Engine call B, 00:04): an epoch swap with its epoch,
//! summary and steps, and a batch of marked folds or folds by kind with the
//! folds it committed. The prefix rides every request of the run right
//! after its task, the same bytes until the next boundary, a request sent
//! again included. Once the backend answers a request that carried it, the
//! executor tells the host the prefix was delivered (Engine call C).
//!
//! The port exchanges only these typed values and rendered text: no server
//! type crosses it. A turn program's pinned entry binds none, and makes no
//! model turn for one (Engine call A).

use std::collections::VecDeque;

use super::driver::EngineNativeExecutor;
use super::types::{EngineExecutorResult, EngineExecutorStatus};
use crate::{EntityId, LlmRequest};

/// The host's side of a native run's self brief.
///
/// The executor calls it on its own thread, between model requests; a host
/// whose custody lives on another runtime blocks on it there, as its
/// [`crate::code_run::AgentVerbDoor`] calls do.
pub trait SelfBriefPort: Send + Sync {
    /// The prefix the run's requests carry from `boundary` on: the rendered
    /// text, the rows it was derived from and the host's token for it.
    /// `None` when the host has no brief: the requests carry none. A refusal
    /// stops the run before its request is sent; the next request asks again
    /// at the same boundary.
    ///
    /// # Errors
    ///
    /// The host could not prepare the prefix.
    fn prepare(&self, boundary: BriefBoundary) -> crate::Result<Option<BriefPrefix>>;

    /// The backend answered a request that carried the prefix `token` names.
    /// Called once per prepared prefix, at the first such answer.
    fn delivered(&self, token: BriefCandidateToken);

    /// The run just committed the fold batch `boundary`, before any request
    /// carries it. Called as the batch lands, so a host can move its own
    /// brief boundary at once and keep it across an entry that ends before
    /// its next request (a full window, a parked hook); the executor still
    /// asks [`Self::prepare`] for the fold before its next request.
    fn folded(&self, _boundary: &FoldBoundary) {}
}

/// Why the executor asks its host for a prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BriefBoundary {
    /// The run's first model request in this executor's life. A fold the run
    /// committed before it is already in what the host reads for it.
    Birth { run_id: EntityId },
    /// A fold batch the run committed since its prefix was last prepared.
    Fold(FoldBoundary),
}

/// One fold batch a run committed, with the identities it committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoldBoundary {
    /// An epoch swap: the epoch its summary was minted at, the summary, and
    /// the first and last steps it covers.
    Epoch {
        run_id: EntityId,
        epoch: u64,
        summary_id: EntityId,
        first_step: u64,
        last_step: u64,
    },
    /// A batch of marked folds or folds by kind: each fold it committed, in
    /// landing order. A fold already in the run's ledger is no part of it.
    Folds { run_id: EntityId, folds: Vec<u64> },
}

impl FoldBoundary {
    /// The boundary of a batch that committed `folds` on run `run_id`;
    /// `None` when it committed none (a batch of failed marks only).
    pub(super) fn landed(run_id: EntityId, folds: Vec<u64>) -> Option<Self> {
        (!folds.is_empty()).then(|| Self::Folds { run_id, folds })
    }
}

/// A prefix the host prepared for a run's requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BriefPrefix {
    /// The rendered brief, sent as it is, as one message of its own.
    pub text: String,
    /// The rows the brief was derived from: they join the source rows of
    /// each request that carries it.
    pub sources: Vec<EntityId>,
    /// The host's own name for this prefix, handed back when it is delivered.
    pub token: BriefCandidateToken,
}

/// The host's name for one prepared prefix: opaque to the executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BriefCandidateToken(pub u64);

/// The executor's side of a bound port: the run it was born for, the prefix
/// its requests carry, and the fold batches committed since that prefix was
/// prepared.
pub(super) struct NativeBrief<'a> {
    port: &'a dyn SelfBriefPort,
    born: Option<EntityId>,
    current: Option<HeldPrefix>,
    pending: VecDeque<FoldBoundary>,
}

/// The prefix a run's requests carry, and whether the host was told of its
/// delivery.
struct HeldPrefix {
    prefix: BriefPrefix,
    delivered: bool,
}

impl HeldPrefix {
    fn new(prefix: BriefPrefix) -> Self {
        Self {
            prefix,
            delivered: false,
        }
    }
}

impl<'a> NativeBrief<'a> {
    pub(super) fn new(port: &'a dyn SelfBriefPort) -> Self {
        Self {
            port,
            born: None,
            current: None,
            pending: VecDeque::new(),
        }
    }

    /// Brings the held prefix to the run's current boundary: birth for a run
    /// this executor has not asked about, then each fold batch committed and
    /// not yet prepared, in commit order. A host may answer birth with the
    /// prefix it already delivered (a run entering again), so a batch that
    /// landed at this entry still asks for its own fold. A boundary leaves
    /// the queue only once its prefix was prepared, so a refusal asks again
    /// at the same one.
    fn prepare_for(&mut self, run_id: EntityId) -> crate::Result<()> {
        if self.born != Some(run_id) {
            let prefix = self.port.prepare(BriefBoundary::Birth { run_id })?;
            self.current = prefix.map(HeldPrefix::new);
            self.born = Some(run_id);
        }
        while let Some(fold) = self.pending.front() {
            let prefix = self.port.prepare(BriefBoundary::Fold(fold.clone()))?;
            self.pending.pop_front();
            self.current = prefix.map(HeldPrefix::new);
        }
        Ok(())
    }
}

impl EngineNativeExecutor<'_> {
    /// The brief this request carries, right after its task: the host's
    /// prefix as it stands at the run's current boundary, the same bytes on
    /// every request until the next one. `None` with no port bound, or when
    /// the host has no brief.
    pub(super) fn brief_prefix_text(
        &mut self,
        run_id: EntityId,
    ) -> EngineExecutorResult<Option<String>> {
        let Some(brief) = self.self_brief.as_mut() else {
            return Ok(None);
        };
        brief.prepare_for(run_id)?;
        Ok(brief.current.as_ref().map(|held| held.prefix.text.clone()))
    }

    /// The rows the brief this request carries was derived from: none when
    /// it carries none.
    pub(super) fn brief_source_rows(&self) -> Vec<EntityId> {
        self.self_brief
            .as_ref()
            .and_then(|brief| brief.current.as_ref())
            .map_or_else(Vec::new, |held| held.prefix.sources.clone())
    }

    /// A fold batch the run committed: the next request's brief is prepared
    /// past it. With no port bound, nothing is kept.
    pub(super) fn brief_fold_committed(&mut self, boundary: FoldBoundary) {
        if let Some(brief) = self.self_brief.as_mut() {
            // The host hears of the batch as it lands, so the boundary
            // outlives this executor if the entry ends before a request.
            brief.port.folded(&boundary);
            brief.pending.push_back(boundary);
        }
    }

    /// The backend answered the request just sent, which carried the held
    /// prefix: the host is told it was delivered, once per prefix.
    pub(super) fn brief_delivered(&mut self) {
        let Some(brief) = self.self_brief.as_mut() else {
            return;
        };
        if let Some(held) = brief.current.as_mut()
            && !held.delivered
        {
            held.delivered = true;
            brief.port.delivered(held.prefix.token);
        }
    }

    /// The by-kind ordering trap (map §2.2): a batch of folds by kind the
    /// token feed landed with no backend pass is a brief boundary that came
    /// after `request` was built. With a port bound, `build` builds the
    /// request again, past the fold and with the brief its host prepares
    /// for it, and its size is fed again, before it is hashed, captured or
    /// sent: no request from before a fold goes out with a brief from after
    /// it. Returns the status a full window parks the run on.
    pub(super) fn refresh_brief_request(
        &mut self,
        request: &mut LlmRequest,
        completed_steps: u64,
        build: impl FnOnce(&mut Self) -> EngineExecutorResult<LlmRequest>,
    ) -> EngineExecutorResult<Option<EngineExecutorStatus>> {
        if !self
            .self_brief
            .as_ref()
            .is_some_and(|brief| !brief.pending.is_empty())
        {
            return Ok(None);
        }
        *request = build(&mut *self)?;
        let used = super::compaction::request_tokens(request);
        Ok(self
            .compaction
            .as_deref_mut()
            .and_then(|seat| seat.recount(used))
            .map(|reason| EngineExecutorStatus::WindowFull {
                next_step_seq: completed_steps,
                reason,
            }))
    }
}
