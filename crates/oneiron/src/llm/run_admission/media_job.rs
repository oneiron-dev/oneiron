//! A media job's polls and its cancel, bound to the call that started the
//! job (FIX 9923). A gate's submit binds the job the provider started to the
//! permit it started on, and a resume after a restart binds the kept job to
//! the permit admitted afresh for it. The permit was started at this gate,
//! so its model, route, locality and offer are this gate's. A poll or a
//! cancel then goes out only for that job, that model and that permit, while
//! the permit is open and started: another job's permit, or one another
//! offer's gate started, reaches no job here. The bindings live with the
//! gate and are rebuilt from the kept job when a restart takes it up.
//! Entry: `MediaJobBindings::check_media_job_continuation`.
use std::sync::{Mutex, PoisonError};

use super::super::{BudgetLease, FatalLlmError, LlmResult, ModelId};
use super::admission::RunInner;

/// One job this gate started or took up: the permit's lease, the model the
/// call named and the provider's handle for the job.
struct MediaJobBinding {
    lease: String,
    model: ModelId,
    job: String,
}

/// The jobs one gate started or took up.
#[derive(Default)]
pub(super) struct MediaJobBindings {
    bound: Mutex<Vec<MediaJobBinding>>,
}

impl MediaJobBindings {
    /// Binds `job`, which the provider started for a call of `model`, to
    /// `lease`, the permit this gate started for it.
    pub(super) fn bind_media_job(&self, lease: &BudgetLease, model: &ModelId, job: &str) {
        self.bound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(MediaJobBinding {
                lease: lease.id().to_owned(),
                model: model.clone(),
                job: job.to_owned(),
            });
    }

    /// Whether a poll or a cancel of `job` for `model` on `lease` continues
    /// a call this gate started: the lease is `run`'s, open and already
    /// sent, and this gate bound exactly that job and model to it.
    pub(super) fn check_media_job_continuation(
        &self,
        run: &RunInner,
        lease: &BudgetLease,
        model: &ModelId,
        job: &str,
    ) -> LlmResult<()> {
        let bound = self
            .bound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|binding| {
                binding.lease == lease.id() && binding.model == *model && binding.job == job
            });
        let started = bound
            && run.lock_calls().contains_key(lease.id())
            && run.guard.lease_open(lease) == Some(true)
            && run.guard.dispatched(lease) == Some(true);
        if started {
            Ok(())
        } else {
            Err(FatalLlmError::InvalidRequest.into())
        }
    }
}
