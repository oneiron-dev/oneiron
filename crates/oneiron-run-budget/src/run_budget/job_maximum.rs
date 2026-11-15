//! The stop at a paid job's declared maximum (CROSS-ARCH-0023 C2).
//!
//! Nothing in the engine stops a running model. A paid job with a declared
//! maximum is the one exception the owner granted, and only under five
//! conditions, which this contract enforces: the customer set the maximum and
//! saw it at the job's start; a warning reaches the customer at 95 percent; a
//! checkpoint is taken after it, before the stop; the stop carries an add-funds notice; and the job
//! resumes from that checkpoint in one step. The job reserves its whole
//! maximum through `RunAdmission::admit_paid` (`oneiron::llm::run_admission`);
//! a resume takes a fresh admission for the next chunk.
//!
//! Apart from the customer's warning, the job itself is told to checkpoint at
//! 50, 80 and 95 percent of its maximum (lifecycle 04). The state is stored
//! with the job's record, so a host restart keeps the warning, the checkpoint
//! and the stop.
use serde::{Deserialize, Serialize};

use super::declaration::LeaseUnit;

/// The percents of the maximum at which the job is told to checkpoint, lowest
/// first (CROSS-ARCH-0023 lifecycle 04).
const CHECKPOINT_PERCENTS: [u8; 3] = [50, 80, 95];

/// The most a job may use, in its service's unit, as the customer set it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredMaximum {
    pub units: u64,
    pub unit: LeaseUnit,
}

/// When the customer was shown the maximum, in host milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaximumShown {
    pub at_ms: u64,
}

/// Where a job's state was saved, as its connector names it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CheckpointRef(pub String);

/// What a job's usage crossed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum JobSignal {
    /// Usage reached `percent` (50, 80 or 95) of the maximum: the job should
    /// checkpoint now. It goes to the job, not the customer. Returned once per
    /// percent in each chunk; a record that passes several returns the highest.
    CheckpointDue { percent: u8 },
    /// 95 percent of the maximum is used. Returned at each record until the
    /// host confirms it reached the customer.
    Warning95 { used_units: u64, maximum_units: u64 },
    /// The maximum is used up. The job may now be stopped, after a checkpoint.
    AtMaximum,
}

/// The notice the customer gets at the stop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddFundsNotice {
    pub job: String,
    pub used_units: u64,
    pub maximum: DeclaredMaximum,
    pub checkpoint: CheckpointRef,
}

/// The customer's one step back in: the job resumes from its checkpoint. Good
/// for one resume of one stop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeOffer {
    pub job: String,
    pub checkpoint: CheckpointRef,
    stop: u32,
}

/// A stop at the maximum: the checkpoint, the notice and the resume offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaximumStop {
    pub notice: AddFundsNotice,
    pub resume: ResumeOffer,
}

/// Why a job could not start under a maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum JobStartRefused {
    /// A job stops at a maximum only if the customer saw it at the start.
    #[error("the customer was not shown the job's maximum at its start")]
    MaximumNotShown,
    #[error("a job's maximum is more than zero units")]
    ZeroMaximum,
}

/// Why a stop was refused. Each is one of the owner's conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum StopRefused {
    #[error("the job has not reached its maximum")]
    NotAtMaximum,
    #[error("the 95 percent warning has not reached the customer")]
    NoWarning,
    #[error("no checkpoint was taken after the warning")]
    NoCheckpoint,
    #[error("the job is already stopped")]
    Stopped,
}

/// Why a resume was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum ResumeRefused {
    #[error("the job is not stopped at its maximum")]
    NotStopped,
    #[error("the resume offer is for another stop or another job")]
    StaleOffer,
    #[error("a resumed job needs a larger maximum, shown to the customer")]
    MaximumNotRaised,
}

/// One paid job's run against its declared maximum. It is not `Clone`: one
/// state decides the stop and consumes its resume. It is stored with the job's
/// record, so a restarted host takes up the same state.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobMaximum {
    job: String,
    maximum: DeclaredMaximum,
    used_units: u64,
    warning_due: bool,
    warning_delivered: bool,
    checkpoint: Option<CheckpointRef>,
    stops: u32,
    stopped: bool,
    /// The highest checkpoint percent signalled in this chunk, 0 for none.
    checkpoint_percent_signalled: u8,
}

/// The highest checkpoint percent `used_units` has reached under
/// `maximum_units`, or 0 below the first.
fn reached_checkpoint_percent(used_units: u64, maximum_units: u64) -> u8 {
    CHECKPOINT_PERCENTS
        .into_iter()
        .rev()
        .find(|percent| {
            u128::from(used_units) * 100 >= u128::from(maximum_units) * u128::from(*percent)
        })
        .unwrap_or(0)
}

impl JobMaximum {
    /// Starts a job under the maximum the customer set and was shown.
    pub fn start(
        job: impl Into<String>,
        maximum: DeclaredMaximum,
        shown: Option<MaximumShown>,
    ) -> Result<Self, JobStartRefused> {
        if shown.is_none() {
            return Err(JobStartRefused::MaximumNotShown);
        }
        if maximum.units == 0 {
            return Err(JobStartRefused::ZeroMaximum);
        }
        Ok(Self {
            job: job.into(),
            maximum,
            used_units: 0,
            warning_due: false,
            warning_delivered: false,
            checkpoint: None,
            stops: 0,
            stopped: false,
            checkpoint_percent_signalled: 0,
        })
    }

    #[must_use]
    pub fn maximum(&self) -> &DeclaredMaximum {
        &self.maximum
    }

    #[must_use]
    pub fn used_units(&self) -> u64 {
        self.used_units
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Whether the host confirmed the 95 percent warning reached the
    /// customer in this chunk.
    #[must_use]
    pub fn warning_delivered(&self) -> bool {
        self.warning_delivered
    }

    /// The checkpoint that counts for the stop: one taken after the warning
    /// reached the customer, or the one a stopped job resumes from.
    #[must_use]
    pub fn counted_checkpoint(&self) -> Option<&CheckpointRef> {
        self.checkpoint.as_ref()
    }

    /// Records the job's usage so far and returns what it crossed, in this
    /// order: a checkpoint percent, the customer's warning, the maximum.
    pub fn record_usage(&mut self, used_units: u64) -> Vec<JobSignal> {
        self.used_units = self.used_units.max(used_units);
        let mut signals = Vec::new();
        let reached = reached_checkpoint_percent(self.used_units, self.maximum.units);
        if reached > self.checkpoint_percent_signalled {
            self.checkpoint_percent_signalled = reached;
            signals.push(JobSignal::CheckpointDue { percent: reached });
        }
        let warn_at = u128::from(self.maximum.units) * 95;
        if u128::from(self.used_units) * 100 >= warn_at {
            self.warning_due = true;
        }
        if self.warning_due && !self.warning_delivered {
            signals.push(JobSignal::Warning95 {
                used_units: self.used_units,
                maximum_units: self.maximum.units,
            });
        }
        if self.used_units >= self.maximum.units {
            signals.push(JobSignal::AtMaximum);
        }
        signals
    }

    /// The host confirms the 95 percent warning reached the customer. Returns
    /// false, and counts nothing, when no warning is due.
    #[must_use]
    pub fn confirm_warning(&mut self) -> bool {
        if self.warning_due {
            self.warning_delivered = true;
        }
        self.warning_delivered
    }

    /// Records a checkpoint. Only one taken after the warning reached the
    /// customer counts for the stop, and a stopped job keeps the checkpoint
    /// its resume offer names.
    pub fn checkpoint(&mut self, checkpoint: CheckpointRef) {
        if self.warning_delivered && !self.stopped {
            self.checkpoint = Some(checkpoint);
        }
    }

    /// Stops the job at its maximum, once every condition holds.
    pub fn stop_at_maximum(&mut self) -> Result<MaximumStop, StopRefused> {
        if self.stopped {
            return Err(StopRefused::Stopped);
        }
        if self.used_units < self.maximum.units {
            return Err(StopRefused::NotAtMaximum);
        }
        if !self.warning_delivered {
            return Err(StopRefused::NoWarning);
        }
        let checkpoint = self.checkpoint.clone().ok_or(StopRefused::NoCheckpoint)?;
        self.stopped = true;
        self.stops = self.stops.saturating_add(1);
        Ok(MaximumStop {
            notice: AddFundsNotice {
                job: self.job.clone(),
                used_units: self.used_units,
                maximum: self.maximum.clone(),
                checkpoint: checkpoint.clone(),
            },
            resume: ResumeOffer {
                job: self.job.clone(),
                checkpoint,
                stop: self.stops,
            },
        })
    }

    /// Resumes a stopped job from its checkpoint under a larger maximum the
    /// customer was shown. Returns the checkpoint to restart from; the next
    /// chunk takes its own admission. The new chunk gets its own checkpoint
    /// signals, from the percents its usage has not reached yet.
    pub fn resume(
        &mut self,
        offer: &ResumeOffer,
        maximum: DeclaredMaximum,
        shown: Option<MaximumShown>,
    ) -> Result<CheckpointRef, ResumeRefused> {
        if !self.stopped {
            return Err(ResumeRefused::NotStopped);
        }
        if offer.job != self.job
            || offer.stop != self.stops
            || Some(&offer.checkpoint) != self.checkpoint.as_ref()
        {
            return Err(ResumeRefused::StaleOffer);
        }
        if shown.is_none()
            || maximum.unit != self.maximum.unit
            || maximum.units <= self.maximum.units
        {
            return Err(ResumeRefused::MaximumNotRaised);
        }
        self.maximum = maximum;
        self.warning_due = false;
        self.warning_delivered = false;
        self.stopped = false;
        self.checkpoint_percent_signalled =
            reached_checkpoint_percent(self.used_units, self.maximum.units);
        Ok(self
            .checkpoint
            .take()
            .expect("a stopped job holds its checkpoint"))
    }
}
