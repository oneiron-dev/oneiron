//! The stop at a paid job's declared maximum (CROSS-ARCH-0023 C2).
//!
//! Nothing in the engine stops a running model. A paid job with a declared
//! maximum is the one exception the owner granted, and only under five
//! conditions, which this contract enforces: the customer set the maximum and
//! saw it at the job's start; a warning goes out at 95 percent; a checkpoint is
//! taken before the stop; the stop carries an add-funds notice; and the job
//! resumes from that checkpoint in one step. The job reserves its whole
//! maximum through [`super::RunAdmission::admit_paid`]; a resume takes a fresh
//! admission for the next chunk.
use serde::{Deserialize, Serialize};

use super::declaration::LeaseUnit;

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
    /// 95 percent of the maximum is used. Sent once, before any stop.
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
    #[error("the 95 percent warning has not gone out")]
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

/// One paid job's run against its declared maximum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobMaximum {
    job: String,
    maximum: DeclaredMaximum,
    used_units: u64,
    warned: bool,
    checkpoint: Option<CheckpointRef>,
    stops: u32,
    stopped: bool,
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
            warned: false,
            checkpoint: None,
            stops: 0,
            stopped: false,
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

    /// Records the job's usage so far and returns what it crossed.
    pub fn record_usage(&mut self, used_units: u64) -> Vec<JobSignal> {
        self.used_units = self.used_units.max(used_units);
        let mut signals = Vec::new();
        let warn_at = u128::from(self.maximum.units) * 95;
        if !self.warned && u128::from(self.used_units) * 100 >= warn_at {
            self.warned = true;
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

    /// Records a checkpoint. Only one taken after the warning counts for the
    /// stop.
    pub fn checkpoint(&mut self, checkpoint: CheckpointRef) {
        if self.warned {
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
        if !self.warned {
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
    /// chunk takes its own admission.
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
        self.warned = false;
        self.stopped = false;
        Ok(self
            .checkpoint
            .take()
            .expect("a stopped job holds its checkpoint"))
    }
}
