//! R4 admission policy constants. Each owner-overridable call has one home.
use std::time::{Duration, Instant};

use oneiron::llm::WorkClass;

pub const DEFAULT_WORK_CLASS: WorkClass = WorkClass::Foreground;
pub const DEFAULT_DEADLINE: Option<Instant> = None;
pub const QUEUE_ORDER: QueueOrder = QueueOrder::ClassDeadlineFifo;
pub const BACKGROUND_FAIRNESS: BackgroundFairness = BackgroundFairness::RoundRobinResidual;
pub const UNKNOWN_MEMORY_POLICY: UnknownMemoryPolicy = UnknownMemoryPolicy::AdmitAsToday;
pub const RESIDENT_FRESHNESS: ResidentFreshness = ResidentFreshness::RefreshBeforeNewGrant;
pub const DEVICE_HEADROOM_MIB: u64 = 2048;
pub const PRESSURE_ACTION_ORDER: [PressureAction; 3] = [
    PressureAction::IdleUnload,
    PressureAction::ApprovedSmallerProfile,
    PressureAction::Wait,
];
pub const AUTO_PROFILE_SUBSTITUTION: bool = false;
pub const UNLOAD_EXTERNAL: bool = false;
pub const UNMEDIATED_SHARED_DEVICE: UnmediatedPolicy = UnmediatedPolicy::AdmitAndRecord;
pub const ADMISSION_WAIT_LIMIT: Option<Duration> = None;
pub const CANCEL_RELEASE_LIMIT: Option<Duration> = None;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueOrder {
    ClassDeadlineFifo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundFairness {
    RoundRobinResidual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownMemoryPolicy {
    AdmitAsToday,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidentFreshness {
    RefreshBeforeNewGrant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressureAction {
    IdleUnload,
    ApprovedSmallerProfile,
    Wait,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmediatedPolicy {
    AdmitAndRecord,
}
