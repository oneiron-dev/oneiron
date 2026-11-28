//! One vocabulary of reasons (pass 34, section 1.3; Engine ruling EM-19 = A). The issuer's
//! `fit`, the start gate and the node say why work cannot run in the same words, so the queue
//! view, the gate's refusal and the node's written refusal name one code.
//!
//! The two built lists keep their variants and their codes: [`WorkloadStartRefusal`] (the start
//! gate, row R2) and the node's `JobRefusal` (the job protocol, row R0) each map onto a
//! [`Blocker`] whose [`Blocker::code`] is the code the built list already gives. The server maps
//! `JobRefusal`, which lives there.
//!
//! Ids are lower hex here, because a blocker crosses the wire as it is stored.
use serde::{Deserialize, Serialize};

use crate::job_workload::{TEMPLATE_CHANGED, TEMPLATE_NOT_OFFERED, WorkloadStartRefusal};

/// Why an order cannot run now on a machine, or at all. On the wire its tag is `code`, the
/// same string [`Blocker::code`] answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum Blocker {
    // Authority: cleared by the owner or the requester.
    /// The Grant the requester ordered under no longer stands for it and the verb (for an
    /// offer's charge, also as the Grant that starts its GPU jobs), or the owner who ordered is
    /// gone.
    GrantNotLive,
    WorkloadUnknown,
    WorkloadNotApproved,
    /// The workload's check-in waits for the owner's answer.
    WorkloadWaiting,
    /// No live `compute.pin` Grant covers the workload on this machine.
    ComputeGrantEnded,
    WorkloadRevoked,
    WorkloadExpired,
    StarterNotNamed,
    RequestAbovePin,
    /// The workload's approval does not name this machine.
    MachineNotApproved,
    FreeFormNotPermitted,

    // Money: cleared at the next period, or by the owner.
    LineRoom {
        pool: String,
        short_secs: u64,
    },
    /// The attempt's maximum is above the one the owner set beside the requester's Grant.
    AllowanceExceeded {
        maximum_secs: u64,
    },
    /// The run admission refused the reservation on the host account.
    BudgetSpent,

    // The machine's standing and switches: cleared by the owner, the box, or time.
    /// The machine did not answer (the gate's `machine_unreachable`; pass 34 calls it
    /// `Offline`).
    MachineUnreachable {
        since_ms: Option<u64>,
    },
    NotEnabled,
    Paused {
        why: String,
    },
    Drained {
        why: String,
    },
    /// The machine could not read its GPUs now, with why.
    DevicesUnreadable {
        why: String,
    },
    OutsideWindow {
        opens_ms: Option<u64>,
    },
    ResumableOnly,
    PeerNotProven,
    NotIssuer,
    OwnGrantEnded,
    IssuerStandingEnded,
    HistoryLost,
    /// This replica is not the issuer of the vault's jobs; `issuer` names it, when known.
    NotTheIssuer {
        issuer: Option<String>,
    },

    // Capability: never cleared by waiting. An order every allowed machine blocks this way is
    // refused at once.
    /// The order names no machine where one is needed.
    MachineMissing,
    NoMachine,
    NoScope {
        missing: Vec<String>,
    },
    /// The order's hard limit allows no scope of the kind its workload's pin runs in.
    ScopeNotAllowed {
        scope: String,
    },
    NoDevice {
        kind: String,
        features: Vec<String>,
    },
    AboveCeiling {
        resource: String,
    },
    /// The machine holds no template of the pin's name (the gate's `template_not_offered`; pass
    /// 34 calls it `TemplateMissing`).
    TemplateNotOffered,
    TemplateChanged,
    WorldNotResident,
    /// A warm key the order lists is an input the machine's template maps to a path that is not
    /// there (pass 34, 7.1 gap 6; row P2): the node fetches nothing, so no wait clears it.
    WarmKeyMissing {
        key: String,
    },
    /// The machine refused for a reason this vocabulary does not name.
    MachineRefuses {
        reason: String,
    },
    /// A line unit's reserve refused for a reason waiting does not clear (an arm or rung that
    /// closed, a contract, a maximum, an offer or a machine the line does not hold). `reason`
    /// leads with the reserve's own code (`rung_closed: ...`), as the reserve answers it.
    LineRefuses {
        reason: String,
    },

    // Capacity: cleared by waiting; every running attempt has a hard cutoff, so the time is
    // known when the machine reports it.
    DeviceBusy {
        device: String,
        free_at_ms: Option<u64>,
    },
    MemoryBusy {
        free_at_ms: Option<u64>,
    },
    ThreadsBusy {
        free_at_ms: Option<u64>,
    },
    DiskShort {
        short_mib: u64,
    },
    KeepHeadroom,

    // Conditions.
    After {
        order: String,
    },
    CapFull {
        cap: String,
        running: u32,
    },
    /// A line unit's reserve refused for a reason that clears by itself or by the line's
    /// people (a period not begun, a rung under review, a forecast not written, a seat lapsed,
    /// machines that have not answered). `reason` leads with the reserve's own code.
    LineNotReady {
        reason: String,
    },
    RetryNotBefore {
        ms: u64,
    },
    /// The order's last attempt has no signed end and no write-off: no new attempt (I1).
    AttemptUnconfirmed {
        key: String,
    },
    /// The PLACE slot's decider (row P1), the Grant `decider` in lower hex, chose to wait for
    /// a better machine; the loop places the order again, and asks again, from `until_ms`
    /// (`policy.slots.wait_reask_ms` after the pick).
    DeciderWait {
        decider: String,
        until_ms: u64,
    },

    // Faults of one key on the node: the issuer's own record disagrees with the node's, or a
    // read of the key's output or log was refused. An operator reads them; they say nothing
    // about the order's fit.
    NotReleasable,
    KeyConflict,
    NotTheKeysIssuer,
    SubmitSignatureInvalid,
    /// A fetch of an output the node does not hand out, with why.
    OutputNotFetchable {
        why: String,
    },
    /// An acknowledgement of a key that has not ended.
    NotAcknowledgeable,
    /// A log tail the node does not read, with why.
    LogNotReadable {
        why: String,
    },
}

/// How a blocker clears, which decides whether an order waits on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Clearing {
    /// The owner or the requester acts.
    Authority,
    /// The next period, or the owner.
    Money,
    /// The owner, the box, or time.
    Standing,
    /// Never by waiting.
    Capability,
    /// By waiting.
    Capacity,
    /// Another order or a time.
    Condition,
    /// An operator.
    Fault,
}

impl Blocker {
    /// The stable code a caller branches on: the panel, the SDK's reason codes and the logs
    /// read this, never the message.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::GrantNotLive => "grant_not_live",
            Self::WorkloadUnknown => "workload_unknown",
            Self::WorkloadNotApproved => "workload_not_approved",
            Self::WorkloadWaiting => "workload_waiting",
            Self::ComputeGrantEnded => "compute_grant_ended",
            Self::WorkloadRevoked => "workload_revoked",
            Self::WorkloadExpired => "workload_expired",
            Self::StarterNotNamed => "starter_not_named",
            Self::RequestAbovePin => "request_above_pin",
            Self::MachineNotApproved => "machine_not_approved",
            Self::FreeFormNotPermitted => "free_form_not_permitted",
            Self::LineRoom { .. } => "line_room",
            Self::AllowanceExceeded { .. } => "allowance_exceeded",
            Self::BudgetSpent => "budget_spent",
            Self::MachineUnreachable { .. } => "machine_unreachable",
            Self::NotEnabled => "not_enabled",
            Self::Paused { .. } => "paused",
            Self::Drained { .. } => "drained",
            Self::DevicesUnreadable { .. } => "devices_unreadable",
            Self::OutsideWindow { .. } => "outside_window",
            Self::ResumableOnly => "resumable_only",
            Self::PeerNotProven => "peer_not_proven",
            Self::NotIssuer => "not_issuer",
            Self::OwnGrantEnded => "own_grant_ended",
            Self::IssuerStandingEnded => "issuer_standing_ended",
            Self::HistoryLost => "history_lost",
            Self::NotTheIssuer { .. } => "not_the_issuer",
            Self::MachineMissing => "machine_missing",
            Self::NoMachine => "no_machine",
            Self::NoScope { .. } => "no_scope",
            Self::ScopeNotAllowed { .. } => "scope_not_allowed",
            Self::NoDevice { .. } => "no_device",
            Self::AboveCeiling { .. } => "above_ceiling",
            Self::TemplateNotOffered => TEMPLATE_NOT_OFFERED,
            Self::TemplateChanged => TEMPLATE_CHANGED,
            Self::WarmKeyMissing { .. } => "warm_key_missing",
            Self::WorldNotResident => "world_not_resident",
            Self::MachineRefuses { .. } => "machine_refuses",
            Self::LineRefuses { .. } => "line_refuses",
            Self::DeviceBusy { .. } => "device_busy",
            Self::MemoryBusy { .. } => "memory_busy",
            Self::ThreadsBusy { .. } => "threads_busy",
            Self::DiskShort { .. } => "disk_short",
            Self::KeepHeadroom => "keep_headroom",
            Self::After { .. } => "after",
            Self::CapFull { .. } => "cap_full",
            Self::LineNotReady { .. } => "line_not_ready",
            Self::RetryNotBefore { .. } => "retry_not_before",
            Self::AttemptUnconfirmed { .. } => "attempt_unconfirmed",
            Self::DeciderWait { .. } => "decider_wait",
            Self::NotReleasable => "not_releasable",
            Self::KeyConflict => "key_conflict",
            Self::NotTheKeysIssuer => "not_the_keys_issuer",
            Self::SubmitSignatureInvalid => "submit_signature_invalid",
            Self::OutputNotFetchable { .. } => "output_not_fetchable",
            Self::NotAcknowledgeable => "not_acknowledgeable",
            Self::LogNotReadable { .. } => "log_not_readable",
        }
    }

    /// How this blocker clears.
    #[must_use]
    pub const fn clearing(&self) -> Clearing {
        match self {
            Self::GrantNotLive
            | Self::WorkloadUnknown
            | Self::WorkloadNotApproved
            | Self::WorkloadWaiting
            | Self::ComputeGrantEnded
            | Self::WorkloadRevoked
            | Self::WorkloadExpired
            | Self::StarterNotNamed
            | Self::RequestAbovePin
            | Self::MachineNotApproved
            | Self::FreeFormNotPermitted => Clearing::Authority,
            Self::LineRoom { .. } | Self::AllowanceExceeded { .. } | Self::BudgetSpent => {
                Clearing::Money
            }
            Self::MachineUnreachable { .. }
            | Self::NotEnabled
            | Self::Paused { .. }
            | Self::Drained { .. }
            | Self::DevicesUnreadable { .. }
            | Self::OutsideWindow { .. }
            | Self::ResumableOnly
            | Self::PeerNotProven
            | Self::NotIssuer
            | Self::OwnGrantEnded
            | Self::IssuerStandingEnded
            | Self::HistoryLost
            | Self::NotTheIssuer { .. } => Clearing::Standing,
            Self::MachineMissing
            | Self::NoMachine
            | Self::LineRefuses { .. }
            | Self::NoScope { .. }
            | Self::ScopeNotAllowed { .. }
            | Self::NoDevice { .. }
            | Self::AboveCeiling { .. }
            | Self::TemplateNotOffered
            | Self::TemplateChanged
            | Self::WorldNotResident
            | Self::WarmKeyMissing { .. }
            | Self::MachineRefuses { .. } => Clearing::Capability,
            Self::DeviceBusy { .. }
            | Self::MemoryBusy { .. }
            | Self::ThreadsBusy { .. }
            | Self::DiskShort { .. }
            | Self::KeepHeadroom => Clearing::Capacity,
            Self::After { .. }
            | Self::CapFull { .. }
            | Self::LineNotReady { .. }
            | Self::RetryNotBefore { .. }
            | Self::AttemptUnconfirmed { .. }
            | Self::DeciderWait { .. } => Clearing::Condition,
            Self::NotReleasable
            | Self::KeyConflict
            | Self::NotTheKeysIssuer
            | Self::SubmitSignatureInvalid
            | Self::OutputNotFetchable { .. }
            | Self::NotAcknowledgeable
            | Self::LogNotReadable { .. } => Clearing::Fault,
        }
    }

    /// Whether waiting can ever clear this blocker. A capability miss cannot: the order is
    /// refused at once when every allowed machine reports one.
    #[must_use]
    pub const fn clears_by_waiting(&self) -> bool {
        !matches!(self.clearing(), Clearing::Capability)
    }

    /// The earliest time this blocker clears by itself, when it is known.
    #[must_use]
    pub const fn clears_at_ms(&self) -> Option<u64> {
        match self {
            Self::DeviceBusy { free_at_ms, .. }
            | Self::MemoryBusy { free_at_ms }
            | Self::ThreadsBusy { free_at_ms } => *free_at_ms,
            Self::OutsideWindow { opens_ms } => *opens_ms,
            Self::RetryNotBefore { ms } | Self::DeciderWait { until_ms: ms, .. } => Some(*ms),
            _ => None,
        }
    }

    /// The blocker a node's refusal reason names, as the start gate passes it on in
    /// [`WorkloadStartRefusal::MachineRefuses`]: the node's code, then optionally `": "` and
    /// why. A reason this vocabulary does not name stays [`Blocker::MachineRefuses`].
    #[must_use]
    pub fn of_node_reason(reason: &str) -> Self {
        let (code, why) = match reason.split_once(':') {
            Some((code, why)) => (code.trim(), why.trim().to_owned()),
            None => (reason.trim(), String::new()),
        };
        match code {
            "not_enabled" => Self::NotEnabled,
            "paused" => Self::Paused { why },
            "drained" => Self::Drained { why },
            "devices_unreadable" => Self::DevicesUnreadable { why },
            "peer_not_proven" => Self::PeerNotProven,
            "not_issuer" => Self::NotIssuer,
            "own_grant_ended" => Self::OwnGrantEnded,
            "issuer_standing_ended" => Self::IssuerStandingEnded,
            "history_lost" => Self::HistoryLost,
            "not_releasable" => Self::NotReleasable,
            "key_conflict" => Self::KeyConflict,
            "not_the_keys_issuer" => Self::NotTheKeysIssuer,
            "submit_signature_invalid" => Self::SubmitSignatureInvalid,
            "output_not_fetchable" => Self::OutputNotFetchable { why },
            "not_acknowledgeable" => Self::NotAcknowledgeable,
            "log_not_readable" => Self::LogNotReadable { why },
            "warm_key_missing" => Self::WarmKeyMissing { key: why },
            code if code == TEMPLATE_CHANGED => Self::TemplateChanged,
            code if code == TEMPLATE_NOT_OFFERED => Self::TemplateNotOffered,
            _ => Self::MachineRefuses {
                reason: reason.to_owned(),
            },
        }
    }
}

impl std::fmt::Display for Blocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

/// The start gate's refusal, by the same code (EM-19).
impl From<&WorkloadStartRefusal> for Blocker {
    fn from(refusal: &WorkloadStartRefusal) -> Self {
        match refusal {
            WorkloadStartRefusal::MachineMissing => Self::MachineMissing,
            WorkloadStartRefusal::WorkloadUnknown => Self::WorkloadUnknown,
            WorkloadStartRefusal::WorkloadNotApproved => Self::WorkloadNotApproved,
            WorkloadStartRefusal::WorkloadWaiting => Self::WorkloadWaiting,
            WorkloadStartRefusal::ComputeGrantEnded => Self::ComputeGrantEnded,
            WorkloadStartRefusal::WorkloadRevoked => Self::WorkloadRevoked,
            WorkloadStartRefusal::WorkloadExpired => Self::WorkloadExpired,
            WorkloadStartRefusal::StarterNotNamed => Self::StarterNotNamed,
            WorkloadStartRefusal::RequestAbovePin => Self::RequestAbovePin,
            WorkloadStartRefusal::MachineNotApproved => Self::MachineNotApproved,
            WorkloadStartRefusal::MachineUnreachable { .. } => {
                Self::MachineUnreachable { since_ms: None }
            }
            WorkloadStartRefusal::MachineRefuses { reason } => Self::of_node_reason(reason),
        }
    }
}

/// One reason an order waits, and the machine it is about (none for a reason about the order
/// itself: its Grant, its approval, a retry's time).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlockedOn {
    /// The MACHINE id, lower hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    pub blocker: Blocker,
}
