//! What a vault machine job is billed (pass 33 section 8.4; pass 34, 9.2): the occupied time of
//! the attempt's leases, from the launch commit to the empty unit, as the node measured it on its
//! boot clock, and never more than the issuer saw pass or the quote's maximum. An attempt with no
//! device lease (CPU only) bills the same way:
//!
//! ```text
//! billed_secs = min(quote maximum, node measured_secs, issuer bracket)
//! issuer bracket = (terminal receipt arrived) - (submit first sent), on the issuer's boot clock
//! ```
//!
//! A node figure above the bracket settles the bracket (`Bracketed`). A key that never started
//! bills zero, and a lost key bills zero with an unknown meter (lead ruling LE-2 = A).
use oneiron::gpu_job::{GpuJobEnd, GpuJobOutput, GpuJobTerminal, MeterVerdict};
use oneiron::job_dispatch::BootMark;

use crate::gpu_execution_node::wire::{JobEnd, JobReceipt, OutputsState};

/// The issuer's own measure of a key's run: the seconds between the first send of its submit
/// and the arrival of its terminal receipt, rounded up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bracket {
    pub secs: u64,
    /// The two marks are of different boots, or name none: the wall clock measured it.
    pub by_wall_clock: bool,
}

/// The bracket from `sent` to `end_seen`: on the boot clock inside one boot, else on the wall
/// clock.
#[must_use]
pub fn bracket(sent: &BootMark, end_seen: &BootMark) -> Bracket {
    if !sent.boot_id.is_empty()
        && sent.boot_id == end_seen.boot_id
        && end_seen.boot_ns >= sent.boot_ns
    {
        Bracket {
            secs: (end_seen.boot_ns - sent.boot_ns).div_ceil(1_000_000_000),
            by_wall_clock: false,
        }
    } else {
        Bracket {
            secs: end_seen.wall_ms.saturating_sub(sent.wall_ms).div_ceil(1000),
            by_wall_clock: true,
        }
    }
}

/// The seconds a terminal receipt bills, and how they were found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Billing {
    pub billed_secs: u64,
    pub meter: MeterVerdict,
}

/// What the terminal `receipt` bills under the cutoff `maximum_secs`, checked against the
/// issuer's `bracket` (`None` when the issuer holds no mark of the submit's first send).
#[must_use]
pub fn billing(receipt: &JobReceipt, maximum_secs: u64, bracket: Option<Bracket>) -> Billing {
    let never_ran = !receipt.started
        || matches!(
            receipt.end,
            Some(JobEnd::Withdrawn | JobEnd::Refused { .. } | JobEnd::LaunchRefused { .. })
        );
    if never_ran {
        return Billing {
            billed_secs: 0,
            meter: MeterVerdict::Agreed,
        };
    }
    let unknown = Billing {
        billed_secs: 0,
        meter: MeterVerdict::Unknown,
    };
    if matches!(receipt.end, Some(JobEnd::Lost { .. }) | None) {
        return unknown;
    }
    let (Some(measured), Some(bracket)) = (receipt.measured_secs, bracket) else {
        return unknown;
    };
    if measured > bracket.secs {
        let billed_secs = bracket.secs.min(maximum_secs);
        Billing {
            billed_secs,
            meter: MeterVerdict::Bracketed { billed_secs },
        }
    } else {
        Billing {
            billed_secs: measured.min(maximum_secs),
            meter: MeterVerdict::Agreed,
        }
    }
}

/// The typed terminal of a confirmed end: the node's end, its seconds, what is billed and the
/// outputs by hash. `revoked` says the issuer stopped the key on a revoke (EN-4), so a stop
/// the node reports reads as the revoke it was. `last_seen_secs` is the newest occupied
/// seconds any receipt of the key carried, which a lost key reports.
#[must_use]
pub fn terminal(
    receipt: &JobReceipt,
    billing: Billing,
    revoked: bool,
    last_seen_secs: u64,
) -> GpuJobTerminal {
    let end = match receipt.end.clone() {
        Some(JobEnd::Stopped) if revoked => GpuJobEnd::Revoked,
        Some(end) => job_end(end, last_seen_secs),
        None => GpuJobEnd::Lost {
            reason: "no_end".to_owned(),
            last_seen_secs,
        },
    };
    let outputs = match &receipt.outputs {
        OutputsState::Hashed(outputs) => outputs
            .iter()
            .map(|output| GpuJobOutput {
                name: output.name.clone(),
                sha256: output.sha256.clone(),
                bytes: output.bytes,
            })
            .collect(),
        OutputsState::Pending | OutputsState::Failed { .. } => Vec::new(),
    };
    GpuJobTerminal {
        end,
        measured_secs: receipt.measured_secs,
        billed_secs: billing.billed_secs,
        meter: billing.meter,
        machine: Some(receipt.machine),
        device_id: receipt.device_id.clone(),
        outputs,
    }
}

/// The node's end as the job's typed terminal names it.
fn job_end(end: JobEnd, last_seen_secs: u64) -> GpuJobEnd {
    match end {
        JobEnd::Exited { code } => GpuJobEnd::Exited { code },
        JobEnd::Signalled { signal } => GpuJobEnd::Signalled { signal },
        JobEnd::TimeLimit => GpuJobEnd::TimeLimit,
        // A session's slice that ran to its paid end while the run went on
        // (row W1): this chunk ended at its maximum. The issuer's step that
        // renews sessions gives it a terminal of its own.
        JobEnd::Continued => GpuJobEnd::TimeLimit,
        JobEnd::MemoryLimit => GpuJobEnd::MemoryLimit,
        JobEnd::DiskLimit => GpuJobEnd::DiskLimit,
        JobEnd::Stopped => GpuJobEnd::Stopped,
        JobEnd::Revoked => GpuJobEnd::Revoked,
        JobEnd::Withdrawn => GpuJobEnd::Withdrawn,
        JobEnd::Refused { reason } => GpuJobEnd::Refused { reason },
        JobEnd::LaunchRefused { reason } => GpuJobEnd::LaunchRefused { reason },
        JobEnd::Lost { reason, .. } => GpuJobEnd::Lost {
            reason,
            last_seen_secs,
        },
    }
}
