//! The receipt: what this node observed about one key, from the journal
//! alone, signed with the machine key under the receipt domain (design
//! pass 33, 5.3).
//!
//! Seconds are occupied device time on the boot clock: from the launch
//! commit to the unit empty. A live key's receipt carries the seconds so far
//! within the launch's boot. A key with no launch commit carries `None`, and
//! so does a key whose end is `Lost` (unknown, never zero). What a key that
//! never started bills is the issuer's rule by its end, not a number here.

use oneiron::machine_signature::MachineSignatures;

use super::journal::NodeKey;
use super::journal_file::JournalEpoch;
use crate::gpu_execution_node::wire::{JobEnd, JobReceipt, JobState, Occupied, SignedJobReceipt};

const NANOS_PER_SEC: u64 = 1_000_000_000;

/// Now, as a receipt is stamped.
#[derive(Debug, Clone)]
pub struct ReceiptClock {
    pub boot_id: String,
    pub boot_ns: u64,
    pub wall_ms: u64,
}

/// The receipt of `key` now.
#[must_use]
pub fn receipt_of(
    key: &NodeKey,
    machine: oneiron::EntityId,
    epoch: JournalEpoch,
    now: &ReceiptClock,
) -> JobReceipt {
    let reserve = key.reserve.as_ref();
    let submit = key.submit.as_ref().map(|signed| &signed.submit);
    let starter = submit
        .map(|submit| submit.starter)
        .or_else(|| reserve.map(|reserve| reserve.starter));
    let maximum_secs = submit
        .map(|submit| submit.maximum_secs)
        .or_else(|| reserve.map(|reserve| reserve.pin.request.maximum_secs));
    let occupied = key.launch.as_ref().map(|launch| Occupied {
        boot_id: launch.boot_id.clone(),
        start_boot_ns: launch.launch_boot_ns,
        end_boot_ns: key.end_boot_ns,
    });
    JobReceipt {
        key: key.key.clone(),
        machine,
        epoch: epoch.to_hex(),
        device_id: key
            .launch
            .as_ref()
            .and_then(|launch| launch.device_id().map(str::to_owned)),
        issuer: key.issuer,
        starter,
        hold: submit.map(|submit| submit.hold.clone()),
        workload: key.pin_digest.clone(),
        state: key.state,
        started: key.started(),
        end: key.end.clone(),
        occupied,
        measured_secs: measured_secs(key, now),
        cutoff_at_ms: key.launch.as_ref().and_then(|launch| {
            maximum_secs.map(|secs| {
                launch
                    .launch_at_ms
                    .saturating_add(secs.saturating_mul(1_000))
            })
        }),
        release: key.release.clone(),
        outputs: key.outputs.clone(),
        scope: None,
        other_compute_pids: key.other_compute_pids.clone(),
        seq: key.seq,
        boot_id: now.boot_id.clone(),
        reported_at_ms: now.wall_ms,
    }
}

/// The occupied seconds, rounded up: `None` before the launch commit, for a
/// lost key, and for a live key whose launch was in another boot.
#[must_use]
pub fn measured_secs(key: &NodeKey, now: &ReceiptClock) -> Option<u64> {
    let launch = key.launch.as_ref()?;
    if matches!(key.end, Some(JobEnd::Lost { .. })) {
        return None;
    }
    let end_boot_ns = match key.end_boot_ns {
        Some(end) => end,
        None if key.state != JobState::Ended && now.boot_id == launch.boot_id => now.boot_ns,
        None => return None,
    };
    let occupied_ns = end_boot_ns.saturating_sub(launch.launch_boot_ns);
    Some(occupied_ns.div_ceil(NANOS_PER_SEC))
}

/// Signs `receipt` with this machine's key, through the one machine-key
/// signing path.
///
/// # Errors
///
/// Why it could not be signed: then no receipt is answered.
pub fn sign_receipt(
    receipt: JobReceipt,
    signer: &dyn MachineSignatures,
) -> Result<SignedJobReceipt, String> {
    SignedJobReceipt::sign(receipt, signer).map_err(|error| error.to_string())
}
