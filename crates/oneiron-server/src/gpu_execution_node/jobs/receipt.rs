//! The receipt: what this node observed about one key, from the journal
//! alone, signed with the machine key under the receipt domain (design
//! pass 33, 5.3).
//!
//! Seconds are occupied device time on the boot clock: from the launch
//! commit to the unit empty. A live key's receipt carries the seconds so far
//! within the launch's boot. A key with no launch commit carries `None`, and
//! so does a key whose end is `Lost` (unknown, never zero). What a key that
//! never started bills is the issuer's rule by its end, not a number here.
//!
//! A session's run that was renewed (pass 34, 2.5; row W1) answers one
//! receipt per chunk key, each its chunk's paid slice of the one run
//! ([`chunk_receipt_of`]): the slices meet at the paid boundaries, which lie
//! whole seconds after the launch, so their seconds add up to the run's.

use oneiron::machine_signature::MachineSignatures;

use super::job_unit::JobKeyId;
use super::journal::{KeyLaunch, NodeKey};
use super::journal_file::JournalEpoch;
use crate::gpu_execution_node::wire::{
    JobEnd, JobReceipt, JobState, Occupied, ReceiptSlice, SignedJobReceipt,
};

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
        slice: None,
    }
}

/// The receipt of chunk `chunk` of `first`'s renewed run: 0 is the first
/// key's own chunk, `n` its `n`th renewal. `None` for a key with no such
/// chunk.
///
/// The chunk's paid slice runs from the end of the chunk before (the launch,
/// for chunk 0) to its own cutoff, and is cut at the run's end:
/// - a slice the run went past, while a later chunk was paid, ends
///   `Continued` with all its seconds;
/// - the slice the run ends in carries the run's own end and its seconds up
///   to the end;
/// - a slice the run never reached ends with the run's end, never started,
///   and bills nothing; while the run lives it is `Accepted`;
/// - a live run's current slice carries the run's state and its seconds so
///   far.
#[must_use]
pub fn chunk_receipt_of(
    first: &NodeKey,
    chunk: u32,
    machine: oneiron::EntityId,
    epoch: JournalEpoch,
    now: &ReceiptClock,
) -> Option<JobReceipt> {
    let launch = first.launch.as_ref()?;
    let place = usize::try_from(chunk).ok()?;
    let (key, submit, from_boot_ns) = match place.checked_sub(1) {
        None => (
            first.key.clone(),
            first.submit.clone(),
            launch.launch_boot_ns,
        ),
        Some(index) => {
            let renewal = first.renewals.get(index)?;
            (
                renewal.key.clone(),
                Some(renewal.submit.clone()),
                renewal.from_boot_ns,
            )
        }
    };
    let last = place == first.renewals.len();
    let to_boot_ns = first
        .renewals
        .get(place)
        .map_or(launch.cutoff_boot_ns, |next| next.from_boot_ns);
    // Where the run is: its end, or, while it lives in the launch's boot,
    // now. `None` when that cannot be read (a lost run, another boot).
    let run_at = match (first.state, &first.end) {
        (JobState::Ended, Some(JobEnd::Lost { .. })) => None,
        (JobState::Ended, _) => first.end_boot_ns,
        _ if now.boot_id == launch.boot_id => Some(now.boot_ns),
        _ => None,
    };
    let ended = first.state == JobState::Ended;
    let mut view = first.clone();
    view.id = JobKeyId::for_key(&key);
    view.key = key;
    view.submit = submit;
    view.renewals = Vec::new();
    // A renewal's slice begins only once the run is past its start: a run
    // that ended on a paid boundary used none of the next chunk.
    let began = place == 0 || run_at.is_none_or(|at| at > from_boot_ns);
    let passed = !last && run_at.is_some_and(|at| at > to_boot_ns);
    view.launch = began.then(|| KeyLaunch {
        launch_boot_ns: from_boot_ns,
        cutoff_boot_ns: to_boot_ns,
        launch_at_ms: launch
            .launch_at_ms
            .saturating_add(from_boot_ns.saturating_sub(launch.launch_boot_ns) / 1_000_000),
        ..launch.clone()
    });
    if passed {
        view.state = JobState::Ended;
        view.end = Some(JobEnd::Continued);
        view.end_boot_ns = Some(to_boot_ns);
    } else if !began && !ended {
        view.state = JobState::Accepted;
        view.end = None;
        view.end_boot_ns = None;
    } else if !began {
        view.end_boot_ns = None;
    }
    let mut receipt = receipt_of(&view, machine, epoch, now);
    receipt.slice = Some(ReceiptSlice {
        first_key: first.key.clone(),
        chunk,
        from_boot_ns,
        to_boot_ns,
    });
    Some(receipt)
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
