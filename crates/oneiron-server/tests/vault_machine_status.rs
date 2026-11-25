#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! DESIGN 33 tests T26-T33c, the issuer's halves (row R4): the four status fields of a job on one
//! of the vault's machines, a stop's confirmation, a sequence that never goes back, a node
//! reset, the keys the issuer does not know, the issuer's drain guard with door 12, the
//! write-off of door 10, and the returned result (EM-12 = A). The node's halves are in
//! `node_job_status.rs`.
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test vault_machine_status
//! ```

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;
#[path = "support/vault_machine_rig.rs"]
mod vault_machine_rig;

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use oneiron::blob_artifact::ArtifactCreateRequest;
use oneiron::gpu_job::{
    GpuConnectorError, GpuEndReason, GpuJobAccounting, GpuJobActor, GpuJobConnector, GpuJobError,
    GpuJobLifecycle, GpuJobNodeView, GpuJobResultBinding, GpuJobState, MeterVerdict,
};
use oneiron::job_dispatch::machine_records::{
    MachineDrainClearRequest, ReturnRefusal, UnattributedSeconds, clear_drain_as,
};
use oneiron::job_dispatch::{DispatchClose, DispatchPhase};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE};
use oneiron::provenance::made_by::MadeByTrigger;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::{EdgeActorClass, EntityId};
use oneiron_server::gpu_execution_node::issuer::{IssuerClock, JobOrphanKeys, UnattributedLedger};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, HoldRef, JobEnd, JobState, JobStatusRequest, OutputDigest, OutputsState,
    SignedJobReceipt, SignedJobSubmit,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use vault_machine_rig::{
    Call, FAR_EXPIRY_MS, JobRun, NOW_MS, Rig, ScriptedNode, make_connector_with, with_rig,
};

/// The host's job step the views are judged against.
const STEP_MS: u64 = 60_000;
/// `jobs.write_off.wait_secs`, its default.
const WRITE_OFF_WAIT_SECS: u64 = 3_600;

fn view(rig: &Rig, run: &JobRun) -> GpuJobNodeView {
    rig.connector
        .node_view(&rig.job(run), rig.clock.now_ms(), STEP_MS)
        .expect("a job on one of the vault's machines has a node view")
}

fn units(run: &JobRun) -> u64 {
    run.job.chunk().expect("the job has a chunk").quote.units
}

/// The node's newest report of `run` ends it as `end`, with `measured_secs`, its device
/// released clean.
fn end_clean(rig: &Rig, run: &JobRun, end: JobEnd, measured_secs: Option<u64>) {
    let at_ms = rig.clock.now_ms();
    rig.node.revise(run.key(), |receipt| {
        receipt.state = JobState::Ended;
        receipt.end = Some(end);
        receipt.measured_secs = measured_secs;
        receipt.release = DeviceRelease::Confirmed { at_ms };
    });
}

fn kinds_for<'a>(calls: &'a [Call], key: &str) -> Vec<&'a str> {
    calls
        .iter()
        .filter(|call| call.key.as_deref() == Some(key))
        .map(|call| call.kind)
        .collect()
}

fn position(calls: &[Call], kind: &str, key: Option<&str>) -> usize {
    calls
        .iter()
        .position(|call| call.kind == kind && call.key.as_deref() == key)
        .unwrap_or_else(|| panic!("no {kind} call for {key:?} in {calls:?}"))
}

/// T26: a node that does not answer is `Unavailable`, never gone. The job stays live, its
/// newest receipt stands, the view marks it stale, and the money stays held.
#[test]
fn an_unreachable_node_is_never_read_as_gone() {
    with_rig(|rig| {
        let workload = rig.approve("unreachable", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        assert_eq!(
            view(rig, &run).lifecycle,
            GpuJobLifecycle::Assigned,
            "the machine holds the key and has not launched it",
        );
        rig.node
            .advance(run.key(), JobState::Running, Some(30), None, true);
        let report = rig.step(&run).expect("poll the running job");
        assert_eq!(report.state, GpuJobState::Running);
        let fresh = view(rig, &run);
        assert_eq!(fresh.lifecycle, GpuJobLifecycle::Running);
        assert_eq!(fresh.machine, rig.node.machine.to_hex());
        let node = fresh.node.as_ref().expect("the machine's receipt");
        assert_eq!(node.state, "running");
        assert_eq!(node.measured_secs, Some(30));
        assert_eq!(node.release, "held");
        assert_eq!(fresh.observed.map(|seen| seen.stale), Some(false));
        assert_eq!(
            fresh.accounting,
            GpuJobAccounting::Held { units: units(&run) }
        );

        rig.node.unreachable(true);
        rig.clock.advance_secs(3 * STEP_MS / 1_000);
        let result = rig.step(&run);
        assert!(
            matches!(
                &result,
                Err(GpuJobError::Connector(
                    GpuConnectorError::Unavailable { .. }
                ))
            ),
            "an unreachable node is Unavailable: {result:?}",
        );
        assert_eq!(
            rig.job(&run).state,
            GpuJobState::Running,
            "the job stays live"
        );
        let stale = view(rig, &run);
        assert_eq!(stale.node, fresh.node, "the newest receipt stands");
        assert_eq!(
            stale.observed.map(|seen| (seen.at_ms, seen.stale)),
            fresh.observed.map(|seen| (seen.at_ms, true)),
            "the sight is as old as it was, and stale past two steps",
        );
        assert_eq!(
            stale.accounting,
            GpuJobAccounting::Held { units: units(&run) },
            "nothing is settled while the node is out of reach",
        );
        assert!(run.settled().is_empty(), "no settlement was written");
    });
}

/// T27, the issuer's half: a stop of a running job is `Pending` while the node reports the
/// unit as ending, and only the node's ended receipt, its device released clean, confirms it.
/// A stop the node stops answering is unconfirmed, never settled.
#[test]
fn a_stop_is_confirmed_only_when_the_unit_is_empty_and_the_lease_waits_for_a_clean_probe() {
    with_rig(|rig| {
        let workload = rig.approve("stop-pending", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        rig.node
            .advance(run.key(), JobState::Running, Some(10), None, true);
        rig.step(&run).expect("poll the running job");
        rig.clock.advance_secs(60);

        let cancelled = rig
            .vault()
            .cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &run.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            )
            .expect("cancel the running job");
        assert_eq!(
            cancelled.state,
            GpuJobState::Ending {
                reason: GpuEndReason::Cancelled
            },
            "the stop is pending while the unit is not empty",
        );
        assert!(
            kinds_for(&rig.node.calls(), run.key()).contains(&"stop"),
            "the cancel sent a stop",
        );
        let ending = view(rig, &run);
        assert_eq!(ending.lifecycle, GpuJobLifecycle::Ending);
        assert_eq!(
            ending.node.as_ref().map(|node| node.state.as_str()),
            Some("ending")
        );
        assert_eq!(
            ending.accounting,
            GpuJobAccounting::Held { units: units(&run) }
        );

        rig.step(&run).expect("poll the ending job");
        assert!(
            matches!(rig.job(&run).state, GpuJobState::Ending { .. }),
            "still ending while the node says the unit is not empty",
        );
        assert!(run.settled().is_empty(), "nothing settles before the end");

        rig.node.unreachable(true);
        rig.clock.advance_secs(3 * STEP_MS / 1_000);
        assert_eq!(
            view(rig, &run).accounting,
            GpuJobAccounting::Unconfirmed {
                why: "stop_not_confirmed".to_owned()
            },
            "a stop the node no longer answers is unconfirmed",
        );

        rig.node.unreachable(false);
        end_clean(rig, &run, JobEnd::Stopped, Some(25));
        let ended = rig.settle(&run);
        assert_eq!(
            ended.state,
            GpuJobState::Ended {
                reason: GpuEndReason::Cancelled
            }
        );
        assert_eq!(
            ended.chunk().and_then(|chunk| chunk.billed_secs),
            Some(25),
            "the occupied seconds up to the empty unit are billed",
        );
        assert_eq!(run.settled().len(), 1, "settled once");
        let done = view(rig, &run);
        assert_eq!(done.lifecycle, GpuJobLifecycle::Terminal);
        assert_eq!(
            done.node.as_ref().map(|node| node.release.as_str()),
            Some("confirmed")
        );
        assert!(
            matches!(done.accounting, GpuJobAccounting::Settled { .. }),
            "{:?}",
            done.accounting
        );
    });
}

/// T29, the issuer's half: a node that rebooted keeps its journal, so its next receipt carries
/// a higher sequence and is taken; an older receipt never replaces a newer one, and a journal
/// that went back is history lost.
#[test]
fn an_older_report_never_replaces_a_newer_one_also_after_a_node_reboot() {
    with_rig(|rig| {
        let workload = rig.approve("sequence", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        rig.node
            .advance(run.key(), JobState::Running, Some(10), None, true);
        rig.step(&run).expect("poll at 10 seconds");
        let older: SignedJobReceipt = rig.node.state().journal[run.key()].clone();
        assert_eq!(rig.observation(&run).seq, older.receipt.seq);

        rig.clock.advance_secs(30);
        rig.node
            .advance(run.key(), JobState::Running, Some(40), None, true);
        rig.step(&run).expect("poll at 40 seconds");

        rig.clock.advance_secs(10);
        let rebooted = rig.node.revise(run.key(), |receipt| {
            receipt.boot_id = "node-boot-2".to_owned();
            receipt.measured_secs = Some(50);
        });
        rig.step(&run).expect("poll after the node's reboot");
        let seen = rig.observation(&run);
        assert_eq!(
            seen.seq, rebooted.receipt.seq,
            "the rebooted node's next receipt is taken"
        );
        assert_eq!(seen.epoch, older.receipt.epoch, "the same journal");
        assert!(seen.seq > older.receipt.seq);
        assert_eq!(seen.last_measured_secs, Some(50));

        rig.node.replay(older);
        let result = rig.step(&run);
        assert!(
            matches!(
                &result,
                Err(GpuJobError::Connector(GpuConnectorError::Unavailable { reason }))
                    if reason == "history_lost"
            ),
            "a journal that went back is history lost: {result:?}",
        );
        let kept = rig.observation(&run);
        assert_eq!(
            kept.seq, rebooted.receipt.seq,
            "the older receipt replaced nothing"
        );
        assert_eq!(kept.receipt, seen.receipt);
        let shown = view(rig, &run);
        assert_eq!(
            shown.node.as_ref().and_then(|node| node.measured_secs),
            Some(50)
        );
        assert_eq!(
            shown.accounting,
            GpuJobAccounting::Unconfirmed {
                why: "history_lost".to_owned()
            },
        );
    });
}

/// T30, the issuer's half: a node reset ends the key `lost`, with no measured seconds. The
/// issuer bills nothing, records the meter as unknown (never zero seconds), and counts it
/// against the machine.
#[test]
fn a_node_reset_reports_lost_with_unknown_seconds_and_bills_nothing() {
    with_rig(|rig| {
        let workload = rig.approve("reset", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        rig.node
            .advance(run.key(), JobState::Running, Some(30), None, true);
        rig.step(&run).expect("poll the running job");
        rig.clock.advance_secs(60);
        rig.node.advance(
            run.key(),
            JobState::Ended,
            None,
            Some(JobEnd::Lost {
                reason: "node_reset".to_owned(),
                last_tick_boot_ns: 0,
                breadcrumbs: Vec::new(),
            }),
            true,
        );
        let ended = rig.settle(&run);
        assert_eq!(
            ended.state,
            GpuJobState::Ended {
                reason: GpuEndReason::Gone
            }
        );
        assert_eq!(ended.chunk().and_then(|chunk| chunk.billed_secs), Some(0));
        assert_eq!(run.settled(), vec![0], "a lost key bills nothing");
        assert_eq!(rig.observation(&run).meter, Some(MeterVerdict::Unknown));
        let shown = view(rig, &run);
        let node = shown.node.expect("the lost receipt");
        assert_eq!(node.end.as_deref(), Some("lost"));
        assert_eq!(node.end_detail.as_deref(), Some("node_reset"));
        assert_eq!(node.measured_secs, None, "unknown, not zero");
        let guard = rig
            .vault()
            .machine_job_guard(rig.node.machine)
            .expect("read the machine's job guard")
            .expect("the loss was counted");
        assert_eq!(guard.failures_in_a_row, 1);
        assert_eq!(guard.last_failure.as_deref(), Some("lost: node_reset"));
        assert_eq!(guard.drained, None, "one failure does not drain");
    });
}

/// The allocation's side in a test: what each node's listing recorded, in the node's call
/// order, so a test sees it before or after a request.
struct RecordingLedger {
    node: Arc<ScriptedNode>,
    recorded: Mutex<Vec<(EntityId, Vec<UnattributedSeconds>)>>,
}

impl RecordingLedger {
    fn recorded(&self) -> Vec<(EntityId, Vec<UnattributedSeconds>)> {
        self.recorded.lock().expect("ledger lock").clone()
    }
}

impl UnattributedLedger for RecordingLedger {
    fn record_node_answer(&self, machine: EntityId, ran: &[UnattributedSeconds]) {
        self.node.state().calls.push(Call {
            node: machine,
            kind: "ledger",
            key: None,
            bytes: Vec::new(),
        });
        self.recorded
            .lock()
            .expect("ledger lock")
            .push((machine, ran.to_vec()));
    }
}

fn orphan_keys(rig: &Rig) -> (Arc<JobOrphanKeys>, Arc<RecordingLedger>) {
    let ledger = Arc::new(RecordingLedger {
        node: rig.node.clone(),
        recorded: Mutex::new(Vec::new()),
    });
    let orphans = Arc::new(JobOrphanKeys {
        vault: Arc::clone(rig.vault()),
        issuer: rig.issuer,
        client: rig.node.clone(),
        signer: rig.signers.as_machine(rig.issuer),
        clock: rig.clock.clone(),
        ledger: ledger.clone(),
    });
    (orphans, ledger)
}

/// A key on the node that this issuer holds no dispatch row for: started, on a hold of
/// `reservation` at `generation`.
fn foreign_key(rig: &Rig, key: &str, reservation: &str, generation: u64) {
    let mut receipt = rig.node.blank(key);
    receipt.state = JobState::Running;
    receipt.started = true;
    receipt.device_id = Some("scripted-gpu".to_owned());
    receipt.release = DeviceRelease::Held;
    receipt.measured_secs = Some(50);
    receipt.hold = Some(HoldRef {
        reservation: reservation.to_owned(),
        generation,
    });
    rig.node.put(receipt);
}

/// T31: a key the issuer does not know is recorded, a live one is asked to stop until it ends,
/// nothing is ever submitted for it, and its seconds are charged to no family.
#[test]
fn a_node_key_the_issuer_does_not_know_is_recorded_stopped_and_charged_to_no_family() {
    with_rig(|rig| {
        let (orphans, ledger) = orphan_keys(rig);
        let connector = make_connector_with(
            rig.vault(),
            rig.issuer,
            &rig.signers,
            &rig.clock,
            &rig.node,
            orphans.clone(),
        );
        foreign_key(rig, "orphan-live", "reservation-live", 7);
        foreign_key(rig, "orphan-ended", "reservation-ended", 7);
        rig.node.revise("orphan-ended", |receipt| {
            receipt.state = JobState::Ended;
            receipt.end = Some(JobEnd::Exited { code: 0 });
            receipt.measured_secs = Some(120);
            receipt.release = DeviceRelease::Confirmed { at_ms: NOW_MS };
        });

        let workload = rig.approve("orphans", FAR_EXPIRY_MS);
        let run = rig.start_job_with(&workload, &connector);
        assert_eq!(run.job.state, GpuJobState::Running);
        let calls = rig.node.calls();
        let keys = position(&calls, "keys", None);
        let stop = position(&calls, "stop", Some("orphan-live"));
        let recorded = position(&calls, "ledger", None);
        let reserve = position(&calls, "reserve", Some(run.key()));
        assert!(
            keys < stop && stop < recorded && recorded < reserve,
            "the reconcile reads, stops and records before the first reserve: {calls:?}",
        );
        for orphan in ["orphan-live", "orphan-ended"] {
            assert!(
                kinds_for(&calls, orphan)
                    .iter()
                    .all(|kind| !matches!(*kind, "reserve" | "submit")),
                "nothing is dispatched for {orphan}",
            );
            assert!(
                rig.vault()
                    .job_dispatch(orphan)
                    .expect("read JOB_DISPATCH")
                    .is_none(),
                "{orphan} belongs to no job of this issuer",
            );
        }

        let machine = rig.node.machine;
        let live = rig
            .vault()
            .job_orphan(machine, "orphan-live")
            .expect("read JOB_ORPHAN")
            .expect("the live orphan's row");
        assert_eq!(live.state, "ending", "the node took the stop");
        assert!(live.stop_sent_at_ms.is_some());
        assert!(live.is_live());
        let ended = rig
            .vault()
            .job_orphan(machine, "orphan-ended")
            .expect("read JOB_ORPHAN")
            .expect("the ended orphan's row");
        assert!(ended.ended.is_some(), "its terminal receipt is kept");
        assert_eq!(ended.stop_sent_at_ms, None, "an ended key gets no stop");
        let seconds = ended.unattributed.clone().expect("it ran");
        assert_eq!(
            (
                seconds.reservation.as_str(),
                seconds.generation,
                seconds.secs
            ),
            ("reservation-ended", 7, 120)
        );
        assert_eq!(ledger.recorded(), vec![(machine, vec![seconds])]);

        // The housekeeping pass stops the live one again until the node answers its end.
        orphans.follow_live_orphans(Some(machine));
        assert_eq!(
            ledger.recorded().len(),
            1,
            "an orphan still ending records nothing"
        );
        end_clean_key(rig, "orphan-live", 55);
        orphans.follow_live_orphans(Some(machine));
        let live = rig
            .vault()
            .job_orphan(machine, "orphan-live")
            .expect("read JOB_ORPHAN")
            .expect("the orphan's row");
        assert!(!live.is_live(), "the end is recorded");
        let seconds = live.unattributed.clone().expect("it ran");
        assert_eq!((seconds.generation, seconds.secs), (7, 55));
        assert_eq!(ledger.recorded().last(), Some(&(machine, vec![seconds])));
        let stops = kinds_for(&rig.node.calls(), "orphan-live")
            .iter()
            .filter(|kind| **kind == "stop")
            .count();
        orphans.follow_live_orphans(Some(machine));
        assert_eq!(
            kinds_for(&rig.node.calls(), "orphan-live")
                .iter()
                .filter(|kind| **kind == "stop")
                .count(),
            stops,
            "an ended orphan is not asked again",
        );
        assert!(
            run.settled().is_empty(),
            "the issuer's own job is untouched"
        );
    });
}

/// `key`'s newest report ends it stopped after `secs`, its device released clean.
fn end_clean_key(rig: &Rig, key: &str, secs: u64) {
    let at_ms = rig.clock.now_ms();
    rig.node.revise(key, |receipt| {
        receipt.state = JobState::Ended;
        receipt.end = Some(JobEnd::Stopped);
        receipt.measured_secs = Some(secs);
        receipt.release = DeviceRelease::Confirmed { at_ms };
    });
}

/// T31b: a job that ended after the issuer's backup was taken is a key the restored issuer has
/// no row for. Its seconds are recorded against the generation its hold named before any new
/// reserve, and a later reconcile tells the ledger the same record, never a second spend.
#[test]
fn a_job_that_ended_after_the_issuers_backup_is_recorded_against_its_generation_before_any_new_start()
 {
    with_rig(|rig| {
        let (orphans, ledger) = orphan_keys(rig);
        foreign_key(rig, "after-backup", "reservation-after-backup", 12);
        end_clean_key(rig, "after-backup", 200);
        let workload = rig.approve("after-backup", FAR_EXPIRY_MS);

        let restored = make_connector_with(
            rig.vault(),
            rig.issuer,
            &rig.signers,
            &rig.clock,
            &rig.node,
            orphans.clone(),
        );
        let first = rig.start_job_with(&workload, &restored);
        let calls = rig.node.calls();
        assert!(
            position(&calls, "ledger", None) < position(&calls, "reserve", Some(first.key())),
            "the seconds are recorded before the first new reserve: {calls:?}",
        );
        let recorded = ledger.recorded();
        assert_eq!(recorded.len(), 1);
        let (machine, ran) = &recorded[0];
        assert_eq!(*machine, rig.node.machine);
        assert_eq!(ran.len(), 1);
        assert_eq!(
            (ran[0].reservation.as_str(), ran[0].generation, ran[0].secs),
            ("reservation-after-backup", 12, 200),
        );

        rig.clock.advance_secs(600);
        let before = rig.node.calls().len();
        let restarted = make_connector_with(
            rig.vault(),
            rig.issuer,
            &rig.signers,
            &rig.clock,
            &rig.node,
            orphans.clone(),
        );
        let second = rig.start_job_with(&workload, &restarted);
        let calls = rig.node.calls();
        let later = &calls[before..];
        assert!(
            position(later, "ledger", None) < position(later, "reserve", Some(second.key())),
            "a restart records again before its first reserve: {later:?}",
        );
        let recorded = ledger.recorded();
        assert_eq!(recorded.len(), 2);
        assert_eq!(
            recorded[1], recorded[0],
            "the same record, with the time it was first recorded: no second spend",
        );
    });
}

/// Starts a job on the rig's machine and lets the node end it as `end` after `secs` measured
/// seconds (`None`: never launched).
fn run_to_end(rig: &Rig, workload: &str, end: JobEnd, secs: Option<u64>) -> GpuJobState {
    let run = rig.start_job(workload);
    rig.clock.advance_secs(30);
    rig.node
        .advance(run.key(), JobState::Ended, secs, Some(end), secs.is_some());
    rig.settle(&run).state
}

fn owner_clears_drain(rig: &Rig) -> Result<String, String> {
    let owner = rig
        .owner
        .actor_for_read(rig.vault())
        .expect("the owner's actor");
    let memory = rig.vault().memory(owner, EdgeActorClass::Human);
    clear_drain_as(
        &memory,
        Some(&rig.owner),
        &MachineDrainClearRequest {
            machine: rig.node.machine.to_hex(),
        },
    )
    .map(|cleared| cleared.was_drained_because)
    .map_err(|error| error.code.clone())
}

/// T32, the issuer's half: three of the machine's own failures in a row drain it on the
/// issuer; a caller's stop neither counts nor resets; a drained machine gets no reserve and no
/// request; door 12 clears it for the owner, once.
#[test]
fn three_machine_failures_in_a_row_drain_the_node_until_a_person_clears_it() {
    with_rig(|rig| {
        let workload = rig.approve("drain", FAR_EXPIRY_MS);
        let guard = || {
            rig.vault()
                .machine_job_guard(rig.node.machine)
                .expect("read the machine's job guard")
                .expect("a counted machine")
        };

        run_to_end(rig, &workload, JobEnd::Exited { code: 1 }, Some(2));
        assert_eq!(
            guard().failures_in_a_row,
            1,
            "an end inside the fast-exit window"
        );

        let stopped = rig.start_job(&workload);
        rig.vault()
            .cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &stopped.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            )
            .expect("the caller stops a job before launch");
        assert_eq!(
            guard().failures_in_a_row,
            1,
            "a caller's stop neither counts nor resets"
        );

        run_to_end(
            rig,
            &workload,
            JobEnd::LaunchRefused {
                reason: "commit_missing".to_owned(),
            },
            None,
        );
        assert_eq!(guard().failures_in_a_row, 2);
        assert_eq!(guard().drained, None);
        run_to_end(
            rig,
            &workload,
            JobEnd::Lost {
                reason: "node_reset".to_owned(),
                last_tick_boot_ns: 0,
                breadcrumbs: Vec::new(),
            },
            Some(0),
        );
        let drained = guard().drained.expect("the third failure drains");
        assert_eq!(
            drained.why,
            "drained after 3 failed jobs in a row; the last: lost: node_reset"
        );
        assert_eq!(guard().last_failure.as_deref(), Some("lost: node_reset"));

        let before = rig.node.calls().len();
        let refused = rig.start_job(&workload);
        assert_eq!(
            refused.job.state,
            GpuJobState::Held {
                reason: "machine_drained".to_owned()
            },
            "the job's reason is the code alone; the cause stays in the machine's guard",
        );
        assert_eq!(refused.settled(), vec![0], "the hold settles at zero");
        assert_eq!(
            rig.node.calls().len(),
            before,
            "a drained machine gets no request"
        );
        assert!(
            rig.vault()
                .job_dispatch(refused.key())
                .expect("read JOB_DISPATCH")
                .is_none(),
            "nothing is written for it",
        );

        assert_eq!(
            owner_clears_drain(rig),
            Ok(drained.why.clone()),
            "the clear answers the cause the drain recorded",
        );
        assert_eq!(guard().drained, None);
        assert_eq!(guard().failures_in_a_row, 0, "the count starts again");
        assert_eq!(
            owner_clears_drain(rig),
            Err(MEMORY_CODE_INVALID_STATE.to_owned()),
            "a machine that is not drained has nothing to clear",
        );
        let resumed = rig.start_job(&workload);
        assert_eq!(resumed.job.state, GpuJobState::Running);
        assert!(kinds_for(&rig.node.calls(), resumed.key()).contains(&"reserve"));
    });
}

/// Pass 34, 2.4: `machines.drain.clear_by` names who clears the issuer's drain of a machine;
/// under `person_at_box` no verb clears it, the owner's included.
#[test]
fn a_drain_is_cleared_only_as_machines_drain_clear_by_allows() {
    with_rig(|rig| {
        let workload = rig.approve("clear-by", FAR_EXPIRY_MS);
        for _ in 0..3 {
            run_to_end(rig, &workload, JobEnd::Exited { code: 1 }, Some(1));
        }
        assert!(
            rig.vault()
                .machine_job_drained(rig.node.machine)
                .expect("read the drain")
                .is_some(),
            "three fast exits drain the machine",
        );
        let outcome = rig
            .vault()
            .set_setting(
                SettingCaller::Owner(&rig.owner),
                SetSetting {
                    item: Some(rig.node.machine.to_hex()),
                    ..SetSetting::vault_value(
                        "machines.drain.clear_by",
                        json!({"by": "person_at_box"}),
                    )
                },
            )
            .expect("the owner tightens who clears");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "{outcome:?}"
        );
        assert_eq!(
            owner_clears_drain(rig),
            Err(MEMORY_CODE_FORBIDDEN.to_owned())
        );
        assert!(
            rig.vault()
                .machine_job_drained(rig.node.machine)
                .expect("read the drain")
                .is_some(),
            "the drain stands",
        );
    });
}

/// T33c: the owner writes off a job whose machine stopped answering, once the start window, the
/// maximum and `jobs.write_off.wait_secs` have passed. It ends `unconfirmed` and settles zero,
/// for good: the key is never asked again, and the machine's later receipt is kept as evidence
/// on the dispatch, counts against the machine, and settles nothing.
#[test]
fn a_write_off_is_final_and_a_later_receipt_does_not_settle() {
    with_rig(|rig| {
        let workload = rig.approve("write-off", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        rig.node
            .advance(run.key(), JobState::Running, Some(30), None, true);
        rig.step(&run).expect("poll the running job");
        rig.node.unreachable(true);
        let write_off = || {
            rig.vault().write_off_gpu_job(
                &rig.owner,
                &run.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            )
        };

        let early = write_off();
        assert!(
            matches!(
                &early,
                Err(GpuJobError::Connector(GpuConnectorError::Refused { reason }))
                    if reason == "write_off_too_early"
            ),
            "a write-off waits for the node's latest cutoff and the wait: {early:?}",
        );
        assert_eq!(rig.job(&run).state, GpuJobState::Running);

        let submit: SignedJobSubmit =
            oneiron_organ_protocol::from_slice(&rig.dispatch(&run).submit)
                .expect("decode the stored submit");
        let earliest_ms = submit.submit.not_after_ms
            + submit.submit.maximum_secs * 1_000
            + WRITE_OFF_WAIT_SECS * 1_000;
        rig.clock
            .advance_secs((earliest_ms - rig.clock.now_ms()) / 1_000 + 1);
        let written = write_off().expect("the owner writes the job off");
        assert_eq!(
            written.state,
            GpuJobState::Ended {
                reason: GpuEndReason::Unconfirmed
            }
        );
        assert_eq!(written.chunk().and_then(|chunk| chunk.billed_secs), None);
        assert_eq!(run.settled(), vec![0], "it settles zero");
        let row = rig.dispatch(&run);
        assert_eq!(row.phase, DispatchPhase::Closed);
        assert!(
            matches!(
                row.closed,
                Some(DispatchClose::WrittenOff {
                    late_receipt: None,
                    ..
                })
            ),
            "{:?}",
            row.closed
        );
        assert_eq!(view(rig, &run).accounting, GpuJobAccounting::WrittenOff);
        let again = write_off();
        assert!(matches!(again, Err(GpuJobError::Ended)), "{again:?}");

        rig.node.unreachable(false);
        rig.node.advance(
            run.key(),
            JobState::Ended,
            Some(900),
            Some(JobEnd::Exited { code: 0 }),
            true,
        );
        let before = rig.node.calls().len();
        rig.step(&run).expect("a step of the written-off job");
        assert_eq!(
            rig.node.calls().len(),
            before,
            "a written-off key is never asked again"
        );

        // A restarted issuer's reconcile reads the node's keys and keeps the late receipt.
        let (orphans, _ledger) = orphan_keys(rig);
        let restarted = make_connector_with(
            rig.vault(),
            rig.issuer,
            &rig.signers,
            &rig.clock,
            &rig.node,
            orphans,
        );
        let next = rig.start_job_with(&workload, &restarted);
        assert_eq!(next.job.state, GpuJobState::Running);
        let row = rig.dispatch(&run);
        let Some(DispatchClose::WrittenOff {
            late_receipt: Some(bytes),
            ..
        }) = &row.closed
        else {
            panic!("the late receipt is kept: {:?}", row.closed);
        };
        let late: SignedJobReceipt =
            oneiron_organ_protocol::from_slice(bytes).expect("decode the late receipt");
        assert_eq!(late.receipt.measured_secs, Some(900));
        assert_eq!(
            rig.job(&run).state,
            GpuJobState::Ended {
                reason: GpuEndReason::Unconfirmed
            },
            "the job stays written off",
        );
        assert_eq!(run.settled(), vec![0], "the late receipt settles nothing");
        let guard = rig
            .vault()
            .machine_job_guard(rig.node.machine)
            .expect("read the machine's job guard")
            .expect("the late receipt was counted");
        assert_eq!(
            guard.last_failure.as_deref(),
            Some("receipt_after_write_off")
        );
    });
}

/// A plain-text artifact with one version and a live task, both the owner's: where a job's
/// result lands, and the task its made_by names. The returnable output is `verdict.json`: each
/// version keeps the artifact's own media type, whatever the file is called (review 10430 P1).
fn result_binding(rig: &Rig) -> GpuJobResultBinding {
    let vault = rig.vault().as_ref();
    let owner = rig
        .owner
        .revalidate(vault)
        .expect("the owner on this vault");
    let human = vault.memory(owner, EdgeActorClass::Human);
    let task = human
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("Read the GPU verdict"),
            None,
            None,
            None,
        ))
        .expect("the owner creates a task")
        .task_ref
        .expect("a landed task");
    let artifact = human
        .artifacts_create(&ArtifactCreateRequest {
            name: "verdict.txt".to_owned(),
            media_type: "text/plain".to_owned(),
            content_base64: STANDARD.encode(b"no verdict yet"),
            run_ref: None,
            made_by: None,
        })
        .expect("the owner uploads the artifact")
        .expect("the artifact's view")
        .artifact_id;
    GpuJobResultBinding { artifact, task }
}

fn bound_inputs(rig: &Rig, binding: &GpuJobResultBinding) -> serde_json::Value {
    json!({"machine": rig.node.machine.to_hex(), "result": binding})
}

/// The node ends `run` after 20 measured seconds, its device released clean, having hashed
/// `outputs` (name, bytes, returnable).
fn end_with_outputs(rig: &Rig, run: &JobRun, outputs: &[(&str, &[u8], bool)]) {
    let at_ms = rig.clock.now_ms();
    let digests: Vec<OutputDigest> = outputs
        .iter()
        .map(|(name, bytes, returnable)| OutputDigest {
            name: (*name).to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            bytes: u64::try_from(bytes.len()).expect("a small output"),
            returnable: *returnable,
        })
        .collect();
    rig.node.revise(run.key(), |receipt| {
        receipt.state = JobState::Ended;
        receipt.started = true;
        receipt.end = Some(JobEnd::Exited { code: 0 });
        receipt.measured_secs = Some(20);
        receipt.device_id = Some("scripted-gpu".to_owned());
        receipt.release = DeviceRelease::Confirmed { at_ms };
        receipt.outputs = OutputsState::Hashed(digests);
    });
}

/// The names `calls` fetched for `key`, in order.
fn fetched(calls: &[Call], key: &str) -> Vec<String> {
    calls
        .iter()
        .filter(|call| call.kind == "fetch" && call.key.as_deref() == Some(key))
        .map(|call| {
            match oneiron_organ_protocol::from_slice::<JobStatusRequest>(&call.bytes)
                .expect("decode the recorded fetch")
            {
                JobStatusRequest::Fetch { name, .. } => name,
                other => panic!("a fetch call recorded {other:?}"),
            }
        })
        .collect()
}

/// T33b, the issuer's half (EM-12 = A): with a quote that binds a result, the returnable
/// output is fetched, checked against the machine's signed digest and length, and proposed as
/// the artifact's next version, pending Keep, made by the task; then the node is told it may
/// clean. A file that is not returnable is never asked for, bytes that do not match the digest
/// land nothing, and a quote with no binding fetches nothing.
#[test]
fn a_returnable_output_is_fetched_and_checked_and_no_other_file_can_be() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let head = vault
            .blob_artifact_head(&binding.artifact)
            .expect("read the artifact's head");
        assert!(head.is_some(), "the artifact has its first version");
        let workload = rig.approve("result", FAR_EXPIRY_MS);
        let verdict: &[u8] = br#"{"verdict":"pass"}"#;
        let notes: &[u8] = b"kept on the machine";

        let run = rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
        rig.clock.advance_secs(30);
        end_with_outputs(
            rig,
            &run,
            &[("verdict.json", verdict, true), ("notes.txt", notes, false)],
        );
        rig.node.put_output(run.key(), "verdict.json", verdict);
        rig.node.put_output(run.key(), "notes.txt", notes);
        rig.settle(&run);
        let calls = rig.node.calls();
        assert_eq!(
            fetched(&calls, run.key()),
            vec!["verdict.json".to_owned()],
            "only the returnable output is fetched",
        );
        assert!(
            position(&calls, "fetch", Some(run.key())) < position(&calls, "ack", Some(run.key())),
            "the node is told to clean only after the landing: {calls:?}",
        );
        let waiting = vault
            .pending_proposals(&binding.artifact)
            .expect("list the artifact's proposals");
        assert_eq!(waiting.len(), 1, "one proposal waits");
        let made_by = waiting[0].made_by.as_ref().expect("its made_by");
        assert_eq!(made_by.trigger, Some(MadeByTrigger::Task(binding.task)));
        assert_eq!(
            vault
                .blob_artifact_head(&binding.artifact)
                .expect("read the artifact's head"),
            head,
            "pending Keep: the head did not move",
        );
        let returned = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(returned.landed, vec!["verdict.json".to_owned()]);
        assert!(returned.refused.is_empty());
        assert!(returned.acknowledged_at_ms.is_some());

        let tampered =
            rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
        rig.clock.advance_secs(30);
        end_with_outputs(rig, &tampered, &[("verdict.json", verdict, true)]);
        rig.node
            .put_output(tampered.key(), "verdict.json", br#"{"verdict":"fail"}"#);
        rig.settle(&tampered);
        let returned = vault
            .job_return(tampered.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(
            returned.refused,
            vec![ReturnRefusal {
                name: "verdict.json".to_owned(),
                why: "digest_mismatch".to_owned(),
            }],
        );
        assert!(returned.landed.is_empty());
        assert_eq!(
            vault
                .pending_proposals(&binding.artifact)
                .expect("list the artifact's proposals")
                .len(),
            1,
            "bytes that do not match the signed digest land nothing",
        );

        let unbound = rig.start_job(&workload);
        rig.clock.advance_secs(30);
        end_with_outputs(rig, &unbound, &[("verdict.json", verdict, true)]);
        rig.node.put_output(unbound.key(), "verdict.json", verdict);
        rig.settle(&unbound);
        let calls = rig.node.calls();
        let kinds = kinds_for(&calls, unbound.key());
        assert!(!kinds.contains(&"fetch"), "no binding, no fetch: {kinds:?}");
        assert!(kinds.contains(&"ack"), "and the node may clean: {kinds:?}");
    });
}

/// A fetch that does not arrive leaves the output owed and the node unacknowledged; the next
/// housekeeping pass lands it and acknowledges, and a pass after that asks nothing.
#[test]
fn a_result_that_does_not_arrive_is_returned_by_the_next_housekeeping_pass() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let workload = rig.approve("result-late", FAR_EXPIRY_MS);
        let verdict: &[u8] = br#"{"verdict":"late"}"#;
        let run = rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
        rig.clock.advance_secs(30);
        end_with_outputs(rig, &run, &[("verdict.json", verdict, true)]);
        rig.node.put_output(run.key(), "verdict.json", verdict);
        rig.node.drop_next("fetch");
        rig.settle(&run);
        let owed = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert!(owed.landed.is_empty() && owed.refused.is_empty());
        assert_eq!(
            owed.acknowledged_at_ms, None,
            "no Ack while an output is owed"
        );
        assert!(!kinds_for(&rig.node.calls(), run.key()).contains(&"ack"));
        assert_eq!(
            vault
                .job_returns_owed()
                .expect("read the owed returns")
                .len(),
            1
        );

        rig.connector.housekeeping();
        let done = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(done.landed, vec!["verdict.json".to_owned()]);
        assert!(done.acknowledged_at_ms.is_some());
        assert!(
            vault
                .job_returns_owed()
                .expect("read the owed returns")
                .is_empty()
        );
        assert_eq!(
            vault
                .pending_proposals(&binding.artifact)
                .expect("list the artifact's proposals")
                .len(),
            1
        );

        let before = rig.node.calls().len();
        rig.connector.housekeeping();
        assert_eq!(
            rig.node.calls().len(),
            before,
            "nothing is owed: a further pass asks nothing"
        );
    });
}
