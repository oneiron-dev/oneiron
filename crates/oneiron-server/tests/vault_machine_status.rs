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
use oneiron::authority::ActSurface;
use oneiron::blob_artifact::ArtifactCreateRequest;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::gpu_job::{
    GpuConnectorError, GpuEndReason, GpuJobAccounting, GpuJobActor, GpuJobConnector, GpuJobError,
    GpuJobLifecycle, GpuJobNodeView, GpuJobResultBinding, GpuJobState, GpuJobStatus, MeterVerdict,
};
use oneiron::job_dispatch::machine_records::{
    MachineDrainClearRequest, ReturnRefusal, UnattributedSeconds, clear_drain_as,
};
use oneiron::job_dispatch::{DispatchClose, DispatchPhase};
use oneiron::job_history::{HistoryViewer, JobHistoryAttempt, JobHistoryRequest, read_job_history};
use oneiron::job_workload::{WorkloadCaller, WorkloadRef, WorkloadStarter};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE};
use oneiron::provenance::made_by::MadeByTrigger;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::task_verb::TaskCreateSpec;
use oneiron::test_doors::derive::expire_agent_grant;
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::{EdgeActorClass, EntityId};
use oneiron_server::gpu_execution_node::issuer::{IssuerClock, JobOrphanKeys, UnattributedLedger};
use oneiron_server::gpu_execution_node::wire::{
    DeviceRelease, HoldRef, JobEnd, JobState, JobStatusRequest, OutputDigest, OutputsState,
    SignedJobReceipt, SignedJobSubmit,
};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use vault_machine_rig::{
    Call, FAR_EXPIRY_MS, JobRun, MAXIMUM_SECS, NOW_MS, Rig, ScriptedNode, make_connector_with,
    with_rig,
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

/// Pass 33, 8.6 (10.3 need 5): a run its node ends at the job's maximum ends the job with the
/// end reason `time_limit`. It is never shown as a natural exit, and never as `stopped`, whose
/// stop offers a resume from a checkpoint: a hard stop offers none.
#[test]
fn a_job_its_node_ends_at_the_maximum_ends_time_limit_not_exited() {
    with_rig(|rig| {
        let workload = rig.approve("time-limit", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        rig.node
            .advance(run.key(), JobState::Running, Some(30), None, true);
        rig.step(&run).expect("poll the running job");
        rig.clock.advance_secs(60);
        end_clean(rig, &run, JobEnd::TimeLimit, Some(90));
        let ended = rig.settle(&run);
        assert_eq!(
            serde_json::to_value(&ended.state).expect("encode the job's state"),
            json!({ "ended": { "reason": "time_limit" } }),
            "the node ended the job at its maximum; it did not end by itself",
        );
        let status = GpuJobStatus::from(&ended);
        assert_eq!(status.state, "ended");
        assert_eq!(status.end_reason.as_deref(), Some("time_limit"));
        assert!(
            status.stop.is_none(),
            "a hard stop offers no resume: {:?}",
            status.stop
        );
        let node = view(rig, &run).node.expect("the node's receipt");
        assert_eq!(node.end.as_deref(), Some("time_limit"));
    });
}

/// The owner's jobs' history row of `run`'s chunk.
fn history_attempt(rig: &Rig, run: &JobRun) -> JobHistoryAttempt {
    let filter = JobHistoryRequest::default()
        .filter()
        .expect("a valid history request");
    read_job_history(rig.vault(), &filter, HistoryViewer::Owner)
        .expect("read the jobs' history")
        .attempts
        .into_iter()
        .find(|attempt| attempt.key == run.key())
        .expect("the chunk's history row")
}

/// Pass 33, 8.6: a cancel that reaches a run its node has already ended at the maximum does not
/// overwrite the cause. The node's confirmed hard stop is the end: the job ends `time_limit`,
/// never `cancelled`, and its history shows the node's measure of the run.
#[test]
fn a_cancel_after_the_nodes_hard_stop_ends_the_job_time_limit_not_cancelled() {
    with_rig(|rig| {
        let workload = rig.approve("time-limit-cancel", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        rig.node
            .advance(run.key(), JobState::Running, Some(30), None, true);
        rig.step(&run).expect("poll the running job");
        rig.clock.advance_secs(60);
        end_clean(rig, &run, JobEnd::TimeLimit, Some(90));

        rig.vault()
            .cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &run.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            )
            .expect("cancel the job before the issuer polls its end");
        let ended = rig.settle(&run);
        assert_eq!(
            serde_json::to_value(&ended.state).expect("encode the job's state"),
            json!({ "ended": { "reason": "time_limit" } }),
            "the node's hard stop came first; the cancel ended nothing",
        );
        assert_eq!(
            GpuJobStatus::from(&ended).end_reason.as_deref(),
            Some("time_limit")
        );
        let attempt = history_attempt(rig, &run);
        assert_eq!(attempt.end, "time_limit");
        assert_eq!(attempt.occupied_secs, Some(90), "the node's measure");
    });
}

/// Pass 33, 8.6: a status taken while the node's journal still said running estimates the run
/// time to the issuer's clock, which can pass the node's own measure to the hard stop. The
/// node's measure at the end is the run's occupancy: the history never shows the estimate.
#[test]
fn a_hard_stop_shows_the_nodes_measure_not_an_earlier_larger_estimate() {
    with_rig(|rig| {
        let workload = rig.approve("time-limit-measure", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        rig.node
            .advance(run.key(), JobState::Running, Some(15), None, true);
        rig.step(&run).expect("poll the running job");
        assert_eq!(rig.job(&run).chunks[0].used_secs, 15, "the live estimate");
        end_clean(rig, &run, JobEnd::TimeLimit, Some(11));

        let ended = rig.settle(&run);
        assert_eq!(
            serde_json::to_value(&ended.state).expect("encode the job's state"),
            json!({ "ended": { "reason": "time_limit" } }),
        );
        assert_eq!(ended.chunks[0].used_secs, 11, "the node's measure");
        let attempt = history_attempt(rig, &run);
        assert_eq!(attempt.end, "time_limit");
        assert_eq!(
            attempt.occupied_secs,
            Some(11),
            "the node measured 11 s to the hard stop; 15 s was an estimate"
        );
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

/// [`end_with_outputs`], the node's end being `end`.
fn end_with_outputs_as(rig: &Rig, run: &JobRun, end: JobEnd, outputs: &[(&str, &[u8], bool)]) {
    end_with_outputs(rig, run, outputs);
    rig.node
        .revise(run.key(), |receipt| receipt.end = Some(end));
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

/// RESULT-LANDING-LAPSED-STARTER = A (Engine 25 Nov 23:19; ARCH-0075): a job the issuer stopped
/// because its workload approval was revoked lands nothing, though its starter (here the owner)
/// still stands. Each returnable output is recorded refused `job_revoked` and never fetched,
/// the node is told it may clean, and no return stays owed.
#[test]
fn a_job_stopped_for_a_revoke_lands_no_output_and_the_node_may_clean() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let workload = rig.approve("result-revoked", FAR_EXPIRY_MS);
        let verdict: &[u8] = br#"{"verdict":"partial"}"#;
        let run = rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
        rig.clock.advance_secs(10);
        rig.node
            .advance(run.key(), JobState::Running, Some(10), None, true);
        rig.step(&run).expect("poll the running job");
        let revoked = vault
            .revoke_job_workload(
                WorkloadCaller::Owner(&rig.owner),
                &WorkloadRef {
                    workload: workload.clone(),
                },
                rig.clock.now_ms(),
            )
            .expect("the owner revokes the approval");
        assert!(revoked.changed, "the revoke was written");
        rig.step(&run).expect("step after the revoke");
        assert_eq!(
            rig.dispatch(&run).closed,
            Some(DispatchClose::Revoked {
                code: "workload_revoked".to_owned()
            }),
            "the issuer closed the key for the revoke",
        );
        rig.clock.advance_secs(2);
        let at_ms = rig.clock.now_ms();
        rig.node.revise(run.key(), |receipt| {
            receipt.state = JobState::Ended;
            receipt.started = true;
            receipt.end = Some(JobEnd::Stopped);
            receipt.measured_secs = Some(12);
            receipt.device_id = Some("scripted-gpu".to_owned());
            receipt.release = DeviceRelease::Confirmed { at_ms };
            receipt.outputs = OutputsState::Hashed(vec![OutputDigest {
                name: "verdict.json".to_owned(),
                sha256: format!("{:x}", Sha256::digest(verdict)),
                bytes: u64::try_from(verdict.len()).expect("a small output"),
                returnable: true,
            }]);
        });
        rig.node.put_output(run.key(), "verdict.json", verdict);
        rig.settle(&run);

        let returned = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(
            returned.refused,
            vec![ReturnRefusal {
                name: "verdict.json".to_owned(),
                why: "job_revoked".to_owned(),
            }],
            "the revoked job's output is refused",
        );
        assert!(returned.landed.is_empty(), "nothing landed");
        assert!(
            returned.acknowledged_at_ms.is_some(),
            "the node is told it may clean"
        );
        let calls = rig.node.calls();
        assert!(
            fetched(&calls, run.key()).is_empty(),
            "no output of a revoked job is fetched: {calls:?}",
        );
        assert!(kinds_for(&calls, run.key()).contains(&"ack"));
        assert!(
            vault
                .pending_proposals(&binding.artifact)
                .expect("list the artifact's proposals")
                .is_empty(),
            "nothing waits on the artifact"
        );
        assert!(
            vault
                .job_returns_owed()
                .expect("read the owed returns")
                .is_empty(),
            "no return is owed"
        );
    });
}

/// The start verb an agent's Grant names to start a GPU job.
const START_VERB: &str = oneiron::gpu_job::GpuJobVerb::Start.name();

/// A named agent on the issuer (made on first use, the same agent after) with a Grant the
/// owner mints for it naming `verbs`, and that Grant's GPU job allowance. Answers the agent and
/// the Grant's row id, the id a workload's starters name.
fn agent_with_grant(rig: &Rig, name: &str, verbs: &[&str]) -> (EntityId, EntityId) {
    let vault = rig.vault();
    let agent_id = vault
        .ensure_agent_principal(name)
        .expect("a named agent on the issuer");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let grant = mint_agent_grant_as(
        vault,
        &rig.owner,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: agent_id,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: Default::default(),
            wallet_ref: None,
            working_view_bounds: None,
            check_in_ref: None,
        },
    )
    .expect("the owner mints the agent's Grant")
    .grant;
    assert!(grant.confers, "the Grant confers");
    vault
        .allow_gpu_jobs(
            &rig.owner,
            &grant.grant_ref,
            MAXIMUM_SECS,
            rig.clock.now_ms(),
        )
        .expect("set the Grant's per-job maximum")
        .expect("the allowance row");
    (agent_id, grant.grant_ref)
}

/// RESULT-LANDING-LAPSED-STARTER = A (Engine 25 Nov 23:19; ARCH-0046): a job that ended by
/// itself still returns its result when its starter stopped standing afterwards. An agent
/// starts it under its own Grant, the job completes, the fetch does not arrive, and then the
/// Grant expires. The next housekeeping pass lands the output in the owner's lane, written by
/// the issuer, pending Keep: the issuer is made_by's process (the writer, FIX 9618), made_by
/// still names the agent as an input and the task as its trigger, and the head does not move.
#[test]
fn a_finished_job_whose_starter_lapsed_lands_its_result_in_the_owners_lane() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let (agent_id, grant_ref) =
            agent_with_grant(rig, "gpu-result-lapsed-starter", &["read", START_VERB]);
        let workload = rig.approve_for_starters(
            "result-lapsed-starter",
            FAR_EXPIRY_MS,
            vec![grant_ref.to_hex()],
        );
        let agent = vault
            .memory(agent_id, EdgeActorClass::Agent)
            .gpu_job_agent();
        let verdict: &[u8] = br#"{"verdict":"kept"}"#;
        let run = rig.start_job_as(
            GpuJobActor::Agent(&agent),
            &workload,
            bound_inputs(rig, &binding),
            &rig.connector,
        );
        assert_eq!(
            rig.job(&run).started_by,
            Some(agent_id),
            "the agent started it"
        );
        rig.clock.advance_secs(30);
        end_with_outputs(rig, &run, &[("verdict.json", verdict, true)]);
        rig.node.put_output(run.key(), "verdict.json", verdict);
        rig.node.drop_next("fetch");
        rig.settle(&run);
        let dispatch = rig.dispatch(&run);
        assert_eq!(dispatch.phase, DispatchPhase::Closed);
        assert!(
            !matches!(dispatch.closed, Some(DispatchClose::Revoked { .. })),
            "the job ended by itself: {:?}",
            dispatch.closed,
        );
        let owed = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert!(owed.landed.is_empty() && owed.refused.is_empty());
        assert_eq!(owed.acknowledged_at_ms, None, "the output is still owed");

        expire_agent_grant(vault, grant_ref).expect("expire the starter's Grant");
        assert!(
            vault
                .dispatch_starter(agent_id)
                .expect("read the starter's standing")
                .is_none(),
            "the starter no longer stands"
        );
        let head = vault
            .blob_artifact_head(&binding.artifact)
            .expect("read the artifact's head");
        rig.connector.housekeeping();

        let done = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(
            done.landed,
            vec!["verdict.json".to_owned()],
            "the paid result still returns: {done:?}",
        );
        assert!(done.refused.is_empty());
        assert!(done.acknowledged_at_ms.is_some(), "then the node may clean");
        let waiting = vault
            .pending_proposals(&binding.artifact)
            .expect("list the artifact's proposals");
        assert_eq!(waiting.len(), 1, "one proposal waits");
        assert_eq!(
            waiting[0].retained_by, rig.issuer,
            "the issuer writes the landing, not the lapsed starter",
        );
        let made_by = waiting[0].made_by.as_ref().expect("its made_by");
        assert_eq!(
            made_by.process.actor, rig.issuer,
            "the writer is made_by's process (FIX 9618)"
        );
        assert!(
            made_by.inputs.iter().any(|input| input.row == agent_id),
            "made_by still names the starter: {made_by:?}",
        );
        assert_eq!(made_by.trigger, Some(MadeByTrigger::Task(binding.task)));
        assert_eq!(
            vault
                .blob_artifact_head(&binding.artifact)
                .expect("read the artifact's head"),
            head,
            "pending Keep: the head did not move",
        );
    });
}

/// RESULT-LANDING-LAPSED-STARTER = A (#10517 review P1-5): the landing judges the Grant the
/// chunk's signed submit names, never another live Grant of the same agent. The agent starts
/// the job under Grant A; the owner then mints it a start-only Grant B (no read); A expires
/// while the result is owed. B makes the agent stand for the start verb, but the result is A's
/// and lands in the owner's lane, written by the issuer.
#[test]
fn a_result_whose_dispatch_grant_lapsed_lands_in_the_owners_lane_though_another_grant_stands() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let name = "gpu-result-second-grant";
        let (agent_id, grant_a) = agent_with_grant(rig, name, &["read", START_VERB]);
        let workload =
            rig.approve_for_starters("result-second-grant", FAR_EXPIRY_MS, vec![grant_a.to_hex()]);
        let agent = vault
            .memory(agent_id, EdgeActorClass::Agent)
            .gpu_job_agent();
        let verdict: &[u8] = br#"{"verdict":"grant a"}"#;
        let run = rig.start_job_as(
            GpuJobActor::Agent(&agent),
            &workload,
            bound_inputs(rig, &binding),
            &rig.connector,
        );
        rig.clock.advance_secs(30);
        end_with_outputs(rig, &run, &[("verdict.json", verdict, true)]);
        rig.node.put_output(run.key(), "verdict.json", verdict);
        rig.node.drop_next("fetch");
        rig.settle(&run);

        let (same_agent, grant_b) = agent_with_grant(rig, name, &[START_VERB]);
        assert_eq!(same_agent, agent_id, "B is the same agent's Grant");
        expire_agent_grant(vault, grant_a).expect("expire the dispatch's Grant");
        assert_eq!(
            vault
                .dispatch_starter(agent_id)
                .expect("read the starter's standing"),
            Some(WorkloadStarter::Grant(grant_b)),
            "the agent still stands for the start verb, under B",
        );
        rig.connector.housekeeping();

        let done = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(
            done.landed,
            vec!["verdict.json".to_owned()],
            "A's result lands: {done:?}"
        );
        assert!(done.acknowledged_at_ms.is_some(), "then the node may clean");
        let waiting = vault
            .pending_proposals(&binding.artifact)
            .expect("list the artifact's proposals");
        assert_eq!(waiting.len(), 1, "one proposal waits");
        assert_eq!(
            waiting[0].retained_by, rig.issuer,
            "the issuer writes it in the owner's lane, not the agent under B",
        );
    });
}

/// #10517 review P1-2: a lapsed starter's result lands in the owner's lane, so a result binds
/// only rows its starter may read. An agent whose Grant names the start verb but no read binds
/// the owner's artifact and task: the first dispatch refuses it, `result_binding_unreadable`,
/// before anything is written or sent.
#[test]
fn a_result_binding_its_agent_starter_cannot_read_is_refused_before_the_dispatch() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let (agent_id, grant) = agent_with_grant(rig, "gpu-result-unreadable", &[START_VERB]);
        let workload =
            rig.approve_for_starters("result-unreadable", FAR_EXPIRY_MS, vec![grant.to_hex()]);
        let agent = vault
            .memory(agent_id, EdgeActorClass::Agent)
            .gpu_job_agent();
        let before = rig.node.calls().len();
        let refused = rig.start_job_as(
            GpuJobActor::Agent(&agent),
            &workload,
            bound_inputs(rig, &binding),
            &rig.connector,
        );
        assert_eq!(
            refused.job.state,
            GpuJobState::Held {
                reason: "result_binding_unreadable".to_owned()
            },
        );
        assert_eq!(
            rig.node.calls().len(),
            before,
            "the machine gets no request"
        );
        assert!(
            vault
                .job_dispatch(refused.key())
                .expect("read JOB_DISPATCH")
                .is_none(),
            "nothing is written for it",
        );
    });
}

/// #10517 review P1-3 and round 2 P1-2: a revoke drops only work it stopped. The node ended
/// the job before the issuer saw the workload approval's revoke: by itself (exit 0), and by a
/// stop at the box (`disable --stop` ends it `Stopped`, the end the issuer's own stop gives),
/// outputs hashed. The issuer asks the node before it closes the key for the revoke, finds the
/// job ended, and closes it as ended, not `Revoked`. The paid result still returns (ARCH-0046),
/// here in the owner's own lane.
#[test]
fn a_job_that_ended_by_itself_before_a_revoke_still_returns_its_result() {
    with_rig(|rig| {
        let vault = rig.vault();
        let ends = [
            ("exited", JobEnd::Exited { code: 0 }),
            ("stopped-at-the-box", JobEnd::Stopped),
        ];
        for (label, end) in ends {
            let binding = result_binding(rig);
            let workload = rig.approve(
                &format!("result-ended-before-revoke-{label}"),
                FAR_EXPIRY_MS,
            );
            let verdict: &[u8] = br#"{"verdict":"done first"}"#;
            let run =
                rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
            rig.clock.advance_secs(10);
            rig.node
                .advance(run.key(), JobState::Running, Some(10), None, true);
            rig.step(&run).expect("poll the running job");
            rig.clock.advance_secs(20);
            end_with_outputs_as(rig, &run, end.clone(), &[("verdict.json", verdict, true)]);
            rig.node.put_output(run.key(), "verdict.json", verdict);
            let revoked = vault
                .revoke_job_workload(
                    WorkloadCaller::Owner(&rig.owner),
                    &WorkloadRef {
                        workload: workload.clone(),
                    },
                    rig.clock.now_ms(),
                )
                .expect("the owner revokes the approval");
            assert!(revoked.changed, "{label}: the revoke was written");
            rig.settle(&run);
            assert_eq!(
                rig.dispatch(&run).closed,
                Some(DispatchClose::Ended),
                "{label}: the node had ended the job, so the issuer closed it as ended",
            );

            let returned = vault
                .job_return(run.key())
                .expect("read JOB_RETURN")
                .expect("the key's return");
            assert_eq!(
                returned.landed,
                vec!["verdict.json".to_owned()],
                "{label}: the result made before the revoke lands: {returned:?}",
            );
            assert!(returned.refused.is_empty(), "{label}: nothing refused");
            assert!(
                returned.acknowledged_at_ms.is_some(),
                "{label}: then the node may clean"
            );
            assert_eq!(
                vault
                    .pending_proposals(&binding.artifact)
                    .expect("list the artifact's proposals")
                    .len(),
                1,
                "{label}: one proposal waits",
            );
        }
    });
}

/// #10517 review round 2 P1-3 (ARCH-0075): a job the node itself ended for a revoke it saw (its
/// grant for the issuer's job protocol ended; EN-4) lands nothing, though the issuer saw no
/// revoke and closed the key as ended. Each returnable output is recorded refused
/// `job_revoked`, never fetched, the node is told it may clean, and nothing waits.
#[test]
fn a_job_the_node_ended_for_its_own_revoke_lands_no_output() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let workload = rig.approve("result-node-revoked", FAR_EXPIRY_MS);
        let verdict: &[u8] = br#"{"verdict":"after the node's revoke"}"#;
        let run = rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
        rig.clock.advance_secs(10);
        rig.node
            .advance(run.key(), JobState::Running, Some(10), None, true);
        rig.step(&run).expect("poll the running job");
        rig.clock.advance_secs(5);
        end_with_outputs_as(
            rig,
            &run,
            JobEnd::Revoked,
            &[("verdict.json", verdict, true)],
        );
        rig.node.put_output(run.key(), "verdict.json", verdict);
        rig.settle(&run);
        assert_eq!(
            rig.dispatch(&run).closed,
            Some(DispatchClose::Ended),
            "the issuer saw no revoke of its own",
        );

        let returned = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(
            returned.refused,
            vec![ReturnRefusal {
                name: "verdict.json".to_owned(),
                why: "job_revoked".to_owned(),
            }],
            "the node's revoke drops the output: {returned:?}",
        );
        assert!(returned.landed.is_empty(), "nothing landed");
        assert!(
            returned.acknowledged_at_ms.is_some(),
            "the node is told it may clean"
        );
        let calls = rig.node.calls();
        assert!(
            fetched(&calls, run.key()).is_empty(),
            "no output of a revoked job is fetched: {calls:?}",
        );
        assert!(
            vault
                .pending_proposals(&binding.artifact)
                .expect("list the artifact's proposals")
                .is_empty(),
            "nothing waits on the artifact"
        );
    });
}

/// Shares the rig's vault with a second live owner, who accepts its founding invitation, and
/// answers the co-owner's PERSON id. Call it before any agent Grant is minted: a vault that
/// already holds an owner's agent Grant does not become shared.
fn share_with_co_owner(rig: &Rig) -> EntityId {
    const SHARED_VAULT: u64 = 42;
    let vault = rig.vault();
    let co_owner = EntityId::now();
    vault
        .put_entity(
            &co_owner,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let owner = rig.owner.revalidate(vault).expect("the owner's id");
    let founding = |member_ref| oneiron::federation::InitialSharedMember {
        member_ref,
        role: Some(oneiron::federation::FederationGrantRole::Owner),
    };
    vault
        .initialize_shared_vault(
            &rig.owner,
            SHARED_VAULT,
            None,
            &[founding(owner), founding(co_owner)],
            1,
        )
        .expect("a shared vault with two owners");
    let proof = vault
        .authenticate_owner(
            co_owner,
            &co_owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("the co-owner's proof");
    let invitation = vault
        .shared_invitations(&proof, SHARED_VAULT)
        .expect("the co-owner's invitations")
        .into_iter()
        .find(|open| open.role == oneiron::federation::FederationGrantRole::Owner)
        .expect("the co-owner's founding invitation");
    vault
        .accept_shared_invitation(&proof, SHARED_VAULT, &invitation.id)
        .expect("the co-owner accepts");
    for id in [owner, co_owner] {
        assert!(
            matches!(
                vault.dispatch_starter(id).expect("read the owner's standing"),
                Some(WorkloadStarter::Owner(found)) if found == id
            ),
            "both are live owners",
        );
    }
    co_owner
}

/// An agent of a shared vault starts a bound job under a Grant `rig.owner` mints; the job
/// completes and the fetch does not arrive, so its output is owed. Answers the job's run and
/// its binding, and the Grant's id.
fn shared_vault_owed_result(rig: &Rig, tag: &str) -> (JobRun, GpuJobResultBinding, EntityId) {
    let vault = rig.vault();
    share_with_co_owner(rig);
    let binding = result_binding(rig);
    let (agent_id, grant_ref) =
        agent_with_grant(rig, &format!("gpu-result-{tag}"), &["read", START_VERB]);
    let workload = rig.approve_for_starters(
        &format!("result-{tag}"),
        FAR_EXPIRY_MS,
        vec![grant_ref.to_hex()],
    );
    let agent = vault
        .memory(agent_id, EdgeActorClass::Agent)
        .gpu_job_agent();
    let verdict: &[u8] = br#"{"verdict":"shared"}"#;
    let run = rig.start_job_as(
        GpuJobActor::Agent(&agent),
        &workload,
        bound_inputs(rig, &binding),
        &rig.connector,
    );
    assert!(
        vault
            .job_dispatch(run.key())
            .expect("read the dispatch table")
            .is_some(),
        "the agent's binding was dispatched in the shared vault",
    );
    rig.clock.advance_secs(30);
    end_with_outputs(rig, &run, &[("verdict.json", verdict, true)]);
    rig.node.put_output(run.key(), "verdict.json", verdict);
    rig.node.drop_next("fetch");
    rig.settle(&run);
    let owed = vault
        .job_return(run.key())
        .expect("read JOB_RETURN")
        .expect("the key's return");
    assert!(
        owed.landed.is_empty() && owed.refused.is_empty(),
        "{owed:?}"
    );
    assert_eq!(owed.acknowledged_at_ms, None, "the output is still owed");
    (run, binding, grant_ref)
}

/// #10517 review round 2 P1-5 (ARCH-0046): in a shared vault with two live owners, a lapsed
/// starter's result lands in the lane of the owner who granted the submit's Grant; it is never
/// refused for want of a sole owner. The Grant expires while the output is owed, and the next
/// housekeeping pass lands it, written by the issuer, pending Keep.
#[test]
fn a_lapsed_starters_result_lands_in_its_granting_owners_lane_in_a_shared_vault() {
    with_rig(|rig| {
        let vault = rig.vault();
        let (run, binding, grant_ref) = shared_vault_owed_result(rig, "shared-granting-owner");
        expire_agent_grant(vault, grant_ref).expect("expire the starter's Grant");
        rig.connector.housekeeping();

        let done = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(
            done.landed,
            vec!["verdict.json".to_owned()],
            "the paid result returns in a shared vault: {done:?}",
        );
        assert!(done.refused.is_empty(), "{done:?}");
        assert!(done.acknowledged_at_ms.is_some(), "then the node may clean");
        let waiting = vault
            .pending_proposals(&binding.artifact)
            .expect("list the artifact's proposals");
        assert_eq!(waiting.len(), 1, "one proposal waits");
        assert_eq!(
            waiting[0].retained_by, rig.issuer,
            "the issuer writes the landing, not the lapsed starter",
        );
    });
}

/// #10517 review round 2 P1-5: a lapsed starter's result that no owner's lane is resolved for
/// stays owed, and is never refused or cleaned. In a shared vault with two live owners, the
/// owner revokes the agent's Grant while its job's output is owed: no Grant names a granting
/// owner and the vault has no sole owner. The housekeeping passes fetch nothing, refuse
/// nothing and acknowledge nothing; the node keeps the payload.
#[test]
fn a_lapsed_starters_result_stays_owed_while_no_owners_lane_is_resolved() {
    with_rig(|rig| {
        let vault = rig.vault();
        let (run, binding, grant_ref) = shared_vault_owed_result(rig, "shared-no-owner");
        oneiron::verbs::revoke_agent_grant_as(
            vault,
            &rig.owner,
            ActSurface::ThisInstall,
            oneiron::verbs::AgentGrantRevokeRequest {
                grant_ref,
                seen: None,
            },
        )
        .expect("the owner revokes the agent's Grant");
        let fetches_before = fetched(&rig.node.calls(), run.key()).len();
        rig.connector.housekeeping();
        rig.connector.housekeeping();

        let owed = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert!(
            owed.landed.is_empty() && owed.refused.is_empty(),
            "nothing landed or refused: {owed:?}",
        );
        assert_eq!(owed.acknowledged_at_ms, None, "the node keeps the result");
        assert!(
            vault
                .job_returns_owed()
                .expect("read the owed returns")
                .iter()
                .any(|owed| owed.key == run.key()),
            "the result stays owed",
        );
        let calls = rig.node.calls();
        assert_eq!(
            fetched(&calls, run.key()).len(),
            fetches_before,
            "nothing is fetched while no lane holds the result: {calls:?}",
        );
        assert!(
            !kinds_for(&calls, run.key()).contains(&"ack"),
            "no Ack: {calls:?}"
        );
        assert!(
            vault
                .pending_proposals(&binding.artifact)
                .expect("list the artifact's proposals")
                .is_empty(),
            "nothing waits on the artifact",
        );
    });
}

/// #10517 review P1-6: a key whose terminal receipt left its outputs pending, and whose node
/// then failed to hash them, has nothing to fetch. The next housekeeping pass reads the node's
/// checked `Failed` receipt as a finished return and tells the node it may clean; no return
/// stays owed.
#[test]
fn an_ended_key_whose_outputs_failed_to_hash_after_pending_is_acknowledged() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let workload = rig.approve("result-hash-failed", FAR_EXPIRY_MS);
        let run = rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
        rig.clock.advance_secs(30);
        let at_ms = rig.clock.now_ms();
        rig.node.revise(run.key(), |receipt| {
            receipt.state = JobState::Ended;
            receipt.started = true;
            receipt.end = Some(JobEnd::Exited { code: 0 });
            receipt.measured_secs = Some(20);
            receipt.device_id = Some("scripted-gpu".to_owned());
            receipt.release = DeviceRelease::Confirmed { at_ms };
            receipt.outputs = OutputsState::Pending;
        });
        rig.settle(&run);
        let owed = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(
            owed.acknowledged_at_ms, None,
            "its outputs are not hashed yet"
        );

        rig.node.revise(run.key(), |receipt| {
            receipt.outputs = OutputsState::Failed {
                why: "a declared output is a directory".to_owned(),
            };
        });
        rig.connector.housekeeping();

        let done = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert!(
            done.landed.is_empty() && done.refused.is_empty(),
            "nothing was fetchable: {done:?}",
        );
        assert!(done.acknowledged_at_ms.is_some(), "the node may clean");
        assert!(
            fetched(&rig.node.calls(), run.key()).is_empty(),
            "nothing is fetched"
        );
        assert!(
            vault
                .job_returns_owed()
                .expect("read the owed returns")
                .is_empty(),
            "no return is owed"
        );
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

/// [JOB-RETURN-OWED-FOREVER-UNSTARTED-KEY]: a key whose workload never started (refused at
/// admission, or inside the launch commit) has no outputs to wait for, because the node hashes
/// outputs only after a run's release. With a quote that binds a result, its return is decided
/// at the confirm: nothing is fetched, the node is told it may clean, no return stays owed, and
/// the next housekeeping pass asks the node nothing.
#[test]
fn a_bound_key_that_never_started_owes_no_return_and_housekeeping_asks_nothing() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let workload = rig.approve("result-never-started", FAR_EXPIRY_MS);
        for end in [
            JobEnd::Refused {
                reason: "no_device_free".to_owned(),
            },
            JobEnd::LaunchRefused {
                reason: "device_fence".to_owned(),
            },
        ] {
            let run =
                rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
            rig.clock.advance_secs(30);
            rig.node.revise(run.key(), |receipt| {
                receipt.state = JobState::Ended;
                receipt.started = false;
                receipt.end = Some(end.clone());
                receipt.measured_secs = None;
                receipt.device_id = None;
                receipt.release = DeviceRelease::NotHeld;
                receipt.outputs = OutputsState::Pending;
            });
            rig.settle(&run);
            let returned = vault
                .job_return(run.key())
                .expect("read JOB_RETURN")
                .expect("the key's return");
            assert!(
                returned.landed.is_empty() && returned.refused.is_empty(),
                "{end:?}: no output to land or refuse"
            );
            assert!(
                returned.acknowledged_at_ms.is_some(),
                "{end:?}: nothing to wait for, so the node is told it may clean"
            );
            let calls = rig.node.calls();
            let kinds = kinds_for(&calls, run.key());
            assert!(!kinds.contains(&"fetch"), "{end:?}: no fetch: {kinds:?}");
            assert!(kinds.contains(&"ack"), "{end:?}: an Ack: {kinds:?}");
        }
        assert!(
            vault
                .job_returns_owed()
                .expect("read the owed returns")
                .is_empty(),
            "no return is owed"
        );
        let before = rig.node.calls().len();
        rig.connector.housekeeping();
        assert_eq!(
            rig.node.calls().len(),
            before,
            "a housekeeping pass asks the node nothing"
        );
        assert!(
            vault
                .pending_proposals(&binding.artifact)
                .expect("list the artifact's proposals")
                .is_empty(),
            "nothing landed on the artifact"
        );
    });
}

/// The node's report of `run` cut off at its maximum: the scripted clock moves on to the run's
/// quoted maximum (it was seen running at 30 measured seconds), and the node ends it
/// `TimeLimit` with that maximum measured, its device released clean, and `partial` hashed as
/// its returnable `verdict.json`.
fn cut_off_with_partial(rig: &Rig, run: &JobRun, partial: &[u8]) {
    let maximum = run
        .job
        .chunk()
        .expect("the job has a chunk")
        .quote
        .maximum_secs;
    rig.clock.advance_secs(maximum.saturating_sub(30));
    let at_ms = rig.clock.now_ms();
    rig.node.revise(run.key(), |receipt| {
        receipt.state = JobState::Ended;
        receipt.started = true;
        receipt.end = Some(JobEnd::TimeLimit);
        receipt.measured_secs = Some(maximum);
        receipt.device_id = Some("scripted-gpu".to_owned());
        receipt.release = DeviceRelease::Confirmed { at_ms };
        receipt.outputs = OutputsState::Hashed(vec![OutputDigest {
            name: "verdict.json".to_owned(),
            sha256: format!("{:x}", Sha256::digest(partial)),
            bytes: u64::try_from(partial.len()).expect("a small output"),
            returnable: true,
        }]);
    });
}

/// Row GPU-JOB-CUTOFF-PROOF, the issuer's half: a job its node cuts off at its maximum returns
/// the partial result it wrote before the cutoff, as every ended key but a revoked one does
/// ("Any other ended key returns its result", ARCH-0046). The returnable output is fetched,
/// checked against the machine's signed digest and length, and proposed as the artifact's next
/// version, pending Keep, made by the task; then the node may clean. The job ends `time_limit`
/// at its quoted maximum (review r1 P1: the cut is at the quote's own maximum, not before it),
/// settled at no more than its quote. A time-limit end never lands bytes past the signed
/// digest: a partial output whose bytes differ from the receipt's (the workload wrote on past
/// the hash) is refused `digest_mismatch`, and nothing lands.
#[test]
fn a_job_cut_at_its_maximum_returns_its_partial_result_and_never_bytes_past_its_digest() {
    with_rig(|rig| {
        let vault = rig.vault();
        let binding = result_binding(rig);
        let head = vault
            .blob_artifact_head(&binding.artifact)
            .expect("read the artifact's head");
        let workload = rig.approve("cutoff-result", FAR_EXPIRY_MS);
        let partial: &[u8] = br#"{"verdict":"partial","steps":3}"#;

        let run = rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
        rig.node
            .advance(run.key(), JobState::Running, Some(30), None, true);
        rig.step(&run).expect("poll the running job");
        cut_off_with_partial(rig, &run, partial);
        rig.node.put_output(run.key(), "verdict.json", partial);
        let ended = rig.settle(&run);
        assert_eq!(
            serde_json::to_value(&ended.state).expect("encode the job's state"),
            json!({ "ended": { "reason": "time_limit" } }),
        );
        let status = GpuJobStatus::from(&ended);
        assert!(
            status.settled_units <= units(&run),
            "settled {} of a {} unit quote",
            status.settled_units,
            units(&run)
        );
        let calls = rig.node.calls();
        assert_eq!(
            fetched(&calls, run.key()),
            vec!["verdict.json".to_owned()],
            "the partial verdict is fetched",
        );
        assert!(
            position(&calls, "fetch", Some(run.key())) < position(&calls, "ack", Some(run.key())),
            "the node is told to clean only after the landing: {calls:?}",
        );
        let returned = vault
            .job_return(run.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(returned.landed, vec!["verdict.json".to_owned()]);
        assert!(returned.refused.is_empty(), "{:?}", returned.refused);
        assert!(returned.acknowledged_at_ms.is_some());
        let waiting = vault
            .pending_proposals(&binding.artifact)
            .expect("list the artifact's proposals");
        assert_eq!(waiting.len(), 1, "the partial result waits for Keep");
        let made_by = waiting[0].made_by.as_ref().expect("its made_by");
        assert_eq!(made_by.trigger, Some(MadeByTrigger::Task(binding.task)));
        assert_eq!(
            vault
                .blob_artifact_head(&binding.artifact)
                .expect("read the artifact's head"),
            head,
            "pending Keep: the head did not move",
        );

        let late =
            rig.start_job_with_inputs(&workload, bound_inputs(rig, &binding), &rig.connector);
        rig.node
            .advance(late.key(), JobState::Running, Some(30), None, true);
        rig.step(&late).expect("poll the running job");
        cut_off_with_partial(rig, &late, partial);
        let mut past = partial.to_vec();
        past.extend_from_slice(b"\n{\"verdict\":\"late\"}");
        rig.node.put_output(late.key(), "verdict.json", &past);
        let ended = rig.settle(&late);
        assert_eq!(
            serde_json::to_value(&ended.state).expect("encode the job's state"),
            json!({ "ended": { "reason": "time_limit" } }),
        );
        let returned = vault
            .job_return(late.key())
            .expect("read JOB_RETURN")
            .expect("the key's return");
        assert_eq!(
            returned.refused,
            vec![ReturnRefusal {
                name: "verdict.json".to_owned(),
                why: "digest_mismatch".to_owned(),
            }],
        );
        assert!(returned.landed.is_empty(), "{:?}", returned.landed);
        assert_eq!(
            vault
                .pending_proposals(&binding.artifact)
                .expect("list the artifact's proposals")
                .len(),
            1,
            "bytes past the signed digest land nothing",
        );
    });
}
