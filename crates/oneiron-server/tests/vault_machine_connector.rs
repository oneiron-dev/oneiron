#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! DESIGN 33 tests T34–T36f for the vault machine connector (except T36c).
//!
//! Run on the fleet, not on a workstation:
//! ```sh
//! RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test vault_machine_connector
//! ```

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;
#[path = "support/vault_machine_rig.rs"]
mod vault_machine_rig;

use std::sync::{Arc, mpsc};

use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    GpuConnectorError, GpuEndReason, GpuJobAccounting, GpuJobActor, GpuJobConnector, GpuJobEnd,
    GpuJobError, GpuJobSignal, GpuJobSpec, GpuJobState, GpuJobStatus, GpuResourceRef,
    GpuResourceStatus, GpuTermination, MeterVerdict,
};
use oneiron::job_dispatch::{DispatchClose, DispatchPhase, JobObservation};
use oneiron::job_workload::{WorkloadCaller, WorkloadRef, WorkloadStartRefusal};
use oneiron::{EntityId, Vault};
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::gpu_jobs::AtMaximum;
use oneiron_server::gpu_execution_node::issuer::{
    IssuerClock, VaultMachineConnector, VaultMachineNotRegistered, not_the_issuer,
    refusal_code_for_caller, vault_machine_backend, vault_machine_inputs,
};
use oneiron_server::gpu_execution_node::wire::{JobEnd, JobState, SignedJobReceipt};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::gpu_backend::gpu_jobs_section;
use serde_json::json;
use vault_machine_rig::{FAR_EXPIRY_MS, make_connector, offer, settings, with_rig, with_rig_offer};

fn revoke(vault: &Vault, owner: &AuthenticatedOwner, workload: &str, now_ms: u64) {
    let revoked = vault
        .revoke_job_workload(
            WorkloadCaller::Owner(owner),
            &WorkloadRef {
                workload: workload.to_owned(),
            },
            now_ms,
        )
        .expect("the owner revokes the approval");
    assert!(revoked.changed, "the revoke was written");
}

struct RevokeBeforeCreate<'a> {
    inner: &'a VaultMachineConnector,
    vault: &'a Vault,
    owner: &'a AuthenticatedOwner,
    now_ms: u64,
}

impl GpuJobConnector for RevokeBeforeCreate<'_> {
    fn create(&self, key: &str, spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let id = EntityId::from_hex(&spec.job).expect("the spec names a job id");
        let reserved = self
            .vault
            .gpu_job(&id)
            .expect("read the job")
            .expect("job already reserved");
        assert_eq!(
            reserved.state,
            GpuJobState::Reserved,
            "the revoke comes after reservation"
        );
        revoke(self.vault, self.owner, &spec.image, self.now_ms);
        self.inner.create(key, spec)
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        self.inner.find(key)
    }

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        self.inner.status(resource)
    }

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        self.inner.signal(resource, signal)
    }

    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        self.inner.terminate(resource)
    }
}

#[test]
fn a_create_that_times_out_resends_the_same_bytes_to_the_machine_in_the_job_row() {
    with_rig(|rig| {
        let workload = rig.approve("retry", FAR_EXPIRY_MS);
        rig.node.drop_next("submit");
        let run = rig.start_job(&workload);
        let row = rig.dispatch(&run);
        let resource = GpuResourceRef(format!("{}#{}", rig.node.machine.to_hex(), run.key()));
        assert_eq!(
            row.machine, rig.node.machine,
            "the dispatch row fixes the target"
        );
        assert_eq!(
            row.phase,
            DispatchPhase::Reserved,
            "only the reserve reached the node"
        );
        assert_eq!(
            run.job.state,
            GpuJobState::Running,
            "find recovered the local resource"
        );
        assert_eq!(
            run.job.chunk().and_then(|chunk| chunk.resource.as_ref()),
            Some(&resource),
            "the resource names the dispatch machine and key",
        );

        // Lose the retry as well so the same key is still Held at restart.
        rig.node.drop_next("submit");
        let result = rig.step(&run);
        assert!(
            result.is_ok(),
            "a Held receipt triggers a submit retry, and a lost retry leaves the job pending: {result:?}",
        );
        let before = rig.node.calls();
        let submits: Vec<_> = before.iter().filter(|call| call.kind == "submit").collect();
        assert_eq!(
            submits.len(),
            2,
            "create and the first step each send a submit"
        );
        assert_eq!(
            submits[0].key.as_deref(),
            Some(run.key()),
            "the submit uses the durable key"
        );
        assert_eq!(
            submits[0].bytes, submits[1].bytes,
            "the retry resends the exact body"
        );

        let restarted =
            make_connector(rig.vault(), rig.issuer, &rig.signers, &rig.clock, &rig.node);
        rig.node.drop_next("submit");
        let result = rig.step_with(&run, &restarted);
        assert!(
            result.is_ok(),
            "restart also retries the unanswered submit, which leaves the job pending: {result:?}",
        );
        let calls = rig.node.calls();
        let restart_calls = &calls[before.len()..];
        let keys_at = restart_calls
            .iter()
            .position(|call| call.kind == "keys")
            .expect("restart reconciles the node");
        let submit_at = restart_calls
            .iter()
            .position(|call| call.kind == "submit")
            .expect("restart sends the submit");
        assert!(keys_at < submit_at, "restart reconciles before re-sending");
        assert_eq!(
            restart_calls[submit_at].bytes, submits[0].bytes,
            "restart repeats the original signed body",
        );
        assert!(
            calls.iter().all(|call| call.node == rig.node.machine),
            "all calls target the machine named by the quote: {calls:?}",
        );
    });
}

#[test]
fn an_absent_key_after_a_held_receipt_is_history_lost_and_is_never_sent_again() {
    with_rig(|rig| {
        let workload = rig.approve("lost-journal", FAR_EXPIRY_MS);
        rig.node.drop_next("submit");
        let run = rig.start_job(&workload);
        assert!(
            rig.dispatch(&run).held.is_some(),
            "the issuer stored a Held receipt"
        );
        rig.node.forget_journal();
        let before = rig.node.calls().len();
        for _ in 0..3 {
            let result = rig.step(&run);
            assert!(
                matches!(
                    &result,
                    Err(GpuJobError::Connector(GpuConnectorError::Unavailable { reason }))
                        if reason == "history_lost"
                ),
                "the missing Held key is history_lost: {result:?}",
            );
            assert!(
                rig.dispatch(&run).history_lost_at_ms.is_some(),
                "loss is durable before another step",
            );
        }
        let calls = rig.node.calls();
        assert!(
            calls[before..]
                .iter()
                .all(|call| !matches!(call.kind, "reserve" | "submit")),
            "no dispatch request follows history loss",
        );
    });
}

#[test]
fn a_cancel_always_sends_a_stop_before_the_job_ends() {
    with_rig(|rig| {
        let workload = rig.approve("cancel-offline-create", FAR_EXPIRY_MS);
        rig.node.unreachable(true);
        let run = rig.start_job(&workload);
        let resource = GpuResourceRef(rig.dispatch(&run).resource());
        assert_eq!(
            run.job.state,
            GpuJobState::Running,
            "an unreachable node does not end the job"
        );
        assert_eq!(
            run.job.chunk().and_then(|chunk| chunk.resource.as_ref()),
            Some(&resource),
            "the engine recovered the resource locally",
        );
        let before_cancel = rig.node.calls().len();

        rig.node.unreachable(false);
        let cancelled = rig
            .vault()
            .cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &run.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            )
            .expect("cancel with the recovered resource");
        let calls = rig.node.calls();
        assert!(
            calls[before_cancel..]
                .iter()
                .any(|call| call.kind == "stop" && call.key.as_deref() == Some(run.key())),
            "cancel sends Stop even though the node missed create",
        );
        assert_eq!(
            cancelled.state,
            GpuJobState::Ended {
                reason: GpuEndReason::Cancelled
            },
            "cancel ends the job after Stop",
        );
        assert_eq!(
            cancelled.chunk().and_then(|chunk| chunk.billed_secs),
            Some(0),
            "a confirmed withdrawal bills zero, not a missing resource",
        );
        assert_eq!(
            cancelled.chunk().and_then(|chunk| chunk.resource.as_ref()),
            Some(&resource),
            "cancel did not take the no-resource path",
        );
    });
}

#[test]
fn billed_seconds_never_pass_the_issuers_bracket_and_a_job_between_two_polls_is_billed() {
    with_rig(|rig| {
        let workload = rig.approve("metering", FAR_EXPIRY_MS);
        let inflated = rig.start_job(&workload);
        rig.clock.advance_secs(100);
        rig.node.advance(
            inflated.key(),
            JobState::Ended,
            Some(500),
            Some(JobEnd::Exited { code: 0 }),
            true,
        );
        let ended = rig.settle(&inflated);
        assert_eq!(
            ended.chunk().and_then(|chunk| chunk.billed_secs),
            Some(100),
            "the node cannot bill beyond the issuer's 100 seconds",
        );
        assert_eq!(
            rig.observation(&inflated).meter,
            Some(MeterVerdict::Bracketed { billed_secs: 100 }),
            "the observation records the bracket",
        );

        let short = rig.start_job(&workload);
        rig.step(&short).expect("poll before the short job starts");
        let accepted: SignedJobReceipt =
            oneiron_organ_protocol::from_slice(&rig.observation(&short).receipt)
                .expect("decode the pre-run observation");
        assert_eq!(
            accepted.receipt.state,
            JobState::Accepted,
            "the first poll saw Accepted, not Running",
        );
        rig.clock.advance_secs(60);
        rig.node.advance(
            short.key(),
            JobState::Ended,
            Some(40),
            Some(JobEnd::Exited { code: 0 }),
            true,
        );
        let ended = rig.settle(&short);
        assert_eq!(
            ended.chunk().and_then(|chunk| chunk.billed_secs),
            Some(40),
            "Accepted to Ended bills occupied time without a Running poll",
        );
        assert_eq!(
            rig.observation(&short).meter,
            Some(MeterVerdict::Agreed),
            "40 measured seconds fit inside the 60-second bracket",
        );
    });
}

#[test]
fn a_job_that_never_started_settles_nothing_and_its_dispatch_keeps_the_nodes_reason() {
    with_rig(|rig| {
        let workload = rig.approve("never-started", FAR_EXPIRY_MS);
        rig.node.refuse_submits(Some("no_device"));
        let refused = rig.start_job(&workload);
        assert_eq!(
            refused.job.state,
            GpuJobState::Ended {
                reason: GpuEndReason::NeverStarted,
            },
            "the job records the refusal without disclosing what the machine said",
        );
        assert_eq!(
            refused.settled(),
            vec![0],
            "a refused submit settles zero units"
        );
        let row = rig.dispatch(&refused);
        assert_eq!(
            row.phase,
            DispatchPhase::Closed,
            "the refusal closes the dispatch"
        );
        assert_eq!(
            row.closed,
            Some(DispatchClose::NodeRefused {
                reason: "no_device".to_owned()
            }),
            "the dispatch keeps the node's refusal reason",
        );

        rig.node.refuse_submits(None);
        let launch_refused = rig.start_job(&workload);
        assert_eq!(
            rig.dispatch(&launch_refused).phase,
            DispatchPhase::Submitted,
            "the second submit was accepted",
        );
        rig.node.advance(
            launch_refused.key(),
            JobState::Ended,
            None,
            Some(JobEnd::LaunchRefused {
                reason: "commit_missing".to_owned(),
            }),
            false,
        );
        let ended = rig.settle(&launch_refused);
        assert_eq!(
            ended.chunk().and_then(|chunk| chunk.billed_secs),
            Some(0),
            "a refused launch bills zero seconds",
        );
        assert_eq!(
            launch_refused.settled(),
            vec![0],
            "a refused launch settles zero units"
        );
        let terminal = rig
            .observation(&launch_refused)
            .terminal
            .expect("typed terminal for launch refusal");
        assert_eq!(
            terminal.end,
            GpuJobEnd::LaunchRefused {
                reason: "commit_missing".to_owned()
            },
            "the observation keeps the launch refusal's reason",
        );
    });
}

#[test]
fn a_launch_refused_key_settles_no_overhead_and_reads_never_started() {
    let mut offer = offer();
    offer.rounding_secs = 1;
    with_rig_offer(offer, |rig| {
        let workload = rig.approve("launch-refused-with-overhead", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        assert_eq!(
            run.job.chunk().expect("quoted chunk").quote.overhead_secs,
            1
        );
        rig.node.advance(
            run.key(),
            JobState::Ended,
            None,
            Some(JobEnd::LaunchRefused {
                reason: "work_dir_unsafe".to_owned(),
            }),
            false,
        );
        let job = rig.settle(&run);
        let observation = rig.observation(&run);
        assert!(!observation.started);
        assert_eq!(
            observation.terminal.expect("confirmed launch refusal").end,
            GpuJobEnd::LaunchRefused {
                reason: "work_dir_unsafe".to_owned(),
            },
        );
        assert_eq!(
            job.state,
            GpuJobState::Ended {
                reason: GpuEndReason::NeverStarted,
            },
        );
        let chunk = job.chunk().expect("settled chunk");
        assert_eq!(chunk.billed_secs, Some(0));
        assert_eq!(chunk.settled_units, Some(0));
        assert_eq!(chunk.unbilled_secs, 0);
        assert_eq!(run.settled(), vec![0]);
        let status = GpuJobStatus::from(&job);
        assert_eq!(status.state, "ended");
        assert_eq!(status.end_reason.as_deref(), Some("never_started"));
    });
}

#[test]
fn a_node_refused_submit_ends_the_job_never_started() {
    with_rig(|rig| {
        let workload = rig.approve("node-refused-submit", FAR_EXPIRY_MS);
        rig.node.refuse_submits(Some("node_drained"));
        let run = rig.start_job(&workload);
        let expected = GpuJobState::Ended {
            reason: GpuEndReason::NeverStarted,
        };
        assert_eq!(run.job.state, expected);
        let job = rig.job(&run);
        assert_eq!(job.state, expected);
        let status = GpuJobStatus::from(&job);
        assert_eq!(status.state, "ended");
        assert_eq!(status.end_reason.as_deref(), Some("never_started"));
        assert_eq!(status.held_reason, None);
        let dispatch = rig.dispatch(&run);
        assert_eq!(dispatch.phase, DispatchPhase::Closed);
        assert_eq!(
            dispatch.closed,
            Some(DispatchClose::NodeRefused {
                reason: "node_drained".to_owned(),
            }),
        );
        assert_eq!(run.settled(), vec![0]);
        let cancelled = rig.vault().cancel_gpu_job(
            GpuJobActor::Owner(&rig.owner),
            &job.id,
            &rig.permits,
            &rig.connector,
            rig.clock.now_ms(),
        );
        assert!(matches!(cancelled, Err(GpuJobError::Ended)));
    });
}

/// A cancel that withdrew a key before it ran still reads as the customer's cancel, not as
/// never started, and settles no overhead (Engine 27 Nov 08:20, LE-2 = A).
#[test]
fn a_cancel_that_withdrew_a_key_reads_cancelled_and_settles_no_overhead() {
    let mut offer = offer();
    offer.rounding_secs = 1;
    with_rig_offer(offer, |rig| {
        let workload = rig.approve("cancel-withdrawn", FAR_EXPIRY_MS);
        let run = rig.start_job(&workload);
        assert_eq!(
            run.job.chunk().expect("quoted chunk").quote.overhead_secs,
            1
        );
        rig.node.advance(
            run.key(),
            JobState::Ended,
            None,
            Some(JobEnd::Withdrawn),
            false,
        );
        rig.vault()
            .cancel_gpu_job(
                GpuJobActor::Owner(&rig.owner),
                &run.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            )
            .expect("the cancel of a live job is taken");
        let job = rig.settle(&run);
        assert_eq!(
            rig.observation(&run)
                .terminal
                .expect("confirmed withdrawal")
                .end,
            GpuJobEnd::Withdrawn,
        );
        assert_eq!(
            job.state,
            GpuJobState::Ended {
                reason: GpuEndReason::Cancelled,
            },
            "a cancel that withdrew the key reads as the cancel"
        );
        let chunk = job.chunk().expect("settled chunk");
        assert_eq!(chunk.settled_units, Some(0));
        assert_eq!(run.settled(), vec![0]);
        assert_eq!(
            GpuJobStatus::from(&job).end_reason.as_deref(),
            Some("cancelled")
        );
    });
}

#[test]
fn a_grant_revoked_between_the_reservation_and_the_dispatch_sends_nothing() {
    with_rig(|rig| {
        let workload = rig.approve("revoked-before-create", FAR_EXPIRY_MS);
        let connector = RevokeBeforeCreate {
            inner: &rig.connector,
            vault: rig.vault(),
            owner: &rig.owner,
            now_ms: rig.clock.now_ms(),
        };
        let run = rig.start_job_with(&workload, &connector);
        assert_eq!(
            run.job.state,
            GpuJobState::Held {
                reason: "workload_revoked".to_owned()
            },
            "create surfaces the live approval recheck refusal",
        );
        assert_eq!(
            run.settled(),
            vec![0],
            "the refused dispatch settles zero units"
        );
        assert!(
            rig.node.calls().is_empty(),
            "a revoke before create prevents all network calls, including reconcile",
        );
        assert!(
            rig.vault()
                .job_dispatch(run.key())
                .expect("read the dispatch table")
                .is_none(),
            "before-send refusal left no dispatch row",
        );
    });
}

#[test]
fn a_revoked_grant_or_workload_stops_its_running_job_and_an_expired_one_does_not() {
    with_rig(|rig| {
        let workload = rig.approve("revoked-after-submit", FAR_EXPIRY_MS);
        let revoked = rig.start_job(&workload);
        rig.clock.advance_secs(10);
        rig.node
            .advance(revoked.key(), JobState::Running, Some(10), None, true);
        assert_eq!(
            rig.step(&revoked).expect("poll the running job").used_secs,
            10,
            "the issuer saw the node running",
        );
        revoke(rig.vault(), &rig.owner, &workload, rig.clock.now_ms());
        let before_revoke_step = rig.node.calls().len();
        rig.step(&revoked).expect("step after the workload revoke");
        let calls = rig.node.calls();
        assert!(
            calls[before_revoke_step..]
                .iter()
                .any(|call| call.kind == "stop" && call.key.as_deref() == Some(revoked.key())),
            "a revoke sends Stop for that running key",
        );
        assert_eq!(
            rig.dispatch(&revoked).closed,
            Some(DispatchClose::Revoked {
                code: "workload_revoked".to_owned()
            }),
            "the dispatch records what caused the stop",
        );
        rig.clock.advance_secs(2);
        rig.node.advance(
            revoked.key(),
            JobState::Ended,
            Some(12),
            Some(JobEnd::Stopped),
            true,
        );
        rig.settle(&revoked);
        assert_eq!(
            rig.observation(&revoked)
                .terminal
                .expect("typed terminal for the stopped job")
                .end,
            GpuJobEnd::Revoked,
            "a stop due to revoke is reported as Revoked",
        );

        let workload = rig.approve("expires-during-run", rig.clock.now_ms() + 20 * 60 * 1_000);
        let expired = rig.start_job(&workload);
        rig.clock.advance_secs(10);
        rig.node
            .advance(expired.key(), JobState::Running, Some(10), None, true);
        assert_eq!(
            rig.step(&expired).expect("poll before expiry").used_secs,
            10,
            "the second job was running before expiry",
        );
        let before_expiry = rig.node.calls().len();
        rig.clock.advance_secs(25 * 60);
        for _ in 0..2 {
            assert_eq!(
                rig.step(&expired).expect("poll after expiry").state,
                GpuJobState::Running,
                "expiry alone leaves the running job live",
            );
        }
        let calls = rig.node.calls();
        assert!(
            calls[before_expiry..]
                .iter()
                .all(|call| call.kind != "stop"),
            "expiry sent no Stop"
        );
    });
}

#[test]
fn a_start_on_a_replica_that_is_not_the_issuer_reserves_nothing() {
    with_rig(|rig| {
        let replica = &rig.mesh.machine(1).device;
        let mut config = SyncServerConfig::default();
        config.gpu_jobs.vault_machine = settings(rig.issuer);
        let server = Arc::new(
            SyncServer::new(Arc::clone(&replica.vault), config)
                .expect("boot the replica with machine 0 configured as issuer"),
        );

        let refusal = not_the_issuer(&server, "vault_machine")
            .expect_err("the start gate refuses the replica");
        assert_eq!(
            refusal.issuer,
            Some(rig.issuer),
            "the refusal names the configured issuer"
        );
        assert_eq!(
            refusal.code(),
            "not_the_issuer",
            "the start gate has a stable refusal code"
        );
        assert!(
            not_the_issuer(&server, "skypilot").is_ok(),
            "the issuer gate does not apply to other backends",
        );
        let refusal = vault_machine_backend(&server, rig.signers.as_machine(replica.machine))
            .err()
            .expect("the connector is not built on this replica");
        assert_eq!(
            refusal,
            VaultMachineNotRegistered::NotTheIssuer {
                issuer: Some(rig.issuer),
                local: replica.machine
            },
            "registration confirms which machine is allowed to issue jobs",
        );
        assert!(
            replica
                .vault
                .gpu_jobs()
                .expect("read replica GPU jobs")
                .is_empty(),
            "the rejected start gate did not reserve a job",
        );
    });
}

#[test]
fn a_caller_who_may_not_read_machines_gets_a_refusal_that_names_none() {
    for (refusal, visible, hidden) in [
        (
            WorkloadStartRefusal::MachineRefuses {
                reason: "no_device".to_owned(),
            },
            "machine_refuses",
            "not_available_to_this_caller",
        ),
        (
            WorkloadStartRefusal::MachineUnreachable {
                reason: "node is offline".to_owned(),
            },
            "machine_unreachable",
            "not_available_to_this_caller",
        ),
        (
            WorkloadStartRefusal::WorkloadRevoked,
            "workload_revoked",
            "workload_revoked",
        ),
    ] {
        assert_eq!(
            refusal_code_for_caller(&refusal, false),
            hidden,
            "restricted caller: {refusal:?}",
        );
        assert_eq!(
            refusal_code_for_caller(&refusal, true),
            visible,
            "caller may read machines: {refusal:?}",
        );
    }
    let hex = EntityId::from_bytes([42; 16])
        .expect("fixture entity id")
        .to_hex();
    assert_eq!(
        vault_machine_inputs(&json!({})),
        Err("machine_missing"),
        "machine is required"
    );
    assert_eq!(
        vault_machine_inputs(&json!({"machine": "zz"})),
        Err("machine_missing"),
        "machine must be an id in hex",
    );
    assert_eq!(
        vault_machine_inputs(&json!({"machine": hex, "device_id": 3})),
        Err("device_id_invalid"),
        "a device selector must be a string",
    );
}

/// A `[gpu_jobs]` section with one own-machine offer.
const OWN_MACHINE_SECTION: &str = r#"
[offers.own-a6000]
class = "a6000"
provider = "own"
region = "home"
backend = "vault_machine"
at_maximum = "stop"
price_per_second = 1
cost_unit = "credit-micros"
catalog_revision = "own-prices-1"
startup_secs = 0
teardown_secs = 0
rounding_secs = 1
"#;

/// Pass 34, 9.2: a `vault_machine` offer states `at_maximum = "stop"`, because its node ends the
/// run at the maximum (pass 33, 8.6); a provisioned offer leaves it out and follows C2.
#[test]
fn a_vault_machine_offer_states_at_maximum_stop() {
    let settings = gpu_jobs_section(OWN_MACHINE_SECTION).expect("an own-machine offer that stops");
    assert_eq!(
        settings.offer("own-a6000").map(|offer| offer.at_maximum),
        Some(Some(AtMaximum::Stop)),
    );
    let unstated = gpu_jobs_section(&OWN_MACHINE_SECTION.replace("at_maximum = \"stop\"\n", ""))
        .expect_err("a vault_machine offer that states no at_maximum");
    assert!(
        format!("{unstated:#}").contains("at_maximum must be \"stop\" or \"renew\""),
        "{unstated:#}"
    );
    let provisioned = gpu_jobs_section(
        &OWN_MACHINE_SECTION.replace("backend = \"vault_machine\"", "backend = \"skypilot\""),
    )
    .expect_err("at_maximum on a provisioned offer");
    assert!(
        format!("{provisioned:#}").contains("vault_machine backend only"),
        "{provisioned:#}"
    );
    let provisioned_renew = gpu_jobs_section(
        &OWN_MACHINE_SECTION
            .replace("backend = \"vault_machine\"", "backend = \"skypilot\"")
            .replace("\"stop\"", "\"renew\""),
    )
    .expect_err("renew on a provisioned offer");
    assert!(
        format!("{provisioned_renew:#}").contains("vault_machine backend only"),
        "{provisioned_renew:#}"
    );
}

/// Pass 34, 9.3 (row W1): a `vault_machine` offer may state `at_maximum = "renew"`, a session,
/// and the offer carries it into every quote; a stop leaves the quote's terms as before.
#[test]
fn a_vault_machine_offer_may_state_at_maximum_renew() {
    let settings = gpu_jobs_section(&OWN_MACHINE_SECTION.replace("\"stop\"", "\"renew\""))
        .expect("an own-machine offer that renews");
    let offer = settings.offer("own-a6000").expect("the offer");
    assert_eq!(offer.at_maximum, Some(AtMaximum::Renew));
    assert_eq!(offer.offer.at_maximum, AtMaximum::Renew);
    let stops = gpu_jobs_section(OWN_MACHINE_SECTION).expect("an own-machine offer that stops");
    assert_eq!(
        stops.offer("own-a6000").map(|offer| offer.offer.at_maximum),
        Some(AtMaximum::Stop),
    );
}

#[test]
fn a_terminate_during_a_create_sends_no_submit_after_its_stop() {
    with_rig(|rig| {
        let workload = rig.approve("terminate-during-create", FAR_EXPIRY_MS);
        let (entered, release) = rig.node.hold_next("reserve");
        // An unanswered Stop leaves the late Reserve free to return Held. A scripted
        // Stop that journals a withdrawal for an unknown key would mask the race.
        rig.node.drop_next("stop");

        let run = std::thread::scope(|scope| {
            let release = release;
            let create = scope.spawn(|| {
                let started = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    rig.start_job(&workload)
                }));
                // Wake the receiver if create never got as far as Reserve.
                drop(rig.node.state().hold_next.take());
                match started {
                    Ok(run) => run,
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            });
            entered.recv().expect("create sent Reserve");
            let key = rig
                .node
                .calls()
                .into_iter()
                .find(|call| call.kind == "reserve")
                .and_then(|call| call.key)
                .expect("Reserve names the key");
            let resource = GpuResourceRef(format!("{}#{key}", rig.node.machine.to_hex()));
            let (terminating, begin_terminate) = mpsc::channel();
            let terminate = scope.spawn(move || {
                terminating.send(()).expect("the test waits for terminate");
                rig.connector.terminate(&resource)
            });
            begin_terminate.recv().expect("terminate thread started");
            // A release before terminate reaches the key can pass on old and new code alike.
            release.send(()).expect("release the held Reserve");
            let run = create.join().expect("create thread panicked");
            let _ = terminate.join().expect("terminate thread panicked");
            run
        });

        let calls = rig.node.calls();
        let first_stop = calls
            .iter()
            .position(|call| call.kind == "stop" && call.key.as_deref() == Some(run.key()))
            .expect("terminate sent Stop for the key");
        assert!(
            calls[first_stop + 1..]
                .iter()
                .all(|call| call.kind != "submit" || call.key.as_deref() != Some(run.key())),
            "no Submit for the key may follow its first Stop: {calls:?}",
        );
        assert!(matches!(
            rig.dispatch(&run).phase,
            DispatchPhase::Closing | DispatchPhase::Closed
        ));
    });
}

#[test]
fn an_absent_key_after_a_stored_receipt_is_history_lost_even_with_no_held_mark() {
    with_rig(|rig| {
        let workload = rig.approve("lost-journal-after-observation", FAR_EXPIRY_MS);
        rig.node.lose_next_answer("reserve");
        let run = rig.start_job(&workload);
        assert_eq!(
            run.job.state,
            GpuJobState::Running,
            "find recovered the key"
        );
        let signed = rig
            .node
            .state()
            .journal
            .get(run.key())
            .expect("the node journaled the unanswered Reserve")
            .clone();
        assert_eq!(signed.receipt.state, JobState::Held);
        rig.vault()
            .put_job_observation(&JobObservation {
                key: run.key().to_owned(),
                machine: signed.receipt.machine,
                device_id: signed.receipt.device_id.clone(),
                receipt: oneiron_organ_protocol::to_vec(&signed).expect("encode the Held receipt"),
                epoch: signed.receipt.epoch.clone(),
                seq: signed.receipt.seq,
                last_measured_secs: None,
                observed_at_ms: rig.clock.now_ms(),
                end_seen: None,
                meter: None,
                terminal: None,
                started: false,
            })
            .expect("write the observation without the dispatch's Held mark");
        let row = rig.dispatch(&run);
        assert!(row.held.is_none());
        assert_eq!(row.phase, DispatchPhase::Reserving);

        rig.node.forget_journal();
        let reserve_calls = || {
            rig.node
                .calls()
                .iter()
                .filter(|call| call.kind == "reserve" && call.key.as_deref() == Some(run.key()))
                .count()
        };
        let before = reserve_calls();
        let _ = rig.step(&run);
        assert_eq!(
            reserve_calls(),
            before,
            "the issuer did not send Reserve again",
        );
        assert!(rig.dispatch(&run).history_lost_at_ms.is_some());
    });
}

#[test]
fn a_node_that_repeats_its_key_cursor_is_not_reconciled_and_gets_no_reserve() {
    with_rig(|rig| {
        let workload = rig.approve("repeated-key-cursor", FAR_EXPIRY_MS);
        rig.node.repeat_key_cursor(10);
        let run = rig.start_job(&workload);
        let _ = rig.step(&run);

        let calls = rig.node.calls();
        assert!(
            calls.iter().all(|call| call.kind != "reserve"),
            "the issuer must not reserve before reconciliation: {calls:?}",
        );
        assert_eq!(
            calls.iter().filter(|call| call.kind == "keys").count(),
            4,
            "create and step each stop reconciliation on their second page",
        );
        assert_eq!(rig.dispatch(&run).phase, DispatchPhase::Reserving);
    });
}

/// Pass 34, 9.3 (row W1): a session's renewal on a node that offers its template as a
/// session's is one continuing submit, on the first key's machine, pin and slot, with no
/// reserve; once the node proves the run passed the first chunk's end, that slice confirms and
/// bills on its own receipt and nothing stops the first key.
#[test]
fn a_session_renewal_sends_a_continuing_submit_and_no_reserve() {
    use oneiron_server::gpu_execution_node::wire::SignedJobSubmit;
    use vault_machine_rig::MAXIMUM_SECS;

    with_rig(|rig| {
        rig.node.state().session_template = true;
        let workload = rig.approve("session", FAR_EXPIRY_MS);
        let run = rig.start_session(&workload);
        let first = run.key().to_owned();
        rig.clock.advance_secs(MAXIMUM_SECS - 300);
        rig.node.advance(
            &first,
            JobState::Running,
            Some(MAXIMUM_SECS - 300),
            None,
            true,
        );
        rig.step_session(&run).expect("the step renews the session");
        let job = rig.job(&run);
        let next = job
            .renewal
            .as_ref()
            .expect("the next chunk is written")
            .idempotency_key
            .clone();
        let calls = rig.node.calls();
        let for_next = |kind: &str| {
            calls
                .iter()
                .filter(|call| call.kind == kind && call.key.as_deref() == Some(next.as_str()))
                .count()
        };
        assert_eq!(
            for_next("reserve"),
            0,
            "a session's next chunk is never reserved"
        );
        assert_eq!(for_next("submit"), 1);
        let row = rig
            .vault()
            .job_dispatch(&next)
            .expect("read JOB_DISPATCH")
            .expect("the next chunk's dispatch row");
        let first_row = rig
            .vault()
            .job_dispatch(&first)
            .expect("read JOB_DISPATCH")
            .expect("the first chunk's dispatch row");
        assert_eq!(row.machine, first_row.machine);
        assert_eq!(row.phase, DispatchPhase::Submitted);
        let submit = oneiron_organ_protocol::from_slice::<SignedJobSubmit>(&row.submit)
            .expect("the signed submit")
            .submit;
        let first_submit = oneiron_organ_protocol::from_slice::<SignedJobSubmit>(&first_row.submit)
            .expect("the first signed submit")
            .submit;
        assert_eq!(submit.continues.as_deref(), Some(first.as_str()));
        assert_eq!(submit.pin, first_submit.pin);
        assert_eq!(submit.slot, first_submit.slot);
        assert_eq!(submit.maximum_secs, MAXIMUM_SECS);

        // The node's journal proves the run passed the first chunk's end.
        rig.clock.advance_secs(300);
        rig.node.advance(
            &first,
            JobState::Ended,
            Some(MAXIMUM_SECS),
            Some(JobEnd::Continued),
            true,
        );
        rig.node
            .advance(&next, JobState::Running, Some(5), None, true);
        rig.step_session(&run)
            .expect("the step moves to the next chunk");
        let passed = rig.job(&run);
        assert_eq!(passed.chunks.len(), 2);
        assert_eq!(passed.state, GpuJobState::Running);
        assert_eq!(
            passed.chunks[0].billed_secs,
            Some(MAXIMUM_SECS),
            "the slice bills its own measured seconds"
        );
        let stops = rig
            .node
            .calls()
            .iter()
            .filter(|call| call.kind == "stop")
            .count();
        assert_eq!(stops, 0, "a passed slice is never stopped");
        let terminal = rig
            .vault()
            .job_observation(&first)
            .expect("read JOB_OBSERVATION")
            .and_then(|observation| observation.terminal)
            .expect("the first slice's terminal");
        assert_eq!(terminal.end, GpuJobEnd::Continued);
        // A read of the passed slice again answers from its terminal, with no stop.
        let again = rig
            .connector
            .status(&GpuResourceRef(format!(
                "{}#{first}",
                rig.node.machine.to_hex()
            )))
            .expect("status of the passed slice");
        assert!(
            matches!(again, GpuResourceStatus::Continued { .. }),
            "{again:?}"
        );
        assert_eq!(
            rig.node
                .calls()
                .iter()
                .filter(|call| call.kind == "stop")
                .count(),
            0
        );
    });
}

/// EM-22 R4 blocking 2 of #10521 (door 10, row W1): a write-off of a session whose next chunk's
/// end the issuer holds (the run passed into it and ended there) is refused before anything
/// closes, so the step settles that chunk as it ran; the current chunk's dispatch stays open.
#[test]
fn a_write_off_refuses_a_session_whose_next_chunk_holds_its_end() {
    use vault_machine_rig::MAXIMUM_SECS;

    with_rig(|rig| {
        rig.node.state().session_template = true;
        let workload = rig.approve("session", FAR_EXPIRY_MS);
        let run = rig.start_session(&workload);
        let first = run.key().to_owned();
        rig.clock.advance_secs(MAXIMUM_SECS - 300);
        rig.node.advance(
            &first,
            JobState::Running,
            Some(MAXIMUM_SECS - 300),
            None,
            true,
        );
        rig.step_session(&run).expect("the step renews the session");
        let next = rig
            .job(&run)
            .renewal
            .as_ref()
            .expect("the next chunk is written")
            .idempotency_key
            .clone();
        // The issuer reads the next chunk's end before it sees the first slice pass.
        rig.node.advance(
            &next,
            JobState::Ended,
            Some(40),
            Some(JobEnd::Exited { code: 0 }),
            true,
        );
        rig.step_session(&run)
            .expect("the step reads the next chunk");
        rig.clock.advance_secs(100_000);
        let refused = rig.vault().write_off_gpu_job(
            &rig.owner,
            &run.job.id,
            &rig.permits,
            &rig.connector,
            rig.clock.now_ms(),
        );
        assert!(
            matches!(
                &refused,
                Err(GpuJobError::Connector(GpuConnectorError::Refused { reason }))
                    if reason == "end_confirmed"
            ),
            "{refused:?}"
        );
        assert!(rig.job(&run).state.is_live());
        let current = rig
            .vault()
            .job_dispatch(&first)
            .expect("read JOB_DISPATCH")
            .expect("the first chunk's dispatch row");
        assert!(
            !matches!(current.closed, Some(DispatchClose::WrittenOff { .. })),
            "nothing is written off: {:?}",
            current.closed
        );
    });
}

/// The `not_after` the issuer signed into `key`'s submit.
fn signed_not_after_ms(vault: &Vault, key: &str) -> u64 {
    let row = vault
        .job_dispatch(key)
        .expect("read JOB_DISPATCH")
        .expect("the key's dispatch row");
    oneiron_organ_protocol::from_slice::<oneiron_server::gpu_execution_node::wire::SignedJobSubmit>(
        &row.submit,
    )
    .expect("the signed submit")
    .submit
    .not_after_ms
}

/// REVIEW-10521 r2 P1 (renewals.rs:272, door 10): a session whose run staged past its first
/// key's window and then renewed is bounded by its first renewal's window, which the node
/// enforces on its own (it renews only a run it launched, and only inside that window). Door 10
/// waits for that bound plus every chunk and the wait, not for the first key's window plus the
/// chunks, which passes while the renewed slice can still run.
#[test]
fn a_write_off_waits_for_a_renewed_run_that_launched_past_its_first_window() {
    use vault_machine_rig::MAXIMUM_SECS;
    /// `jobs.write_off.wait_secs`, its default.
    const WAIT_SECS: u64 = 3_600;

    with_rig(|rig| {
        rig.node.state().session_template = true;
        let workload = rig.approve("session", FAR_EXPIRY_MS);
        let run = rig.start_session(&workload);
        let first = run.key().to_owned();
        let first_not_after_ms = signed_not_after_ms(rig.vault(), &first);
        // The node staged past the first key's window: the run launched 4,000 s after it.
        let launched_ms = first_not_after_ms + 4_000_000;
        rig.clock
            .advance_secs((launched_ms - rig.clock.now_ms()) / 1_000 + MAXIMUM_SECS - 300);
        rig.node.advance(
            &first,
            JobState::Running,
            Some(MAXIMUM_SECS - 300),
            None,
            true,
        );
        rig.step_session(&run).expect("the step renews the session");
        let next = rig
            .job(&run)
            .renewal
            .as_ref()
            .expect("the next chunk is written")
            .idempotency_key
            .clone();
        let next_not_after_ms = signed_not_after_ms(rig.vault(), &next);
        rig.clock.advance_secs(300);
        rig.node.advance(
            &first,
            JobState::Ended,
            Some(MAXIMUM_SECS),
            Some(JobEnd::Continued),
            true,
        );
        rig.node
            .advance(&next, JobState::Running, Some(5), None, true);
        rig.step_session(&run)
            .expect("the step moves to the next chunk");
        assert_eq!(rig.job(&run).chunks.len(), 2, "the renewed slice runs");

        // The run can hold the node until its launch plus both chunks.
        let run_end_ms = launched_ms + 2 * MAXIMUM_SECS * 1_000;
        let first_window_bound_ms = first_not_after_ms + (2 * MAXIMUM_SECS + WAIT_SECS) * 1_000;
        assert!(first_window_bound_ms < run_end_ms);
        rig.clock
            .advance_secs((first_window_bound_ms - rig.clock.now_ms()) / 1_000 + 1);
        let early = rig.vault().write_off_gpu_job(
            &rig.owner,
            &run.job.id,
            &rig.permits,
            &rig.connector,
            rig.clock.now_ms(),
        );
        assert!(
            matches!(
                &early,
                Err(GpuJobError::Connector(GpuConnectorError::Refused { reason }))
                    if reason == "write_off_too_early"
            ),
            "the renewed slice may still run: {early:?}"
        );
        assert!(rig.job(&run).state.is_live());
        let current = rig
            .vault()
            .job_dispatch(&next)
            .expect("read JOB_DISPATCH")
            .expect("the renewed chunk's dispatch row");
        assert!(
            !matches!(current.closed, Some(DispatchClose::WrittenOff { .. })),
            "nothing is written off: {:?}",
            current.closed
        );

        // From the first renewal's window plus both chunks and the wait, the door closes it.
        let renewal_bound_ms = next_not_after_ms + (2 * MAXIMUM_SECS + WAIT_SECS) * 1_000;
        assert!(renewal_bound_ms >= run_end_ms + WAIT_SECS * 1_000);
        rig.clock
            .advance_secs((renewal_bound_ms - rig.clock.now_ms()) / 1_000);
        let written = rig
            .vault()
            .write_off_gpu_job(
                &rig.owner,
                &run.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            )
            .expect("the write-off once the renewed run met its cutoff");
        assert_eq!(
            written.state,
            GpuJobState::Ended {
                reason: GpuEndReason::Unconfirmed
            }
        );
    });
}

/// REVIEW-10521 r2 P1 (view.rs:132, door 8): once a session's next chunk is admitted while the
/// current chunk still runs, both permits hold their units, and door 8 counts both.
#[test]
fn door_8_counts_a_session_next_chunk_hold_beside_the_current_one() {
    use vault_machine_rig::MAXIMUM_SECS;

    with_rig(|rig| {
        rig.node.state().session_template = true;
        let workload = rig.approve("session", FAR_EXPIRY_MS);
        let run = rig.start_session(&workload);
        let first = run.key().to_owned();
        rig.clock.advance_secs(MAXIMUM_SECS - 300);
        rig.node.advance(
            &first,
            JobState::Running,
            Some(MAXIMUM_SECS - 300),
            None,
            true,
        );
        rig.step_session(&run).expect("the step renews the session");
        let job = rig.job(&run);
        let current_units = job.chunk().expect("the current chunk").quote.units;
        // The step writes the next chunk only once its own permit holds its quote.
        let next_units = job
            .renewal
            .as_ref()
            .expect("the next chunk is admitted")
            .quote
            .units;
        assert!(current_units > 0 && next_units > 0);
        let view = rig
            .connector
            .node_view(&job, rig.clock.now_ms(), 60_000)
            .expect("a job on one of the vault's machines has a node view");
        assert_eq!(
            view.accounting,
            GpuJobAccounting::Held {
                units: current_units + next_units
            }
        );
    });
}

/// The rig's connector, with a refusal of a session's next chunk lost on its way back to the
/// step: the state a host leaves when it stops after the issuer stored the node's signed refusal
/// and before the step settled the chunk at zero (REVIEW-10521 r2 P1 2).
struct RenewalRefusalLost<'a>(&'a VaultMachineConnector);

impl GpuJobConnector for RenewalRefusalLost<'_> {
    fn create(&self, key: &str, spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        self.0.create(key, spec)
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        self.0.find(key)
    }

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        self.0.status(resource)
    }

    fn signal(
        &self,
        resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        self.0.signal(resource, signal)
    }

    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        self.0.terminate(resource)
    }

    fn renew(
        &self,
        key: &str,
        continues: &str,
        spec: &GpuJobSpec,
    ) -> Result<GpuResourceRef, GpuConnectorError> {
        match self.0.renew(key, continues, spec) {
            Err(GpuConnectorError::Refused { .. }) => Err(GpuConnectorError::Timeout),
            other => other,
        }
    }
}

/// Starts a session and runs it to its renewal. The node refuses the next chunk with a signed
/// end saying it never started; the issuer stores it, and the step never settles the chunk.
/// Then the node goes silent, so no step can. Answers the run and its two keys.
fn session_with_a_stored_unsettled_renewal_refusal(
    rig: &vault_machine_rig::Rig,
) -> (vault_machine_rig::JobRun, String, String) {
    use vault_machine_rig::MAXIMUM_SECS;

    rig.node.state().session_template = true;
    let workload = rig.approve("session", FAR_EXPIRY_MS);
    let run = rig.start_session(&workload);
    let first = run.key().to_owned();
    rig.clock.advance_secs(MAXIMUM_SECS - 300);
    rig.node.advance(
        &first,
        JobState::Running,
        Some(MAXIMUM_SECS - 300),
        None,
        true,
    );
    rig.node.refuse_submits(Some("session_max_reached"));
    rig.step_session_with(&run, &RenewalRefusalLost(&rig.connector))
        .expect("the step sends the renewal");
    let job = rig.job(&run);
    let renewal = job.renewal.as_ref().expect("the next chunk is written");
    assert_eq!(renewal.billed_secs, None, "the step never settled it");
    let next = renewal.idempotency_key.clone();
    let stored = rig
        .vault()
        .job_observation(&next)
        .expect("read JOB_OBSERVATION")
        .expect("the issuer stored the node's answer");
    let receipt = oneiron_organ_protocol::from_slice::<SignedJobReceipt>(&stored.receipt)
        .expect("the stored receipt")
        .receipt;
    assert_eq!((receipt.state, receipt.started), (JobState::Ended, false));
    rig.node.unreachable(true);
    assert!(
        rig.step_session(&run).is_err(),
        "the node is silent, so no step settles the next chunk"
    );
    (run, first, next)
}

/// What door 10 may write for `run`: its job row and the dispatch rows of `keys`.
fn door_10_rows(
    rig: &vault_machine_rig::Rig,
    run: &vault_machine_rig::JobRun,
    keys: &[&str],
) -> (
    oneiron::gpu_job::GpuJob,
    Vec<Option<oneiron::job_dispatch::JobDispatch>>,
) {
    let rows = keys
        .iter()
        .map(|key| rig.vault().job_dispatch(key).expect("read JOB_DISPATCH"))
        .collect();
    (rig.job(run), rows)
}

/// REVIEW-10521 r2 P1 (renewals.rs:289, door 10; ANSWER W1-DOOR10-NEVER-STARTED-RENEWAL = A):
/// the node refused a session's next chunk with a signed end saying it never started, the
/// issuer stored it, the host stopped before the step settled the chunk, and the node went
/// silent. Door 10 settles that chunk at zero and writes the current chunk off under the run's
/// bound: both holds are released and the job ends. The old door refused `end_confirmed` for
/// good, and the job and both holds stayed.
#[test]
fn a_write_off_settles_a_renewal_the_node_signed_as_never_started_at_zero() {
    with_rig(|rig| {
        let (run, first, next) = session_with_a_stored_unsettled_renewal_refusal(rig);
        rig.clock.advance_secs(100_000);
        let written = match rig.vault().write_off_gpu_job(
            &rig.owner,
            &run.job.id,
            &rig.permits,
            &rig.connector,
            rig.clock.now_ms(),
        ) {
            Ok(job) => job,
            Err(error) => panic!("door 10 settles a renewal that never started: {error:?}"),
        };
        assert_eq!(
            written.state,
            GpuJobState::Ended {
                reason: GpuEndReason::Unconfirmed
            }
        );
        let renewal = written
            .renewal
            .as_ref()
            .expect("the next chunk stays on the job");
        assert_eq!(renewal.idempotency_key, next);
        assert_eq!(
            (renewal.billed_secs, renewal.settled_units),
            (Some(0), Some(0))
        );
        assert_eq!(
            written.chunk().expect("the current chunk").settled_units,
            Some(0)
        );
        assert!(!rig.permits.holds(&run.job.id), "both holds are released");
        assert_eq!(run.settled(), vec![0, 0], "each hold settles once, at zero");
        let current = rig
            .vault()
            .job_dispatch(&first)
            .expect("read JOB_DISPATCH")
            .expect("the current chunk's dispatch row");
        assert!(
            matches!(current.closed, Some(DispatchClose::WrittenOff { .. })),
            "{:?}",
            current.closed
        );
        let refused = rig
            .vault()
            .job_dispatch(&next)
            .expect("read JOB_DISPATCH")
            .expect("the next chunk's dispatch row");
        assert_eq!(refused.phase, DispatchPhase::Closed);
    });
}

/// ANSWER W1-DOOR10-NEVER-STARTED-RENEWAL = A, condition 4: a next chunk whose signed end says
/// the run passed into it still refuses door 10 with `end_confirmed`, so the step bills it;
/// nothing is written.
#[test]
fn a_write_off_still_refuses_a_renewal_whose_signed_end_says_it_ran() {
    use vault_machine_rig::MAXIMUM_SECS;

    with_rig(|rig| {
        rig.node.state().session_template = true;
        let workload = rig.approve("session", FAR_EXPIRY_MS);
        let run = rig.start_session(&workload);
        let first = run.key().to_owned();
        rig.clock.advance_secs(MAXIMUM_SECS - 300);
        rig.node.advance(
            &first,
            JobState::Running,
            Some(MAXIMUM_SECS - 300),
            None,
            true,
        );
        rig.step_session(&run).expect("the step renews the session");
        let next = rig
            .job(&run)
            .renewal
            .as_ref()
            .expect("the next chunk is written")
            .idempotency_key
            .clone();
        // The run passed into the next chunk and on past it: its signed end says it ran.
        rig.node.advance(
            &next,
            JobState::Ended,
            Some(MAXIMUM_SECS),
            Some(JobEnd::Continued),
            true,
        );
        rig.step_session(&run)
            .expect("the step reads the next chunk");
        rig.node.unreachable(true);
        rig.clock.advance_secs(100_000);
        let before = door_10_rows(rig, &run, &[&first, &next]);
        let refused = rig.vault().write_off_gpu_job(
            &rig.owner,
            &run.job.id,
            &rig.permits,
            &rig.connector,
            rig.clock.now_ms(),
        );
        assert!(
            matches!(
                &refused,
                Err(GpuJobError::Connector(GpuConnectorError::Refused { reason }))
                    if reason == "end_confirmed"
            ),
            "{refused:?}"
        );
        assert!(
            door_10_rows(rig, &run, &[&first, &next]) == before,
            "nothing is written"
        );
    });
}

/// ANSWER W1-DOOR10-NEVER-STARTED-RENEWAL = A, condition 1: door 10 checks a stored
/// never-started end again before it settles anything on it. A receipt changed under the
/// node's signature, or one the node signed for another chunk, refuses with the failed check's
/// name, and nothing is written.
#[test]
fn a_write_off_refuses_a_never_started_end_that_fails_its_checks() {
    with_rig(|rig| {
        let (run, first, next) = session_with_a_stored_unsettled_renewal_refusal(rig);
        rig.clock.advance_secs(100_000);
        let stored = rig
            .vault()
            .job_observation(&next)
            .expect("read JOB_OBSERVATION")
            .expect("the stored answer");
        let signed = oneiron_organ_protocol::from_slice::<SignedJobReceipt>(&stored.receipt)
            .expect("the stored receipt");
        let mut changed = signed.clone();
        changed.receipt.seq += 1;
        let mut other = signed.receipt.clone();
        other.key = format!("{}:9", run.job.id.to_hex());
        let elsewhere = rig.node.put(other);
        for (planted, check) in [
            (changed, "end_unverified: receipt_signature_invalid"),
            (elsewhere, "end_unverified: receipt_names_another_chunk"),
        ] {
            let mut observation = stored.clone();
            observation.receipt =
                oneiron_organ_protocol::to_vec(&planted).expect("encode the planted receipt");
            rig.vault()
                .put_job_observation(&observation)
                .expect("plant the receipt");
            let before = door_10_rows(rig, &run, &[&first, &next]);
            let refused = rig.vault().write_off_gpu_job(
                &rig.owner,
                &run.job.id,
                &rig.permits,
                &rig.connector,
                rig.clock.now_ms(),
            );
            assert!(
                matches!(
                    &refused,
                    Err(GpuJobError::Connector(GpuConnectorError::Refused { reason }))
                        if reason == check
                ),
                "{check}: {refused:?}"
            );
            assert!(
                door_10_rows(rig, &run, &[&first, &next]) == before,
                "{check}: nothing is written"
            );
        }
    });
}

/// ANSWER W1-DOOR10-NEVER-STARTED-RENEWAL = A, condition 3: door 10 asked twice writes once.
/// The second call, and the backend's own close asked again with the job as the first call saw
/// it, change no row and settle no hold again.
#[test]
fn a_second_write_off_of_a_never_started_renewal_changes_nothing() {
    with_rig(|rig| {
        let (run, first, next) = session_with_a_stored_unsettled_renewal_refusal(rig);
        rig.clock.advance_secs(100_000);
        let seen = rig.job(&run);
        let first_call = rig.vault().write_off_gpu_job(
            &rig.owner,
            &run.job.id,
            &rig.permits,
            &rig.connector,
            rig.clock.now_ms(),
        );
        let after = door_10_rows(rig, &run, &[&first, &next]);
        let settled = run.settled();
        let second = rig.vault().write_off_gpu_job(
            &rig.owner,
            &run.job.id,
            &rig.permits,
            &rig.connector,
            rig.clock.now_ms(),
        );
        if first_call.is_ok() {
            assert!(matches!(second, Err(GpuJobError::Ended)), "{second:?}");
        }
        let again = rig.connector.write_off(&seen, rig.clock.now_ms());
        assert_eq!(again.is_ok(), first_call.is_ok(), "{again:?}");
        assert!(
            door_10_rows(rig, &run, &[&first, &next]) == after,
            "the second call writes nothing"
        );
        assert_eq!(run.settled(), settled, "no hold settles twice");
    });
}
