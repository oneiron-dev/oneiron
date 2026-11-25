#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! The execution node's opt-in and its gate (pass 33 row R1,
//! `33-exec-node/DESIGN.md` section 11 T3, T4, T5, T5b, and the authority
//! tick of EN-4 A), between the owner's servers with their real mesh
//! listeners (`support/mesh_machines.rs`).
//!
//! In each test A is the issuer: the one machine a node's `[execution_node]`
//! file names. B is a node. C, where there is one, is another of the
//! owner's machines that B grants both job protocols but does not name.
//! On Linux the listener opens the node's journal (row R3a) and attaches it
//! before it serves, so a request that passes the gate and names a key is
//! answered by the journal; every refusal before it names its gate.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test execution_node_gate`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/execution_nodes.rs"]
mod execution_nodes;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use engine_stack::on_engine_stack;
use execution_nodes::{NodeFiles, PROBE_TEMPLATE};
use mesh_machines::{Machine, Machines, TestResult, at};
use oneiron::EntityId;
use oneiron::job_workload::{DeviceKind, Sharing};
use oneiron_mesh_transport::MeshError;
use oneiron_mesh_transport::message::exchange;
use oneiron_server::gpu_execution_node::node::{DISABLED_MARKER_EXTENSION, marker_beside};
use oneiron_server::gpu_execution_node::wire::{
    DeviceClaim, HoldRef, JOB_ALPN, JOB_PROTOCOL, JOB_STATUS_ALPN, JobAnswer, JobRefusal,
    JobRequest, JobReserve, JobStatusAnswer, JobStatusRequest, JobSubmit, LogStream,
    LogTailRequest, NetworkMode, ResourceRequest, ScopeKind, SignedJobSubmit, SlotSelector,
    Starter, WorkloadPin,
};
use oneiron_server::gpu_execution_node::{
    ExecutionNode, GpuDeviceOffer, GpuSlotTable, NodeKeys, NvidiaSmiProbe,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
const BOTH: [&[u8]; 2] = [JOB_ALPN, JOB_STATUS_ALPN];
/// How long one dial and its exchange may take on loopback.
const ASK_WITHIN: Duration = Duration::from_secs(30);

/// `from` dials `to` on `alpn` and sends `request` on one stream: the
/// answer, or why it got none.
async fn ask<Q, R>(
    from: &Machine,
    to: &Machine,
    alpn: &[u8],
    request: &Q,
) -> TestResult<Result<R, MeshError>>
where
    Q: Serialize + Sync,
    R: DeserializeOwned,
{
    let transport = from.served.transport()?;
    let asked = async {
        let connection = transport.dial(to.device.machine, alpn).await?;
        let answer = exchange(JOB_PROTOCOL, connection.as_ref(), request).await;
        connection.close();
        answer
    };
    tokio::time::timeout(ASK_WITHIN, asked).await.map_err(|_| {
        format!(
            "the ask on {} did not end within {ASK_WITHIN:?}",
            String::from_utf8_lossy(alpn)
        )
        .into()
    })
}

/// A pin of the nodes' probe template (its digest is not checked here: the
/// gate refuses before any template is read).
fn probe_pin() -> WorkloadPin {
    WorkloadPin {
        template: PROBE_TEMPLATE.to_owned(),
        template_digest: "0".repeat(64),
        commit: "a".repeat(40),
        contract_sha256: "b".repeat(64),
        contract_path: "contract.json".to_owned(),
        entry: "tools/units/run.sh".to_owned(),
        args: Vec::new(),
        request: ResourceRequest {
            cpu_threads: 0,
            memory_mib: 1_024,
            disk_mib: 1_024,
            devices: vec![DeviceClaim {
                kind: DeviceKind::Gpu,
                count: 1,
                memory_mib: 1_024,
                features: Vec::new(),
                sharing: Sharing::Exclusive,
            }],
            maximum_secs: 600,
        },
        scope: ScopeKind::Host,
        network: NetworkMode::None,
        outputs: Vec::new(),
    }
}

/// Whether `answer` came from past B's gate, from its keys. On Linux they are
/// the node's journal, which the listener opened before it served: a
/// receipt, or `Busy` while its start-up reconciliation waits on a service
/// manager that does not answer (a container with no systemd). Elsewhere no
/// journal is attached, and the keys answer `NotEnabled`.
fn answered_by_the_keys(answer: &JobAnswer) -> bool {
    if cfg!(target_os = "linux") {
        matches!(answer, JobAnswer::Receipt(_) | JobAnswer::Busy { .. })
    } else {
        *answer == JobAnswer::Refused(JobRefusal::NotEnabled)
    }
}

fn reserve(issuer: EntityId) -> JobRequest {
    JobRequest::Reserve(JobReserve {
        key: "key-1".to_owned(),
        pin: probe_pin(),
        slot: SlotSelector::default(),
        issuer,
        starter: Starter::Owner,
        issued_at_ms: 0,
        not_after_ms: u64::MAX,
    })
}

fn submit(issuer: EntityId) -> JobRequest {
    JobRequest::Submit(SignedJobSubmit {
        submit: JobSubmit {
            key: "key-1".to_owned(),
            job: issuer,
            chunk: 0,
            pin: probe_pin(),
            slot: SlotSelector::default(),
            maximum_secs: 600,
            issued_at_ms: 0,
            not_after_ms: u64::MAX,
            issuer,
            starter: Starter::Owner,
            hold: HoldRef {
                reservation: "reservation-1".to_owned(),
                generation: 1,
            },
            authority_heads: Vec::new(),
            continues: None,
        },
        signature: [0; 64],
    })
}

/// A, B and C, where B is a node whose one issuer is A, B holds its own job
/// grant, and B grants A and C both job protocols; A and C grant B both.
async fn issuer_node_and_other(files: &NodeFiles) -> TestResult<Machines> {
    let mesh = Machines::start_with(3, |index, machines| match index {
        B => files.enabled(B, machines[A]),
        _ => NodeFiles::none(),
    })
    .await?;
    mesh.grant(B, A, &BOTH)?;
    mesh.grant(B, C, &BOTH)?;
    mesh.grant(A, B, &BOTH)?;
    mesh.grant(C, B, &BOTH)?;
    mesh.grant_own(B, &[JOB_ALPN])?;
    Ok(mesh)
}

#[test]
fn a_node_that_is_not_enabled_serves_no_job_protocol() -> TestResult {
    on_engine_stack(node_not_enabled_serves_no_job_protocol)
}

async fn node_not_enabled_serves_no_job_protocol() -> TestResult {
    let files = NodeFiles::new()?;
    // B names no node file; C's file says `enabled = false`. Each grants A
    // both job protocols, so only the opt-in can refuse A.
    let mesh = Machines::start_with(3, |index, _| match index {
        C => files.disabled(C),
        _ => NodeFiles::none(),
    })
    .await?;
    for node in [B, C] {
        mesh.grant(node, A, &BOTH)?;
        mesh.grant(A, node, &BOTH)?;
    }
    let a = mesh.machine(A);
    for node in [B, C] {
        let node = mesh.machine(node);
        let refused = ask::<_, JobAnswer>(a, node, JOB_ALPN, &JobRequest::Node).await?;
        assert!(
            refused.is_err(),
            "a machine that is not an enabled node must refuse oneiron/job/1 at the handshake: {refused:?}"
        );
        let refused = ask::<_, JobStatusAnswer>(
            a,
            node,
            JOB_STATUS_ALPN,
            &JobStatusRequest::Keys { after: None },
        )
        .await?;
        assert!(
            refused.is_err(),
            "a machine that is not an enabled node must refuse oneiron/job-status/1 at the handshake: {refused:?}"
        );
    }
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_revoked_job_grant_refuses_the_next_stream_and_leaves_the_status_route() -> TestResult {
    on_engine_stack(revoked_job_grant_refuses_the_next_stream)
}

async fn revoked_job_grant_refuses_the_next_stream() -> TestResult {
    let files = NodeFiles::new()?;
    let mesh = issuer_node_and_other(&files).await?;
    let (a, b) = (mesh.machine(A), mesh.machine(B));

    // One connection of A's on oneiron/job/1: its first stream is answered.
    let transport = a.served.transport()?;
    let connection = tokio::time::timeout(ASK_WITHIN, transport.dial(b.device.machine, JOB_ALPN))
        .await
        .map_err(|_| "A's dial of B on oneiron/job/1 hung")?
        .map_err(at("A dials B on oneiron/job/1"))?;
    let first = tokio::time::timeout(
        ASK_WITHIN,
        exchange::<_, JobAnswer>(JOB_PROTOCOL, connection.as_ref(), &JobRequest::Node),
    )
    .await
    .map_err(|_| "A's first Node hung")?;
    let epoch = match first {
        Ok(JobAnswer::Node(node)) => {
            assert!(node.enabled, "B is an enabled node: {node:?}");
            node.epoch
                .ok_or("B's Node must name the epoch of the journal it keeps")?
        }
        other => panic!("B must answer its issuer's Node on oneiron/job/1: {other:?}"),
    };

    // The owner withdraws A's job grant on B: the next stream of the same
    // connection gets no answer but a refusal, and a new connection is
    // refused at the handshake.
    mesh.revoke(B, A, &[JOB_ALPN])?;
    let next = tokio::time::timeout(
        ASK_WITHIN,
        exchange::<_, JobAnswer>(JOB_PROTOCOL, connection.as_ref(), &JobRequest::Node),
    )
    .await
    .map_err(|_| "A's second Node hung")?;
    assert!(
        matches!(
            next,
            Err(_) | Ok(JobAnswer::Refused(JobRefusal::PeerNotProven))
        ),
        "the stream after the revoke must be refused: {next:?}"
    );
    connection.close();
    let refused = ask::<_, JobAnswer>(a, b, JOB_ALPN, &JobRequest::Node).await?;
    assert!(
        refused.is_err(),
        "a new connection after the revoke must be refused at the handshake: {refused:?}"
    );

    // The status route stands: A still holds B's status grant, and its ask
    // passes B's gate to the journal B keeps, which holds no key-1.
    assert_eq!(
        ask::<_, JobStatusAnswer>(
            a,
            b,
            JOB_STATUS_ALPN,
            &JobStatusRequest::Find {
                key: "key-1".to_owned()
            }
        )
        .await?
        .map_err(|error| format!("A's Find on oneiron/job-status/1: {error:?}"))?,
        JobStatusAnswer::Absent { epoch },
        "B must still answer its issuer on oneiron/job-status/1"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_granted_machine_that_is_not_the_nodes_issuer_cannot_reserve_submit_read_or_stop() -> TestResult
{
    on_engine_stack(granted_machine_not_the_issuer_is_refused)
}

async fn granted_machine_not_the_issuer_is_refused() -> TestResult {
    let files = NodeFiles::new()?;
    let mesh = issuer_node_and_other(&files).await?;
    let (a, b, c) = (mesh.machine(A), mesh.machine(B), mesh.machine(C));
    let not_issuer = JobAnswer::Refused(JobRefusal::NotIssuer);

    // C holds both of B's grants, and B's file names A alone.
    for request in [
        JobRequest::Node,
        JobRequest::Availability,
        reserve(c.device.machine),
        JobRequest::Release {
            key: "key-1".to_owned(),
        },
        submit(c.device.machine),
    ] {
        let answer = ask::<_, JobAnswer>(c, b, JOB_ALPN, &request)
            .await?
            .map_err(|error| format!("C's {request:?} on oneiron/job/1: {error:?}"))?;
        assert_eq!(answer, not_issuer, "B must refuse C's {request:?}");
    }
    for request in [
        JobStatusRequest::Find {
            key: "key-1".to_owned(),
        },
        JobStatusRequest::Status {
            key: "key-1".to_owned(),
        },
        JobStatusRequest::Stop {
            key: "key-1".to_owned(),
        },
        JobStatusRequest::Keys { after: None },
        JobStatusRequest::Fetch {
            key: "key-1".to_owned(),
            name: "verdict.json".to_owned(),
        },
        JobStatusRequest::Tail(LogTailRequest {
            key: "key-1".to_owned(),
            stream: LogStream::Stdout,
            offset: 0,
            max: 1024,
        }),
    ] {
        let answer = ask::<_, JobStatusAnswer>(c, b, JOB_STATUS_ALPN, &request)
            .await?
            .map_err(|error| format!("C's {request:?} on oneiron/job-status/1: {error:?}"))?;
        assert_eq!(
            answer,
            JobStatusAnswer::Refused(JobRefusal::NotIssuer),
            "B must refuse C's {request:?}"
        );
    }

    // A, the issuer B names, passes the same gate: `Node` is answered, and
    // a reserve reaches the keys.
    match ask::<_, JobAnswer>(a, b, JOB_ALPN, &JobRequest::Node).await? {
        Ok(JobAnswer::Node(node)) => {
            assert!(node.enabled, "B is an enabled node: {node:?}");
            assert_eq!(
                node.templates
                    .iter()
                    .map(|template| template.name.as_str())
                    .collect::<Vec<_>>(),
                [PROBE_TEMPLATE],
                "B offers its one template"
            );
        }
        other => panic!("B must answer its issuer's Node: {other:?}"),
    }
    let answer = ask::<_, JobAnswer>(a, b, JOB_ALPN, &reserve(a.device.machine))
        .await?
        .map_err(|error| format!("A's reserve: {error:?}"))?;
    assert!(
        answered_by_the_keys(&answer),
        "A's reserve must pass B's gate: {answer:?}"
    );

    // `disable` at the box: C still learns nothing, and A reads that B takes
    // no work.
    std::fs::write(
        marker_beside(&files.path(B), DISABLED_MARKER_EXTENSION),
        "disabled\n",
    )?;
    assert_eq!(
        ask::<_, JobAnswer>(c, b, JOB_ALPN, &JobRequest::Node)
            .await?
            .map_err(|error| format!("C's Node of a disabled B: {error:?}"))?,
        not_issuer,
        "a disabled node must still refuse a machine its file does not name"
    );
    match ask::<_, JobAnswer>(a, b, JOB_ALPN, &JobRequest::Node).await? {
        Ok(JobAnswer::Node(node)) => assert!(!node.enabled, "B is disabled at the box: {node:?}"),
        other => panic!("a disabled B must answer its issuer's Node: {other:?}"),
    }
    assert_eq!(
        ask::<_, JobAnswer>(a, b, JOB_ALPN, &reserve(a.device.machine))
            .await?
            .map_err(|error| format!("A's reserve of a disabled B: {error:?}"))?,
        JobAnswer::Refused(JobRefusal::NotEnabled),
        "a disabled node admits no work"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_node_whose_own_job_grant_ended_refuses_a_still_granted_issuer() -> TestResult {
    on_engine_stack(node_whose_own_grant_ended_refuses)
}

async fn node_whose_own_grant_ended_refuses() -> TestResult {
    let files = NodeFiles::new()?;
    let mesh = issuer_node_and_other(&files).await?;
    let (a, b) = (mesh.machine(A), mesh.machine(B));
    let issuer = a.device.machine;
    let answer = ask::<_, JobAnswer>(a, b, JOB_ALPN, &reserve(issuer))
        .await?
        .map_err(|error| format!("A's reserve: {error:?}"))?;
    assert!(
        answered_by_the_keys(&answer),
        "with its own job grant live, B passes its issuer's reserve to its keys: {answer:?}"
    );

    // B's own job grant ends in B's own fold; B still grants A.
    mesh.revoke(B, B, &[JOB_ALPN])?;
    for request in [reserve(issuer), submit(issuer)] {
        assert_eq!(
            ask::<_, JobAnswer>(a, b, JOB_ALPN, &request)
                .await?
                .map_err(|error| format!("A's {request:?}: {error:?}"))?,
            JobAnswer::Refused(JobRefusal::OwnGrantEnded),
            "B must refuse work while its own job grant has ended: {request:?}"
        );
    }
    // What B offers is still readable by its issuer.
    match ask::<_, JobAnswer>(a, b, JOB_ALPN, &JobRequest::Node).await? {
        Ok(JobAnswer::Node(node)) => assert!(node.enabled, "B is still enabled: {node:?}"),
        other => panic!("B must still answer its issuer's Node: {other:?}"),
    }
    mesh.stop().await;
    Ok(())
}

/// The node's keys as a test sees them: every call the tick hands on.
#[derive(Default)]
struct RecordedKeys {
    calls: Mutex<Vec<String>>,
}

impl RecordedKeys {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.calls.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn record(&self, call: String) {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call);
    }
}

impl NodeKeys for RecordedKeys {
    fn reserve(&self, _peer: EntityId, _reserve: JobReserve) -> JobAnswer {
        JobAnswer::Refused(JobRefusal::NotEnabled)
    }
    fn release(&self, _peer: EntityId, _key: &str) -> JobAnswer {
        JobAnswer::Refused(JobRefusal::NotEnabled)
    }
    fn submit(&self, _peer: EntityId, _signed: SignedJobSubmit) -> JobAnswer {
        JobAnswer::Refused(JobRefusal::NotEnabled)
    }
    fn swept(&self) -> bool {
        true
    }
    fn epoch(&self) -> Option<String> {
        None
    }
    fn booked_disk_mib(&self) -> u64 {
        0
    }
    fn live_issuers(&self) -> BTreeSet<EntityId> {
        BTreeSet::new()
    }
    fn revoke_live_keys(&self, issuer: Option<EntityId>, why: &str) {
        self.record(format!(
            "revoke {} {why}",
            issuer.map_or_else(|| "all".to_owned(), |issuer| issuer.to_hex())
        ));
    }
    fn stop_live_keys(&self) {
        self.record("stop".to_owned());
    }
}

#[test]
fn the_authority_tick_stops_the_work_a_revoke_ended() -> TestResult {
    on_engine_stack(authority_tick_stops_the_work_a_revoke_ended)
}

async fn authority_tick_stops_the_work_a_revoke_ended() -> TestResult {
    let files = NodeFiles::new()?;
    let mesh = issuer_node_and_other(&files).await?;
    let issuer = mesh.machine(A).device.machine;
    let node = ExecutionNode::new(
        files.path(B),
        Arc::clone(&mesh.machine(B).device.vault),
        Arc::new(GpuSlotTable::new(
            Arc::new(NvidiaSmiProbe),
            GpuDeviceOffer::default(),
        )),
    );
    let keys = Arc::new(RecordedKeys::default());
    if node
        .attach_keys(Arc::clone(&keys) as Arc<dyn NodeKeys>)
        .is_err()
    {
        return Err("the node's keys attach once".into());
    }

    node.authority_tick();
    assert_eq!(
        keys.take(),
        Vec::<String>::new(),
        "a live fold stops nothing"
    );

    // B's own job grant ends: the tick ends every key.
    mesh.revoke(B, B, &[JOB_ALPN])?;
    node.authority_tick();
    assert_eq!(keys.take(), ["revoke all own_grant_ended"]);

    // B holds its grant again, and its issuer's job grant ends: the tick
    // ends that issuer's keys.
    mesh.grant(B, B, &[JOB_ALPN])?;
    mesh.revoke(B, A, &[JOB_ALPN])?;
    node.authority_tick();
    let hex = issuer.to_hex();
    assert_eq!(
        keys.take(),
        [format!("revoke {hex} issuer_standing_ended: {hex}")]
    );

    // `disable --stop` at the box stops every job on the next tick.
    mesh.grant(B, A, &[JOB_ALPN])?;
    std::fs::write(
        marker_beside(&files.path(B), DISABLED_MARKER_EXTENSION),
        "stop\n",
    )?;
    node.authority_tick();
    assert_eq!(keys.take(), ["stop"]);
    mesh.stop().await;
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn an_enabled_node_opens_and_attaches_its_job_journal_before_it_serves() -> TestResult {
    on_engine_stack(enabled_node_opens_its_job_journal_before_it_serves)
}

/// FIX R3A-NODE-JOBS-ATTACH: B's server opens B's job journal on the
/// `state_dir` its file names and attaches it before its listener serves,
/// answers its issuer from it, and lets it go when the listener stops.
#[cfg(target_os = "linux")]
async fn enabled_node_opens_its_job_journal_before_it_serves() -> TestResult {
    use oneiron_server::gpu_execution_node::jobs::journal_file::{
        EPOCH_FILE_NAME, JOURNAL_FILE_NAME, JournalWriterLock, WRITER_LOCK_FILE_NAME,
    };

    let files = NodeFiles::new()?;
    let mesh = issuer_node_and_other(&files).await?;
    let (a, b) = (mesh.machine(A), mesh.machine(B));
    let state_dir = files.state_dir(B);

    // B's listener is up and no request has reached it: its journal is
    // made, and its job service holds the journal's writer lock.
    for name in [JOURNAL_FILE_NAME, EPOCH_FILE_NAME] {
        assert!(
            state_dir.join(name).is_file(),
            "B must open its job journal before its listener serves: no {name} in {}",
            state_dir.display()
        );
    }
    match JournalWriterLock::take(&state_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        other => {
            return Err(format!(
                "B's job service must hold its journal's writer lock while B serves: {other:?}"
            )
            .into());
        }
    }

    // A reads the journal's epoch in B's Node answer.
    let epoch = match ask::<_, JobAnswer>(a, b, JOB_ALPN, &JobRequest::Node).await? {
        Ok(JobAnswer::Node(node)) => node.epoch,
        other => return Err(format!("B must answer its issuer's Node: {other:?}").into()),
    };
    assert!(
        epoch.is_some(),
        "B's Node must name the epoch of the journal it keeps"
    );

    // A's reserve is answered by the journal, never refused as `NotEnabled`.
    let answer = ask::<_, JobAnswer>(a, b, JOB_ALPN, &reserve(a.device.machine))
        .await?
        .map_err(|error| format!("A's reserve: {error:?}"))?;
    assert!(
        matches!(answer, JobAnswer::Receipt(_) | JobAnswer::Busy { .. }),
        "B's journal must answer A's reserve: {answer:?}"
    );
    if let JobAnswer::Receipt(signed) = &answer {
        assert_eq!(
            signed.receipt.machine, b.device.machine,
            "B's journal signs its receipt as B"
        );
        assert_eq!(
            Some(&signed.receipt.epoch),
            epoch.as_ref(),
            "the receipt carries the epoch B's Node named"
        );
    }

    // The listener's stop drops the job service: the journal's writer lock
    // is free again (a tick still running lets it go when it returns).
    mesh.stop().await;
    let lock_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(state_dir.join(WRITER_LOCK_FILE_NAME))?;
    let freed = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || lock_file.lock()),
    )
    .await;
    match freed {
        Ok(Ok(Ok(()))) => Ok(()),
        other => Err(format!(
            "B's journal must be free within 10 s of its listener's stop: {other:?}"
        )
        .into()),
    }
}
