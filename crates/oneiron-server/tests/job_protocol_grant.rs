#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! The job protocols' grant is the gate, for each protocol id on its own
//! (pass 33 row R0, `33-exec-node/DESIGN.md` section 11 T2; EM-1 = A):
//! `oneiron/job/1` admits new work and `oneiron/job-status/1` serves the keys
//! a node holds, and a machine the serving vault grants one protocol and not
//! the other is admitted on the one and refused at the handshake on the
//! other.
//!
//! Three of the owner's servers run with their real mesh listeners
//! (`support/mesh_machines.rs`). B and C are execution nodes whose one
//! issuer is A (row R1: a machine serves the job protocols only when its
//! `[execution_node]` file enables it). Each replica's grants, as the owner
//! set them with `vault.mesh.set_alpn_grant`:
//! - B grants A both job protocols, and C the status protocol alone;
//! - C grants A the job protocol alone, and B both;
//! - A grants B and C both, so A dials each on each.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test job_protocol_grant`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/execution_nodes.rs"]
mod execution_nodes;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::time::Duration;

use engine_stack::on_engine_stack;
use execution_nodes::NodeFiles;
use mesh_machines::{Machine, Machines, TestResult, eventually, inbound_path_receipts};
use oneiron::sync::mesh_path::MeshPathOutcome;
use oneiron_mesh_transport::MeshError;
use oneiron_mesh_transport::message::exchange;
use oneiron_server::gpu_execution_node::wire::{
    JOB_ALPN, JOB_PROTOCOL, JOB_STATUS_ALPN, JobAnswer, JobRefusal, JobRequest, JobStatusAnswer,
    JobStatusRequest,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
const BOTH: [&[u8]; 2] = [JOB_ALPN, JOB_STATUS_ALPN];
/// How long one dial and its exchange may take on loopback.
const ASK_WITHIN: Duration = Duration::from_secs(30);
/// How long the refused path receipt may take to land.
const RECEIPT_WITHIN: Duration = Duration::from_secs(15);

/// `from` dials `to` on `alpn` and sends `request` on one stream: the
/// answer, or why it got none. A dial or exchange that hangs past
/// [`ASK_WITHIN`] fails the test.
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

#[test]
fn a_machine_without_the_job_grant_is_refused_at_the_handshake() -> TestResult {
    on_engine_stack(machine_without_the_job_grant_is_refused)
}

async fn machine_without_the_job_grant_is_refused() -> TestResult {
    let files = NodeFiles::new()?;
    let mesh = Machines::start_with(3, |index, machines| match index {
        B | C => files.enabled(index, machines[A]),
        _ => NodeFiles::none(),
    })
    .await?;
    mesh.grant(B, A, &BOTH)?;
    mesh.grant(B, C, &[JOB_STATUS_ALPN])?;
    mesh.grant(C, A, &[JOB_ALPN])?;
    mesh.grant(C, B, &BOTH)?;
    mesh.grant(A, B, &BOTH)?;
    mesh.grant(A, C, &BOTH)?;
    let (a, b, c) = (mesh.machine(A), mesh.machine(B), mesh.machine(C));

    // A holds both of B's grants: B answers it on each protocol. B's node
    // answers its issuer's `Node`, and refuses a status request as not
    // enabled until row R4 answers it, so an answer is the proof the stream
    // was admitted.
    match ask::<_, JobAnswer>(a, b, JOB_ALPN, &JobRequest::Node).await? {
        Ok(JobAnswer::Node(node)) => assert!(node.enabled, "B is a node: {node:?}"),
        other => panic!("B must answer A's Node on oneiron/job/1: {other:?}"),
    }
    assert_eq!(
        ask::<_, JobStatusAnswer>(
            a,
            b,
            JOB_STATUS_ALPN,
            &JobStatusRequest::Keys { after: None }
        )
        .await?
        .map_err(|error| format!("A's Keys on oneiron/job-status/1: {error:?}"))?,
        JobStatusAnswer::Refused(JobRefusal::NotEnabled),
        "B must answer A on oneiron/job-status/1"
    );

    // C holds B's status grant and not its job grant: refused at the
    // handshake on oneiron/job/1, answered on oneiron/job-status/1.
    let refused = ask::<_, JobAnswer>(c, b, JOB_ALPN, &JobRequest::Node).await?;
    assert!(
        refused.is_err(),
        "B must refuse C on oneiron/job/1 before any answer: {refused:?}"
    );
    let b_vault = std::sync::Arc::clone(&b.device.vault);
    let c_machine = c.device.machine;
    assert!(
        eventually(RECEIPT_WITHIN, || {
            inbound_path_receipts(&b_vault, c_machine, JOB_ALPN)
                .iter()
                .any(|receipt| receipt.outcome == MeshPathOutcome::Refused)
        })
        .await,
        "B must hold a refused inbound path receipt for C on oneiron/job/1: {:?}",
        inbound_path_receipts(&b_vault, c_machine, JOB_ALPN)
    );
    assert!(
        !inbound_path_receipts(&b_vault, c_machine, JOB_ALPN)
            .iter()
            .any(|receipt| receipt.outcome == MeshPathOutcome::Admitted),
        "B must never admit C on oneiron/job/1"
    );
    assert_eq!(
        ask::<_, JobStatusAnswer>(
            c,
            b,
            JOB_STATUS_ALPN,
            &JobStatusRequest::Keys { after: None }
        )
        .await?
        .map_err(|error| format!("C's Keys on oneiron/job-status/1: {error:?}"))?,
        JobStatusAnswer::Refused(JobRefusal::NotIssuer),
        "B must answer C on oneiron/job-status/1, which it grants C: past the handshake, \
         its gate refuses a machine its file does not name"
    );

    // A holds C's job grant and not its status grant: the other protocol id
    // is gated on its own.
    match ask::<_, JobAnswer>(a, c, JOB_ALPN, &JobRequest::Node).await? {
        Ok(JobAnswer::Node(node)) => assert!(node.enabled, "C is a node: {node:?}"),
        other => panic!("C must answer A's Node on oneiron/job/1: {other:?}"),
    }
    let refused = ask::<_, JobStatusAnswer>(
        a,
        c,
        JOB_STATUS_ALPN,
        &JobStatusRequest::Keys { after: None },
    )
    .await?;
    assert!(
        refused.is_err(),
        "C must refuse A on oneiron/job-status/1 before any answer: {refused:?}"
    );
    let c_vault = std::sync::Arc::clone(&c.device.vault);
    let a_machine = a.device.machine;
    assert!(
        eventually(RECEIPT_WITHIN, || {
            inbound_path_receipts(&c_vault, a_machine, JOB_STATUS_ALPN)
                .iter()
                .any(|receipt| receipt.outcome == MeshPathOutcome::Refused)
        })
        .await,
        "C must hold a refused inbound path receipt for A on oneiron/job-status/1: {:?}",
        inbound_path_receipts(&c_vault, a_machine, JOB_STATUS_ALPN)
    );

    mesh.stop().await;
    Ok(())
}
