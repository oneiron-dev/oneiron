#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! Withdrawing a machine's sync grant or revoking it outright closes its
//! open sync connection and every stream on it. Revoking another machine
//! leaves the connection serving (SYNC-REVOKE-CLOSES-OPEN-CONNECTION = A,
//! FIX [SYNC-OPEN-SOCKET-OUTLIVES-MESH-REVOKE]).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mesh_sync_revoke_closes_connection`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::time::Duration;

use engine_stack::on_engine_stack;
use mesh_machines::{Machines, TestResult, at};
use oneiron::sync::mesh_path::SYNC_ALPN;
use oneiron::test_support::test_host_issuer;
use oneiron_mesh_transport::{MeshConnection, MeshDuplex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The machine that dials.
const A: usize = 0;
/// The machine that serves and revokes.
const B: usize = 1;
/// Another machine of the owner's.
const C: usize = 2;
/// How long a dial or initial stream open may take.
const DIAL_WITHIN: Duration = Duration::from_secs(30);
/// Well under the listener's 60-second recheck: only the notice can meet it.
const CLOSE_WITHIN: Duration = Duration::from_secs(10);
/// How long to wait before asking the open stream again.
const POLL: Duration = Duration::from_millis(250);
/// Time for B's listener to handle a notice that must not close A.
const SETTLE: Duration = Duration::from_secs(1);
/// The largest response head the fixture accepts, in bytes.
const HEAD_MAX: usize = 16 * 1024;
/// An unrouted path; any HTTP/1.1 status line proves the stream still serves.
const PROBE: &[u8] = b"GET /mesh-sync-revoke-probe HTTP/1.1\r\nHost: mesh\r\n\r\n";

enum Answer {
    Served(String),
    Ended,
}

async fn ask(stream: &mut Box<dyn MeshDuplex>) -> TestResult<Answer> {
    if stream.write_all(PROBE).await.is_err() || stream.flush().await.is_err() {
        return Ok(Answer::Ended);
    }
    let mut head = Vec::new();
    let mut byte = [0];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(0) | Err(_) => return Ok(Answer::Ended),
            Ok(_) => head.push(byte[0]),
        }
        if head.len() > HEAD_MAX {
            return Err("FIXTURE: the probe response head is too large".into());
        }
    }
    let head = std::str::from_utf8(&head).map_err(at("FIXTURE: read the probe response head"))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .filter(|line| line.starts_with("HTTP/1.1 "))
        .ok_or("FIXTURE: the probe did not return an HTTP/1.1 status line")?;
    let mut length = 0;
    for (name, value) in lines.filter_map(|line| line.split_once(':')) {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("FIXTURE: the probe response used transfer encoding".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = value
                .trim()
                .parse::<usize>()
                .map_err(at("FIXTURE: read the probe response content length"))?;
        }
    }
    if stream.read_exact(&mut vec![0; length]).await.is_err() {
        return Ok(Answer::Ended);
    }
    Ok(Answer::Served(status.to_owned()))
}

async fn open_sync(mesh: &Machines) -> TestResult<(Box<dyn MeshConnection>, Box<dyn MeshDuplex>)> {
    mesh.grant(A, B, &[SYNC_ALPN])?;
    mesh.grant(B, A, &[SYNC_ALPN])?;
    let transport = mesh.machine(A).served.transport()?;
    let connection = tokio::time::timeout(
        DIAL_WITHIN,
        transport.dial(mesh.machine(B).device.machine, SYNC_ALPN),
    )
    .await
    .map_err(|_| "A's dial of B on sync hung")?
    .map_err(at("A dials B on sync"))?;
    let stream = tokio::time::timeout(DIAL_WITHIN, connection.open_duplex())
        .await
        .map_err(|_| "A's open of a sync stream to B hung")?
        .map_err(at("A opens a sync stream to B"))?;
    Ok((connection, stream))
}

async fn ends_within(stream: &mut Box<dyn MeshDuplex>) -> TestResult<bool> {
    match tokio::time::timeout(CLOSE_WITHIN, async {
        loop {
            match ask(stream).await? {
                Answer::Served(_status) => {
                    // testkit-lint: allow(sleep) the poll interval; the listener signals nothing the dialer can await
                    tokio::time::sleep(POLL).await;
                }
                Answer::Ended => return Ok(true),
            }
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Ok(false),
    }
}

#[test]
fn a_machine_whose_sync_grant_is_withdrawn_loses_its_open_sync_connection_at_once() -> TestResult {
    on_engine_stack(withdrawing_a_sync_grant_closes_the_connection)
}

async fn withdrawing_a_sync_grant_closes_the_connection() -> TestResult {
    let mesh = Machines::start(2).await?;
    let (connection, mut stream) = open_sync(&mesh).await?;
    assert!(
        matches!(ask(&mut stream).await?, Answer::Served(_)),
        "B serves A's open sync stream before the revoke"
    );
    mesh.revoke(B, A, &[SYNC_ALPN])?;
    assert!(
        ends_within(&mut stream).await?,
        "A's open sync stream still served {CLOSE_WITHIN:?} after B withdrew A's sync grant"
    );
    let reopened = tokio::time::timeout(CLOSE_WITHIN, connection.open_duplex())
        .await
        .map_err(|_| "a stream on the closed connection hung")?;
    assert!(
        reopened.is_err(),
        "B closed A's whole sync connection, not only its stream"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_machine_revoked_outright_loses_its_open_sync_connection_at_once() -> TestResult {
    on_engine_stack(revoking_a_machine_outright_closes_the_connection)
}

async fn revoking_a_machine_outright_closes_the_connection() -> TestResult {
    let mesh = Machines::start(2).await?;
    let (connection, mut stream) = open_sync(&mesh).await?;
    assert!(
        matches!(ask(&mut stream).await?, Answer::Served(_)),
        "B serves A's open sync stream before the revoke"
    );
    mesh.machine(B)
        .device
        .vault
        .revoke_mesh_machine(&test_host_issuer(), mesh.machine(A).device.machine)
        .map_err(at("B revokes A outright"))?;
    assert!(
        ends_within(&mut stream).await?,
        "A's open sync stream still served {CLOSE_WITHIN:?} after B revoked A outright"
    );
    let reopened = tokio::time::timeout(CLOSE_WITHIN, connection.open_duplex())
        .await
        .map_err(|_| "a stream on the closed connection hung")?;
    assert!(
        reopened.is_err(),
        "B closed A's whole sync connection, not only its stream"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_revoke_of_another_machine_leaves_an_open_sync_connection_serving() -> TestResult {
    on_engine_stack(revoking_another_machine_leaves_the_connection_serving)
}

async fn revoking_another_machine_leaves_the_connection_serving() -> TestResult {
    let mesh = Machines::start(3).await?;
    let (_connection, mut stream) = open_sync(&mesh).await?;
    mesh.grant(B, C, &[SYNC_ALPN])?;
    assert!(
        matches!(ask(&mut stream).await?, Answer::Served(_)),
        "B serves A's open sync stream before the revoke"
    );
    mesh.revoke(B, C, &[SYNC_ALPN])?;
    assert!(
        !mesh
            .machine(B)
            .device
            .admits(&mesh.machine(C).device, SYNC_ALPN)?,
        "FIXTURE: B withdrew C's sync grant"
    );
    // testkit-lint: allow(sleep) B's listener signals nothing when it has judged a notice; the test gives it the time to over-close
    tokio::time::sleep(SETTLE).await;
    for _ in 0..2 {
        assert!(
            matches!(ask(&mut stream).await?, Answer::Served(_)),
            "A's open sync stream still serves after B revoked C"
        );
    }
    mesh.stop().await;
    Ok(())
}
