#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! An enrolled machine's binding may be granted every protocol the engine
//! serves, and only those (MESH-PAIRING-CEILING = A, Engine 25 Nov 01:1x).
//!
//! Enrolment mints the binding's pairing slip; every later grant
//! (`vault.mesh.set_alpn_grant`) must narrow it. The pairing covers the mesh
//! verb of each protocol in `SERVED_MESH_ALPNS`, so the owner can grant a
//! machine enrolled for sync the job protocols later, one at a time. A
//! protocol the engine does not serve is still refused: the grant check
//! stays exact.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mesh_pairing_ceiling`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use engine_stack::on_engine_stack;
use mesh_machines::{Machines, TestResult, home};
use oneiron::authority::MeshEnrolment;
use oneiron::job_workload::JOB_ALPN;
use oneiron::sync::mesh_path::SYNC_ALPN;
use oneiron_server::SERVED_MESH_ALPNS;

const A: usize = 0;
const B: usize = 1;

#[test]
fn an_enrolled_machine_can_be_granted_every_served_protocol_and_no_other() -> TestResult {
    on_engine_stack(enrolled_machine_takes_every_served_protocol)
}

async fn enrolled_machine_takes_every_served_protocol() -> TestResult {
    let mesh = Machines::start(2).await?;
    for alpn in SERVED_MESH_ALPNS {
        mesh.grant(B, A, &[alpn]).map_err(|error| {
            format!("B must grant A {}: {error}", String::from_utf8_lossy(alpn))
        })?;
    }
    let unserved: &[u8] = b"oneiron/not-served/1";
    assert!(
        mesh.grant(B, A, &[unserved]).is_err(),
        "a protocol the engine does not serve is outside every binding's ceiling"
    );
    mesh.stop().await;
    Ok(())
}

#[test]
fn a_machine_bound_under_a_narrower_ceiling_takes_the_served_one_when_it_re_enrols() -> TestResult {
    let home = home()?;
    // A binding made before this ruling: its pairing covers sync alone.
    let device = home.enrol_with(0x0a, &[SYNC_ALPN])?;
    assert!(
        home.grant(&device, JOB_ALPN).is_err(),
        "a sync-only binding cannot take the job grant"
    );

    // The owner re-enrols the machine with a new machine link: the binding
    // moves to the served ceiling, keeps its sync grant, and takes the job
    // grant.
    match home.re_enrol(&device, 0x0b, &SERVED_MESH_ALPNS)? {
        Some(MeshEnrolment::AlreadyGranted { machine, .. }) => {
            assert_eq!(machine, device.machine, "the same machine re-enrolled");
        }
        other => panic!("a re-enrolment keeps the standing sync grant: {other:?}"),
    }
    home.grant(&device, JOB_ALPN)?;
    Ok(())
}
