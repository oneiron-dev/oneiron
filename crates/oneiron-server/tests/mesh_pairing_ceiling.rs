#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! An enrolled machine's binding may be granted every protocol the engine
//! serves, and only those (MESH-PAIRING-CEILING = A, Engine 25 Nov 01:1x).
//!
//! Enrolment mints the binding's pairing slip; every later grant
//! (`vault.mesh.set_alpn_grant`) must narrow it. The pairing covers the mesh
//! verb of each protocol in `SERVED_MESH_ALPNS`, so the owner can grant a
//! machine enrolled for sync the job protocols later, one at a time. A
//! protocol the engine does not serve is still refused: the grant check
//! stays exact. A machine bound under a narrower ceiling takes the served one
//! when it re-enrols, and the pairing it leaves stays standing for every
//! other replica that bound the machine on it. The re-enrolment names the
//! new pairing, and another replica's owner binds the machine again on it,
//! which keeps the grants that replica holds for it. A replica whose vault
//! was closed binds on a pairing the home minted meanwhile: a pairing's start
//! is its presence in the home's signed fold, never the replica's clock,
//! which stood still while the vault was closed (MESH-PAIRING-REPLICA-CLOCK
//! = A, Engine 25 Nov 11:55). Its end is judged no earlier than the newest
//! time a live owner signed into the fold, so such a replica stops admitting
//! on a pairing once it folds a home act signed past the pairing's expiry
//! (MESH-REPLICA-CLOCK-LIFETIMES = A, Engine 25 Nov 19:45).
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test mesh_pairing_ceiling`.

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/mesh_machines.rs"]
mod mesh_machines;

use std::time::Duration;

use engine_stack::on_engine_stack;
use mesh_machines::{Machines, TestResult, home};
use oneiron::authority::MeshEnrolment;
use oneiron::job_workload::JOB_ALPN;
use oneiron::sync::mesh_path::SYNC_ALPN;
use oneiron_server::SERVED_MESH_ALPNS;

const A: usize = 0;
const B: usize = 1;

/// How long a replica's vault stays closed: its clock then reads about this
/// far behind the home's.
const REPLICA_CLOSED: Duration = Duration::from_secs(5);

/// How long the short pairing of the expiry test runs, in seconds: well
/// inside [`REPLICA_CLOSED`], so the replica's own clock stays before its end.
const SHORT_PAIRING_SECS: u64 = 2;

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

#[test]
fn a_re_enrolment_leaves_standing_the_pairing_another_replica_binds_on() -> TestResult {
    let home = home()?;
    let a = home.enrol_with(0x0c, &[SYNC_ALPN])?;
    let b = home.enrol(0x0d)?;
    home.share_history(&[&a, &b])?;
    // B binds A on the pairing H minted for A, and grants it sync.
    b.bind_at(&a, Vec::new())?;
    b.grant(&a, SYNC_ALPN)?;
    assert!(b.admits(&a, SYNC_ALPN)?, "B admits A on sync");

    // A re-enrols on H: H's binding of A moves to a new pairing. B takes
    // H's history again, and its binding of A still stands on the first
    // pairing, which the re-enrolment leaves to its expiry.
    match home.re_enrol(&a, 0x0e, &SERVED_MESH_ALPNS)? {
        Some(MeshEnrolment::AlreadyGranted { machine, .. }) => {
            assert_eq!(machine, a.machine, "the same machine re-enrolled");
        }
        other => panic!("a re-enrolment keeps the standing sync grant: {other:?}"),
    }
    home.share_history(&[&b])?;
    assert!(
        b.admits(&a, SYNC_ALPN)?,
        "a re-enrolment on H never ends B's binding of A"
    );
    Ok(())
}

#[test]
fn another_replica_binds_a_re_enrolled_machine_again_on_its_new_pairing_and_keeps_its_grants()
-> TestResult {
    let home = home()?;
    let a = home.enrol_with(0x10, &[SYNC_ALPN])?;
    let b = home.enrol(0x11)?;
    home.share_history(&[&a, &b])?;
    b.bind_at(&a, Vec::new())?;
    b.grant(&a, SYNC_ALPN)?;

    // A re-enrols on H, whose answer names the pairing H's binding moved to.
    let pairing = match home.re_enrol(&a, 0x12, &SERVED_MESH_ALPNS)? {
        Some(MeshEnrolment::AlreadyGranted {
            re_paired: Some(pairing),
            ..
        }) => pairing,
        other => panic!("a re-enrolment that moves the binding names its new pairing: {other:?}"),
    };
    home.share_history(&[&b])?;
    assert!(
        b.grant(&a, JOB_ALPN).is_err(),
        "B's binding of A still stands on A's first pairing, which covers sync alone"
    );
    assert!(
        b.bind_at(&a, Vec::new()).is_err(),
        "a second bind on the pairing the binding stands on moves nothing"
    );

    // B's owner binds A again on the new pairing: B's binding moves to it,
    // keeps its sync grant, and takes the job grant.
    b.bind_on(&a, Vec::new(), pairing)?;
    assert!(
        b.admits(&a, SYNC_ALPN)?,
        "a re-bind keeps the grants B holds for A"
    );
    b.grant(&a, JOB_ALPN)?;
    assert!(b.admits(&a, JOB_ALPN)?, "B admits A on the job protocol");
    Ok(())
}

#[test]
fn a_replica_whose_vault_was_closed_binds_a_pairing_the_home_minted_meanwhile() -> TestResult {
    let home = home()?;
    let a = home.enrol_with(0x10, &[SYNC_ALPN])?;
    let b = home.enrol(0x11)?;
    home.share_history(&[&a, &b])?;
    b.bind_at(&a, Vec::new())?;
    b.grant(&a, SYNC_ALPN)?;

    // B's vault is closed for a while. Its authority clock stops there and
    // resumes from its floor when the vault opens again, so B reads behind H.
    let b = b.reopened_after(REPLICA_CLOSED)?;
    let pairing = match home.re_enrol(&a, 0x13, &SERVED_MESH_ALPNS)? {
        Some(MeshEnrolment::AlreadyGranted {
            re_paired: Some(pairing),
            ..
        }) => pairing,
        other => panic!("a re-enrolment that moves the binding names its new pairing: {other:?}"),
    };
    home.share_history(&[&b])?;

    // H minted the new pairing at a second B's clock has not reached. B
    // binds A on it all the same, and keeps the grant it holds for A.
    b.bind_on(&a, Vec::new(), pairing)?;
    assert!(
        b.admits(&a, SYNC_ALPN)?,
        "a replica behind the home keeps its grants on the new pairing"
    );
    b.grant(&a, JOB_ALPN)?;
    assert!(b.admits(&a, JOB_ALPN)?, "B admits A on the job protocol");
    Ok(())
}

#[test]
fn a_replica_behind_the_home_ends_a_pairing_at_the_newest_time_the_home_signed() -> TestResult {
    let home = home()?;
    let b = home.enrol(0x11)?;
    // B's vault is closed for a while: its clock then reads about
    // REPLICA_CLOSED behind H's, longer than the pairing below runs.
    let b = b.reopened_after(REPLICA_CLOSED)?;
    home.limit_pairings(SHORT_PAIRING_SECS)?;
    let a = home.enrol_with(0x10, &[SYNC_ALPN])?;
    let expires_at = home.pairing_expiry(&a)?;
    home.share_history(&[&a, &b])?;

    // No time H signed has reached the pairing's end: B judges it on its own
    // clock, as before, and binds and admits A.
    b.bind_at(&a, Vec::new())?;
    b.grant(&a, SYNC_ALPN)?;
    assert!(
        b.admits(&a, SYNC_ALPN)?,
        "with no home act signed past the pairing's end, B admits A on it"
    );

    // H signs an act once its own clock has passed the pairing's end, and B
    // folds it while B's own clock still reads before that end.
    home.sign_act_from(expires_at)?;
    home.share_history(&[&b])?;
    assert!(
        b.vault.capability_slip_now()? < expires_at,
        "FIXTURE: B's own clock still reads before the pairing's end"
    );
    assert!(
        !b.admits(&a, SYNC_ALPN)?,
        "B ends H's pairing at the newest time H signed, not at its own clock"
    );
    assert!(
        b.bind_at(&a, Vec::new()).is_err(),
        "B no longer binds A on the ended pairing"
    );
    Ok(())
}
