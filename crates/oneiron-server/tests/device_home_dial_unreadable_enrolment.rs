#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! FIX-LIST [HOME-SELF-MARK-STALE-AS-DEVICE], case 2: a machine whose
//! enrolment record is there but does not read is still a device of its home.
//!
//! Serve asks `device_sync::dials_home` (a managed vault's coordinator
//! `dials_home_managed`) before its AI host attaches: a host that dials a home
//! claims no home of its own, declares no candidacy and marks no full copy
//! (`ai_host/workers.rs` `served_without_dreamer`). Its link reads the same
//! record (`device_sync/dial.rs` `Dial::resolve_for_vault`) and refuses to
//! configure on one that does not read. The dial question read such a record
//! as no enrolment, so the machine served as a home and marked its own copy
//! held, which the standby peer order and the MACRO election rank.
//!
//! Each test builds the enrolled device the Mac app holds
//! (`embedded_peer_fixture::enrolled_device`: an enrolment record and no
//! `[device_sync]` section). A record that does not parse, and one that parses
//! but does not validate, still dial a home (red at main 35dd01df2123 with the
//! door alone: both answer false); a readable record dials it, and with no
//! record the machine dials none (green at both heads).
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! device_home_dial_unreadable_enrolment`.

use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::test_doors::device_home_dial::{
    dials_home, dials_home_managed, enrolment_record,
};
use oneiron_server::test_doors::embedded_peer_fixture::enrolled_device;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Runs `test` on a thread with the engine's stack, inside a multi-thread
/// runtime with that stack, as the server's binary runs.
fn on_engine_stack(test: fn() -> TestResult) -> TestResult {
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            let _entered = runtime.enter();
            test().map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        // A failed assertion fails the test with its own message.
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// The enrolled device's record holds `bytes` in place of what `oneiron
/// device enrol` wrote; both dial questions are then asked.
fn dials_with_record(bytes: &[u8]) -> TestResult<(bool, bool)> {
    let dir = tempfile::tempdir()?;
    let (vault, config) = enrolled_device(dir.path())?;
    let record = enrolment_record(&config, &vault)?;
    assert!(
        record.is_file(),
        "the fixture writes its enrolment record where serve reads it"
    );
    assert!(
        dials_home(&config, &vault),
        "the fixture's readable enrolment dials its home"
    );
    std::fs::write(&record, bytes)?;
    Ok((
        dials_home(&config, &vault),
        dials_home_managed(&config, &vault),
    ))
}

#[test]
fn an_enrolment_record_that_does_not_parse_still_dials_a_home() -> TestResult {
    on_engine_stack(|| {
        let (plain, managed) = dials_with_record(b"not a device enrolment\n")?;
        assert!(
            plain,
            "plain serve took a machine whose enrolment record does not parse for a home"
        );
        assert!(
            managed,
            "a managed vault took a machine whose enrolment record does not parse for a home"
        );
        Ok(())
    })
}

#[test]
fn an_enrolment_record_that_does_not_validate_still_dials_a_home() -> TestResult {
    on_engine_stack(|| {
        // Parses as an enrolment; its home's sync node id 0 fails validation.
        let record = serde_json::json!({
            "home_machine": oneiron::EntityId::now().to_hex(),
            "home_node_id": 0,
            "home_url": "ws://127.0.0.1:9/ws",
        });
        let (plain, managed) = dials_with_record(&serde_json::to_vec_pretty(&record)?)?;
        assert!(
            plain,
            "plain serve took a machine whose enrolment record does not validate for a home"
        );
        assert!(
            managed,
            "a managed vault took a machine whose enrolment record does not validate for a home"
        );
        Ok(())
    })
}

#[test]
fn a_readable_enrolment_record_dials_its_home() -> TestResult {
    on_engine_stack(|| {
        let dir = tempfile::tempdir()?;
        let (vault, config) = enrolled_device(dir.path())?;
        assert!(dials_home(&config, &vault));
        assert!(dials_home_managed(&config, &vault));
        Ok(())
    })
}

#[test]
fn a_machine_with_no_enrolment_record_dials_no_home() -> TestResult {
    on_engine_stack(|| {
        let dir = tempfile::tempdir()?;
        let (vault, config) = enrolled_device(dir.path())?;
        std::fs::remove_file(enrolment_record(&config, &vault)?)?;
        assert!(!dials_home(&config, &vault));
        assert!(!dials_home_managed(&config, &vault));
        Ok(())
    })
}
