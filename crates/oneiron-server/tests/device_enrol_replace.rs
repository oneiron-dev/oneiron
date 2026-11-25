#![cfg(all(oneiron_test_support, feature = "mesh"))]
//! An enrolled machine enrols again with a new link only through `oneiron
//! device enrol --replace`, and keeps its enrolment until the new one is
//! stored (review r1 of #10417, P1 `device_sync/enrolment.rs:214`). The
//! owner re-enrols a machine so its home's binding moves to a pairing that
//! covers every protocol the engine serves (MESH-PAIRING-CEILING = A); the
//! command refused every enrolled machine before it reached the home.
//!
//! Each test builds the enrolled device the Mac app holds
//! (`embedded_peer_fixture::enrolled_device`). A link that does not parse
//! fails at the first step past the guard, before any request, so these
//! tests need no home.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! device_enrol_replace`.

use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::test_doors::device_enrolment::{enrol, enrolment_files, replace_enrolment};
use oneiron_server::test_doors::device_home_dial::dials_home;
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

#[test]
fn an_enrolled_machine_enrols_again_only_with_replace_and_keeps_its_enrolment_when_that_fails()
-> TestResult {
    on_engine_stack(|| {
        let dir = tempfile::tempdir()?;
        let (vault, config) = enrolled_device(dir.path())?;
        let (record, credential) = enrolment_files(&config, &vault)?;
        let before = (std::fs::read(&record)?, std::fs::read(&credential)?);

        let refused = enrol(&config, &vault, "not a pairing link", false)
            .err()
            .ok_or("an enrolled machine enrolled again without --replace")?;
        assert!(
            format!("{refused:#}").contains("already enrolled"),
            "without --replace an enrolled machine is refused at the guard: {refused:#}"
        );

        // With --replace the enrolment goes on to the link, whose parse is
        // the first step past the guard, before any request to a home.
        let failed = enrol(&config, &vault, "not a pairing link", true)
            .err()
            .ok_or("a link that does not parse enrolled the machine")?;
        assert!(
            format!("{failed:#}").contains("does not parse"),
            "with --replace an enrolled machine reaches its link: {failed:#}"
        );
        assert_eq!(
            (std::fs::read(&record)?, std::fs::read(&credential)?),
            before,
            "a re-enrolment that fails leaves the stored enrolment as it was"
        );
        assert!(
            dials_home(&config, &vault),
            "the machine still dials its home"
        );
        Ok(())
    })
}

#[test]
fn a_replaced_enrolment_holds_the_new_credential_beside_a_record_that_reads() -> TestResult {
    on_engine_stack(|| {
        let dir = tempfile::tempdir()?;
        let (vault, config) = enrolled_device(dir.path())?;
        let (record, credential) = enrolment_files(&config, &vault)?;
        let replacement = "v2.cred.replacement-slip.replacement-seed";
        replace_enrolment(&config, &vault, replacement)?;
        assert_eq!(
            std::fs::read_to_string(&credential)?,
            format!("{replacement}\n"),
            "the credential file holds the new credential"
        );
        assert!(record.is_file(), "the record stands beside it");
        assert!(
            dials_home(&config, &vault),
            "the replaced record reads, and the machine dials its home"
        );
        let staged = std::fs::read_dir(record.parent().ok_or("the record has no directory")?)?
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".new"))
            .count();
        assert_eq!(staged, 0, "no staged file is left beside the enrolment");
        Ok(())
    })
}
