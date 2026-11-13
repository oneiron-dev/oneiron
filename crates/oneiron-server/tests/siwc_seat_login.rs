//! SEAT-PARK-MODEL-STEP-PATH, server leg: an SIWC offer's refusals name its model seat, and the
//! housekeeping tick restores a lapsed SIWC login's seat.
//!
//! 1. The offer's seat is the digest of its credential file's absolute path. A lapsed login (the
//!    vendor's 401 or 403, read as Auth) becomes `SeatSignedOut` on that seat, and a spent window
//!    names the seat. Spent credit, a rate limit and other refusals stay as they are.
//! 2. A Dreamer try parked on a lapsed SIWC login's seat (no reset) stays parked while the
//!    credential file is signed out: the tick opens it once on a change, fails and writes nothing,
//!    and does not open an unchanged file again. Once the CLI's sign-in rewrites the file, the
//!    next tick opens it, writes the seat Available (LoginRestored) at its generation, and the park
//!    resumes.
//!
//! Doors: `oneiron_server::test_doors::siwc_seat` and
//! `oneiron::test_doors::seat_park_model_step`, built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::dreamer_runner::{
    DreamerParkWait, DreamerRunnerStore, ModelSeatAvailability, ModelSeatSource,
};
use oneiron::llm::SpentKind;
use oneiron::test_doors::seat_park_model_step as core_doors;
use oneiron::{FatalLlmError, LlmError, RetryableLlmError, Vault, VaultConfig};
use oneiron_server::test_doors::siwc_seat as doors;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The credential file's name inside each test's own directory.
const CREDENTIAL_FILE: &str = "siwc-credential.json";

fn spent(kind: SpentKind, seat: Option<oneiron::EntityId>) -> LlmError {
    RetryableLlmError::QuotaSpent {
        kind,
        retry_after: Some(3_600),
        resets_at: Vec::new(),
        seat,
    }
    .into()
}

/// Case 1: the offer's refusals name its seat; every other refusal stays as it is.
#[test]
fn an_siwc_offers_lapsed_login_and_spent_window_name_its_seat() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join(CREDENTIAL_FILE);
    let seat = doors::siwc_offer_seat(&file)?;
    assert_eq!(
        seat,
        oneiron::dispatch_byoa::siwc_offer_seat_id(&std::path::absolute(&file)?)
            .map_err(|error| error.to_string())?,
        "the offer's seat is the digest of its credential file's absolute path"
    );
    assert_ne!(
        seat,
        doors::siwc_offer_seat(&dir.path().join("another-login.json"))?,
        "another credential file is another seat"
    );
    assert_eq!(
        doors::seat_refusal(seat, FatalLlmError::Auth.into()),
        LlmError::from(FatalLlmError::SeatSignedOut { seat }),
        "a failed login is the seat's lapsed login"
    );
    assert_eq!(
        doors::seat_refusal(seat, spent(SpentKind::Window, None)),
        spent(SpentKind::Window, Some(seat)),
        "a spent window names the seat"
    );
    assert_eq!(
        doors::seat_refusal(seat, spent(SpentKind::Credit, None)),
        spent(SpentKind::Credit, None),
        "spent credit names no seat"
    );
    let rate_limited: LlmError = RetryableLlmError::RateLimited {
        retry_after: Some(30),
        resets_at: Vec::new(),
    }
    .into();
    assert_eq!(
        doors::seat_refusal(seat, rate_limited.clone()),
        rate_limited,
        "a short rate limit stays the step's own retry"
    );
    assert_eq!(
        doors::seat_refusal(seat, FatalLlmError::ContentFiltered.into()),
        LlmError::from(FatalLlmError::ContentFiltered),
        "another refusal stays as it is"
    );
    Ok(())
}

/// Case 2: the tick restores a lapsed login's seat once the credential file is signed in again.
#[test]
fn a_rewritten_credential_file_wakes_the_lapsed_seat_park_at_the_next_tick() -> TestResult {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join(CREDENTIAL_FILE);
    doors::write_siwc_credential(&file, false)?;
    let seat = doors::siwc_offer_seat(&file)?;
    let vault_dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let attempt = core_doors::park_try_on_seat(&vault, seat, None, "siwc-lapsed-login", now)?;
    let store = DreamerRunnerStore::new(&vault);
    let park = store
        .parked_attempt(attempt)?
        .expect("the lapsed login's park");
    assert!(
        matches!(
            park.wait.as_ref().map(|wait| &wait.wait),
            Some(DreamerParkWait::Seat {
                seat: waited,
                generation: 1,
                reset_at_s: None,
            }) if *waited == seat
        ),
        "the try waits on the offer's seat at generation 1 with no reset"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let tick = doors::SiwcSeatTick::new(&file)?;

    // The CLI signs out again after the park: the next tick opens the changed file, the open
    // fails, and nothing is written.
    doors::write_siwc_credential(&file, false)?;
    assert_eq!(
        runtime.block_on(tick.run(&vault)),
        (1, 0),
        "a changed but signed-out file is opened once and restores nothing"
    );
    assert!(
        store.parked_attempt(attempt)?.is_some(),
        "the park stays while the login is lapsed"
    );
    assert_eq!(
        vault
            .model_seat_state(seat)?
            .expect("the seat's row")
            .availability,
        ModelSeatAvailability::Unavailable,
        "a failed open writes nothing"
    );
    assert_eq!(
        runtime.block_on(tick.run(&vault)),
        (0, 0),
        "an unchanged file is not opened again before the retry interval"
    );

    // The CLI's sign-in rewrites the file: the next tick restores the seat and the park resumes.
    doors::write_siwc_credential(&file, true)?;
    assert_eq!(
        runtime.block_on(tick.run(&vault)),
        (1, 1),
        "the rewritten signed-in file is opened and the seat restored"
    );
    assert!(
        store.parked_attempt(attempt)?.is_none(),
        "the restored login wakes the park"
    );
    let state = vault.model_seat_state(seat)?.expect("the seat's row");
    assert_eq!(
        state.availability,
        ModelSeatAvailability::Available,
        "the seat is available"
    );
    assert_eq!(
        state.source,
        ModelSeatSource::LoginRestored,
        "a restored login wrote it"
    );
    assert_eq!(
        state.generation, 1,
        "the write answers the park's generation"
    );
    assert_eq!(
        runtime.block_on(tick.run(&vault)),
        (0, 0),
        "an available seat is not opened"
    );
    Ok(())
}
