//! ARCH-0063 #searched-mail (UNBUILT-01): mail that a search finds inside
//! an off-record conversation "stays in the session overlay and is dropped
//! at close". The session reads the found message while it lasts, a second
//! search in it reads the overlay and fetches nothing again, and base never
//! holds the message, before close or after.
//!
//! Red on origin/main: no search entry takes a session, so every hit lands
//! in base, whatever session the search ran in.
//!
//! Reaches the crate-private session view and occurrence table through the
//! test door `oneiron::test_doors::mail_search_off_record`, so it runs only
//! under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test mail_search_off_record`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::test_doors::mail_search_off_record::{
    CountingSearchWire, base_holds_found_message, connect_search_mailbox, search_in_session,
    session_reads_found_message,
};
use oneiron::{Vault, VaultConfig};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A fresh vault opened owned, with the host's start a self-hosted server
/// makes: the process keystore, the vault rooted under the host, and this
/// install profiled.
fn fresh_vault(directory: &std::path::Path) -> Result<Vault, Box<dyn std::error::Error>> {
    let vault = Vault::open_owned(directory, VaultConfig::default())?;
    let _owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"mail search off record test host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    Ok(vault)
}

fn now_sec() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

#[test]
fn searched_mail_in_off_record_session_drops_at_close() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = fresh_vault(directory.path())?;
    let now = now_sec();
    let mailbox = connect_search_mailbox(&vault, now)?;
    let wire = CountingSearchWire::new(now);
    let session = vault
        .off_record_session_vault()
        .enter("sess-mail-search-close", OffRecordBackendClass::Local)?;

    let report = search_in_session(&vault, &mailbox, &session, &wire)?;
    assert_eq!(
        (report.found, report.landed, report.skipped),
        (1, 1, 0),
        "FIXTURE: the search finds and keeps the one message: {report:?}"
    );
    assert!(
        session_reads_found_message(&vault, &mailbox, &session)?,
        "the session does not read the message its search found"
    );
    assert!(
        !base_holds_found_message(&vault, &mailbox)?,
        "a search inside an off-record session landed its hit in base"
    );

    session.close()?;
    assert!(
        !base_holds_found_message(&vault, &mailbox)?,
        "the found message is in base after the session closed"
    );
    Ok(())
}

#[test]
fn second_search_in_session_reads_overlay_without_refetch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = fresh_vault(directory.path())?;
    let now = now_sec();
    let mailbox = connect_search_mailbox(&vault, now)?;
    let wire = CountingSearchWire::new(now);
    let session = vault
        .off_record_session_vault()
        .enter("sess-mail-search-twice", OffRecordBackendClass::Local)?;

    let first = search_in_session(&vault, &mailbox, &session, &wire)?;
    assert_eq!(first.landed, 1, "FIXTURE: the first search keeps the message: {first:?}");
    let second = search_in_session(&vault, &mailbox, &session, &wire)?;
    assert_eq!(
        (second.found, second.landed, second.same),
        (1, 0, 1),
        "the second search in the session did not read the message as held: {second:?}"
    );
    assert_eq!(
        wire.whole_reads(),
        1,
        "the second search in the session fetched the message again"
    );
    assert!(
        !base_holds_found_message(&vault, &mailbox)?,
        "the message the second search read as held is held in base, not in the session"
    );

    // Close drops it: a search in a new session finds nothing held and
    // fetches the message again.
    session.close()?;
    let later = vault
        .off_record_session_vault()
        .enter("sess-mail-search-later", OffRecordBackendClass::Local)?;
    let third = search_in_session(&vault, &mailbox, &later, &wire)?;
    assert_eq!(
        (third.landed, wire.whole_reads()),
        (1, 2),
        "a search after close read the closed session's message as held: {third:?}"
    );
    later.close()?;
    assert!(
        !base_holds_found_message(&vault, &mailbox)?,
        "the found message is in base after both sessions closed"
    );
    Ok(())
}
