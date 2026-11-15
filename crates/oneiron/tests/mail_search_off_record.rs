//! ARCH-0063 #searched-mail (UNBUILT-01): mail that a search finds inside
//! an off-record conversation "stays in the session overlay and is dropped
//! at close". The session reads the found message while it lasts, a second
//! search in it reads the overlay and fetches nothing again, and base never
//! holds the message, before close or after.
//!
//! A room's stretch is the one exception (UNBUILT-01-ROOM-READERS): its
//! other members would read the hits, so a search there is refused before
//! the provider is asked, and nothing is fetched or kept, until the owner
//! allows mail search in that room (`mail.search.in_room`, off by default;
//! owner 16 Nov 00:44). Then the room's stretch keeps the hits as a solo one
//! does, and every member of the room reads them until close.
//!
//! Red on origin/main: no search entry takes a session, so every hit lands
//! in base, whatever session the search ran in, a room's included. The two
//! room-key tests are red on #8356's head with the Setting primitive merged:
//! no such key, and a room's stretch is refused whatever the owner set.
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
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::test_doors::mail_search_off_record::{
    CountingSearchWire, SearchMailbox, base_holds_found_message, connect_search_mailbox,
    search_in_session, session_reads_found_message,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

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
    assert_eq!(
        first.landed, 1,
        "FIXTURE: the first search keeps the message: {first:?}"
    );
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

#[test]
fn search_in_a_room_stretch_is_refused_and_keeps_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = fresh_vault(directory.path())?;
    let now = now_sec();
    let mailbox = connect_search_mailbox(&vault, now)?;
    let wire = CountingSearchWire::new(now);
    let owner = vault.ensure_embedded_owner_actor()?;
    let room = EntityId::now();
    vault.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![owner],
            ..Default::default()
        },
        WriteActor::new(owner, EdgeActorClass::Human),
        vault.now_recorded_at(),
    )?;
    let session = vault.off_record_session_vault().enter_in_room_as(
        "sess-mail-search-room",
        OffRecordBackendClass::Local,
        room,
        &mailbox.owner,
    )?;

    let searched = search_in_session(&vault, &mailbox, &session, &wire);
    assert!(
        searched.is_err(),
        "a search inside a room's stretch was not refused: {searched:?}"
    );
    assert_eq!(
        (wire.searches(), wire.whole_reads()),
        (0, 0),
        "a refused search in a room's stretch asked the provider"
    );
    assert!(
        !session_reads_found_message(&vault, &mailbox, &session)?,
        "a refused search in a room's stretch kept the message where the room reads it"
    );
    assert!(
        !base_holds_found_message(&vault, &mailbox)?,
        "a refused search in a room's stretch kept the message in base"
    );
    session.close()?;
    Ok(())
}

/// A PERSON: a member of a room other than the owner.
fn person(vault: &Vault) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )?;
    Ok(id)
}

/// A group room of the owner and `others`.
fn group_room(vault: &Vault, others: &[EntityId]) -> Result<EntityId, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    let room = EntityId::now();
    let mut member_ids = vec![owner];
    member_ids.extend_from_slice(others);
    vault.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids,
            ..Default::default()
        },
        WriteActor::new(owner, EdgeActorClass::Human),
        vault.now_recorded_at(),
    )?;
    Ok(room)
}

/// The owner allows mail search in `room`: `mail.search.in_room` on at the
/// room conversation's thread scope.
fn allow_mail_search_in(vault: &Vault, mailbox: &SearchMailbox, room: EntityId) -> TestResult {
    let outcome = vault.set_setting(
        SettingCaller::Owner(&mailbox.owner),
        SetSetting {
            key: "mail.search.in_room".to_owned(),
            item: None,
            scope: SettingScope::Thread(room),
            mode: SettingMode::Value,
            value: Some(serde_json::Value::Bool(true)),
            expected_revision: None,
            why: None,
            check_in_ref: None,
        },
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "FIXTURE: the owner's change did not apply: {outcome:?}"
    );
    Ok(())
}

#[test]
fn a_room_opened_to_mail_search_keeps_hits_its_members_read_until_close() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = fresh_vault(directory.path())?;
    let now = now_sec();
    let mailbox = connect_search_mailbox(&vault, now)?;
    let wire = CountingSearchWire::new(now);
    let member = person(&vault)?;
    let room = group_room(&vault, &[member])?;
    allow_mail_search_in(&vault, &mailbox, room)?;
    let session = vault.off_record_session_vault().enter_in_room_as(
        "sess-mail-search-room-allowed",
        OffRecordBackendClass::Local,
        room,
        &mailbox.owner,
    )?;

    let report = search_in_session(&vault, &mailbox, &session, &wire)?;
    assert_eq!(
        (report.found, report.landed, report.skipped),
        (1, 1, 0),
        "a search in a room whose owner allowed mail search did not keep its hit: {report:?}"
    );
    assert!(
        session_reads_found_message(&vault, &mailbox, &session)?,
        "the room's stretch does not read the message its search found"
    );
    let as_member = vault.off_record_session_vault().bind_in_room(
        "sess-mail-search-room-allowed",
        room,
        member,
    )?;
    assert!(
        session_reads_found_message(&vault, &mailbox, &as_member)?,
        "a member of the room does not read the message the owner's search kept there"
    );
    drop(as_member);
    assert!(
        !base_holds_found_message(&vault, &mailbox)?,
        "a search inside a room's stretch landed its hit in base"
    );

    session.close()?;
    assert!(
        !base_holds_found_message(&vault, &mailbox)?,
        "the found message is in base after the room's stretch closed"
    );
    Ok(())
}

#[test]
fn mail_search_allowed_in_another_room_leaves_this_room_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    let vault = fresh_vault(directory.path())?;
    let now = now_sec();
    let mailbox = connect_search_mailbox(&vault, now)?;
    let wire = CountingSearchWire::new(now);
    let allowed = group_room(&vault, &[])?;
    let room = group_room(&vault, &[])?;
    allow_mail_search_in(&vault, &mailbox, allowed)?;
    let session = vault.off_record_session_vault().enter_in_room_as(
        "sess-mail-search-other-room",
        OffRecordBackendClass::Local,
        room,
        &mailbox.owner,
    )?;

    let searched = search_in_session(&vault, &mailbox, &session, &wire);
    assert!(
        searched.is_err(),
        "a search in a room the owner did not open to mail search was not refused: {searched:?}"
    );
    assert_eq!(
        (wire.searches(), wire.whole_reads()),
        (0, 0),
        "a refused search in a room's stretch asked the provider"
    );
    assert!(
        !session_reads_found_message(&vault, &mailbox, &session)?,
        "a refused search in a room's stretch kept the message where the room reads it"
    );
    assert!(
        !base_holds_found_message(&vault, &mailbox)?,
        "a refused search in a room's stretch kept the message in base"
    );
    session.close()?;
    Ok(())
}
