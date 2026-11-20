//! FIX FENCE-ERASE-STAND-IN-DIGESTS-RAW-VALUE: an erase keeps each bridge
//! request's stand-in identity (FIX 6534), the digest of the request with
//! each handle the side-row wall placed read as one stand-in. A scrub of a
//! stored row reads the handle the wall placed for a passphrase custody
//! holds. A put fence erases a record before the wall reads it, so its
//! request still held the passphrase as written, and the stand-in identity
//! digested it as written: anyone holding the erased row who could rebuild
//! the rest of the request could test a guessed passphrase against it.
//!
//! An erase that reads custody now reads each value base custody holds as
//! the stand-in too, as the wall reads that value's handle: a fenced row and
//! a scrubbed row of the identical call keep one stand-in identity, and a
//! guess read as written no longer meets it.
//!
//! Each case stores the call writing a passphrase custody holds, for a new
//! agent, through the wall; deletes the agent, which erases that row; then
//! puts the identical call in a second run, in the vault or on a room's
//! route, where the put fence erases it in its writer.
//!
//! Blind review round 1 of #9692 found two more places the passphrase was
//! digested as written: a note held as a MessagePack body, which the wall
//! opens and the admission form read as written, and a pinned entry's
//! resume page, which listed each call's identity read off its row before
//! the wall and the fence.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fenced_erase_stand_in_identity`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::off_record::{OffRecordBackendClass, OffRecordSession};
use oneiron::test_doors::erased_request_identity::{
    note_call_identity_as_written, resume_page_request_digest, room_stored_call_erased,
    room_stored_call_identity, room_stored_call_is, store_note_body_across_delete,
    store_note_call_across_delete, store_note_call_with_resume, stored_body_call_is,
    stored_call_erased, stored_call_identity, stored_call_is,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Passphrases no shape rule reads as a secret, two custody records hold.
const HELD_PASSPHRASE: &str = "winter orchard notebook lantern";
const OTHER_HELD_PASSPHRASE: &str = "autumn meadow candle ribbon";

/// A vault whose custody holds each passphrase in its own record.
fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    vault.register_test_secret(
        "orchard passphrase",
        HELD_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;
    vault.register_test_secret(
        "meadow passphrase",
        OTHER_HELD_PASSPHRASE.as_bytes(),
        Vec::new(),
        1,
    )?;
    Ok((directory, vault))
}

fn words(value: &str) -> String {
    format!("unlock the archive with {value}")
}

/// The call writing the held passphrase, stored and then erased by its
/// agent's delete, and the identical call put after the delete, in the vault
/// or, with `session`, on its room's route: the agent, the scrubbed run and
/// the fenced run.
fn scrubbed_and_fenced(
    vault: &Vault,
    session: Option<&OffRecordSession<'_>>,
) -> TestResult<[EntityId; 3]> {
    let calls = store_note_call_across_delete(vault, session, &words(HELD_PASSPHRASE))?;
    assert!(
        stored_call_erased(vault, calls[1])?,
        "the agent's delete erases the stored call"
    );
    let fenced = match session {
        Some(session) => room_stored_call_erased(session, calls[2])?,
        None => stored_call_erased(vault, calls[2])?,
    };
    assert!(fenced, "the put fence erases the call of a gone agent");
    Ok(calls)
}

/// The vault's put fence keeps the stand-in identity the scrub of the
/// identical stored call keeps. Red on the base: the fence digested the
/// passphrase as written, the scrub the handle the wall placed for it.
#[test]
fn a_vault_fenced_call_keeps_the_stand_in_identity_a_scrub_keeps() -> TestResult {
    let (_directory, vault) = vault()?;
    let [_, scrubbed, fenced] = scrubbed_and_fenced(&vault, None)?;
    assert_eq!(
        stored_call_identity(&vault, fenced)?,
        stored_call_identity(&vault, scrubbed)?
    );
    Ok(())
}

/// A room's put fence keeps the stand-in identity the scrub of the identical
/// stored call keeps. Red on the base, as above.
#[test]
fn a_rooms_fenced_call_keeps_the_stand_in_identity_a_scrub_keeps() -> TestResult {
    let (_directory, vault) = vault()?;
    let session = vault
        .off_record_session_vault()
        .enter("sess-fenced-stand-in", OffRecordBackendClass::Local)?;
    let [_, scrubbed, fenced] = scrubbed_and_fenced(&vault, Some(&session))?;
    assert_eq!(
        room_stored_call_identity(&session, fenced)?,
        stored_call_identity(&vault, scrubbed)?
    );
    Ok(())
}

/// A guess of the passphrase, read as written with no custody read in
/// reach, does not meet a fenced row by its stand-in identity, in the vault
/// or in a room. Red on the base: the fenced row's stand-in identity was the
/// digest of the request holding the passphrase as written, so the guess
/// met it.
#[test]
fn a_guess_read_as_written_does_not_meet_a_fenced_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, _, fenced] = scrubbed_and_fenced(&vault, None)?;
    assert!(
        !stored_call_is(&vault, [agent, fenced], &words(HELD_PASSPHRASE), false)?,
        "a guess meets the vault's fenced row"
    );
    let session = vault
        .off_record_session_vault()
        .enter("sess-fenced-guess", OffRecordBackendClass::Local)?;
    let [agent, _, fenced] = scrubbed_and_fenced(&vault, Some(&session))?;
    assert!(
        !room_stored_call_is(
            &vault,
            &session,
            [agent, fenced],
            &words(HELD_PASSPHRASE),
            false
        )?,
        "a guess meets the room's fenced row"
    );
    Ok(())
}

/// Guard: the call made again with the passphrase the fenced row held meets
/// it, and another passphrase custody holds is another call, read with
/// custody in reach, on the base and the head.
#[test]
fn a_fenced_call_made_again_meets_its_row_by_its_custody_identity() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, _, fenced] = scrubbed_and_fenced(&vault, None)?;
    assert!(stored_call_is(
        &vault,
        [agent, fenced],
        &words(HELD_PASSPHRASE),
        true
    )?);
    assert!(!stored_call_is(
        &vault,
        [agent, fenced],
        &words(OTHER_HELD_PASSPHRASE),
        true
    )?);
    let session = vault
        .off_record_session_vault()
        .enter("sess-fenced-guard", OffRecordBackendClass::Local)?;
    let [agent, _, fenced] = scrubbed_and_fenced(&vault, Some(&session))?;
    assert!(room_stored_call_is(
        &vault,
        &session,
        [agent, fenced],
        &words(HELD_PASSPHRASE),
        true
    )?);
    assert!(!room_stored_call_is(
        &vault,
        &session,
        [agent, fenced],
        &words(OTHER_HELD_PASSPHRASE),
        true
    )?);
    Ok(())
}

/// The note `text` as a MessagePack map body, `{"text": text}`: bytes that
/// are no UTF-8 text, which the wall opens as a body of its own.
fn messagepack_body(text: &str) -> TestResult<Vec<u8>> {
    let mut body = vec![0x81, 0xa4];
    body.extend_from_slice(b"text");
    body.push(0xd9);
    body.push(u8::try_from(text.len())?);
    body.extend_from_slice(text.as_bytes());
    Ok(body)
}

/// The call writing the held passphrase inside a MessagePack body, stored
/// and then erased by its agent's delete, and the identical call put after
/// the delete in the vault: the agent, the scrubbed run and the fenced run.
fn scrubbed_and_fenced_body(vault: &Vault) -> TestResult<([EntityId; 3], Vec<u8>)> {
    let body = messagepack_body(&words(HELD_PASSPHRASE))?;
    let calls = store_note_body_across_delete(vault, &body)?;
    assert!(
        stored_call_erased(vault, calls[1])?,
        "the delete erases the stored call"
    );
    assert!(
        stored_call_erased(vault, calls[2])?,
        "the put fence erases the call"
    );
    Ok((calls, body))
}

/// The vault's put fence keeps the stand-in identity the scrub of the
/// identical stored call keeps when the passphrase sits inside a body of its
/// own. Red on the PR's first head: the fence read the body as written, the
/// scrub the handle the wall placed in it.
#[test]
fn a_fenced_call_with_a_body_keeps_the_stand_in_identity_a_scrub_keeps() -> TestResult {
    let (_directory, vault) = vault()?;
    let ([_, scrubbed, fenced], _) = scrubbed_and_fenced_body(&vault)?;
    assert_eq!(
        stored_call_identity(&vault, fenced)?,
        stored_call_identity(&vault, scrubbed)?
    );
    Ok(())
}

/// A guess of the passphrase inside the body, read as written with no
/// custody read in reach, does not meet the fenced row. Red on the PR's
/// first head: the stand-in identity digested the body as written.
#[test]
fn a_guess_read_as_written_does_not_meet_a_fenced_call_with_a_body() -> TestResult {
    let (_directory, vault) = vault()?;
    let ([agent, _, fenced], body) = scrubbed_and_fenced_body(&vault)?;
    assert!(
        !stored_body_call_is(&vault, [agent, fenced], &body, false)?,
        "a guess meets the fenced row"
    );
    Ok(())
}

/// Guard: the call made again with the passphrase inside the body meets the
/// scrubbed row and the fenced row with custody in reach, by the custody
/// identity each keeps, and a body with another passphrase custody holds is
/// another call, on both heads.
#[test]
fn a_call_with_a_body_made_again_meets_its_erased_rows_with_custody() -> TestResult {
    let (_directory, vault) = vault()?;
    let ([agent, scrubbed, fenced], body) = scrubbed_and_fenced_body(&vault)?;
    let other = messagepack_body(&words(OTHER_HELD_PASSPHRASE))?;
    assert!(stored_body_call_is(&vault, [agent, fenced], &body, true)?);
    assert!(!stored_body_call_is(&vault, [agent, fenced], &other, true)?);
    assert!(
        stored_body_call_is(&vault, [agent, scrubbed], &body, true)?,
        "the call made again misses the scrubbed row"
    );
    assert!(!stored_body_call_is(
        &vault,
        [agent, scrubbed],
        &other,
        true
    )?);
    Ok(())
}

/// A pinned entry's resume page lists the identity of the call's row as the
/// wall stored it, never the digest of the passphrase as written. Red on
/// the PR's first head: the page listed the identity read off the row
/// before the wall.
#[test]
fn a_resume_page_lists_the_identity_of_the_stored_row() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, run] = store_note_call_with_resume(&vault, &words(HELD_PASSPHRASE), false)?;
    assert!(
        !stored_call_erased(&vault, run)?,
        "the agent's call is live"
    );
    let listed = resume_page_request_digest(&vault, run)?.ok_or("no resume page")?;
    assert_ne!(
        listed,
        note_call_identity_as_written(agent, &words(HELD_PASSPHRASE))?,
        "the page digests the passphrase as written"
    );
    assert_eq!(listed, stored_call_identity(&vault, run)?);
    Ok(())
}

/// A pinned entry's resume page of a call the put fence erased lists the
/// stand-in identity the erased row keeps. Red on the PR's first head, as
/// above.
#[test]
fn a_resume_page_of_a_fenced_call_lists_its_stand_in_identity() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, run] = store_note_call_with_resume(&vault, &words(HELD_PASSPHRASE), true)?;
    assert!(
        stored_call_erased(&vault, run)?,
        "the put fence erases the call"
    );
    let listed = resume_page_request_digest(&vault, run)?.ok_or("no resume page")?;
    assert_ne!(
        listed,
        note_call_identity_as_written(agent, &words(HELD_PASSPHRASE))?,
        "the page digests the passphrase as written"
    );
    assert_eq!(listed, stored_call_identity(&vault, run)?);
    Ok(())
}
