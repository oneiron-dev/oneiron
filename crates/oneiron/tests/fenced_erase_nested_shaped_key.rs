//! FIX REQUEST-IDENTITY-NESTED-SHAPED-KEY-AS-WRITTEN: an erase keeps each
//! bridge request's stand-in identity (FIX 6534), the digest of the request
//! in its admission form, where each secret the side-row wall places and
//! each handle it placed reads as one stand-in. The wall opens a member that
//! carries a body of its own (a MessagePack map held as bytes, such as an
//! encoded definition) and lifts a key a shape rule reads inside it. The
//! admission form read such a body as written. So a put fence, which erases
//! a request before the wall reads it, digested a key custody does not hold
//! as written there, while a scrub of the stored row digested the handle the
//! wall placed: the fenced row answered a guess of its own key, read with no
//! custody, and no other key of its shape. A replay that compares a stored
//! row with the call made again in memory missed it too.
//!
//! The admission form now reads each such body as the wall reads it. A row
//! an erase kept before this fix still meets its call: the compare tries
//! the form those rows were taken in once the new form misses (stored-data
//! rule: keep).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test fenced_erase_nested_shaped_key`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;

use oneiron::test_doors::erased_request_identity::{
    fenced_body_call_erased_before_is, store_note_bodies_across_delete, store_note_body,
    stored_body_call_admits_in_memory, stored_body_call_erased_before_is, stored_body_call_is,
    stored_call_erased, stored_call_identity,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Keys of one shape a shape rule reads as a secret. Custody holds none at
/// first: the wall lifts the first from a stored call, the put fence erases
/// the second before any wall reads it, and the third no call holds.
const LIFTED_KEY: &str = "AKIA1234567890123456";
const FENCED_KEY: &str = "AKIA1234567890123457";
const OTHER_KEY: &str = "AKIA1234567890123458";

fn vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open(directory.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    Ok((directory, vault))
}

/// The note writing `key` as a MessagePack map body, `{"text": ...}`: bytes
/// that are no UTF-8 text, which the wall opens as a body of its own.
fn body(key: &str) -> TestResult<Vec<u8>> {
    let text = format!("unlock the archive with {key}");
    let mut body = vec![0x81, 0xa4];
    body.extend_from_slice(b"text");
    body.push(0xd9);
    body.push(u8::try_from(text.len())?);
    body.extend_from_slice(text.as_bytes());
    Ok(body)
}

/// The call writing [`LIFTED_KEY`] in a body, stored through the wall and
/// erased by its agent's delete, and the call writing [`FENCED_KEY`] in a
/// body, put after the delete, which the put fence erases: the agent, the
/// scrubbed run and the fenced run.
fn scrubbed_and_fenced(vault: &Vault) -> TestResult<[EntityId; 3]> {
    let calls = store_note_bodies_across_delete(vault, [&body(LIFTED_KEY)?, &body(FENCED_KEY)?])?;
    assert!(
        stored_call_erased(vault, calls[1])?,
        "the agent's delete erases the stored call"
    );
    assert!(
        stored_call_erased(vault, calls[2])?,
        "the put fence erases the call of a gone agent"
    );
    Ok(calls)
}

/// The put fence keeps, for a key no custody record holds inside a body, the
/// stand-in identity a scrub keeps for the call whose key the wall lifted
/// there: one stand-in, whichever key. Red on the base: the fence digested
/// its key as written, the scrub the handle the wall placed.
#[test]
fn a_fenced_call_with_a_shaped_key_in_a_body_keeps_the_stand_in_identity_a_scrub_keeps()
-> TestResult {
    let (_directory, vault) = vault()?;
    let [_, scrubbed, fenced] = scrubbed_and_fenced(&vault)?;
    assert_eq!(
        stored_call_identity(&vault, fenced)?,
        stored_call_identity(&vault, scrubbed)?
    );
    Ok(())
}

/// A guess read with no custody in reach learns nothing of the key a fenced
/// row held inside a body: the row answers that key and another of its
/// shape alike. Red on the base: it met its own key, read as written, and
/// no other.
#[test]
fn a_fenced_call_with_a_shaped_key_in_a_body_answers_every_key_of_its_shape_alike() -> TestResult {
    let (_directory, vault) = vault()?;
    let [agent, _, fenced] = scrubbed_and_fenced(&vault)?;
    assert_eq!(
        stored_body_call_is(&vault, [agent, fenced], &body(FENCED_KEY)?, false)?,
        stored_body_call_is(&vault, [agent, fenced], &body(OTHER_KEY)?, false)?,
        "the fenced row tells its own key from another of its shape"
    );
    Ok(())
}

/// A replay that compares a stored call with the call made again in memory,
/// with no custody read in reach, reads the key the wall lifted from a body
/// and the key offered again in it as one stand-in. Red on the base: the
/// held body kept the handle as written and the offered body the key, and
/// the call drifted.
#[test]
fn a_stored_call_with_a_shaped_key_in_a_body_admits_its_call_in_memory() -> TestResult {
    let (_directory, vault) = vault()?;
    let lifted = body(LIFTED_KEY)?;
    let call = store_note_body(&vault, &lifted)?;
    assert!(
        !stored_call_erased(&vault, call[1])?,
        "the call is stored live"
    );
    assert!(stored_body_call_admits_in_memory(&vault, call, &lifted)?);
    Ok(())
}

/// Guard: a row a scrub erased before this fix, with no custody read in
/// reach, kept the handle the wall placed in the body as written in its
/// stand-in identity. It still meets the call made again with custody in
/// reach, and a key no record holds is another call, on the base and the
/// head.
#[test]
fn a_row_a_scrub_erased_before_meets_its_call_with_custody() -> TestResult {
    let (_directory, vault) = vault()?;
    let call = store_note_body(&vault, &body(LIFTED_KEY)?)?;
    assert!(stored_body_call_erased_before_is(
        &vault,
        call,
        &body(LIFTED_KEY)?,
        true
    )?);
    assert!(!stored_body_call_erased_before_is(
        &vault,
        call,
        &body(OTHER_KEY)?,
        true
    )?);
    Ok(())
}

/// Guard: a row a put fence erased before this fix kept the key no record
/// holds inside the body as written in its stand-in identity. It still
/// meets the call made again with that key, and another key of its shape
/// is another call, on the base and the head.
#[test]
fn a_row_a_fence_erased_before_meets_its_call() -> TestResult {
    let (_directory, vault) = vault()?;
    let agent = EntityId::now();
    let held = body(FENCED_KEY)?;
    assert!(fenced_body_call_erased_before_is(
        &vault,
        agent,
        [&held, &held],
        false
    )?);
    assert!(!fenced_body_call_erased_before_is(
        &vault,
        agent,
        [&held, &body(OTHER_KEY)?],
        false
    )?);
    Ok(())
}
