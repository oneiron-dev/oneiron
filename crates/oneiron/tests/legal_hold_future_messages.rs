//! An owner's hold may name future messages until a set end (Ruling
//! L10-21-OWNER-FUTURE-MESSAGES = A, ARCH-0038 :320-321): each matching new
//! MESSAGE joins the hold's copy as it is written, until `until` or the lift.
//! A hold without `future_messages` captures nothing new, and the user's own
//! erase of such a message is never gated.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test legal_hold_future_messages`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::{LegalHoldFutureMessages, LegalHoldTarget, MessageSelector};
use oneiron::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::legal_hold::{
    OpenedHoldComponent, hold_dir, open_clone, prospective_standing,
};
use oneiron::verbs::{
    RecordEraseConfirmRequest, RecordEraseRequest, confirm_record_erase, preview_record_erase,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_store::witness_message_body::WitnessMessageEnvelope;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A device keystore with install signing on `vault`, and its embedded
/// owner's proof.
fn owner_on(vault: &Vault) -> TestResult<(EntityId, AuthenticatedOwner)> {
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .map_err(at("install signing"))?;
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(at("owner proof"))?;
    Ok((actor, owner))
}

/// The fixture clock's start, in recorded seconds.
const T0: u64 = 1_000_000;

/// An owned vault on a manual clock whose hold store lies outside its
/// directory, with the embedded owner's proof.
struct Fixture {
    _vault_dir: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    clock: Arc<ManualClock>,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn fixture() -> TestResult<Fixture> {
    let vault_dir = tempfile::tempdir()?;
    let store_dir = tempfile::tempdir()?;
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device().with_legal_hold_store(store_dir.path().to_path_buf());
    config.store_clock = clock.bundle();
    let vault = Vault::open_owned(vault_dir.path(), config).map_err(at("open owned"))?;
    let (actor, owner) = owner_on(&vault)?;
    Ok(Fixture {
        _vault_dir: vault_dir,
        _store_dir: store_dir,
        clock,
        vault,
        actor,
        owner,
    })
}

/// A PERSON row named `name` at a fresh id.
fn named_row(vault: &Vault, name: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name }))?;
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(1), 1, &body)
        .map_err(at("put a fixture row"))?;
    Ok(id)
}

/// A base MESSAGE row with `content` at a fresh id.
fn message_row(vault: &Vault, content: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = WitnessMessageEnvelope {
        author: "user",
        message_type: "text",
        content,
        parts: None,
        metadata: None,
        is_visible: true,
        order: 0,
    }
    .encode_body()
    .map_err(at("a fixture message"))?;
    vault
        .put_entity(&id, ENTITY_TYPE_MESSAGE, range(1), 1, &body)
        .map_err(at("put a fixture message"))?;
    Ok(id)
}

/// Whether `components` hold `message`'s row.
fn holds_row(components: &[OpenedHoldComponent], message: EntityId) -> bool {
    components.iter().any(|component| {
        component.source == *message.as_bytes()
            && component.family == "entities"
            && component.key == message.as_bytes().to_vec()
    })
}

/// A hold that names future messages copies a new message: the sealed copy
/// holds each new message's row, one flushed file per write, and the user's
/// own erase of it succeeds while the copy keeps it.
#[test]
fn a_hold_that_names_future_messages_copies_a_new_message() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let now = vault.now_recorded_at();
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            Some(LegalHoldFutureMessages {
                selector: MessageSelector::Vault,
                until: now + 3600,
            }),
        )
        .map_err(at("place with future messages"))?;
    let message = message_row(vault, "a future message")?;
    let second = message_row(vault, "a second future message")?;
    let components = open_clone(vault, hold.hold_id).map_err(at("open the sealed copy"))?;
    assert!(
        holds_row(&components, message),
        "the copy holds the new message's row"
    );
    assert!(
        holds_row(&components, second),
        "the copy holds the second message's row from its own file"
    );
    let memory = vault.memory(fixture.actor, EdgeActorClass::Human);
    let preview = preview_record_erase(&memory, RecordEraseRequest { record: message })
        .map_err(at("erase preview"))?;
    let outcome = confirm_record_erase(
        &memory,
        &fixture.owner,
        RecordEraseConfirmRequest {
            record: message,
            preview_digest: preview.preview_digest,
            also_same_bytes: false,
        },
    )
    .map_err(at("erase confirm"))?;
    assert!(
        outcome.first.receipt_ref.is_some(),
        "the confirmed erase wrote a receipt"
    );
    let components = open_clone(vault, hold.hold_id).map_err(at("reopen the sealed copy"))?;
    assert!(
        holds_row(&components, message),
        "the copy keeps the erased message's row"
    );
    Ok(())
}

/// A message after `until` joins no copy: past the term, a new MESSAGE is
/// absent from the sealed copy.
#[test]
fn a_message_after_until_joins_no_copy() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let now = vault.now_recorded_at();
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            Some(LegalHoldFutureMessages {
                selector: MessageSelector::Vault,
                until: now + 10,
            }),
        )
        .map_err(at("place with future messages"))?;
    fixture.clock.set(now + 20);
    let message = message_row(vault, "a late message")?;
    let components = open_clone(vault, hold.hold_id).map_err(at("open the sealed copy"))?;
    assert!(
        !components
            .iter()
            .any(|component| component.source == *message.as_bytes()),
        "the late message joins no copy"
    );
    Ok(())
}

/// A lifted hold captures no new message: after the lift no standing
/// remains and the hold directory is gone.
#[test]
fn a_lifted_hold_captures_no_new_message() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let now = vault.now_recorded_at();
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            Some(LegalHoldFutureMessages {
                selector: MessageSelector::Vault,
                until: now + 3600,
            }),
        )
        .map_err(at("place with future messages"))?;
    vault
        .lift_legal_hold(&fixture.owner, hold.hold_id)
        .map_err(at("lift the hold"))?;
    let _message = message_row(vault, "a message after lift")?;
    assert!(
        !prospective_standing(vault, hold.hold_id).map_err(at("the standing"))?,
        "no standing remains"
    );
    let dir = hold_dir(vault, hold.hold_id).map_err(at("the hold's directory"))?;
    assert!(!dir.exists(), "the hold directory is gone");
    Ok(())
}

/// A hold without future messages captures nothing new: the sealed copy
/// holds only the place capture's rows, and no standing exists.
#[test]
fn a_hold_without_future_messages_captures_nothing_new() -> TestResult {
    let fixture = fixture()?;
    let vault = &fixture.vault;
    let held = named_row(vault, "held record")?;
    let hold = vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(held)],
            None,
            None,
        )
        .map_err(at("place without future messages"))?;
    let _message = message_row(vault, "an unheld message")?;
    let components = open_clone(vault, hold.hold_id).map_err(at("open the sealed copy"))?;
    let sources: BTreeSet<[u8; 16]> = components
        .iter()
        .map(|component| component.source)
        .collect();
    assert_eq!(
        sources,
        BTreeSet::from([*held.as_bytes()]),
        "the copy holds only the place capture's rows"
    );
    assert!(
        !prospective_standing(vault, hold.hold_id).map_err(at("the standing"))?,
        "no standing exists"
    );
    Ok(())
}
