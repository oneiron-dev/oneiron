//! UC-05 PR 2b: an embedded handle answers asks as this install's owner
//! device (`OneironClient::as_owner_device`). A code consent ask refuses a
//! word with no owner proof (PR 2); on the owner-device handle each word
//! carries the proof the owner key this install holds mints for it. The two
//! cases the Engine named (16 Nov 16:11): a handle on an install with no
//! enrolled owner key refuses `owner_key_required`, and the same handle
//! proves once the owner enrols the key.
//!
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-remote --all-features --test owner_device_answer`: the test doors
//! that raise the ask and open the device vault exist only under that flag.
#![cfg(oneiron_test_support)]

use oneiron::memory::MemoryError;
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::task_verb::sdk::TaskAnswerRequest;
use oneiron::task_verb::{TaskAskHandle, TaskAskOptionId, TaskAskWord};
use oneiron::test_doors::ask_answer_proof::mint_code_consent_ask;
use oneiron::test_doors::owner_device_answer::{OwnerDeviceVault, open_owner_device_vault};
use oneiron::{EntityId, TimeRange};
use oneiron_remote::{OneironClient, OpenOptions};

/// The stable reason code of the owner key refusal
/// (`oneiron::error::OWNER_KEY_REQUIRED`).
const OWNER_KEY_REQUIRED: &str = "owner_key_required";

/// A hosted device vault with its embedded owner, an embedded handle
/// attached to it, and a code consent ask that asks the owner. The handle
/// drops before the vault, and the vault before its directory.
struct Fixture {
    client: OneironClient,
    device: OwnerDeviceVault,
    handle: TaskAskHandle,
    _dir: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("a tempdir");
    let device = open_owner_device_vault(dir.path()).expect("the hosted device vault");
    let client = OneironClient::attach(dir.path(), device.vault.clone(), &OpenOptions::default())
        .expect("an embedded handle on the device vault");
    assert_eq!(
        client.actor_ref().expect("the handle's actor"),
        device.owner.to_hex(),
        "the embedded handle binds the vault's embedded owner"
    );
    let handle =
        mint_code_consent_ask(&device.vault, device.owner, &[]).expect("the code consent ask");
    Fixture {
        client,
        device,
        handle,
        _dir: dir,
    }
}

impl Fixture {
    /// The owner's `approve_once` word on the ask, given through `client`.
    fn answer(
        &self,
        client: &OneironClient,
    ) -> Result<oneiron::task_verb::TaskAskAnswer, MemoryError> {
        let mut word = TaskAskWord::new(put_turn(&self.device.vault));
        word.option = Some(TaskAskOptionId::new("approve_once").expect("the option id"));
        client.tasks_answer(&TaskAnswerRequest {
            handle: self.handle,
            word,
        })
    }
}

/// A TURN row for a word's result, its body the map `{"role": "answer"}`.
fn put_turn(vault: &oneiron::Vault) -> EntityId {
    const BODY: [u8; 13] = [
        0x81, 0xa4, b'r', b'o', b'l', b'e', 0xa6, b'a', b'n', b's', b'w', b'e', b'r',
    ];
    let turn = EntityId::now();
    vault
        .put_entity(
            &turn,
            ENTITY_TYPE_TURN,
            TimeRange { start: 11, end: 11 },
            11,
            &BODY,
        )
        .expect("a turn row");
    turn
}

fn assert_owner_key_refusal<T: std::fmt::Debug>(result: Result<T, MemoryError>) {
    let error = result.expect_err("the word is refused for the owner's key");
    assert!(
        error
            .reason_codes
            .iter()
            .any(|code| code == OWNER_KEY_REQUIRED),
        "the refusal is the owner key refusal: {error:?}"
    );
}

/// On an install that holds no key the fold trusts as the owner's (the host
/// root is in the host's custody, no device key is enrolled), the
/// owner-device handle refuses the owner's word `owner_key_required`. The
/// plain handle is refused by the ask's own guard, for the missing proof.
#[test]
fn an_owner_device_handle_with_no_enrolled_key_refuses_owner_key_required() {
    let fx = fixture();
    let refused = fx
        .answer(&fx.client)
        .expect_err("the plain handle's word carries no owner proof");
    assert!(
        refused.message.contains("consent owner not authenticated"),
        "the plain handle's word is refused by the ask's guard: {refused:?}"
    );
    let device = fx
        .client
        .as_owner_device()
        .expect("the owner-device handle");
    assert_owner_key_refusal(fx.answer(&device));
}

/// The same owner-device handle proves once the owner enrols this install's
/// owner signing key: the owner's word is admitted under the proof the key
/// mints for it. The plain handle is still refused.
#[test]
fn the_same_owner_device_handle_proves_after_enrolment() {
    let fx = fixture();
    let device = fx
        .client
        .as_owner_device()
        .expect("the owner-device handle");
    assert_owner_key_refusal(fx.answer(&device));
    fx.device
        .enrol_owner_key()
        .expect("the owner enrols this install's owner signing key");
    assert!(
        fx.answer(&fx.client).is_err(),
        "the plain handle's word still carries no owner proof"
    );
    fx.answer(&device)
        .expect("the owner's word under the owner key's proof is admitted");
}
