//! FIX SETTING-WALL-CREDENTIAL-NAMED-MEMBERS: the side-row wall reads every setting value before
//! it is stored, and its field rule lifts the member under a credential name into custody. A
//! setting value's type fixes each member's shape, and a handle can stand only where the type
//! takes text:
//! - a count under a credential name is stored as written, and so is a rule the owner keys by a
//!   name that reads as a credential name;
//! - text under a credential name still goes to custody and leaves its handle, inside such a
//!   rule too.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_wall_credential_named_members`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const KEY: &str = "test.credential_named_members";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open_owned(dir.path(), config).expect("owned vault");
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let _owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            _issuer: issuer,
            owner,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }
}

/// The owner sets `value` at the vault: the answer, or why the set was refused.
fn owner_sets(memory: &Memory<'_>, value: &Value) -> Value {
    let input = json!({ "key": KEY, "scope": { "kind": "vault" }, "value": value });
    let answer =
        invoke(memory, SET, input).unwrap_or_else(|error| panic!("the owner's set: {error:?}"));
    assert_eq!(answer["status"], json!("applied"), "{answer}");
    answer
}

/// The key's value in force at the vault.
fn stored(memory: &Memory<'_>) -> Value {
    invoke(memory, GET, json!({ "key": KEY, "at": [] })).expect("the owner's read")["value"].clone()
}

/// Whether `value` is a custody handle the wall left: `sc12`, or `[secret sc12]`.
fn custody_handle(value: &Value) -> bool {
    let bare = |text: &str| {
        text.strip_prefix("sc").is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    };
    value.as_str().is_some_and(|text| {
        bare(text)
            || text
                .strip_prefix("[secret ")
                .and_then(|rest| rest.strip_suffix(']'))
                .is_some_and(bare)
    })
}

#[test]
fn a_count_under_a_credential_name_in_a_setting_value_is_stored_as_written() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let value = json!({ "bytes_per_token": 3, "rules": {}, "api_token": null });
    let answer = owner_sets(&me, &value);
    assert_eq!(stored(&me), value, "the count is stored as written");
    assert_eq!(answer["value"], value, "the answer shows the stored value");
}

#[test]
fn a_rule_keyed_by_a_credential_name_in_a_setting_value_is_read_member_by_member() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let refresh = ["rt-", "Zq7vN2", "kP9xW4", "mT6bR1"].concat();
    let value = json!({
        "bytes_per_token": null,
        "rules": {
            "service.access_token": { "normalize_text": false, "weight": 2, "refresh_token": null },
            "mail.api_key": { "normalize_text": true, "weight": 1, "refresh_token": refresh },
        },
        "api_token": null,
    });
    owner_sets(&me, &value);
    let held = stored(&me);
    assert_eq!(
        held["rules"]["service.access_token"], value["rules"]["service.access_token"],
        "a rule under a credential name holds no text, and is stored as written: {held}"
    );
    let rule = &held["rules"]["mail.api_key"];
    assert_eq!(rule["normalize_text"], json!(true), "{held}");
    assert_eq!(rule["weight"], json!(1), "{held}");
    assert!(
        custody_handle(&rule["refresh_token"]),
        "text under a credential name inside the rule takes its handle: {held}"
    );
    assert!(
        !held.to_string().contains(refresh.as_str()),
        "the text never lands raw: {held}"
    );
}

#[test]
fn text_under_a_credential_name_in_a_setting_value_still_takes_its_handle() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let text = ["tk-", "Hb3sL8", "qW5nC2", "vX0dJ7"].concat();
    let value = json!({ "bytes_per_token": null, "rules": {}, "api_token": text });
    owner_sets(&me, &value);
    let held = stored(&me);
    assert!(
        custody_handle(&held["api_token"]),
        "the text under a credential name takes its handle: {held}"
    );
    assert!(
        !held.to_string().contains(text.as_str()),
        "the text never lands raw: {held}"
    );
    assert_eq!(held["bytes_per_token"], Value::Null, "{held}");
    assert_eq!(held["rules"], json!({}), "{held}");
}
