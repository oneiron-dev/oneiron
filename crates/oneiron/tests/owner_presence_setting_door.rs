//! The Setting door asks from the value in force and judges the change again in its write.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use oneiron::authority::{ActAuthority, ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::error::{DevicePinRefusal, GateError, OwnerPresenceRefusal, RecordError, SecretError};
use oneiron::policy_model::SecretScanMode;
use oneiron::recovery::PassphraseCost;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingView};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_doors::setting::setting_changes;
use oneiron::test_doors::setting_door_between::set_setting_between;
use oneiron::test_support::provision_engine_machines;
use oneiron::verbs::{SettingGetRequest, setting_get_with_request_owner};
use oneiron::world_keys::DevicePin;
use oneiron::{EdgeActorClass, Error, HostingPrivacyPosture, Vault, VaultConfig};
use oneiron_keystore::{
    ManualPresenceClock, MemoryKeystore, PRESENCE_WINDOW_SECS, PresenceClock, PresenceError,
    PresenceGate, PresenceInstant, PresenceWindow, ScriptedPresence,
};
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const T0: u64 = 1_790_000_000;
const CAP: &str = "test.ordered_cap";
const OWNER_NUMBER: &str = "test.owner_number";
const NEUTRAL_LABEL: &str = "test.neutral_label";
const INSTALL_MODE: &str = "test.install_mode";
const CREDENTIAL_MEMBERS: &str = "test.credential_named_members";
const SETTING_CHANGE_REASON: &str = "change a vault setting";

struct ServedVault {
    vault: Vault,
    owner: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl ServedVault {
    fn hosted() -> Self {
        Self::with_keystore(Arc::new(MemoryKeystore::default()))
    }

    fn with_keystore(keystore: Arc<MemoryKeystore>) -> Self {
        let (vault, dir) = open_vault();
        vault.install_device_keystore(keystore);
        let issuer = provision_engine_machines(&vault);
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile under the host root");
        let (_, owner) = embedded_owner(&vault).expect("authenticated embedded owner");
        vault
            .enrol_device_owner_signing_key(
                &ActAuthority::Owner(owner.clone(), ActSurface::ThisInstall),
                &issuer,
            )
            .expect("enrol this install's owner signing key");
        Self {
            vault,
            owner,
            _dir: dir,
        }
    }

    fn set(&self, request: SetSetting) -> oneiron::Result<SetSettingOutcome> {
        self.vault
            .set_setting(SettingCaller::Owner(&self.owner), request)
    }

    fn read(&self, key: &str) -> SettingView {
        let actor = self.owner.actor_for_read(&self.vault).expect("owner actor");
        let memory = self.vault.memory(actor, EdgeActorClass::Human);
        setting_get_with_request_owner(
            &memory,
            || Some(self.owner.clone()),
            SettingGetRequest {
                key: key.to_owned(),
                item: None,
                at: Vec::new(),
            },
        )
        .expect("read the value in force")
    }
}

fn open_vault() -> (Vault, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::device();
    config.privacy.posture = HostingPrivacyPosture::Hosted;
    config.store_clock = ManualClock::new(T0).bundle();
    let vault = Vault::open(dir.path(), config).expect("vault");
    (vault, dir)
}

/// Each clock reading is more than a confirmation window after the last one.
struct ExpiresAtOnce {
    next_ms: AtomicU64,
}

impl PresenceClock for ExpiresAtOnce {
    fn now(&self) -> PresenceInstant {
        let ms = self
            .next_ms
            .fetch_add(PRESENCE_WINDOW_SECS * 1_000 + 1, Ordering::SeqCst);
        PresenceInstant {
            wall_ms: ms,
            monotonic_ms: ms,
        }
    }
}

fn scripted_gate(
    vault: &Vault,
    answers: impl IntoIterator<Item = Result<(), PresenceError>>,
) -> Arc<ScriptedPresence> {
    let presence = Arc::new(ScriptedPresence::new(answers));
    let window = PresenceWindow::new(Arc::new(ExpiresAtOnce {
        next_ms: AtomicU64::new(1_000_000),
    }));
    vault.install_presence_gate(Arc::new(PresenceGate::new(presence.clone(), window)));
    presence
}

struct PinDevice {
    served: ServedVault,
    pin: Arc<DevicePin>,
}

impl PinDevice {
    fn with_pin_set() -> Self {
        const PIN: &[u8] = b"quiet harbour lantern";
        let keystore = Arc::new(MemoryKeystore::new());
        let served = ServedVault::with_keystore(keystore.clone());
        let pin = DevicePin::with_clock_and_cost(
            keystore,
            ManualPresenceClock::new(1_000_000, 1_000_000),
            PassphraseCost::FLOOR,
        )
        .expect("device PIN over the vault's keystore");
        served
            .vault
            .install_device_pin(pin.clone())
            .expect("install device PIN");
        served
            .vault
            .set_device_pin_as(
                &ActAuthority::Owner(served.owner.clone(), ActSurface::ThisInstall),
                PIN,
                false,
            )
            .expect("seal the enrolled owner key under the device PIN");
        Self { served, pin }
    }
}

fn request(key: &str, value: Value) -> SetSetting {
    SetSetting {
        surface: Some(ActSurface::ThisInstall),
        ..SetSetting::vault_value(key, value)
    }
}

fn clear_cap() -> SetSetting {
    SetSetting {
        value: None,
        ..request(CAP, Value::Null)
    }
}

fn credential_members() -> Value {
    let text = ["tk-", "Hb3sL8", "qW5nC2", "vX0dJ7"].concat();
    json!({ "bytes_per_token": null, "rules": {}, "api_token": text })
}

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

/// An ordered cap asks only when its change widens the value in force.
#[test]
fn an_owner_change_of_an_ordered_key_asks_only_when_it_widens() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(()), Ok(())]);
    for (value, prompts, writes) in [(5, 0, true), (5, 0, false), (8, 1, true), (3, 1, true)] {
        let before = served.read(CAP);
        let outcome = served.set(request(CAP, json!(value))).expect("set the cap");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { sequence, .. } if sequence.is_some() == writes)
        );
        let stored = served.read(CAP);
        assert_eq!(stored.value, json!(value));
        assert_eq!(stored.revision != before.revision, writes);
        assert_eq!(presence.prompts(), prompts);
    }
    served.set(clear_cap()).expect("clear the cap");
    assert_eq!(served.read(CAP).value, json!(10));
    assert_eq!(presence.prompts(), 2);
}

/// A key with no order asks for each change but not for an unchanged row.
#[test]
fn an_owner_change_of_a_key_with_no_order_asks_unless_it_leaves_the_row_as_it_is() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(()), Ok(())]);
    for (value, prompts, writes) in [(9, 1, true), (9, 1, false), (8, 2, true)] {
        let outcome = served
            .set(request(OWNER_NUMBER, json!(value)))
            .expect("set the number");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { sequence, .. } if sequence.is_some() == writes)
        );
        assert_eq!(served.read(OWNER_NUMBER).value, json!(value));
        assert_eq!(presence.prompts(), prompts);
    }
}

/// A neutral key's label asks while the scan is on, because the wall reads its text in the write;
/// with the scan off its changed labels land without a prompt.
#[test]
fn an_owner_change_of_a_neutral_key_asks_only_while_the_wall_reads_its_text() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(())]);
    for (label, scan, prompts) in [
        ("morning", SecretScanMode::On, 1),
        ("evening", SecretScanMode::Off, 1),
        ("morning", SecretScanMode::Off, 1),
    ] {
        served
            .vault
            .set_secret_scan_mode(&served.owner, scan, T0)
            .expect("set the scan switch");
        let outcome = served
            .set(request(NEUTRAL_LABEL, json!(label)))
            .expect("set the label");
        assert!(matches!(
            outcome,
            SetSettingOutcome::Applied {
                sequence: Some(_),
                ..
            }
        ));
        assert_eq!(served.read(NEUTRAL_LABEL).value, json!(label));
        assert_eq!(presence.prompts(), prompts);
    }
}

/// Declining the setting prompt stores no widening and does not block a narrowing.
#[test]
fn a_declined_confirm_refuses_a_widening_setting_change_and_stores_nothing() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let before = served.read(CAP);
    let changes = setting_changes(&served.vault).expect("change stream before the refusal");
    let refused = served.set(request(CAP, json!(20)));
    assert!(
        matches!(
            refused,
            Err(Error::Record(RecordError::OwnerPresenceRequired {
                here: OwnerPresenceRefusal::Declined,
            }))
        ),
        "{refused:?}"
    );
    assert_eq!(presence.reasons(), [SETTING_CHANGE_REASON]);
    assert_eq!(served.read(CAP), before);
    assert_eq!(
        setting_changes(&served.vault).expect("change stream after the refusal"),
        changes
    );

    served
        .set(request(CAP, json!(5)))
        .expect("narrow under the same gate");
    assert_eq!(served.read(CAP).value, json!(5));
    assert_eq!(presence.prompts(), 1, "the narrowing added no prompt");
}

/// Argument and row refusals come before the prompt and leave the row and stream alone.
#[test]
fn a_setting_change_refused_on_its_read_never_raises_the_prompt() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(())]);
    let before = served.read(CAP);
    let changes = setting_changes(&served.vault).expect("change stream before the refusals");
    for change in [
        request(CAP, json!(true)),
        SetSetting {
            expected_revision: Some(before.revision + 1),
            ..request(CAP, json!(20))
        },
        SetSetting {
            item: Some("mail".to_owned()),
            ..request(CAP, json!(20))
        },
        SetSetting {
            weight_runs: Some(1.0),
            ..request(CAP, json!(20))
        },
        SetSetting {
            mode: SettingMode::Carried,
            ..request(CAP, json!(20))
        },
    ] {
        let refused = served.set(change);
        assert!(
            matches!(refused, Err(Error::InvalidConfig(_))),
            "{refused:?}"
        );
        assert_eq!(presence.prompts(), 0);
        assert_eq!(served.read(CAP), before);
        assert_eq!(
            setting_changes(&served.vault).expect("change stream after the refusal"),
            changes
        );
    }
}

/// The read refuses another vault's proof before asking, even when it cannot judge past the wall.
#[test]
fn an_owner_proof_of_another_vault_never_raises_the_prompt_at_the_setting_door() {
    let served = ServedVault::hosted();
    let other = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(())]);
    for change in [
        request(CAP, json!(20)),
        request(CREDENTIAL_MEMBERS, credential_members()),
    ] {
        let refused = served
            .vault
            .set_setting(SettingCaller::Owner(&other.owner), change);
        assert!(
            matches!(
                refused,
                Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                    "owner proof belongs to another vault"
                )))
            ),
            "{refused:?}"
        );
        assert_eq!(presence.prompts(), 0);
    }
}

/// A narrowing that becomes a widening is refused without overwriting the intervening row.
#[test]
fn a_setting_change_that_widens_since_the_door_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(()), Ok(()), Ok(())]);
    served
        .set(request(CAP, json!(8)))
        .expect("set the starting cap");
    let mut between_state = None;
    let refused = set_setting_between(
        &served.vault,
        SettingCaller::Owner(&served.owner),
        request(CAP, json!(6)),
        || {
            let changed = served
                .set(request(CAP, json!(4)))
                .expect("narrow in between");
            let SetSettingOutcome::Applied {
                sequence: Some(_),
                revision,
                ..
            } = changed
            else {
                panic!("the intervening change must land: {changed:?}");
            };
            let changes =
                setting_changes(&served.vault).expect("stream after the intervening change");
            between_state = Some((revision, changes));
        },
    );
    assert!(
        matches!(refused, Err(Error::ConcurrentWrite(_))),
        "{refused:?}"
    );
    assert_eq!(presence.prompts(), 0);
    let (revision, changes) = between_state.expect("between ran");
    let stored = served.read(CAP);
    assert_eq!(stored.value, json!(4));
    assert_eq!(stored.revision, revision);
    assert_eq!(
        setting_changes(&served.vault).expect("stream after the conflict"),
        changes
    );
}

/// With the scan on the wall reads a text value in the write before its type does, so the door
/// asks first and the write refuses its shape; with the scan off the read refuses it and asks
/// nothing.
#[test]
fn a_text_value_the_wall_reads_is_asked_before_its_shape_is_refused() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Ok(())]);
    let before = served.read(CAP);
    let changes = setting_changes(&served.vault).expect("change stream before the refusals");
    for (scan, prompts) in [(SecretScanMode::On, 1), (SecretScanMode::Off, 1)] {
        served
            .vault
            .set_secret_scan_mode(&served.owner, scan, T0)
            .expect("set the scan switch");
        let refused = served.set(request(CAP, json!("not a number")));
        assert!(
            matches!(refused, Err(Error::InvalidConfig(_))),
            "{refused:?}"
        );
        assert_eq!(presence.prompts(), prompts);
        assert_eq!(served.read(CAP), before);
        assert_eq!(
            setting_changes(&served.vault).expect("change stream after the refusal"),
            changes
        );
    }
}

/// A closed PIN window answers a text value before anything reads its shape or custody, and still
/// lets the read refuse a value with no text for its shape.
#[test]
fn a_text_value_on_a_device_whose_pin_window_ended_answers_pin_required_before_its_shape() {
    let device = PinDevice::with_pin_set();
    device.pin.end_window();
    let served = &device.served;
    let before = served.read(CAP);
    let refused = served.set(request(CAP, json!("not a number")));
    assert!(
        matches!(
            refused,
            Err(Error::Secret(SecretError::DevicePin(
                DevicePinRefusal::Required
            )))
        ),
        "{refused:?}"
    );
    let refused = served.set(request(CAP, json!(true)));
    assert!(
        matches!(refused, Err(Error::InvalidConfig(_))),
        "{refused:?}"
    );
    assert_eq!(served.read(CAP), before);
}

/// A value the read judged with the scan off, which the wall reads once the scan is on, is a
/// conflict: the write refuses it before the wall, under the ordinary witness of a change that
/// left the row as it is.
#[test]
fn a_value_the_wall_reads_since_the_door_asked_is_a_conflict() {
    let served = ServedVault::hosted();
    served
        .vault
        .set_secret_scan_mode(&served.owner, SecretScanMode::Off, T0)
        .expect("turn the scan off");
    let stored = json!({ "bytes_per_token": null, "rules": {}, "api_token": null });
    served
        .set(request(CREDENTIAL_MEMBERS, stored.clone()))
        .expect("set with the scan off");
    let presence = scripted_gate(&served.vault, []);
    let before = served.read(CREDENTIAL_MEMBERS);
    let changes = setting_changes(&served.vault).expect("change stream before the conflict");
    // The stored row again, with a member under a credential name that its type does not read.
    let mut offered = stored;
    offered["api_key"] = Value::String(["tk-", "Hb3sL8", "qW5nC2", "vX0dJ7"].concat());
    let refused = set_setting_between(
        &served.vault,
        SettingCaller::Owner(&served.owner),
        request(CREDENTIAL_MEMBERS, offered),
        || {
            served
                .vault
                .set_secret_scan_mode(&served.owner, SecretScanMode::On, T0)
                .expect("turn the scan on in between");
        },
    );
    assert!(
        matches!(refused, Err(Error::ConcurrentWrite(_))),
        "{refused:?}"
    );
    assert_eq!(presence.prompts(), 0);
    assert_eq!(served.read(CREDENTIAL_MEMBERS), before);
    assert_eq!(
        setting_changes(&served.vault).expect("change stream after the conflict"),
        changes
    );
}

/// A change that cannot sign an act lands on this install without asking.
#[test]
fn an_owner_change_that_signs_no_act_asks_nothing() {
    let served = ServedVault::hosted();
    let presence = scripted_gate(&served.vault, [Err(PresenceError::Declined)]);
    let outcome = served
        .set(SetSetting::vault_value(INSTALL_MODE, json!(1)))
        .expect("set the install mode");
    assert!(matches!(
        outcome,
        SetSettingOutcome::Applied {
            sequence: Some(_),
            ..
        }
    ));
    assert_eq!(served.read(INSTALL_MODE).value, json!(1));
    assert_eq!(presence.prompts(), 0);
}

/// A closed PIN window refuses changed travelling rows, but not an unchanged row.
#[test]
fn a_device_whose_pin_window_ended_answers_pin_required_at_the_setting_door() {
    let device = PinDevice::with_pin_set();
    device.pin.end_window();
    let served = &device.served;
    let presence = scripted_gate(&served.vault, []);
    let before = served.read(CAP);
    let changes = setting_changes(&served.vault).expect("change stream before the PIN refusals");
    for value in [5, 20] {
        let refused = served.set(request(CAP, json!(value)));
        assert!(
            matches!(
                refused,
                Err(Error::Secret(SecretError::DevicePin(
                    DevicePinRefusal::Required
                )))
            ),
            "{refused:?}"
        );
        assert_eq!(served.read(CAP), before);
        assert_eq!(
            setting_changes(&served.vault).expect("change stream after the PIN refusal"),
            changes
        );
    }
    let unchanged = served
        .set(clear_cap())
        .expect("clearing the absent cap needs no PIN");
    assert!(matches!(
        unchanged,
        SetSettingOutcome::Applied { sequence: None, .. }
    ));
    assert_eq!(served.read(CAP), before);
    assert_eq!(
        setting_changes(&served.vault).expect("change stream after the no-op"),
        changes
    );
    assert_eq!(
        presence.prompts(),
        0,
        "the device PIN takes priority over the prompt"
    );
}

/// A repeat offer that the wall will lift asks and stores a custody handle instead of the text.
#[test]
fn a_value_the_wall_lifts_in_the_write_is_asked_as_an_important_act() {
    let served = ServedVault::hosted();
    let raw = credential_members();
    served
        .vault
        .set_secret_scan_mode(&served.owner, SecretScanMode::Off, T0)
        .expect("turn the scan off");
    let first = served
        .set(request(CREDENTIAL_MEMBERS, raw.clone()))
        .expect("set with the scan off");
    assert!(matches!(
        first,
        SetSettingOutcome::Applied {
            sequence: Some(_),
            ..
        }
    ));
    assert_eq!(served.read(CREDENTIAL_MEMBERS).value, raw);

    let presence = scripted_gate(&served.vault, [Ok(())]);
    served
        .vault
        .set_secret_scan_mode(&served.owner, SecretScanMode::On, T0)
        .expect("turn the scan on");
    assert_eq!(presence.prompts(), 0, "the switch does not ask");
    assert_eq!(
        served.read(CREDENTIAL_MEMBERS).value,
        raw,
        "the queued lift has not yet run"
    );
    let second = served
        .set(request(CREDENTIAL_MEMBERS, raw))
        .expect("set with the scan on");
    assert!(matches!(
        second,
        SetSettingOutcome::Applied {
            sequence: Some(_),
            ..
        }
    ));
    assert_eq!(presence.prompts(), 1);
    let stored = served.read(CREDENTIAL_MEMBERS);
    assert!(custody_handle(&stored.value["api_token"]), "{stored:?}");
}
