//! DESIGN 15-setting-primitive, stage 7a-1 (RULING SETTING-7A-SIGNED-ACT-BASE = A): an owner's
//! change of a catalogue key is signed on the main log, as the older setting doors sign theirs
//! (FIX 4624, FIX 5660).
//! - an owner's change that names its act surface appends one `PolicySettingSet` on the key's
//!   reserved target, and its change row names the entry and the surface;
//! - a second change and a clear each append one more on that target, so each act's `seen`
//!   named the one before it (the fold counts no other), and the clear keeps no value;
//! - an equal value writes nothing and signs nothing;
//! - a change that names no surface signs nothing, as before this stage;
//! - changes in one write are each signed, and a caller's write that fails leaves none;
//! - only the owner's change names a surface: an agent naming one is refused, nothing written;
//! - the verb signs the owner's change from this install;
//! - an older door's act keeps its wire name and its target (`undo_send`).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_signed_act`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::Memory;
use oneiron::policy_setting_doors::{owner_act_target, policy_setting_target};
use oneiron::receipt::AuthorityAuditQuery;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingChange};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::{set_settings_in_one_write, setting_change};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const UNDO_SEND_SET: &str = "vault.consent.undo_send.set";
const NUMBER: &str = "test.owner_number";
const MODE: &str = "test.optional_mode";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    _issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault whose install carries the owner's acts (its machine key and serving
    /// profile stand), opened owned: the writer lease is what lets the owner's handle call the
    /// owner verbs by name.
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
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            _issuer: issuer,
            owner,
            owner_proof,
        }
    }

    fn as_owner(&self) -> Memory<'_> {
        self.vault.memory(self.owner, EdgeActorClass::Human)
    }

    /// `request` as the owner, through the door itself.
    fn owner_sets(&self, request: SetSetting) -> SetSettingOutcome {
        self.vault
            .set_setting(SettingCaller::Owner(&self.owner_proof), request)
            .expect("the owner's change")
    }

    /// The owner's setting acts on the main log, as the owner's audit lists them: each entry's
    /// hash, its detail (`<setting> set` or `<setting> clear`) and its target.
    fn setting_acts(&self) -> Vec<SettingAct> {
        self.vault
            .authority_audit(
                &self.owner_proof,
                &AuthorityAuditQuery {
                    limit: Some(500),
                    ..AuthorityAuditQuery::default()
                },
            )
            .expect("the owner's audit")
            .rows
            .into_iter()
            .filter(|row| row.source_op == "policy_setting")
            .map(|row| SettingAct {
                entry: row.entry_hash,
                detail: row.detail.unwrap_or_default(),
                target: row.subject_ref.unwrap_or_default(),
            })
            .collect()
    }

    /// The change row an applied outcome names.
    fn change_of(&self, outcome: &SetSettingOutcome) -> SettingChange {
        let SetSettingOutcome::Applied {
            sequence: Some(sequence),
            ..
        } = outcome
        else {
            panic!("an applied change that wrote a row: {outcome:?}");
        };
        setting_change(&self.vault, *sequence)
            .expect("the change stream")
            .expect("the change row")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SettingAct {
    entry: String,
    detail: String,
    target: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The target every act on `key` names (32 hex).
fn target_of(key: &str) -> String {
    policy_setting_target(key).expect("a key's target").to_hex()
}

fn signed_from(surface: ActSurface, request: SetSetting) -> SetSetting {
    SetSetting {
        surface: Some(surface),
        ..request
    }
}

/// The act of `change` among `acts`, by the entry its change row names.
fn act_of<'a>(acts: &'a [SettingAct], change: &SettingChange) -> &'a SettingAct {
    let entry = hex(&change
        .signed
        .expect("the change row names its signed entry"));
    acts.iter()
        .find(|act| act.entry == entry)
        .unwrap_or_else(|| panic!("the main log holds the entry {entry}: {acts:?}"))
}

#[test]
fn an_owners_change_naming_its_surface_is_signed_on_the_keys_target() {
    let fx = Fixture::rooted();
    let before = fx.setting_acts();

    let set = fx.owner_sets(signed_from(
        ActSurface::ThisInstall,
        SetSetting::vault_value(NUMBER, json!(3)),
    ));
    let change = fx.change_of(&set);
    assert_eq!(change.surface, Some(ActSurface::ThisInstall));
    let acts = fx.setting_acts();
    assert_eq!(acts.len(), before.len() + 1, "one signed act: {acts:?}");
    let act = act_of(&acts, &change);
    assert_eq!(act.detail, format!("{NUMBER} set"));
    assert_eq!(act.target, target_of(NUMBER));
    assert_eq!(
        act.target,
        owner_act_target(&format!("settings.{NUMBER}"))
            .expect("target")
            .to_hex(),
        "the target is derived from the key name as the older settings' are"
    );
}

#[test]
fn each_later_change_and_a_clear_sign_on_the_same_target_and_an_equal_value_signs_nothing() {
    let fx = Fixture::rooted();
    let surface = ActSurface::LinkedDevice {
        machine: EntityId::now(),
    };
    let first = fx.change_of(&fx.owner_sets(signed_from(
        surface,
        SetSetting::vault_value(NUMBER, json!(3)),
    )));
    let second = fx.change_of(&fx.owner_sets(signed_from(
        surface,
        SetSetting::vault_value(NUMBER, json!(4)),
    )));
    let after_second = fx.setting_acts();

    // The same value again writes nothing, so it signs nothing.
    let equal = fx.owner_sets(signed_from(
        surface,
        SetSetting::vault_value(NUMBER, json!(4)),
    ));
    assert!(
        matches!(equal, SetSettingOutcome::Applied { sequence: None, .. }),
        "{equal:?}"
    );
    assert_eq!(
        fx.setting_acts(),
        after_second,
        "an equal value signs nothing"
    );

    let clear = fx.change_of(&fx.owner_sets(signed_from(
        surface,
        SetSetting {
            value: None,
            ..SetSetting::vault_value(NUMBER, json!(0))
        },
    )));
    assert_eq!(clear.value, None, "the change cleared the row");
    let acts = fx.setting_acts();
    // Each act counted only because its `seen` named the act before it on this target.
    for (change, detail) in [(&first, "set"), (&second, "set"), (&clear, "clear")] {
        let act = act_of(&acts, change);
        assert_eq!(act.detail, format!("{NUMBER} {detail}"));
        assert_eq!(act.target, target_of(NUMBER));
        assert_eq!(change.surface, Some(surface));
    }
    let entries: std::collections::BTreeSet<_> = [&first, &second, &clear]
        .iter()
        .map(|change| change.signed)
        .collect();
    assert_eq!(entries.len(), 3, "three entries, one per change");
}

#[test]
fn a_change_naming_no_surface_signs_nothing() {
    let fx = Fixture::rooted();
    let before = fx.setting_acts();
    let change = fx.change_of(&fx.owner_sets(SetSetting::vault_value(NUMBER, json!(5))));
    assert_eq!(change.surface, None);
    assert_eq!(change.signed, None);
    assert_eq!(fx.setting_acts(), before, "no act without a surface");
}

#[test]
fn changes_in_one_write_are_each_signed_and_a_failed_write_signs_none() {
    let fx = Fixture::rooted();
    let before = fx.setting_acts();
    let requests = [
        signed_from(
            ActSurface::ThisInstall,
            SetSetting::vault_value(NUMBER, json!(2)),
        ),
        signed_from(
            ActSurface::ThisInstall,
            SetSetting::vault_value(MODE, json!(9)),
        ),
    ];

    let failed = set_settings_in_one_write(&fx.vault, &fx.owner_proof, &requests, true);
    assert!(failed.is_err(), "{failed:?}");
    assert_eq!(
        fx.setting_acts(),
        before,
        "a failed write leaves no signed act on the log"
    );

    let outcomes = set_settings_in_one_write(&fx.vault, &fx.owner_proof, &requests, false)
        .expect("both changes commit together");
    let acts = fx.setting_acts();
    assert_eq!(acts.len(), before.len() + 2, "{acts:?}");
    for (outcome, key) in outcomes.iter().zip([NUMBER, MODE]) {
        let act = act_of(&acts, &fx.change_of(outcome));
        assert_eq!(act.detail, format!("{key} set"));
        assert_eq!(act.target, target_of(key));
    }
}

#[test]
fn only_the_owners_change_names_a_surface() {
    let fx = Fixture::rooted();
    let before = fx.setting_acts();
    let refused = fx
        .vault
        .set_setting(
            SettingCaller::Agent(EntityId::now()),
            signed_from(
                ActSurface::ThisInstall,
                SetSetting::vault_value(NUMBER, json!(1)),
            ),
        )
        .expect_err("an agent never names the owner's surface");
    assert!(
        format!("{refused:?}").contains("an act surface is the owner's"),
        "{refused:?}"
    );
    let read = invoke(&fx.as_owner(), GET, json!({ "key": NUMBER, "at": [] }))
        .expect("the owner reads the key");
    assert_eq!(
        read["value"],
        json!(7),
        "the default stands: nothing written"
    );
    assert_eq!(fx.setting_acts(), before);
}

#[test]
fn the_verb_signs_the_owners_change_from_this_install() {
    let fx = Fixture::rooted();
    let before = fx.setting_acts();
    let outcome = invoke(
        &fx.as_owner(),
        SET,
        json!({ "key": NUMBER, "scope": { "kind": "vault" }, "value": 6 }),
    )
    .expect("the owner sets the key by its verb");
    let sequence = outcome["sequence"].as_u64().expect("a change sequence");
    let change = setting_change(&fx.vault, sequence)
        .expect("the change stream")
        .expect("the change row");
    assert_eq!(change.surface, Some(ActSurface::ThisInstall));
    let acts = fx.setting_acts();
    assert_eq!(acts.len(), before.len() + 1, "{acts:?}");
    let act = act_of(&acts, &change);
    assert_eq!(act.detail, format!("{NUMBER} set"));
    assert_eq!(act.target, target_of(NUMBER));
}

#[test]
fn an_older_doors_act_keeps_its_wire_name_and_target() {
    let fx = Fixture::rooted();
    let before = fx.setting_acts();
    invoke(
        &fx.as_owner(),
        UNDO_SEND_SET,
        json!({ "all_channels_secs": 60 }),
    )
    .expect("the owner sets the undo-send window");
    let acts: Vec<Value> = fx
        .setting_acts()
        .into_iter()
        .filter(|act| !before.contains(act))
        .map(|act| json!({ "detail": act.detail, "target": act.target }))
        .collect();
    assert_eq!(
        acts,
        [json!({
            "detail": "undo_send set",
            "target": owner_act_target("settings.undo_send").expect("target").to_hex(),
        })],
        "the older door's act reads as before"
    );
    assert_eq!(
        target_of("undo_send"),
        owner_act_target("settings.undo_send")
            .expect("target")
            .to_hex()
    );
}
