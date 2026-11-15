//! DESIGN 15-setting-primitive, stage 2, lane SETTING-DIALS PR D3a: three owner acts of
//! `settings/` become catalogue keys.
//! - `rooms.private_threads.admin_walk_in`, `rooms.private_threads.admin_delete` and
//!   `outbound.undo_send` are in the catalogue and read their old defaults, through the verb and
//!   through each kept reader (`Vault::room_thread_admin_settings`, `vault.consent.undo_send`);
//! - the owner sets each through `vault.settings.set`, and the kept reader returns that value; the
//!   undo-send window is stored as its old `normalized()` stored it, and a window it refused is
//!   refused;
//! - they stay owner acts: an agent's change waits on a check-in, and an agent reads none of them;
//! - the owner's change of each through the verb is signed on the key's own target from this
//!   install, as the old doors signed theirs (stage 7a-1, RULING SETTING-7A-SIGNED-ACT-BASE = A).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dials_3`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::policy_setting_doors::policy_setting_target;
use oneiron::receipt::AuthorityAuditQuery;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::setting::setting_change;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const UNDO_SEND_READ: &str = "vault.consent.undo_send";
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

    fn as_agent(&self, agent: EntityId) -> Memory<'_> {
        self.vault.memory(agent, EdgeActorClass::Agent)
    }

    /// An enabled, active agent definition the owner creates.
    fn agent(&self) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": format!("dials3-agent-{}", id.to_hex()),
                    "desc": "setting dials 3 fixture",
                    "version": "1.0.0",
                    "ceiling": "auto",
                    "enabled": true,
                }))
                .expect("agent spec"),
            },
        )
        .expect("the owner creates the agent");
        id
    }

    /// The owner's live Grant for `agent` naming `read` and `verbs`.
    fn grant(&self, agent: EntityId, verbs: &[&str]) {
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope: scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner mints the Grant");
        assert!(minted.grant.confers, "the Grant confers");
    }

    /// The owner's setting acts on the main log, as the owner's audit lists them: each entry's
    /// hash (hex), its detail (`<key> set` or `<key> clear`) and its target (hex).
    fn setting_acts(&self) -> Vec<(String, String, String)> {
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
            .map(|row| {
                (
                    row.entry_hash,
                    row.detail.unwrap_or_default(),
                    row.subject_ref.unwrap_or_default(),
                )
            })
            .collect()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> String {
    format!(
        "{:?}",
        invoke(memory, verb, input).expect_err("the call is refused")
    )
}

fn set(key: &str, value: Value) -> Value {
    json!({ "key": key, "scope": { "kind": "vault" }, "value": value })
}

fn get(memory: &Memory<'_>, key: &str) -> Value {
    call(memory, GET, json!({ "key": key }))
}

const WALK_IN: &str = "rooms.private_threads.admin_walk_in";
const DELETE: &str = "rooms.private_threads.admin_delete";
const UNDO_SEND: &str = "outbound.undo_send";

#[test]
fn the_three_keys_read_their_old_defaults() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    for key in [WALK_IN, DELETE] {
        let read = get(&me, key);
        assert_eq!(read["value"], json!(true), "{key}: {read}");
        assert_eq!(read["source"], json!({ "from": "default" }), "{key}");
    }
    let switches = fx.vault.room_thread_admin_settings().expect("read");
    assert!(
        switches.admin_walk_in && switches.admin_delete,
        "absent reads on"
    );

    let window = get(&me, UNDO_SEND);
    assert_eq!(
        window["value"],
        json!({ "all_channels_secs": 0, "channels": [] }),
        "{window}"
    );
    let consent = call(&me, UNDO_SEND_READ, json!({}));
    assert_eq!(consent["all_channels_secs"], json!(0), "{consent}");
    assert_eq!(consent["channels"], json!([]), "{consent}");
}

#[test]
fn an_owner_set_is_what_the_kept_reader_returns() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let applied = call(&me, SET, set(WALK_IN, json!(false)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let switches = fx.vault.room_thread_admin_settings().expect("read");
    assert!(!switches.admin_walk_in, "walk-in is off");
    assert!(
        switches.admin_delete,
        "delete stays on: each switch is its own key"
    );
    call(&me, SET, set(DELETE, json!(false)));
    assert!(
        !fx.vault
            .room_thread_admin_settings()
            .expect("read")
            .admin_delete
    );
    call(&me, SET, set(WALK_IN, Value::Null));
    assert!(
        fx.vault
            .room_thread_admin_settings()
            .expect("read")
            .admin_walk_in,
        "a cleared switch reads on again"
    );

    // Channels out of order, in another spelling's order: stored in channel order, as
    // `normalized()` stored them.
    let applied = call(
        &me,
        SET,
        set(
            UNDO_SEND,
            json!({
                "all_channels_secs": 30,
                "channels": [
                    { "channel": "email_resend", "secs": 5 },
                    { "channel": "discord", "secs": 0 },
                ],
            }),
        ),
    );
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let stored = json!([
        { "channel": "discord", "secs": 0 },
        { "channel": "email_resend", "secs": 5 },
    ]);
    assert_eq!(applied["value"]["channels"], stored, "{applied}");
    let consent = call(&me, UNDO_SEND_READ, json!({}));
    assert_eq!(consent["all_channels_secs"], json!(30), "{consent}");
    assert_eq!(consent["channels"], stored, "{consent}");

    for refused_window in [
        json!({ "all_channels_secs": 10, "channels": [{ "channel": "esign", "secs": 5 }] }),
        json!({ "all_channels_secs": 10, "channels": [{ "channel": "no_such_channel", "secs": 5 }] }),
        json!({
            "all_channels_secs": 10,
            "channels": [
                { "channel": "discord", "secs": 5 },
                { "channel": "discord", "secs": 6 },
            ],
        }),
    ] {
        refused(&me, SET, set(UNDO_SEND, refused_window));
    }
    assert_eq!(
        call(&me, UNDO_SEND_READ, json!({}))["all_channels_secs"],
        json!(30),
        "a refused window changes nothing"
    );
}

#[test]
fn they_stay_owner_acts_and_no_agent_reads_them() {
    let fx = Fixture::rooted();
    let asker = fx.agent();
    fx.grant(asker, &[SET, GET]);
    let them = fx.as_agent(asker);

    for (key, value) in [
        (WALK_IN, json!(false)),
        (DELETE, json!(false)),
        (
            UNDO_SEND,
            json!({ "all_channels_secs": 60, "channels": [] }),
        ),
    ] {
        let pending = call(&them, SET, set(key, value));
        assert_eq!(pending["status"], json!("pending"), "{key}: {pending}");
        refused(&them, GET, json!({ "key": key }));
    }
    let switches = fx.vault.room_thread_admin_settings().expect("read");
    assert!(
        switches.admin_walk_in && switches.admin_delete,
        "nothing applied"
    );
    assert_eq!(
        get(&fx.as_owner(), UNDO_SEND)["value"]["all_channels_secs"],
        json!(0),
        "nothing applied"
    );
}

#[test]
fn the_owners_change_of_each_key_is_signed_on_its_target() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    for (key, value) in [
        (WALK_IN, json!(false)),
        (DELETE, json!(false)),
        (
            UNDO_SEND,
            json!({ "all_channels_secs": 45, "channels": [] }),
        ),
    ] {
        let applied = call(&me, SET, set(key, value));
        let sequence = applied["sequence"]
            .as_u64()
            .unwrap_or_else(|| panic!("{key}: a change sequence: {applied}"));
        let change = setting_change(&fx.vault, sequence)
            .expect("the change stream")
            .expect("the change row");
        assert_eq!(change.surface, Some(ActSurface::ThisInstall), "{key}");
        let entry = hex(&change
            .signed
            .unwrap_or_else(|| panic!("{key}: the change row names its signed entry")));
        let acts = fx.setting_acts();
        let (_, detail, target) = acts
            .iter()
            .find(|(hash, _, _)| *hash == entry)
            .unwrap_or_else(|| panic!("{key}: the main log holds the entry {entry}: {acts:?}"));
        assert_eq!(*detail, format!("{key} set"));
        assert_eq!(
            *target,
            policy_setting_target(key).expect("a key's target").to_hex(),
            "{key}: signed on the key's own target"
        );
    }
}
