//! DESIGN 15-setting-primitive, stage 1, lane SETTING-DIALS PR D1: four plain settings of
//! `settings/` become catalogue keys.
//! - `backup.policy`, `client.customization`, `models.responses_store` and
//!   `dreamer.plugin_suggestions` are in the catalogue and read their old defaults, through the
//!   verb and through each kept reader;
//! - the owner sets each through `vault.settings.set`, and the kept reader returns that value; a
//!   value its old rules refused is refused;
//! - they stay owner acts: an agent's change waits on a check-in, and only the customization
//!   profile reads for any member.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dials_1`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::Memory;
use oneiron::settings::backup::BackupPolicy;
use oneiron::settings::{CustomizationSettings, ModeLayer, WorldLayer};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
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
                    "agent_id": format!("dials-agent-{}", id.to_hex()),
                    "desc": "setting dials fixture",
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

#[test]
fn the_four_keys_read_their_old_defaults() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let backup = get(&me, "backup.policy");
    assert_eq!(backup["value"], Value::Null, "{backup}");
    assert_eq!(backup["source"], json!({ "from": "default" }));
    assert_eq!(fx.vault.backup_policy().expect("read"), None);

    let profile = get(&me, "client.customization");
    assert_eq!(
        profile["value"],
        serde_json::to_value(CustomizationSettings::default()).expect("json"),
        "{profile}"
    );
    assert_eq!(
        fx.vault.customization_settings().expect("read"),
        CustomizationSettings::default()
    );

    assert_eq!(get(&me, "models.responses_store")["value"], json!(false));
    assert!(!fx.vault.responses_store().expect("read"));

    assert_eq!(get(&me, "dreamer.plugin_suggestions")["value"], json!(true));
    assert!(fx.vault.plugin_suggestions_enabled().expect("read"));
}

#[test]
fn an_owner_set_is_what_the_kept_reader_returns() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let policy = BackupPolicy {
        enabled: true,
        every_hours: 6,
        keep: 3,
    };
    let applied = call(&me, SET, set("backup.policy", json!(policy)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(fx.vault.backup_policy().expect("read"), Some(policy));
    refused(
        &me,
        SET,
        set(
            "backup.policy",
            json!({ "enabled": true, "every_hours": 0, "keep": 3 }),
        ),
    );
    assert_eq!(
        fx.vault.backup_policy().expect("read"),
        Some(policy),
        "a refused policy changes nothing"
    );
    call(&me, SET, set("backup.policy", Value::Null));
    assert_eq!(
        fx.vault.backup_policy().expect("read"),
        None,
        "null is no choice again"
    );

    let mut profile = CustomizationSettings::default();
    profile.mode = ModeLayer::new("dark").expect("mode");
    profile.world = WorldLayer::new(None, Some("Home".into())).expect("world");
    call(
        &me,
        SET,
        set(
            "client.customization",
            serde_json::to_value(&profile).expect("json"),
        ),
    );
    assert_eq!(fx.vault.customization_settings().expect("read"), profile);
    let mut bad = serde_json::to_value(&profile).expect("json");
    bad["mode"]["mode"] = json!("not a token");
    refused(&me, SET, set("client.customization", bad));

    call(&me, SET, set("models.responses_store", json!(true)));
    assert!(fx.vault.responses_store().expect("read"));

    call(&me, SET, set("dreamer.plugin_suggestions", json!(false)));
    assert!(!fx.vault.plugin_suggestions_enabled().expect("read"));
}

#[test]
fn they_stay_owner_acts_and_only_the_profile_reads_for_members() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let asker = fx.agent();
    fx.grant(asker, &[SET, GET]);
    let them = fx.as_agent(asker);

    for (key, value) in [
        (
            "backup.policy",
            json!({ "enabled": true, "every_hours": 1, "keep": 1 }),
        ),
        ("models.responses_store", json!(true)),
        ("dreamer.plugin_suggestions", json!(false)),
        (
            "client.customization",
            serde_json::to_value(CustomizationSettings::default()).expect("json"),
        ),
    ] {
        let pending = call(&them, SET, set(key, value));
        assert_eq!(pending["status"], json!("pending"), "{key}: {pending}");
    }
    assert!(
        fx.vault.plugin_suggestions_enabled().expect("read"),
        "nothing applied"
    );

    refused(&them, GET, json!({ "key": "models.responses_store" }));
    refused(&them, GET, json!({ "key": "backup.policy" }));
    let mut profile = CustomizationSettings::default();
    profile.mode = ModeLayer::new("light").expect("mode");
    call(
        &me,
        SET,
        set(
            "client.customization",
            serde_json::to_value(&profile).expect("json"),
        ),
    );
    assert_eq!(
        get(&them, "client.customization")["value"],
        serde_json::to_value(&profile).expect("json"),
        "every member reads the profile"
    );
}
