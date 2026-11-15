//! DESIGN 15-setting-primitive, stage 1 (SETTING-KEYED-B, KB1): the message-stream policy's
//! table becomes catalogue keys, read through the kept public reader.
//! - each moved key is in the catalogue and reads its old default until a row stands;
//! - the owner's rows, set through `vault.settings.set`, are what `Vault::message_stream_policy`
//!   reads; an agent's own write-mode row decides for that agent only;
//! - the old checks refuse what they refused: a zero idle timeout, a zero streaming window;
//! - an agent's change waits on a check-in under its own Grant.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_keyed_b_1`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    DEFAULT_MESSAGE_STREAM_IDLE_MS, Memory, MessageStreamPolicy, MessageWriteMode, StreamCadence,
    StreamSyncVisibility,
};
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
const MODE: &str = "memory.message_stream.mode";
const IDLE: &str = "memory.message_stream.idle_timeout_ms";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Vault,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
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
                    "agent_id": format!("keyed-b-agent-{}", id.to_hex()),
                    "desc": "setting keyed-b fixture",
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

fn vault_scope() -> Value {
    json!({ "kind": "vault" })
}

fn agent_scope(id: EntityId) -> Value {
    json!({ "kind": "agent", "id": id.to_hex() })
}

fn set(key: &str, scope: Value, value: Value) -> Value {
    json!({ "key": key, "scope": scope, "value": value })
}

fn get(memory: &Memory<'_>, key: &str, at: Value) -> Value {
    call(memory, GET, json!({ "key": key, "at": at }))
}

fn streamed_all_devices() -> Value {
    json!({ "streamed": { "visibility": "all_devices", "cadence": { "per_window": { "chars": 40 } } } })
}

#[test]
fn the_message_stream_keys_read_their_old_defaults() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let mode = get(&me, MODE, json!([]));
    assert_eq!(mode["value"], json!("atomic"), "{mode}");
    assert_eq!(mode["source"], json!({ "from": "default" }));
    let idle = get(&me, IDLE, json!([]));
    assert_eq!(
        idle["value"],
        json!(DEFAULT_MESSAGE_STREAM_IDLE_MS),
        "{idle}"
    );
    assert_eq!(idle["source"], json!({ "from": "default" }));

    assert_eq!(
        fx.vault.message_stream_policy().expect("policy"),
        MessageStreamPolicy::default(),
        "with no row the policy reads as the old table's absent row did"
    );
}

#[test]
fn the_owners_rows_are_what_the_policy_reads() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let applied = call(&me, SET, set(MODE, vault_scope(), streamed_all_devices()));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    let applied = call(&me, SET, set(IDLE, vault_scope(), json!(45_000)));
    assert_eq!(applied["status"], json!("applied"), "{applied}");

    assert_eq!(
        fx.vault.message_stream_policy().expect("policy"),
        MessageStreamPolicy {
            default_mode: MessageWriteMode::Streamed {
                visibility: StreamSyncVisibility::AllDevices,
                cadence: StreamCadence::PerWindow { chars: 40 },
            },
            idle_timeout_ms: 45_000,
        }
    );

    let cleared = call(
        &me,
        SET,
        json!({ "key": IDLE, "scope": vault_scope(), "value": null }),
    );
    assert_eq!(cleared["status"], json!("applied"), "{cleared}");
    assert_eq!(
        fx.vault
            .message_stream_policy()
            .expect("policy")
            .idle_timeout_ms,
        DEFAULT_MESSAGE_STREAM_IDLE_MS,
        "a cleared row reads the default again"
    );
}

#[test]
fn an_agents_own_mode_row_decides_for_that_agent_only() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();
    let agent = fx.agent();
    let other = fx.agent();

    call(
        &me,
        SET,
        set(
            MODE,
            agent_scope(agent),
            json!({ "streamed": { "visibility": "originator_only", "cadence": "per_token" } }),
        ),
    );

    let own = get(&me, MODE, json!([agent_scope(agent)]));
    assert_eq!(
        own["value"],
        json!({ "streamed": { "visibility": "originator_only", "cadence": "per_token" } }),
        "{own}"
    );
    assert_eq!(
        own["source"],
        json!({ "from": "row", "scope": agent_scope(agent) })
    );
    let others = get(&me, MODE, json!([agent_scope(other)]));
    assert_eq!(others["value"], json!("atomic"), "{others}");
    assert_eq!(
        fx.vault
            .message_stream_policy()
            .expect("policy")
            .default_mode,
        MessageWriteMode::Atomic,
        "the vault's mode is not the agent's"
    );
}

#[test]
fn the_old_checks_refuse_what_they_refused() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let zero_idle = refused(&me, SET, set(IDLE, vault_scope(), json!(0)));
    assert!(zero_idle.contains("idle timeout"), "{zero_idle}");
    let zero_window = refused(
        &me,
        SET,
        set(
            MODE,
            vault_scope(),
            json!({ "streamed": { "visibility": "all_devices", "cadence": { "per_window": { "chars": 0 } } } }),
        ),
    );
    assert!(zero_window.contains("window"), "{zero_window}");
    assert_eq!(
        fx.vault.message_stream_policy().expect("policy"),
        MessageStreamPolicy::default(),
        "nothing refused was written"
    );
}

#[test]
fn an_agents_change_of_the_policy_waits_on_a_check_in() {
    let fx = Fixture::rooted();
    let agent = fx.agent();
    fx.grant(agent, &[SET, GET]);
    let it = fx.as_agent(agent);

    let asked = call(&it, SET, set(IDLE, vault_scope(), json!(5_000)));
    assert_eq!(asked["status"], json!("pending"), "{asked}");
    assert_eq!(
        fx.vault
            .message_stream_policy()
            .expect("policy")
            .idle_timeout_ms,
        DEFAULT_MESSAGE_STREAM_IDLE_MS,
        "a waiting change writes nothing"
    );
}
