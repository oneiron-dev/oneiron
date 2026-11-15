//! DESIGN 15-setting-primitive, stage 1, lane SETTING-DIALS PR D2: two plain model settings of
//! `llm/` become catalogue keys.
//! - `models.description_policy` and `models.resident_route` (one row per model slot) are in the
//!   catalogue and read their old defaults, through the verb and through each kept reader;
//! - the owner sets the description policy through `vault.settings.set`, and routing reads that
//!   policy; a policy `DescriptionPolicy::validate` refuses is refused;
//! - a resident route lands only while the manifest in force admits it, and a stored route a
//!   later manifest no longer admits reads as the slot's pin until one admits it again;
//! - both stay owner acts: an agent's change waits on a check-in, and an agent with no class
//!   reads neither.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test setting_dials_2`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oneiron::authority::{ActSurface, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::ReasoningEffort;
use oneiron::llm::manifest::{
    MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
};
use oneiron::llm::registry::ModelWireFormat;
use oneiron::llm::routing::{DescriptionPolicy, ModelDescription, OwnerModelLine};
use oneiron::memory::Memory;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, ModelId, ModelLocality, ModelTierRef, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

const GET: &str = "vault.settings.get";
const SET: &str = "vault.settings.set";
const POLICY: &str = "models.description_policy";
const ROUTE: &str = "models.resident_route";
const T0: u64 = 1_790_000_000;
const TIER: &str = "setting-dials";

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

fn set(key: &str, item: Option<&str>, value: Value) -> Value {
    json!({ "key": key, "item": item, "scope": { "kind": "vault" }, "value": value })
}

fn get(memory: &Memory<'_>, key: &str, item: Option<&str>) -> Value {
    call(memory, GET, json!({ "key": key, "item": item }))
}

fn model(id: &str) -> ModelId {
    ModelId::new(id.to_owned()).expect("model id")
}

/// A description policy `DescriptionPolicy::validate` takes: one model with the owner's line.
fn policy() -> DescriptionPolicy {
    DescriptionPolicy {
        models: vec![ModelDescription {
            model: model("dials/described@r1"),
            wire: ModelWireFormat::OpenaiCompat,
            locality: ModelLocality::OwnServer,
            owner: Some(OwnerModelLine {
                model: model("dials/described@r1"),
                text: "the owner's everyday model".into(),
                expected_quality: 800_000,
            }),
            public_benchmark: None,
            vendor: None,
            effort_ladder: vec![ReasoningEffort::Low, ReasoningEffort::High],
        }],
        contradiction_margin_millionths: 100_000,
        vault_effort: Some(ReasoningEffort::Low),
        purpose_effort: BTreeMap::new(),
        global_effort: None,
    }
}

/// A v2 manifest binding every role to its own model: the extraction encoder on the Oneironer
/// slot (pinned on the device), every other role on the LLM slot (pinned to the owner's server).
/// With `local`, every LLM-slot role but the teacher also names an on-device model, so a
/// narrowing of the LLM slot to the device is admitted; the teacher's row is the same either way,
/// so the saved probe approval holds for both.
fn manifest(local: bool) -> ModelManifest {
    let mut roles = BTreeMap::new();
    for role in MODEL_ROLES {
        let slot = if role == ModelRole::ExtractionEncoder {
            ModelSlot::Oneironer
        } else {
            ModelSlot::Llm
        };
        let route_models =
            if local && slot == ModelSlot::Llm && role != ModelRole::ExtractionTeacher {
                BTreeMap::from([(
                    ModelLocality::OnDevice,
                    model(&format!("dials/{role:?}-local@r1")),
                )])
            } else {
                BTreeMap::new()
            };
        roles.insert(
            role,
            ModelBinding {
                model: model(&format!("dials/{role:?}@r1")),
                slot,
                tier: ModelTierRef(TIER.to_owned()),
                route_models,
                disposition: None,
                reads_audio: false,
            },
        );
    }
    ModelManifest {
        version: 2,
        roles,
        routes: BTreeMap::from([
            (ModelSlot::Llm, ModelLocality::OwnServer),
            (ModelSlot::Embedder, ModelLocality::OwnServer),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]),
        verdict: None,
        seat_policy: None,
    }
}

/// Pins `manifest` with a passing teacher-probe approval, as the bench publishes one.
fn pin_manifest(vault: &Vault, manifest: &ModelManifest) {
    let probe = vault.teacher_probe_policy(None).expect("probe policy");
    let approval = TeacherProbeApproval::for_scored_checkpoint(manifest, &probe, 1_000_000)
        .expect("probe approval");
    vault
        .set_model_manifest_with_teacher_approval(manifest, &approval)
        .expect("manifest pinned");
}

#[test]
fn the_two_keys_read_their_old_defaults() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let read = get(&me, POLICY, None);
    assert_eq!(read["value"], Value::Null, "{read}");
    assert_eq!(read["source"], json!({ "from": "default" }));
    assert_eq!(fx.vault.description_policy().expect("read"), None);

    pin_manifest(&fx.vault, &manifest(true));
    for item in ["llm", "embedder", "oneironer"] {
        let read = get(&me, ROUTE, Some(item));
        assert_eq!(read["value"], Value::Null, "{item}: {read}");
    }
    assert_eq!(
        fx.vault.model_route(ModelSlot::Llm).expect("read"),
        Some(ModelLocality::OwnServer),
        "no narrowing: the slot takes its pin"
    );
}

#[test]
fn an_owner_set_description_policy_is_what_routing_reads() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    let applied = call(
        &me,
        SET,
        set(POLICY, None, serde_json::to_value(policy()).expect("json")),
    );
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(fx.vault.description_policy().expect("read"), Some(policy()));

    let mut bad = policy();
    bad.contradiction_margin_millionths = 2_000_000;
    refused(
        &me,
        SET,
        set(POLICY, None, serde_json::to_value(bad).expect("json")),
    );
    let mut empty = policy();
    empty.models.clear();
    refused(
        &me,
        SET,
        set(POLICY, None, serde_json::to_value(empty).expect("json")),
    );
    assert_eq!(
        fx.vault.description_policy().expect("read"),
        Some(policy()),
        "a refused policy changes nothing"
    );

    call(&me, SET, set(POLICY, None, Value::Null));
    assert_eq!(
        fx.vault.description_policy().expect("read"),
        None,
        "null is no policy again"
    );
}

#[test]
fn a_resident_route_narrows_only_while_the_manifest_admits_it() {
    let fx = Fixture::rooted();
    let me = fx.as_owner();

    refused(&me, SET, set(ROUTE, Some("llm"), json!("on_device")));
    pin_manifest(&fx.vault, &manifest(true));

    let applied = call(&me, SET, set(ROUTE, Some("llm"), json!("on_device")));
    assert_eq!(applied["status"], json!("applied"), "{applied}");
    assert_eq!(
        fx.vault.model_route(ModelSlot::Llm).expect("read"),
        Some(ModelLocality::OnDevice)
    );
    refused(&me, SET, set(ROUTE, Some("llm"), json!("third_party")));
    refused(&me, SET, set(ROUTE, Some("oneironer"), json!("own_server")));
    refused(&me, SET, set(ROUTE, Some("gpu"), json!("on_device")));
    assert_eq!(
        fx.vault.model_route(ModelSlot::Llm).expect("read"),
        Some(ModelLocality::OnDevice),
        "a refused route changes nothing"
    );

    fx.vault
        .set_model_manifest(&manifest(false))
        .expect("a manifest with no on-device models");
    assert_eq!(
        fx.vault.model_route(ModelSlot::Llm).expect("read"),
        Some(ModelLocality::OwnServer),
        "a narrowing the manifest no longer admits reads as the pin"
    );
    assert_eq!(
        get(&me, ROUTE, Some("llm"))["value"],
        json!("on_device"),
        "the owner's row stays as set"
    );

    fx.vault
        .set_model_manifest(&manifest(true))
        .expect("the on-device models again");
    assert_eq!(
        fx.vault.model_route(ModelSlot::Llm).expect("read"),
        Some(ModelLocality::OnDevice),
        "the stored narrowing is in force again"
    );
    call(&me, SET, set(ROUTE, Some("llm"), Value::Null));
    assert_eq!(
        fx.vault.model_route(ModelSlot::Llm).expect("read"),
        Some(ModelLocality::OwnServer),
        "a clear always lands"
    );
}

#[test]
fn they_stay_owner_acts() {
    let fx = Fixture::rooted();
    pin_manifest(&fx.vault, &manifest(true));
    let asker = fx.agent();
    fx.grant(asker, &[SET, GET]);
    let them = fx.as_agent(asker);

    for (key, item, value) in [
        (POLICY, None, serde_json::to_value(policy()).expect("json")),
        (ROUTE, Some("llm"), json!("on_device")),
    ] {
        let pending = call(&them, SET, set(key, item, value));
        assert_eq!(pending["status"], json!("pending"), "{key}: {pending}");
    }
    assert_eq!(
        fx.vault.description_policy().expect("read"),
        None,
        "nothing applied"
    );
    assert_eq!(
        fx.vault.model_route(ModelSlot::Llm).expect("read"),
        Some(ModelLocality::OwnServer),
        "nothing applied"
    );

    refused(&them, GET, json!({ "key": POLICY }));
    refused(&them, GET, json!({ "key": ROUTE, "item": "llm" }));
}
