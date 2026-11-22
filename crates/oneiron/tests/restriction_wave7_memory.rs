#![cfg(oneiron_test_support)]
//! Restriction wave 7 through the engine (C27): an agent whose own live owner grant names
//! `vault.structural.put` mints a PERSON while the owner's setting `memory.person.agent_may_mint`
//! is on. Key absent, grant without the verb, and MACHINE stay refused.
//!
//! The owner sets the key through the `vault.settings.set` verb, as
//! `setting_primitive.rs` does; the agent's grant is the owner's live grant minted through the
//! public verbs. Uses only APIs that exist on the base, so the red test fails there by a
//! refusal, not a compile error.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test restriction_wave7_memory`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, StructuralPutInput};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use serde_json::json;

const SET: &str = "vault.settings.set";
const KEY: &str = "memory.person.agent_may_mint";
const PUT_VERB: &str = "vault.structural.put";

struct Fixture {
    vault: Vault,
    _dir: tempfile::TempDir,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned: the
    /// writer lease is what lets the owner's handle call the owner verbs by name.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let keystore = Arc::new(MemoryKeystore::new());
        let vault = Vault::open_owned(dir.path(), VaultConfig::device()).expect("owned vault");
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
    fn agent(&self, name: &str) -> EntityId {
        let id = self.vault.new_entity_id().expect("agent id");
        create_agent_definition_as(
            &self.vault,
            &self.owner_proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: id,
                definition: serde_json::from_value(json!({
                    "agent_id": name,
                    "desc": "restriction wave 7 fixture",
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

    /// The owner turns `KEY` on at the vault scope through its verb.
    fn turn_key_on(&self) {
        let applied = invoke(
            &self.as_owner(),
            SET,
            json!({ "key": KEY, "scope": {"kind": "vault"}, "value": true }),
        )
        .unwrap_or_else(|error| panic!("{SET} answers: {error:?}"));
        assert_eq!(applied["status"], json!("applied"), "{applied}");
        assert_eq!(applied["value"], json!(true), "{applied}");
    }

    /// This agent mints one PERSON through the structural put.
    fn mint_person(
        &self,
        agent: EntityId,
    ) -> Result<oneiron::memory::EntityRefReceipt, MemoryError> {
        let now = self.vault.now_recorded_at();
        self.as_agent(agent).put_structural(&StructuralPutInput {
            id: None,
            kind: "PERSON".to_owned(),
            body: json!({"name": "Wave Seven Minted"}),
            text_fields: None,
            edges: None,
            occurred_at: now,
            learned_at: None,
        })
    }
}

fn assert_forbidden(error: &MemoryError, what: &str) {
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{what}: {error:?}");
}

/// C27 red: key on, the agent's grant names the put's verb, and the agent
/// mints a PERSON. On the base the put is refused.
#[test]
fn c27_agent_mints_person_when_key_on() {
    let fx = Fixture::rooted();
    let agent = fx.agent("wave7-minter");
    fx.grant(agent, &[PUT_VERB]);
    fx.turn_key_on();

    let receipt = fx
        .mint_person(agent)
        .expect("the granted agent mints a PERSON");
    let id = EntityId::from_hex(&receipt.id_hex).expect("minted id");
    assert_eq!(
        fx.vault.get_entity_type(&id).expect("read the row"),
        Some(ENTITY_TYPE_PERSON),
        "the minted row is typed PERSON"
    );
}

/// C27 guard: key absent, the agent's grant names the verb, and the mint
/// keeps today's refusal.
#[test]
fn c27_agent_refused_person_when_key_absent() {
    let fx = Fixture::rooted();
    let agent = fx.agent("wave7-key-absent");
    fx.grant(agent, &[PUT_VERB]);

    let error = fx
        .mint_person(agent)
        .expect_err("no mint with the key absent");
    assert_forbidden(&error, "mint with the key absent");
    assert!(
        error.message.contains("may not mint PERSON"),
        "today's refusal text is kept: {error:?}"
    );
}

/// C27 guard: key on, the agent's grant names another verb, and the mint
/// is refused.
#[test]
fn c27_agent_refused_person_when_grant_lacks_verb() {
    let fx = Fixture::rooted();
    let agent = fx.agent("wave7-grant-lacks");
    fx.grant(agent, &["vault.runs.review"]);
    fx.turn_key_on();

    let error = fx
        .mint_person(agent)
        .expect_err("no mint with a grant lacking the verb");
    assert_forbidden(&error, "mint with a grant lacking the verb");
}

/// C27 guard: key on, and MACHINE stays refused for the agent.
#[test]
fn c27_machine_still_refused_when_key_on() {
    let fx = Fixture::rooted();
    let agent = fx.agent("wave7-machine");
    fx.grant(agent, &[PUT_VERB]);
    fx.turn_key_on();

    let now = fx.vault.now_recorded_at();
    let error = fx
        .as_agent(agent)
        .put_structural(&StructuralPutInput {
            id: None,
            kind: "MACHINE".to_owned(),
            body: json!({}),
            text_fields: None,
            edges: None,
            occurred_at: now,
            learned_at: None,
        })
        .expect_err("no MACHINE through the facade");
    assert_forbidden(&error, "MACHINE with the key on");
    assert!(
        error.message.contains("MACHINE"),
        "the MACHINE refusal stands: {error:?}"
    );
}
