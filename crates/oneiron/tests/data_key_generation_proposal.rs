//! An agent may ask the owners to start a new data-key generation behind a
//! Grant (DATAKEY-GEN-WHO = C): `vault.data_key.generation.propose` takes an
//! agent's ask when its live owner Grant lists the verb, one inbox ask per
//! owner and generation; the owner's act settles it, and the next ask names
//! the next generation. The act itself stays the owner's, and no secret
//! passes through the agent. Stored change: keep (the same Ask record; a new
//! inbox producer).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test data_key_generation_proposal`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::authority::{ActAuthority, ActSurface};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::inbox::{NotificationKind, NotificationRow};
use oneiron::memory::MEMORY_CODE_FORBIDDEN;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::world_keys::{DataKeyGenerationCause, DataKeyGenerationWays};
use oneiron::{EdgeActorClass, EntityId, Vault};
use serde_json::{Value, json};

/// The verb under test, as a literal so this file compiles before the row
/// exists (then every propose fails: no such verb row).
const PROPOSE: &str = "vault.data_key.generation.propose";
/// The ask's inbox producer, as a literal for the same reason.
const PRODUCER: &str = "vault.data_key_generation.proposal";
const REASON: &str = "a laptop was lost";

/// An owner's vault with its data key held, its owner id and proof.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_owner_carrier_vault(dir.path()).expect("owner carrier vault");
        vault.ensure_vault_key().expect("mint the vault data key");
        let owner_proof = owner(&vault).expect("owner proof");
        let owner = vault.ensure_embedded_owner_actor().expect("owner id");
        Self {
            _dir: dir,
            vault,
            owner,
            owner_proof,
        }
    }

    /// A fresh agent holding the owner's live Grant with `verbs`, and whether
    /// it confers.
    fn agent_with_verbs(&self, verbs: ScopeAxis<String>) -> (EntityId, bool) {
        let agent = define_agent(&self.vault).expect("an agent");
        let mut authority_scope = Scope::top();
        authority_scope.verbs = verbs;
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
            },
        )
        .expect("the owner's Grant");
        (agent, minted.grant.confers)
    }

    /// A fresh agent whose live Grant lists `read` and the propose verb.
    fn granted_agent(&self) -> EntityId {
        let (agent, confers) = self.agent_with_verbs(ScopeAxis::Some(BTreeSet::from([
            "read".to_owned(),
            PROPOSE.to_owned(),
        ])));
        assert!(confers, "the Grant confers");
        agent
    }

    fn propose(
        &self,
        agent: EntityId,
        reason: Option<&str>,
    ) -> oneiron::memory::MemoryResult<Value> {
        let mut input = serde_json::Map::new();
        if let Some(reason) = reason {
            input.insert("reason".to_owned(), json!(reason));
        }
        invoke(
            &self.vault.memory(agent, EdgeActorClass::Agent),
            PROPOSE,
            Value::Object(input),
        )
    }

    /// The owner's inbox asks from the proposal producer.
    fn owner_asks(&self) -> Vec<NotificationRow> {
        self.vault
            .memory(self.owner, EdgeActorClass::Human)
            .inbox_list(None, 100)
            .expect("the owner's inbox")
            .rows
            .into_iter()
            .filter(|row| row.kind == NotificationKind::Ask && row.source.producer == PRODUCER)
            .collect()
    }
}

#[test]
fn an_agent_whose_grant_lists_the_verb_asks_the_owner_once_per_generation() {
    let fx = Fixture::new();
    let agent = fx.granted_agent();
    let answer = fx
        .propose(agent, Some(REASON))
        .expect("the granted agent asks");
    assert_eq!(answer, json!({"generation": 0, "asked": true}));
    let asks = fx.owner_asks();
    assert_eq!(asks.len(), 1, "the owner holds one ask: {asks:?}");
    assert_eq!(asks[0].source.result.as_deref(), Some("0"));
    assert_eq!(asks[0].source.detail.as_deref(), Some(REASON));
    assert_eq!(asks[0].subject_refs, vec![agent.to_hex()]);
    assert!(!asks[0].acked, "the ask is not acked: {asks:?}");

    let again = fx
        .propose(agent, Some(REASON))
        .expect("the agent asks again");
    assert_eq!(again, json!({"generation": 0, "asked": false}));
    let second = fx.granted_agent();
    let second_answer = fx
        .propose(second, Some("another agent asks too"))
        .expect("a second granted agent asks");
    assert_eq!(second_answer, json!({"generation": 0, "asked": false}));
    let asks = fx.owner_asks();
    assert_eq!(asks.len(), 1, "still exactly one ask: {asks:?}");
    assert_eq!(
        asks[0].source.detail.as_deref(),
        Some(REASON),
        "the first ask stands: {asks:?}"
    );
}

#[test]
fn an_agent_whose_grant_does_not_list_the_verb_is_refused_and_no_one_is_asked() {
    let fx = Fixture::new();
    let (agent, confers) =
        fx.agent_with_verbs(ScopeAxis::Some(BTreeSet::from(["read".to_owned()])));
    assert!(confers, "the read Grant confers");
    let refused = fx
        .propose(agent, Some(REASON))
        .expect_err("a Grant without the verb asks nothing");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    let (all, _) = fx.agent_with_verbs(ScopeAxis::All);
    let refused_all = fx
        .propose(all, Some(REASON))
        .expect_err("a Grant over every verb names none");
    assert_eq!(refused_all.code, MEMORY_CODE_FORBIDDEN, "{refused_all:?}");
    assert!(fx.owner_asks().is_empty(), "no one is asked");
}

#[test]
fn the_owner_is_no_agent_and_is_refused() {
    let fx = Fixture::new();
    let refused = invoke(
        &fx.vault.memory(fx.owner, EdgeActorClass::Human),
        PROPOSE,
        json!({"reason": REASON}),
    )
    .expect_err("the owner is no agent");
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");
    assert!(fx.owner_asks().is_empty(), "no one is asked");
}

#[test]
fn a_reason_past_the_limit_is_refused() {
    let fx = Fixture::new();
    let agent = fx.granted_agent();
    let long = "x".repeat(281);
    assert!(
        fx.propose(agent, Some(&long)).is_err(),
        "a reason past 280 characters is refused"
    );
    assert!(fx.owner_asks().is_empty(), "no one is asked");
}

#[test]
fn the_owners_new_generation_settles_the_ask_and_the_next_ask_names_the_next_generation() {
    let fx = Fixture::new();
    let agent = fx.granted_agent();
    let answer = fx
        .propose(agent, Some(REASON))
        .expect("the granted agent asks");
    assert_eq!(answer, json!({"generation": 0, "asked": true}));

    fx.vault
        .add_vault_key_device()
        .expect("this install's device wrap");
    let uncovered = fx
        .vault
        .data_key_generation_preview(&DataKeyGenerationWays {
            password: None,
            passkeys: Vec::new(),
            escrows: Vec::new(),
            confirmed_removals: BTreeSet::new(),
        })
        .expect("preview");
    let confirmed: BTreeSet<String> = uncovered.iter().map(|info| info.id.clone()).collect();
    let owner_proof = owner(&fx.vault).expect("owner proof");
    let outcome = fx
        .vault
        .start_data_key_generation_as(
            &ActAuthority::Owner(owner_proof, ActSurface::ThisInstall),
            DataKeyGenerationCause::OwnerRequest,
            &DataKeyGenerationWays {
                password: None,
                passkeys: Vec::new(),
                escrows: Vec::new(),
                confirmed_removals: confirmed,
            },
        )
        .expect("the owner starts a new generation");
    assert_eq!(outcome.generation, 1);

    let asks = fx.owner_asks();
    assert_eq!(asks.len(), 1, "one ask stands: {asks:?}");
    assert_eq!(asks[0].source.result.as_deref(), Some("0"));
    assert!(asks[0].acked, "the generation-0 ask is settled: {asks:?}");

    let next = fx
        .propose(agent, Some(REASON))
        .expect("the agent asks again");
    assert_eq!(next, json!({"generation": 1, "asked": true}));
    let asks = fx.owner_asks();
    assert_eq!(asks.len(), 2, "a second ask exists: {asks:?}");
    let second = asks
        .iter()
        .find(|row| row.source.result.as_deref() == Some("1"))
        .expect("the generation-1 ask");
    assert!(!second.acked, "the new ask is not acked: {asks:?}");
}
