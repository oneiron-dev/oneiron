//! `vault.worlds.vectors` by verb name, as a code-mode or SDK caller runs it: the
//! owner without a grant, or a holder of a Steward grant naming `read` that
//! reaches the whole vault, reads where each world's text vectors are made on
//! the install that answers. Others are refused. No `world_vectors` import:
//! this file compiles on origin/main, where the verb is unknown, and fails
//! there at run time.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test world_vectors_grant`.
#![cfg(all(feature = "sync", oneiron_test_support))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::claim::base_world_id;
use oneiron::embed::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingReconciler,
};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryResult};
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::{ENGINE_CONTROLS_VERBS, define_agent};
use oneiron::test_doors::steward::{STEWARD_READ_VERB, stand_steward_grant};
use oneiron::test_doors::substrate_reads::stand_project_steward_grant;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

struct GrantEmbedder;

impl Embedder for GrantEmbedder {
    fn model_id(&self) -> &str {
        "test/vault-text@v1"
    }

    fn dimensions(&self) -> usize {
        8
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        Ok(inputs.iter().map(|_| vec![0.0; 8]).collect())
    }
}

fn open_grant_vault(dir: &tempfile::TempDir) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.dimensions = 8;
    config.embedding_model = Some("test/vault-text@v1".to_owned());
    let vault = Vault::open(dir.path(), config).expect("grant vault");
    oneiron::test_support::provision_engine_machines(&vault);
    Arc::new(vault)
}

fn open_owned_grant_vault(dir: &tempfile::TempDir) -> Arc<Vault> {
    let mut config = VaultConfig::device();
    config.dimensions = 8;
    config.embedding_model = Some("test/vault-text@v1".to_owned());
    let vault = Vault::open_owned(dir.path(), config).expect("owned grant vault");
    oneiron::test_support::provision_engine_machines(&vault);
    Arc::new(vault)
}

fn read(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    verb: &str,
    input: Value,
) -> MemoryResult<Value> {
    invoke(&vault.memory(actor, class), verb, input)
}

fn assert_refused(answer: MemoryResult<Value>, verb: &str) {
    let error = answer.expect_err(&format!("{verb}: an ungranted reader is refused"));
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{verb}: {error:?}");
}

fn base_vectors(answer: &Value) -> &str {
    let base = base_world_id().to_hex();
    let worlds = answer
        .get("worlds")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("worlds array missing: {answer}"));
    for entry in worlds {
        if entry.get("world").and_then(Value::as_str) == Some(base.as_str()) {
            return entry
                .get("vectors")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("vectors string missing: {answer}"));
        }
    }
    panic!("base world {base} missing: {answer}")
}

#[test]
fn a_steward_reader_reads_world_vectors_and_an_ungranted_agent_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_grant_vault(&dir);
    let _reconciler = PendingEmbeddingReconciler::new(Arc::clone(&vault), Arc::new(GrantEmbedder));
    let agent = define_agent(&vault).expect("an agent");
    let worlds = || {
        read(
            &vault,
            agent,
            EdgeActorClass::Agent,
            "vault.worlds.vectors",
            json!({}),
        )
    };

    assert_refused(worlds(), "vault.worlds.vectors");

    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB]).expect("a read grant");
    let answer =
        worlds().unwrap_or_else(|error| panic!("a Steward `read` holder reads: {error:?}"));
    assert_eq!(
        base_vectors(&answer),
        "vault_space",
        "base reality answers vault_space"
    );

    // The verb is the grant's own: an agent holding only `engine.controls`
    // reads no world vectors.
    let controls_only = define_agent(&vault).expect("a second agent");
    stand_steward_grant(&vault, controls_only, &ENGINE_CONTROLS_VERBS).expect("a controls grant");
    assert_refused(
        read(
            &vault,
            controls_only,
            EdgeActorClass::Agent,
            "vault.worlds.vectors",
            json!({}),
        ),
        "vault.worlds.vectors",
    );
}

#[test]
fn a_grant_narrowed_to_one_project_reads_no_world_vectors() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_grant_vault(&dir);
    let _reconciler = PendingEmbeddingReconciler::new(Arc::clone(&vault), Arc::new(GrantEmbedder));
    let agent = define_agent(&vault).expect("an agent");
    let own_project = EntityId::now();
    let worlds = || {
        read(
            &vault,
            agent,
            EdgeActorClass::Agent,
            "vault.worlds.vectors",
            json!({}),
        )
    };

    stand_project_steward_grant(&vault, agent, &[STEWARD_READ_VERB], own_project)
        .expect("a grant narrowed to one project");
    assert_refused(worlds(), "vault.worlds.vectors");

    stand_steward_grant(&vault, agent, &[STEWARD_READ_VERB])
        .expect("a grant across the whole vault");
    let answer = worlds().unwrap_or_else(|error| panic!("a whole-vault holder reads: {error:?}"));
    assert_eq!(
        base_vectors(&answer),
        "vault_space",
        "base reality answers vault_space"
    );
}

#[test]
fn the_owner_reads_world_vectors_without_a_grant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open_owned_grant_vault(&dir);
    let _reconciler = PendingEmbeddingReconciler::new(Arc::clone(&vault), Arc::new(GrantEmbedder));
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let answer = read(
        &vault,
        owner,
        EdgeActorClass::Human,
        "vault.worlds.vectors",
        json!({}),
    )
    .unwrap_or_else(|error| panic!("the owner reads: {error:?}"));
    assert_eq!(
        base_vectors(&answer),
        "vault_space",
        "base reality answers vault_space"
    );
}
