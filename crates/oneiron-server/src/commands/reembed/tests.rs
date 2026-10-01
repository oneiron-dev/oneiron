//! Rows for the `reembed` door.

use std::path::Path;
use std::sync::Arc;

use oneiron::embed::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingReconciler,
};

use super::*;
use crate::config::{EmbedderConfig, EmbedderProvider};

const DIMS: usize = 4;
const OLD: &str = "test/old@v1";
const NEW: &str = "test/new@v2";

/// Embeds every input as one unit vector, in one space.
struct FixtureEmbedder(&'static str);

impl Embedder for FixtureEmbedder {
    fn model_id(&self) -> &str {
        self.0
    }

    fn dimensions(&self) -> usize {
        DIMS
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        Ok(vec![vec![1.0, 0.0, 0.0, 0.0]; inputs.len()])
    }
}

/// What `serve` resolves for a vault at `path` whose embedder names `model`.
fn serve_config(path: &Path, model: &str) -> ServeConfig {
    ServeConfig {
        vault_path: path.to_path_buf(),
        dimensions: DIMS,
        embedder: Some(EmbedderConfig {
            provider: EmbedderProvider::Local,
            model_id: model.to_owned(),
            dimensions: DIMS,
            ..EmbedderConfig::default()
        }),
        ..ServeConfig::default()
    }
}

fn open(config: &ServeConfig) -> oneiron::Result<Arc<oneiron::Vault>> {
    oneiron::Vault::open_owned(&config.vault_path, config.vault_config()).map(Arc::new)
}

fn put_claim(vault: &oneiron::Vault, text: &str) -> oneiron::EntityId {
    let subject = oneiron::EntityId::now();
    vault
        .put_entity(
            &subject,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )
        .expect("put subject");
    let id = oneiron::EntityId::now();
    let body = oneiron::ClaimBody::new(
        "test.reembed",
        oneiron::ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        oneiron::ClaimApprovalStatus::Auto,
        oneiron::ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    vault
        .put_claim(&id, &body, oneiron::TimeRange { start: 1, end: 1 }, 1)
        .expect("put claim");
    id
}

/// Runs the engine's reconciler with `model` until nothing is leased.
fn fill(vault: &Arc<oneiron::Vault>, model: &'static str) -> usize {
    let reconciler =
        PendingEmbeddingReconciler::new(Arc::clone(vault), Arc::new(FixtureEmbedder(model)));
    let mut filled = 0;
    for _ in 0..10 {
        let report = reconciler.reconcile_once().expect("reconcile pass");
        filled += report.filled;
        if report.leased == 0 {
            break;
        }
    }
    filled
}

/// A vault filled in one space refuses a server configured for another, and
/// `reembed` is the door across: the vault reopens in the configured space with
/// every claim queued, and the configured model fills them all.
#[test]
fn a_vault_filled_in_one_space_moves_to_the_configured_one_and_refills() {
    let dir = tempfile::tempdir().expect("vault dir");
    let old = serve_config(dir.path(), OLD);
    let new = serve_config(dir.path(), NEW);
    // Opening seeds the vault's own policy claims, so the count filled is
    // every embeddable claim, not only the three written here.
    let (ids, embedded) = {
        let vault = open(&old).expect("the vault opens in its first space");
        let ids: Vec<_> = (0..3)
            .map(|index| put_claim(&vault, &format!("claim {index}")))
            .collect();
        let embedded = fill(&vault, OLD);
        assert!(embedded >= ids.len());
        for id in &ids {
            assert!(vault.get_vector(id).expect("vector read").is_some());
        }
        (ids, embedded)
    };

    let refused = open(&new).err().expect("a different space is refused");
    assert_eq!(refused.kind(), oneiron::ErrorKind::EmbeddingModelChanged);

    let outcome = reembed_with_config(&new).expect("reembed");
    assert_eq!(
        outcome,
        ReembedOutcome {
            from: Some(OLD.to_owned()),
            to: NEW.to_owned(),
            migrated: true,
        }
    );

    let vault = open(&new).expect("the vault opens in the configured space");
    for id in &ids {
        assert_eq!(
            vault.get_vector(id).expect("vector read"),
            None,
            "the old space's vector is gone"
        );
    }
    assert_eq!(fill(&vault, NEW), embedded, "every claim is embedded again");
    for id in &ids {
        assert!(vault.get_vector(id).expect("vector read").is_some());
    }
    drop(vault);

    assert_eq!(
        reembed_with_config(&new).expect("a second reembed"),
        ReembedOutcome {
            from: None,
            to: NEW.to_owned(),
            migrated: false,
        },
        "a vault already in the configured space is left as it is"
    );
}

/// The door never creates a vault, and needs a model to move to.
#[test]
fn reembed_refuses_a_missing_vault_and_a_missing_embedder() {
    let dir = tempfile::tempdir().expect("parent dir");
    let missing = dir.path().join("absent");
    let error = reembed_with_config(&serve_config(&missing, NEW))
        .expect_err("a missing vault is refused")
        .to_string();
    assert!(error.contains("does not exist"), "{error}");
    assert!(!missing.exists(), "nothing was created");

    let rung_zero = ServeConfig {
        vault_path: dir.path().to_path_buf(),
        ..ServeConfig::default()
    };
    let error = reembed_with_config(&rung_zero)
        .expect_err("no embedder, no target space")
        .to_string();
    assert!(error.contains("[embedder]"), "{error}");
}
