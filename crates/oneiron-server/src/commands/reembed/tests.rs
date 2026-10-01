//! Rows for the `reembed` door.

use std::path::Path;
use std::sync::Arc;

use oneiron::embed::{
    Embedder, EmbedderLocality, PendingEmbeddingInput, PendingEmbeddingReconciler,
};

use super::*;
use crate::config::{EmbedderAttention, EmbedderConfig, EmbedderProvider, LocalEmbedderConfig};

const DIMS: usize = 4;
const OLD: &str = "test/old@v1";
const NEW: &str = "test/new@v2";

/// Embeds every input as one unit vector of `dimensions`, in one space.
struct FixtureEmbedder {
    model: &'static str,
    dimensions: usize,
}

impl Embedder for FixtureEmbedder {
    fn model_id(&self) -> &str {
        self.model
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> oneiron::Result<Vec<Vec<f32>>> {
        let mut unit = vec![0.0; self.dimensions];
        unit[0] = 1.0;
        Ok(vec![unit; inputs.len()])
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
    fill_at(vault, model, DIMS)
}

fn fill_at(vault: &Arc<oneiron::Vault>, model: &'static str, dimensions: usize) -> usize {
    let reconciler = PendingEmbeddingReconciler::new(
        Arc::clone(vault),
        Arc::new(FixtureEmbedder { model, dimensions }),
    );
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

    let outcome = reembed_with_config(&new, false).expect("reembed");
    assert_eq!(
        outcome,
        ReembedOutcome {
            from: Some(OLD.to_owned()),
            to: NEW.to_owned(),
            transform: None,
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
        reembed_with_config(&new, false).expect("a second reembed"),
        ReembedOutcome {
            from: None,
            to: NEW.to_owned(),
            transform: None,
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
    reembed_with_config(&serve_config(&missing, NEW), false)
        .expect_err("a missing vault is refused");
    assert!(!missing.exists(), "nothing was created");

    let rung_zero = ServeConfig {
        vault_path: dir.path().to_path_buf(),
        ..ServeConfig::default()
    };
    reembed_with_config(&rung_zero, false).expect_err("no embedder, no target space");
    assert!(
        !dir.path().join("data.mdb").exists(),
        "nothing was created without a target space"
    );
}

/// `--force` runs the same swap under the pin the vault already holds: every
/// vector dropped, every record queued, and the model fills them all again.
#[test]
fn a_forced_reembed_refills_a_vault_already_in_the_configured_space() {
    let dir = tempfile::tempdir().expect("vault dir");
    let config = serve_config(dir.path(), NEW);
    let (ids, embedded) = {
        let vault = open(&config).expect("the vault opens");
        let ids: Vec<_> = (0..2)
            .map(|index| put_claim(&vault, &format!("claim {index}")))
            .collect();
        (ids, fill(&vault, NEW))
    };
    assert_eq!(
        reembed_with_config(&config, true).expect("forced reembed"),
        ReembedOutcome {
            from: None,
            to: NEW.to_owned(),
            transform: None,
            migrated: true,
        }
    );
    let vault = open(&config).expect("the vault still opens in its space");
    for id in &ids {
        assert_eq!(vault.get_vector(id).expect("vector read"), None);
    }
    assert_eq!(
        fill(&vault, NEW),
        embedded,
        "every record is embedded again"
    );
}

/// A vault's width is fixed when it is created: a model of another width is
/// refused with the index refusal underneath, and the vault is left as it was.
#[test]
fn a_model_of_another_width_is_refused_and_the_vault_left_alone() {
    let dir = tempfile::tempdir().expect("vault dir");
    let old = serve_config(dir.path(), OLD);
    let id = {
        let vault = open(&old).expect("the vault opens");
        let id = put_claim(&vault, "claim");
        fill(&vault, OLD);
        id
    };
    let mut wider = serve_config(dir.path(), NEW);
    wider.dimensions = DIMS * 2;
    if let Some(embedder) = wider.embedder.as_mut() {
        embedder.dimensions = DIMS * 2;
    }
    let error = reembed_with_config(&wider, false).expect_err("another width is refused");
    assert_eq!(
        error
            .downcast_ref::<oneiron::Error>()
            .map(oneiron::Error::kind),
        Some(oneiron::ErrorKind::HnswConfigChanged)
    );
    let vault = open(&old).expect("the vault still opens in its own space");
    assert!(vault.get_vector(&id).expect("vector read").is_some());
}

/// `serve`'s refusal of another model's vault keeps its typed kind under the
/// remedy it adds.
#[test]
fn the_model_change_remedy_keeps_the_typed_refusal() {
    let dir = tempfile::tempdir().expect("vault dir");
    {
        let vault = open(&serve_config(dir.path(), OLD)).expect("the vault opens");
        put_claim(&vault, "claim");
        fill(&vault, OLD);
    }
    let refused = open(&serve_config(dir.path(), NEW))
        .err()
        .expect("a different space is refused");
    let explained = super::with_model_change_remedy(refused);
    assert_eq!(
        explained
            .downcast_ref::<oneiron::Error>()
            .map(oneiron::Error::kind),
        Some(oneiron::ErrorKind::EmbeddingModelChanged)
    );
}

// ─── the transform pin ───────────────────────────────────────────────────

/// The committed metadata of a model whose files say: bidirectional, mean
/// pooled, int8-quantised, 1024 wide.
const MODEL_FILES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/embed/models/pplx"
);
const WIDE: usize = 1024;

/// What `serve` resolves for a vault whose local model's files are on this
/// host, with the attention the section names.
fn local_config(path: &Path, attention: EmbedderAttention) -> ServeConfig {
    ServeConfig {
        vault_path: path.to_path_buf(),
        dimensions: WIDE,
        embedder: Some(EmbedderConfig {
            provider: EmbedderProvider::Local,
            model_id: OLD.to_owned(),
            dimensions: WIDE,
            local: LocalEmbedderConfig {
                model_dir: Some(MODEL_FILES.into()),
                attention,
                ..LocalEmbedderConfig::default()
            },
            ..EmbedderConfig::default()
        }),
        ..ServeConfig::default()
    }
}

fn refusal_kind(config: &ServeConfig) -> Option<oneiron::ErrorKind> {
    open(config).err().map(|error| error.kind())
}

/// Opens a vault under `config`, writes a claim and fills it.
fn filled(config: &ServeConfig) {
    let vault = open(config).expect("the vault opens");
    put_claim(&vault, "claim");
    assert!(fill_at(&vault, OLD, WIDE) >= 1);
}

/// Changing how the model's output becomes a vector, under the same model,
/// is a different space: open refuses, and keeps refusing across restarts,
/// until `reembed` repins the transform and queues every record again.
#[test]
fn a_changed_attention_refuses_open_until_reembed_moves_the_vault() {
    let dir = tempfile::tempdir().expect("vault dir");
    let own = local_config(dir.path(), EmbedderAttention::Auto);
    let causal = local_config(dir.path(), EmbedderAttention::Causal);
    filled(&own);

    for _restart in 0..2 {
        assert_eq!(
            refusal_kind(&causal),
            Some(oneiron::ErrorKind::EmbeddingTransformChanged)
        );
    }
    assert_eq!(
        refusal_kind(&own),
        None,
        "the vault's own transform still opens"
    );
    let refused = open(&causal).err().expect("refused");
    assert_eq!(
        super::with_model_change_remedy(refused)
            .downcast_ref::<oneiron::Error>()
            .map(oneiron::Error::kind),
        Some(oneiron::ErrorKind::EmbeddingTransformChanged),
        "serve's remedy keeps the typed refusal"
    );

    let outcome = reembed_with_config(&causal, false).expect("reembed");
    assert_eq!(outcome.from, None, "the model did not change");
    assert!(outcome.migrated);
    assert_eq!(outcome.transform, causal.vault_config().embedding_transform);

    let vault = open(&causal).expect("the vault opens in the new transform");
    assert!(
        fill_at(&vault, OLD, WIDE) >= 1,
        "every record is embedded again"
    );
    drop(vault);
    assert_eq!(
        refusal_kind(&own),
        Some(oneiron::ErrorKind::EmbeddingTransformChanged),
        "the pin moved with the vectors"
    );
}

/// Settings that never touch a stored vector leave the vault open: query
/// prompts, weight precision, batch size.
#[test]
fn a_query_only_change_keeps_the_vault_open() {
    let dir = tempfile::tempdir().expect("vault dir");
    let own = local_config(dir.path(), EmbedderAttention::Auto);
    filled(&own);
    let mut queried = own.clone();
    if let Some(embedder) = queried.embedder.as_mut() {
        embedder.query_instruction = Some("Represent this question: ".to_owned());
        embedder.batch_size = 4;
        embedder.local.quant = crate::config::EmbedderQuant::None;
    }
    assert_eq!(
        queried.vault_config().embedding_transform,
        own.vault_config().embedding_transform
    );
    assert_eq!(refusal_kind(&queried), None);
}

/// A vault filled before the transform was pinned holds the model's own
/// transform. The first open under a declared transform adopts it, and from
/// then on another transform is refused.
#[test]
fn a_vault_without_a_pinned_transform_adopts_the_configured_one() {
    let dir = tempfile::tempdir().expect("vault dir");
    let own = local_config(dir.path(), EmbedderAttention::Auto);
    {
        let mut unpinned = own.vault_config();
        unpinned.embedding_transform = None;
        let vault = oneiron::Vault::open_owned(dir.path(), unpinned)
            .map(Arc::new)
            .expect("the vault opens without a transform");
        put_claim(&vault, "claim");
        assert!(fill_at(&vault, OLD, WIDE) >= 1);
    }
    assert_eq!(
        refusal_kind(&own),
        None,
        "the first declared transform is adopted"
    );
    assert_eq!(
        refusal_kind(&local_config(dir.path(), EmbedderAttention::Causal)),
        Some(oneiron::ErrorKind::EmbeddingTransformChanged)
    );
}
