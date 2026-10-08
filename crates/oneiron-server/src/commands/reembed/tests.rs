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

/// The committed metadata of a four-wide model: bidirectional, mean pooled,
/// normalised. Read in place, as an operator's `model_dir` is.
const TINY_FILES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/embed/models/tiny"
);
/// The transform those files declare.
const TINY: &str =
    "attn=bidirectional;pool=mean;include_prompt=true;doc_prompt=none;chain=normalize;dims=4";

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

/// What `serve` resolves for a vault at `path` whose embedder names `model`,
/// read from the four-wide model's files.
fn serve_config(path: &Path, model: &str) -> ServeConfig {
    ServeConfig {
        vault_path: path.to_path_buf(),
        dimensions: DIMS,
        embedder: Some(EmbedderConfig {
            provider: EmbedderProvider::Local,
            model_id: model.to_owned(),
            dimensions: DIMS,
            local: LocalEmbedderConfig {
                model_dir: Some(TINY_FILES.into()),
                ..LocalEmbedderConfig::default()
            },
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
            transform: Some(TINY.to_owned()),
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
            transform: Some(TINY.to_owned()),
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
            transform: Some(TINY.to_owned()),
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
    // The four-wide model's files, twice as wide.
    let wide_files = tempfile::tempdir().expect("model dir");
    for file in ["config.json", "modules.json", "1_Pooling/config.json"] {
        let raw = std::fs::read_to_string(Path::new(TINY_FILES).join(file)).expect("read");
        let target = wide_files.path().join(file);
        std::fs::create_dir_all(target.parent().expect("parent")).expect("module dir");
        std::fs::write(
            target,
            raw.replace("\"hidden_size\": 4", "\"hidden_size\": 8")
                .replace(
                    "\"word_embedding_dimension\": 4",
                    "\"word_embedding_dimension\": 8",
                ),
        )
        .expect("write");
    }
    let mut wider = serve_config(dir.path(), NEW);
    wider.dimensions = DIMS * 2;
    if let Some(embedder) = wider.embedder.as_mut() {
        embedder.dimensions = DIMS * 2;
        embedder.local.model_dir = Some(wide_files.path().to_path_buf());
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
fn filled(config: &ServeConfig) -> oneiron::EntityId {
    let vault = open(config).expect("the vault opens");
    let id = put_claim(&vault, "claim");
    assert!(fill_at(&vault, OLD, WIDE) >= 1);
    id
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

/// `reembed` never decides on a transform it has not resolved. A host
/// without the configured model's metadata, configured for a transform the
/// vault does not hold, is refused before the vault is touched — with or
/// without `--force` — rather than reporting the vault current, or dropping
/// its vectors under the pin it already holds.
#[test]
fn reembed_refuses_a_target_whose_transform_it_cannot_resolve() {
    let dir = tempfile::tempdir().expect("vault dir");
    let own = local_config(dir.path(), EmbedderAttention::Auto);
    let id = filled(&own);
    let empty = tempfile::tempdir().expect("no model files");
    let mut unresolved = local_config(dir.path(), EmbedderAttention::Causal);
    if let Some(embedder) = unresolved.embedder.as_mut() {
        embedder.local.model_dir = Some(empty.path().to_path_buf());
    }
    assert_eq!(
        unresolved.vault_config().embedding_transform,
        None,
        "nothing to read at open"
    );
    for force in [false, true] {
        let error = reembed_with_config(&unresolved, force).expect_err("unresolved is refused");
        assert_eq!(
            error
                .downcast_ref::<oneiron::Error>()
                .map(oneiron::Error::kind),
            Some(oneiron::ErrorKind::InvalidConfig)
        );
    }
    let vault = open(&own).expect("the vault opens in its own transform");
    assert!(vault.get_vector(&id).expect("vector read").is_some());
    drop(vault);
    assert_eq!(
        refusal_kind(&local_config(dir.path(), EmbedderAttention::Causal)),
        Some(oneiron::ErrorKind::EmbeddingTransformChanged),
        "the pin is the one the vectors were made under"
    );
}

/// A configured commit that is not a plain name — one that climbs out of the
/// models root, or an absolute one — is refused before anything is fetched
/// or written for it, and the vault is left as it was.
#[test]
fn reembed_refuses_a_commit_that_is_not_a_plain_name_before_writing_anything() {
    let dir = tempfile::tempdir().expect("vault dir");
    let own = serve_config(dir.path(), OLD);
    drop(open(&own).expect("a vault"));
    let outer = tempfile::tempdir().expect("models parent");
    for revision in [
        "../../../perplexity-ai/pplx-embed-v1-0.6b/resolve/2c4d510dd4a732063c31a0f70193e35067b51fd8",
        "/tmp/escape",
        "..",
    ] {
        let mut config = serve_config(dir.path(), &format!("test/new@{revision}"));
        if let Some(embedder) = config.embedder.as_mut() {
            embedder.local = LocalEmbedderConfig {
                repo: "test/new".to_owned(),
                revision: revision.to_owned(),
                models_dir: Some(outer.path().join("models")),
                ..LocalEmbedderConfig::default()
            };
        }
        let error = reembed_with_config(&config, false).expect_err("refused");
        assert_eq!(
            error
                .downcast_ref::<oneiron::Error>()
                .map(oneiron::Error::kind),
            Some(oneiron::ErrorKind::InvalidConfig),
            "{revision}: {error:#}"
        );
    }
    assert_eq!(
        std::fs::read_dir(outer.path()).expect("parent").count(),
        0,
        "nothing was written, inside the root or out of it"
    );
    open(&own).expect("the vault opens as it was");
}

/// What `serve` resolves for a vault served by an endpoint under the same
/// model and width as [`local_config`].
fn endpoint_config(path: &Path) -> ServeConfig {
    ServeConfig {
        vault_path: path.to_path_buf(),
        dimensions: WIDE,
        embedder: Some(EmbedderConfig {
            provider: EmbedderProvider::Endpoint,
            model_id: OLD.to_owned(),
            dimensions: WIDE,
            endpoint: crate::config::EndpointEmbedderConfig {
                endpoint: Some("http://127.0.0.1:9/v1".to_owned()),
                model_key: Some("k".to_owned()),
                ..crate::config::EndpointEmbedderConfig::default()
            },
            ..EmbedderConfig::default()
        }),
        ..ServeConfig::default()
    }
}

/// A route is not a space. A vault filled locally opens under an endpoint
/// serving the same model, needs no reembed there, and opens locally again
/// afterwards: the endpoint neither checks nor touches the local descriptor,
/// which still refuses a local transform the vectors were not made with.
#[test]
fn a_vault_moves_between_local_and_an_endpoint_of_the_same_model_without_a_reembed() {
    let dir = tempfile::tempdir().expect("vault dir");
    let own = local_config(dir.path(), EmbedderAttention::Auto);
    let id = filled(&own);
    let endpoint = endpoint_config(dir.path());
    assert_eq!(
        refusal_kind(&endpoint),
        None,
        "the endpoint opens the vault"
    );
    assert_eq!(
        reembed_with_config(&endpoint, false).expect("reembed"),
        ReembedOutcome {
            from: None,
            to: OLD.to_owned(),
            transform: None,
            migrated: false,
        }
    );
    assert_eq!(refusal_kind(&own), None, "back on local, with no reembed");
    let vault = open(&own).expect("opens");
    assert!(vault.get_vector(&id).expect("vector read").is_some());
    drop(vault);
    assert_eq!(
        refusal_kind(&local_config(dir.path(), EmbedderAttention::Causal)),
        Some(oneiron::ErrorKind::EmbeddingTransformChanged),
        "the local descriptor survived the endpoint"
    );
}
