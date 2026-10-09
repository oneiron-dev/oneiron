//! Local-provider rows.
//!
//! Everything that can be proved without the model's weights runs here and in
//! CI. The rows that need a checkpoint (1.19 GB for the earlier default,
//! 2.38 GB for the default) are marked `#[ignore]` and
//! named in the PR body with their measured numbers: a gate that downloads a
//! gigabyte from the internet is not a gate.

use candle_core::{DType, Device};

use super::*;
use crate::config::{EmbedderDevice, EmbedderOutputQuantization, EmbedderQuant};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/embed");

// ─── the sentence-transformers chain ─────────────────────────────────────

/// Writes a model directory holding `modules.json` and the module configs.
fn module_dir(modules: &str, configs: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("fixture dir");
    std::fs::write(dir.path().join("modules.json"), modules).expect("write modules.json");
    for (path, body) in configs {
        let file = dir.path().join(path);
        std::fs::create_dir_all(file.parent().expect("parent")).expect("module dir");
        std::fs::write(file, body).expect("write module config");
    }
    dir
}

/// The chain in `dir`, ready to run on the CPU.
fn chain_at(
    dir: &std::path::Path,
    quantization: EmbedderOutputQuantization,
) -> oneiron::Result<st_modules::StModules> {
    let chain = st_modules::Chain::read(dir, quantization)?;
    st_modules::StModules::load(chain, dir, &Device::Cpu)
}

const TRANSFORMER: &str =
    r#"{"idx":0,"name":"0","path":"","type":"sentence_transformers.models.Transformer"}"#;
const POOLING: &str =
    r#"{"idx":1,"name":"1","path":"1_Pooling","type":"sentence_transformers.models.Pooling"}"#;

fn pooling_config(mode: &str, include_prompt: bool) -> String {
    format!(
        r#"{{"word_embedding_dimension":4,"pooling_mode_{mode}":true,"include_prompt":{include_prompt}}}"#
    )
}

/// A `modules.json` path is a plain name under the model directory. One that
/// climbs out of it, starts at a root, or reads as more than a path in a URL
/// is refused when the file is admitted, before anything is read or fetched:
/// here a sibling revision's valid pooling config sits where `..` would land.
#[test]
fn a_module_path_outside_the_model_directory_is_refused() {
    let root = tempfile::tempdir().expect("models root");
    let sibling = root.path().join("otherrev").join("1_Pooling");
    std::fs::create_dir_all(&sibling).expect("sibling revision");
    std::fs::write(
        sibling.join("config.json"),
        pooling_config("mean_tokens", true),
    )
    .expect("sibling pooling config");
    let model = root.path().join("thisrev");
    std::fs::create_dir_all(&model).expect("model dir");
    for path in [
        "../otherrev/1_Pooling",
        "/etc/1_Pooling",
        "1_Pooling/../../otherrev/1_Pooling",
        "1_Pooling//x",
        r"1_Pooling\x",
        "1_Pooling?x=",
    ] {
        let modules = format!(
            r#"[{TRANSFORMER},{{"idx":1,"name":"1","path":{},"type":"sentence_transformers.models.Pooling"}}]"#,
            serde_json::to_string(path).expect("json string")
        );
        assert!(
            matches!(
                model_manager::planned_files(&modules),
                Err(oneiron::Error::InvalidConfig(_))
            ),
            "{path}"
        );
        std::fs::write(model.join("modules.json"), &modules).expect("write modules.json");
        assert!(
            matches!(
                chain_at(&model, EmbedderOutputQuantization::Int8),
                Err(oneiron::Error::InvalidConfig(_))
            ),
            "{path}"
        );
    }
}

// ─── the generic path: a model is its files ──────────────────────────────

/// The shipped defaults' metadata files, as committed fixtures.
fn model_fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(FIXTURES).join("models").join(name)
}

fn spec_config() -> crate::config::EmbedderConfig {
    crate::config::EmbedderConfig {
        dimensions: 1024,
        ..crate::config::EmbedderConfig::default()
    }
}

/// [`spec_config`] naming the earlier default, so its fixture reads as that
/// checkpoint, prompt file and all.
fn harrier_config() -> crate::config::EmbedderConfig {
    let mut config = spec_config();
    let harrier = &model_manager::PINNED_MODELS[1];
    config.local.repo = harrier.repo.to_owned();
    config.local.revision = harrier.revision.to_owned();
    config
}

/// The transform the vault pins is read from the same files by the same code:
/// it names how each shipped model turns its output into stored vectors, moves
/// with an override that changes them, and ignores query-only settings.
#[test]
fn each_shipped_model_declares_its_transform_from_its_own_files() {
    let pplx = spec::LocalModelSpec::read(&model_fixture("pplx"), &spec_config()).expect("reads");
    assert_eq!(
        pplx.transform(),
        "attn=bidirectional;pool=mean;include_prompt=true;doc_prompt=none;chain=quantize:int8;dims=1024"
    );
    let harrier =
        spec::LocalModelSpec::read(&model_fixture("harrier"), &harrier_config()).expect("reads");
    assert_eq!(
        harrier.transform(),
        "attn=causal;pool=lasttoken;include_prompt=true;doc_prompt=none;chain=normalize;dims=1024"
    );

    let mut config = harrier_config();
    config.query_instruction = Some("Represent this question: ".to_owned());
    config.query_prompt_name = Some("web_search_query".to_owned());
    config.batch_size = 1;
    config.local.quant = EmbedderQuant::None;
    let queried = spec::LocalModelSpec::read(&model_fixture("harrier"), &config).expect("reads");
    assert_eq!(queried.transform(), harrier.transform());

    config.local.attention = crate::config::EmbedderAttention::Bidirectional;
    let bidirectional =
        spec::LocalModelSpec::read(&model_fixture("harrier"), &config).expect("reads");
    assert_ne!(bidirectional.transform(), harrier.transform());
    let mut config = spec_config();
    config.local.output_quantization = EmbedderOutputQuantization::Binary;
    let binary = spec::LocalModelSpec::read(&model_fixture("pplx"), &config).expect("reads");
    assert_ne!(binary.transform(), pplx.transform());
}

/// A Dense step is pinned by everything the runtime reads for it: the
/// directory its weights come from, its widths, its activation and its bias.
/// The input cap is left out on purpose: it changes how much of a document is
/// read, not the space its vector lands in.
#[test]
fn the_transform_names_every_dense_setting_the_runtime_reads_and_not_the_input_cap() {
    const TANH: &str = "torch.nn.modules.activation.Tanh";
    let transform = |path: &str, bias: bool, activation: &str| {
        let dense = format!(
            r#"{{"idx":2,"name":"2","path":"{path}","type":"sentence_transformers.models.Dense"}}"#
        );
        let dir = module_dir(
            &format!("[{TRANSFORMER},{POOLING},{dense}]"),
            &[
                (
                    "1_Pooling/config.json",
                    &pooling_config("mean_tokens", true),
                ),
                (
                    &format!("{path}/config.json"),
                    &format!(
                        r#"{{"in_features":4,"out_features":2,"bias":{bias},"activation_function":"{activation}"}}"#
                    ),
                ),
            ],
        );
        std::fs::copy(
            model_fixture("tiny").join("config.json"),
            dir.path().join("config.json"),
        )
        .expect("copy the body's config");
        let mut config = spec_config();
        config.dimensions = 2;
        spec::LocalModelSpec::read(dir.path(), &config)
            .expect("reads")
            .transform()
    };
    let own = transform("2_Dense", true, TANH);
    assert_eq!(
        own,
        r#"attn=bidirectional;pool=mean;include_prompt=true;doc_prompt=none;chain=dense:path="2_Dense":4>2:tanh:bias=true;dims=2"#
    );
    assert_ne!(transform("2_Dense", false, TANH), own, "bias");
    assert_ne!(
        transform("3_Dense", true, TANH),
        own,
        "the weights' directory"
    );
    assert_ne!(
        transform("2_Dense", true, "torch.nn.modules.linear.Identity"),
        own,
        "activation"
    );

    let mut capped = spec_config();
    capped.max_input_tokens = 512;
    let mut uncapped = spec_config();
    uncapped.max_input_tokens = 8192;
    assert_eq!(
        spec::LocalModelSpec::read(&model_fixture("pplx"), &capped)
            .expect("reads")
            .transform(),
        spec::LocalModelSpec::read(&model_fixture("pplx"), &uncapped)
            .expect("reads")
            .transform()
    );
}

// ─── the artifact manager ────────────────────────────────────────────────

fn local_config(dir: &std::path::Path) -> crate::config::LocalEmbedderConfig {
    crate::config::LocalEmbedderConfig {
        models_dir: Some(dir.to_path_buf()),
        ..crate::config::LocalEmbedderConfig::default()
    }
}

/// `model_dir` is the offline door: it downloads nothing, and it says which file
/// is missing rather than reaching for the network.
#[test]
fn an_incomplete_model_dir_names_the_missing_file_and_never_downloads() {
    let dir = tempfile::tempdir().expect("model dir");
    let config = crate::config::LocalEmbedderConfig {
        model_dir: Some(dir.path().to_path_buf()),
        ..crate::config::LocalEmbedderConfig::default()
    };
    let error = model_manager::ModelManager::default()
        .ensure_all(&config)
        .expect_err("an incomplete directory is refused");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(ref message) if message.contains("config.json")),
        "{error:?}"
    );
    assert!(
        !dir.path().join(".cache").exists(),
        "no cache directory appears beside an operator-supplied model dir"
    );
}

/// The repository and commit name a directory under the models root and a
/// path on the source, so each must be a plain name. One that climbs out of
/// the root, an absolute one, or URL syntax is refused before any directory
/// is made, any file fetched or any marker written.
#[test]
fn a_repository_or_commit_that_is_not_a_plain_name_is_refused_before_anything_is_written() {
    let source = StubSource::start();
    let outer = tempfile::tempdir().expect("models parent");
    let manager = model_manager::ModelManager::with_base_url(&source.base);
    let repo = crate::config::embedder::DEFAULT_LOCAL_REPO;
    for (repo, revision) in [
        (
            repo,
            "../../../perplexity-ai/pplx-embed-v1-0.6b/resolve/2c4d510dd4a732063c31a0f70193e35067b51fd8",
        ),
        (repo, "/tmp/escape"),
        (repo, ".."),
        (repo, "."),
        (repo, ""),
        (repo, "main?x=1"),
        (repo, "main#frag"),
        (repo, "ma%2Fin"),
        (repo, "c:main"),
        (repo, "ma\\in"),
        ("/abs/name", "main"),
        ("org/..", "main"),
        ("org//name", "main"),
        ("org/name/extra", "main"),
        ("orgname", "main"),
    ] {
        let config = crate::config::LocalEmbedderConfig {
            repo: repo.to_owned(),
            revision: revision.to_owned(),
            models_dir: Some(outer.path().join("models")),
            ..crate::config::LocalEmbedderConfig::default()
        };
        for error in [
            manager.ensure_metadata(&config).expect_err("refused"),
            manager.ensure_all(&config).expect_err("refused"),
        ] {
            assert!(
                matches!(error, oneiron::Error::InvalidConfig(ref message) if message.contains("plain")),
                "{repo} {revision}: {error:?}"
            );
        }
        assert_eq!(model_manager::verified_metadata_dir(&config), None);
    }
    assert!(source.paths().is_empty(), "nothing was fetched");
    assert_eq!(
        std::fs::read_dir(outer.path()).expect("parent").count(),
        0,
        "nothing was written, inside the root or out of it"
    );
}

/// Copies the metadata of a committed model fixture into `dir`.
fn copy_metadata(fixture: &str, dir: &std::path::Path, files: &[&str]) {
    for file in files {
        let target = dir.join(file);
        std::fs::create_dir_all(target.parent().expect("parent")).expect("model dir");
        std::fs::copy(model_fixture(fixture).join(file), target).expect("copy");
    }
}

/// The transform a vault is checked against at open is read only from
/// metadata the loader would accept as it stands: a shipped default's files
/// by their digests, any other repository's complete, with its prompt file
/// present or confirmed absent upstream. Anything less defers the check to
/// the loaded model, which fetches, repairs and verifies first.
#[test]
fn an_early_transform_is_read_only_from_complete_verified_metadata() {
    const METADATA: [&str; 3] = ["config.json", "modules.json", "1_Pooling/config.json"];
    let root = tempfile::tempdir().expect("models root");
    let mut config = crate::config::EmbedderConfig {
        dimensions: 1024,
        ..crate::config::EmbedderConfig::default()
    };
    config.local.models_dir = Some(root.path().to_path_buf());
    let dir = model_manager::model_dir(&config.local).expect("model dir");

    // The default, pinned: its files as measured.
    copy_metadata("pplx", &dir, &METADATA[..2]);
    assert_eq!(
        super::transform_on_disk(&config),
        None,
        "a module config is missing"
    );
    copy_metadata("pplx", &dir, &METADATA[2..]);
    assert_eq!(
        super::transform_on_disk(&config).as_deref(),
        Some(
            "attn=bidirectional;pool=mean;include_prompt=true;doc_prompt=none;chain=quantize:int8;dims=1024"
        )
    );
    // Damaged from mean to CLS at the same size: it still parses and fits,
    // and its digest is what refuses it.
    let pooling = dir.join("1_Pooling/config.json");
    let raw = std::fs::read_to_string(&pooling).expect("read");
    let damaged = raw
        .replace(
            "\"pooling_mode_cls_token\": false",
            "\"pooling_mode_cls_token\": true",
        )
        .replace(
            "\"pooling_mode_mean_tokens\": true",
            "\"pooling_mode_mean_tokens\": false",
        );
    assert_eq!(damaged.len(), raw.len());
    std::fs::write(&pooling, damaged).expect("damage");
    assert!(
        spec::LocalModelSpec::read(&dir, &config).is_ok(),
        "the damage reads as another model"
    );
    assert_eq!(super::transform_on_disk(&config), None);

    // Another repository, unpinned: complete, and its prompt file settled.
    config.local.repo = "someone/else".to_owned();
    let dir = model_manager::model_dir(&config.local).expect("model dir");
    copy_metadata("pplx", &dir, &METADATA);
    assert_eq!(
        super::transform_on_disk(&config),
        None,
        "no prompt file, and not known to be absent"
    );
    std::fs::write(dir.join("config_sentence_transformers.json.absent"), b"").expect("marker");
    assert!(super::transform_on_disk(&config).is_some());
    std::fs::remove_file(dir.join("config_sentence_transformers.json.absent")).expect("rm");
    std::fs::write(
        dir.join(prompts::PROMPT_FILE),
        r#"{"prompts":{"document":"passage: "}}"#,
    )
    .expect("prompt file");
    assert!(
        super::transform_on_disk(&config)
            .is_some_and(|transform| transform.contains(r#"doc_prompt="passage: ""#))
    );

    // An operator's directory is taken as it stands.
    let operator = tempfile::tempdir().expect("model dir");
    copy_metadata("pplx", operator.path(), &METADATA);
    config.local.model_dir = Some(operator.path().to_path_buf());
    assert!(super::transform_on_disk(&config).is_some());
}

/// A shipped default whose commit has no prompt file carries no prompt. A
/// stray file by that name in its cache — copied there, or left by another
/// model — is never read: the early door, the metadata-only door and the
/// spec the full load reads all describe the checkpoint as its pins do.
#[test]
fn a_stray_prompt_file_in_a_pinned_cache_is_never_read() {
    let root = tempfile::tempdir().expect("models root");
    let mut config = crate::config::EmbedderConfig {
        dimensions: 1024,
        ..crate::config::EmbedderConfig::default()
    };
    config.local.models_dir = Some(root.path().to_path_buf());
    let dir = model_manager::model_dir(&config.local).expect("model dir");
    copy_metadata(
        "pplx",
        &dir,
        &["config.json", "modules.json", "1_Pooling/config.json"],
    );
    let pinned = super::transform_on_disk(&config).expect("verified metadata");
    std::fs::write(
        dir.join(prompts::PROMPT_FILE),
        r#"{"prompts":{"query":"query: ","document":"passage: "}}"#,
    )
    .expect("stray prompt file");

    assert_eq!(super::transform_on_disk(&config), Some(pinned.clone()));
    assert_eq!(
        super::resolve_transform(&config).expect("metadata resolves"),
        pinned
    );
    let spec = spec::LocalModelSpec::read(&dir, &config).expect("reads");
    assert_eq!(spec.prompts, prompts::Prompts::default());
    assert_eq!(spec.transform(), pinned);
}

// ─── the artifact source, stubbed on loopback ────────────────────────────

/// The bytes the stub serves, and the pin that makes them the right bytes.
const STUB_BODY: &str = "harrier stub artifact\n";
const STUB_ARTIFACT: model_manager::PinnedArtifact = model_manager::PinnedArtifact {
    file: std::borrow::Cow::Borrowed("config.json"),
    sha256: "a7f696052a04543b70eb9211a5af7430d87d38d753c0e1c0c8a3655d6a2fe671",
    bytes: STUB_BODY.len() as u64,
};

/// The `modules.json` the stub serves: a Transformer and a Pooling module.
const STUB_MODULES: &str = r#"[{"idx":0,"name":"0","path":"","type":"sentence_transformers.models.Transformer"},{"idx":1,"name":"1","path":"1_Pooling","type":"sentence_transformers.models.Pooling"}]"#;

/// A one-file artifact source on loopback.
///
/// The fetch path is not reachable otherwise without the network, and a row
/// that asserts what the manager does with a bad file on disk has to be able to
/// watch it fetch a good one.
struct StubSource {
    base: String,
    paths: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    // Dropping the runtime stops the server; the field keeps it alive for the
    // length of the test.
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for StubSource {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl StubSource {
    fn start() -> Self {
        let paths = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route(
                "/{*path}",
                axum::routing::get(
                    |axum::extract::State(paths): axum::extract::State<
                        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
                    >,
                     uri: axum::http::Uri| async move {
                        use axum::response::IntoResponse;
                        paths
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(uri.path().to_owned());
                        // A chain the provider can run, no prompt file, and the
                        // same small body for every other file.
                        if uri.path().ends_with("/modules.json") {
                            return STUB_MODULES.into_response();
                        }
                        if uri.path().ends_with("/config_sentence_transformers.json") {
                            return axum::http::StatusCode::NOT_FOUND.into_response();
                        }
                        STUB_BODY.into_response()
                    },
                ),
            )
            .with_state(std::sync::Arc::clone(&paths));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("stub runtime");
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("stub listener");
        let addr = listener.local_addr().expect("stub addr");
        runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base: format!("http://{addr}"),
            paths,
            runtime: Some(runtime),
        }
    }

    fn paths(&self) -> Vec<String> {
        self.paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// A file on disk whose digest does not match is removed and fetched again.
/// Leaving it in place would fail the same way on every restart, and a fetch is
/// the only thing that can repair it.
#[test]
fn an_artifact_with_a_wrong_digest_is_removed_and_fetched_again() {
    let source = StubSource::start();
    let models = tempfile::tempdir().expect("models dir");
    let config = local_config(models.path());
    let dir = model_manager::model_dir(&config).expect("a configured root");
    std::fs::create_dir_all(&dir).expect("create the model dir");
    let path = dir.join(STUB_ARTIFACT.file.as_ref());
    // The right size and the wrong bytes, so the size check passes and the
    // digest is what refuses it.
    std::fs::write(&path, "x".repeat(STUB_BODY.len())).expect("write a wrong file");

    let manager = model_manager::ModelManager::with_base_url(&source.base);
    let fetched = manager
        .ensure_one(&config, &dir, &STUB_ARTIFACT)
        .expect("a refused file is fetched again");

    assert!(fetched, "the manager reports that it fetched the artifact");
    assert_eq!(
        std::fs::read_to_string(&path).expect("the refetched artifact"),
        STUB_BODY,
        "the bad bytes are gone and the source's bytes are in their place"
    );
    assert_eq!(
        source.paths(),
        vec![format!(
            "/{}/resolve/{}/{}",
            config.repo, config.revision, STUB_ARTIFACT.file
        )],
        "the manager asks the source for exactly the pinned path, once"
    );
}

// ─── rows that need the checkpoint ───────────────────────────────────────

mod with_model {
    use super::*;
    use crate::config::EmbedderConfig;
    use model_manager::{PINNED_MODELS, PinnedModel};

    /// The instruction vaults pinned to the earlier default were queried with.
    /// That model's own file names its prompts by task, so a vault that wants
    /// this one says so in config, as these rows do.
    const HARRIER_QUERY_INSTRUCTION: &str =
        "Instruct: Given a question, retrieve passages that answer it\nQuery: ";

    /// A shipped model's config: its repository and commit and nothing else
    /// about it, reachable only when its artifacts are on this host. Offline
    /// GPU hosts can name a directory already holding the verified checkpoint
    /// in `dir_env` without downloading it again or changing the test fixture.
    fn model_config(model: &PinnedModel, dir_env: &str, device: EmbedderDevice) -> EmbedderConfig {
        EmbedderConfig {
            model_id: format!("{}@{}", model.repo, model.revision),
            dimensions: 1024,
            batch_size: 16,
            local: crate::config::LocalEmbedderConfig {
                repo: model.repo.to_owned(),
                revision: model.revision.to_owned(),
                device,
                model_dir: std::env::var_os(dir_env).map(std::path::PathBuf::from),
                ..crate::config::LocalEmbedderConfig::default()
            },
            ..EmbedderConfig::default()
        }
    }

    fn harrier_config(device: EmbedderDevice) -> EmbedderConfig {
        EmbedderConfig {
            query_instruction: Some(HARRIER_QUERY_INSTRUCTION.to_owned()),
            ..model_config(&PINNED_MODELS[1], "ONEIRON_EMBED_TEST_MODEL_DIR", device)
        }
    }

    fn pplx_config(device: EmbedderDevice) -> EmbedderConfig {
        model_config(
            &PINNED_MODELS[0],
            "ONEIRON_EMBED_TEST_PPLX_MODEL_DIR",
            device,
        )
    }

    /// Artifacts are already on this host for every row here, so the manager
    /// only verifies them.
    fn manager() -> model_manager::ModelManager {
        model_manager::ModelManager::default()
    }

    fn reference_vectors() -> Vec<Vec<f32>> {
        let raw = std::fs::read(std::path::Path::new(FIXTURES).join("spec_reference_64.f16"))
            .expect("the committed reference vectors");
        raw.chunks_exact(2)
            .map(|pair| half::f16::from_le_bytes([pair[0], pair[1]]).to_f32())
            .collect::<Vec<f32>>()
            .chunks_exact(1024)
            .map(<[f32]>::to_vec)
            .collect()
    }

    fn jsonl_texts(file: &str) -> Vec<String> {
        std::fs::read_to_string(std::path::Path::new(FIXTURES).join(file))
            .expect("the committed text fixture")
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("text json")["text"]
                    .as_str()
                    .expect("text")
                    .to_owned()
            })
            .collect()
    }

    fn reference_chunks() -> Vec<String> {
        jsonl_texts("spec_chunks_64.jsonl")
    }

    /// Twenty fixed inputs: English, Japanese, Chinese and mixed text, one-token
    /// inputs, ~2k-token inputs, and one long enough to be truncated at the
    /// default input cap.
    fn pplx_parity_texts() -> Vec<String> {
        jsonl_texts("pplx_parity_20.jsonl")
    }

    /// sentence-transformers' own output for [`pplx_parity_texts`]: fp32 on the
    /// CPU, the model's whole module chain, `max_seq_length` 4096, run as
    /// padded batches of uneven lengths. Int8, as the model emits it.
    fn pplx_reference_vectors() -> Vec<Vec<f32>> {
        std::fs::read(std::path::Path::new(FIXTURES).join("pplx_reference_20.i8"))
            .expect("the committed reference vectors")
            .into_iter()
            .map(|byte| f32::from(byte as i8))
            .collect::<Vec<f32>>()
            .chunks_exact(1024)
            .map(<[f32]>::to_vec)
            .collect()
    }

    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        dot / (na * nb)
    }

    /// Every input's cosine against its reference, at least `floor`; returns
    /// the worst and the mean.
    fn agreement(ours: &[Vec<f32>], theirs: &[Vec<f32>], floor: f32) -> (f32, f32) {
        assert_eq!(ours.len(), theirs.len());
        let scores: Vec<f32> = ours.iter().zip(theirs).map(|(a, b)| cosine(a, b)).collect();
        println!("per-input cosine: {scores:?}");
        for (index, score) in scores.iter().enumerate() {
            assert!(
                *score >= floor,
                "input {index} agrees to only {score} with the reference"
            );
        }
        let worst = scores.iter().copied().fold(1.0f32, f32::min);
        (worst, scores.iter().sum::<f32>() / scores.len() as f32)
    }

    /// The load-bearing row: our rebuilt stack must land in the same place in
    /// the space as the reference runtime's Q8_0 of the same weights.
    #[test]
    #[ignore = "needs the 1.19 GB checkpoint; run with --run-ignored=all"]
    fn the_committed_subset_matches_the_reference_runtime() {
        let embedder = LocalEmbedder::load(&harrier_config(EmbedderDevice::Auto), &manager())
            .expect("model loads");
        let measured = embedder
            .embed_documents(&reference_chunks())
            .expect("embedded");
        let (worst, mean) = agreement(&measured, &reference_vectors(), 0.99);
        println!("worst cosine against the reference runtime: {worst} (mean {mean})");
    }

    /// The default model's port, unquantised, against sentence-transformers'
    /// fp32 output. At f32 only rounding separates the two, so this is where a
    /// port error would show; bf16 is what `quant = "none"` runs, and the
    /// precision the model card warns fp16 overflows at.
    #[test]
    #[ignore = "needs the 2.38 GB pplx-embed-v1 checkpoint; run with --run-ignored=all"]
    fn pplx_unquantised_matches_sentence_transformers() {
        let mut config = pplx_config(EmbedderDevice::Auto);
        config.local.quant = EmbedderQuant::None;
        for (dtype, floor) in [(DType::F32, 0.999), (DType::BF16, 0.99)] {
            let embedder = LocalEmbedder::load_at(&config, &manager(), dtype).expect("model loads");
            let measured = embedder
                .embed_documents(&pplx_parity_texts())
                .expect("embedded");
            let (worst, mean) = agreement(&measured, &pplx_reference_vectors(), floor);
            println!("pplx {dtype:?} vs sentence-transformers: worst cosine {worst}, mean {mean}");
        }
    }

    /// The default model as it ships: Q8_0 projections, f32 activations.
    #[test]
    #[ignore = "needs the 2.38 GB pplx-embed-v1 checkpoint; run with --run-ignored=all"]
    fn pplx_q8_0_matches_sentence_transformers() {
        let embedder = LocalEmbedder::load(&pplx_config(EmbedderDevice::Auto), &manager())
            .expect("model loads");
        let measured = embedder
            .embed_documents(&pplx_parity_texts())
            .expect("embedded");
        let (worst, mean) = agreement(&measured, &pplx_reference_vectors(), 0.99);
        println!("pplx Q8_0 vs sentence-transformers: worst cosine {worst}, mean {mean}");
    }

    fn bench_device() -> EmbedderDevice {
        std::env::var("ONEIRON_EMBED_BENCH_DEVICE")
            .unwrap_or_else(|_| "auto".to_owned())
            .parse::<EmbedderDevice>()
            .expect("ONEIRON_EMBED_BENCH_DEVICE: auto, cpu, metal or cuda")
    }

    /// The full spec corpus, its three query sets, and the throughput numbers
    /// the PR body reports, for the earlier default. The pins are its R@10 on
    /// the 2026-09-07 harness.
    #[test]
    #[ignore = "needs the checkpoint and ONEIRON_EMBED_BENCH_DIR; reported in the PR body"]
    fn the_full_corpus_reproduces_the_recall_the_blueprint_pins() {
        full_corpus_recall(&harrier_config(bench_device()), [0.9811, 0.8775, 0.9700]);
    }

    /// The same corpus through the default model. The pins are its R@10 on the
    /// 2026-10-01 retest, which scored sentence-transformers' bf16 output.
    #[test]
    #[ignore = "needs the checkpoint and ONEIRON_EMBED_BENCH_DIR; reported in the PR body"]
    fn the_full_corpus_reproduces_the_default_models_retest_recall() {
        full_corpus_recall(&pplx_config(bench_device()), [0.9717, 0.8475, 0.9550]);
    }

    /// Embeds the corpus held in `ONEIRON_EMBED_BENCH_DIR` and checks R@10 on
    /// each query set against `pinned`.
    ///
    /// The corpus is 13 MB of measurement data that has no business in the
    /// repository, so the directory holding it is named by
    /// `ONEIRON_EMBED_BENCH_DIR` and the row says so rather than silently
    /// passing when it is unset. With `ONEIRON_EMBED_RUN_DIR` also set, every
    /// query's top 100 is written there in the retest's run format
    /// (`S0__q1__card.json`: query id to `[[doc id, score], …]`), so the
    /// retest's own scorer can grade the provider's rankings, and the document
    /// vectors as `S0_docs.f32` (little-endian rows of `dimensions`), so they
    /// can be compared with the retest's own.
    fn full_corpus_recall(config: &EmbedderConfig, pinned: [f32; 3]) {
        let Some(bench) = std::env::var_os("ONEIRON_EMBED_BENCH_DIR").map(std::path::PathBuf::from)
        else {
            panic!(
                "set ONEIRON_EMBED_BENCH_DIR to the directory holding chunks.jsonl and q1..q3.json"
            );
        };
        let run_dir = std::env::var_os("ONEIRON_EMBED_RUN_DIR").map(std::path::PathBuf::from);
        let chunks: Vec<serde_json::Value> = std::fs::read_to_string(bench.join("chunks.jsonl"))
            .expect("chunks.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).expect("chunk json"))
            .collect();
        let texts: Vec<String> = chunks
            .iter()
            .map(|chunk| chunk["text"].as_str().expect("chunk text").to_owned())
            .collect();

        let load_started = std::time::Instant::now();
        let embedder = LocalEmbedder::load(config, &manager()).expect("model loads");
        let load_ms = load_started.elapsed().as_millis();

        let embed_started = std::time::Instant::now();
        let documents = embedder
            .embed_documents(&texts)
            .expect("documents embedded");
        let embed_secs = embed_started.elapsed().as_secs_f64();
        if let Some(dir) = run_dir.as_ref() {
            std::fs::create_dir_all(dir).expect("run dir");
            let bytes: Vec<u8> = documents
                .iter()
                .flatten()
                .flat_map(|value| value.to_le_bytes())
                .collect();
            std::fs::write(dir.join("S0_docs.f32"), bytes).expect("document vectors written");
        }
        println!(
            "{} on {}: load+quantise {load_ms} ms; {} chunks in {embed_secs:.1} s = {:.2} chunks/s",
            config.model_id,
            config.local.device.as_str(),
            texts.len(),
            texts.len() as f64 / embed_secs
        );

        for ((name, file), pinned) in [("q1", "q1.json"), ("q2", "q2.json"), ("q3", "q3.json")]
            .into_iter()
            .zip(pinned)
        {
            let queries: Vec<serde_json::Value> =
                serde_json::from_str(&std::fs::read_to_string(bench.join(file)).expect(file))
                    .expect("query json");
            let ranked: Vec<Vec<(f32, usize)>> = queries
                .iter()
                .map(|query| {
                    let probe = embedder
                        .embed_query(query["query"].as_str().expect("query text"))
                        .expect("query embedded");
                    rank(&probe, &documents)
                })
                .collect();
            let recall = recall_at_10(&queries, &chunks, &ranked);
            println!("{name} R@10 {recall:.4} (pinned {pinned:.4})");
            if let Some(dir) = run_dir.as_ref() {
                write_run(dir, name, &queries, &ranked);
            }
            assert!(
                (recall - pinned).abs() <= 0.005,
                "{name} R@10 {recall} is more than 0.005 from the pinned {pinned}"
            );
        }
    }

    /// Every document by cosine to the probe, best first.
    fn rank(probe: &[f32], documents: &[Vec<f32>]) -> Vec<(f32, usize)> {
        let mut scored: Vec<(f32, usize)> = documents
            .iter()
            .enumerate()
            .map(|(index, doc)| (cosine(probe, doc), index))
            .collect();
        scored.sort_by(|a, b| b.0.total_cmp(&a.0));
        scored
    }

    /// Recall@10 over one query set, scored exactly as the bench scored it:
    /// a hit when any relevant chunk ranks in the top ten, relevance by page
    /// for Q1 and Q3 and by chunk index for Q2.
    fn recall_at_10(
        queries: &[serde_json::Value],
        chunks: &[serde_json::Value],
        ranked: &[Vec<(f32, usize)>],
    ) -> f32 {
        let hits = queries
            .iter()
            .zip(ranked)
            .filter(|(query, ranking)| {
                let relevant = relevant_indices(query, chunks);
                ranking
                    .iter()
                    .take(10)
                    .any(|(_, index)| relevant.contains(index))
            })
            .count();
        hits as f32 / queries.len() as f32
    }

    /// One query set's top 100 per query, in the retest's run format.
    fn write_run(
        dir: &std::path::Path,
        name: &str,
        queries: &[serde_json::Value],
        ranked: &[Vec<(f32, usize)>],
    ) {
        let run: serde_json::Map<String, serde_json::Value> = queries
            .iter()
            .zip(ranked)
            .map(|(query, ranking)| {
                let top: Vec<serde_json::Value> = ranking
                    .iter()
                    .take(100)
                    .map(|(score, index)| serde_json::json!([index.to_string(), score]))
                    .collect();
                (
                    format!("{name}-{}", query["qid"]),
                    serde_json::Value::from(top),
                )
            })
            .collect();
        std::fs::create_dir_all(dir).expect("run dir");
        std::fs::write(
            dir.join(format!("S0__{name}__card.json")),
            serde_json::to_vec(&run).expect("run json"),
        )
        .expect("run written");
    }

    /// The chunk indices a query counts as relevant.
    fn relevant_indices(
        query: &serde_json::Value,
        chunks: &[serde_json::Value],
    ) -> std::collections::HashSet<usize> {
        if let Some(ids) = query["chunk_ids"].as_array() {
            return ids
                .iter()
                .filter_map(|id| id.as_u64().map(|id| id as usize))
                .collect();
        }
        let pages: Vec<&str> = query["page_keys"]
            .as_array()
            .expect("a query names pages or chunks")
            .iter()
            .filter_map(|page| page.as_str())
            .collect();
        chunks
            .iter()
            .enumerate()
            .filter(|(_, chunk)| {
                chunk["page_key"]
                    .as_str()
                    .is_some_and(|page| pages.contains(&page))
            })
            .map(|(index, _)| index)
            .collect()
    }
}
