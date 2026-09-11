//! Local-provider rows.
//!
//! Everything that can be proved without the model's weights runs here and in
//! CI. The rows that need the 1.19 GB checkpoint are marked `#[ignore]` and
//! named in the PR body with their measured numbers: a gate that downloads a
//! gigabyte from the internet is not a gate.

use candle_core::{DType, Device, Tensor};

use super::*;
use crate::config::{EmbedderDevice, EmbedderQuant};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/embed");

// ─── batching ────────────────────────────────────────────────────────────

#[test]
fn equal_lengths_group_together_in_first_appearance_order() {
    assert_eq!(
        batcher::group_equal_lengths(&[5, 7, 5, 9], 32),
        vec![vec![0, 2], vec![1], vec![3]]
    );
}

#[test]
fn a_batch_size_of_one_makes_every_input_its_own_group() {
    let groups = batcher::group_equal_lengths(&[5, 7, 5, 9], 1);
    assert_eq!(groups.len(), 4);
    assert!(groups.iter().all(|group| group.len() == 1));
    let mut flat: Vec<usize> = groups.into_iter().flatten().collect();
    flat.sort_unstable();
    assert_eq!(flat, vec![0, 1, 2, 3]);
}

#[test]
fn every_input_appears_in_exactly_one_group() {
    let lengths = [3, 3, 3, 4, 4, 9, 3, 4];
    let groups = batcher::group_equal_lengths(&lengths, 2);
    let mut seen: Vec<usize> = groups.iter().flatten().copied().collect();
    seen.sort_unstable();
    assert_eq!(seen, (0..lengths.len()).collect::<Vec<_>>());
    for group in &groups {
        assert!(group.len() <= 2, "a group never exceeds the batch size");
        assert!(
            group
                .iter()
                .all(|index| lengths[*index] == lengths[group[0]]),
            "a group holds one length only"
        );
    }
}

// ─── the sentence-transformers chain ─────────────────────────────────────

#[test]
fn the_models_own_module_chain_pools_the_last_token_and_normalises() {
    let modules = st_modules::StModules::load(std::path::Path::new(FIXTURES))
        .expect("the committed module fixtures parse");
    assert_eq!(modules.dimensions(), 1024);
    let hidden = Tensor::from_vec(
        vec![1.0f32, 0.0, 0.0, 0.0, 0.0, 3.0, 0.0, 4.0],
        (1, 2, 4),
        &Device::Cpu,
    )
    .expect("hidden states");
    let pooled: Vec<Vec<f32>> = modules
        .apply(&hidden)
        .and_then(|pooled| pooled.to_vec2())
        .expect("pooled");
    // The LAST row, L2-normalised: [0, 3, 0, 4] / 5.
    assert_eq!(pooled, vec![vec![0.0, 0.6, 0.0, 0.8]]);
}

#[test]
fn a_module_chain_that_does_not_start_with_a_transformer_is_refused() {
    let dir = tempfile::tempdir().expect("fixture dir");
    std::fs::write(
        dir.path().join("modules.json"),
        br#"[{"idx":0,"name":"0","path":"1_Pooling","type":"sentence_transformers.models.Pooling"}]"#,
    )
    .expect("write modules.json");
    let error = st_modules::StModules::load(dir.path()).expect_err("refused");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(ref message) if message.contains("Transformer")),
        "{error:?}"
    );
}

#[test]
fn an_unsupported_module_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("fixture dir");
    std::fs::write(
        dir.path().join("modules.json"),
        br#"[{"idx":0,"name":"0","path":"","type":"sentence_transformers.models.Transformer"},
             {"idx":1,"name":"1","path":"2_Dense","type":"sentence_transformers.models.Dense"}]"#,
    )
    .expect("write modules.json");
    let error = st_modules::StModules::load(dir.path()).expect_err("refused");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(ref message) if message.contains("Dense")),
        "{error:?}"
    );
}

#[test]
fn mean_pooling_equals_the_hand_computed_mean() {
    let dir = tempfile::tempdir().expect("fixture dir");
    std::fs::write(
        dir.path().join("modules.json"),
        br#"[{"idx":0,"name":"0","path":"","type":"Transformer"},
             {"idx":1,"name":"1","path":"pool","type":"Pooling"}]"#,
    )
    .expect("write modules.json");
    std::fs::create_dir_all(dir.path().join("pool")).expect("pool dir");
    std::fs::write(
        dir.path().join("pool").join("config.json"),
        br#"{"word_embedding_dimension":4,"pooling_mode_mean_tokens":true}"#,
    )
    .expect("write pooling config");
    let modules = st_modules::StModules::load(dir.path()).expect("mean pooling parses");

    let hidden = Tensor::from_vec(
        (0..24).map(|n| n as f32).collect::<Vec<f32>>(),
        (2, 3, 4),
        &Device::Cpu,
    )
    .expect("hidden states");
    let pooled: Vec<Vec<f32>> = modules
        .apply(&hidden)
        .and_then(|pooled| pooled.to_vec2())
        .expect("pooled");
    // Rows 0,4,8 of the first sequence average to 4; 1,5,9 to 5; and so on.
    assert_eq!(pooled[0], vec![4.0, 5.0, 6.0, 7.0]);
    assert_eq!(pooled[1], vec![16.0, 17.0, 18.0, 19.0]);
}

// ─── quantise at load ────────────────────────────────────────────────────

/// Q8_0 is a lossy format, so the row that matters is how lossy: a quantised
/// projection must agree with the full-precision one to within a couple of
/// percent, which is what the recall parity on the spec corpus rests on.
#[test]
fn a_quantised_projection_agrees_with_the_dense_one() {
    let (out_dim, in_dim) = (64usize, 32usize);
    let weight: Vec<f32> = (0..out_dim * in_dim)
        .map(|n| ((n as f32 * 0.37).sin()) * 0.5)
        .collect();
    let weight = Tensor::from_vec(weight, (out_dim, in_dim), &Device::Cpu).expect("weight");
    let input: Vec<f32> = (0..in_dim).map(|n| (n as f32 * 0.11).cos()).collect();
    let input = Tensor::from_vec(input, (1, in_dim), &Device::Cpu).expect("input");

    let dense = candle_nn::Linear::new(weight.clone(), None);
    let quantised = candle_core::quantized::QTensor::quantize_onto(
        &weight,
        candle_core::quantized::GgmlDType::Q8_0,
        &Device::Cpu,
    )
    .and_then(candle_core::quantized::QMatMul::from_qtensor)
    .expect("quantised weight");

    let reference: Vec<Vec<f32>> = candle_core::Module::forward(&dense, &input)
        .and_then(|out| out.to_vec2())
        .expect("dense output");
    let measured: Vec<Vec<f32>> = candle_core::Module::forward(&quantised, &input)
        .and_then(|out| out.to_vec2())
        .expect("quantised output");

    let error: f32 = reference[0]
        .iter()
        .zip(&measured[0])
        .map(|(a, b)| (a - b) * (a - b))
        .sum::<f32>()
        .sqrt();
    let scale: f32 = reference[0].iter().map(|a| a * a).sum::<f32>().sqrt();
    assert!(
        error / scale < 2e-2,
        "relative L2 error {} exceeds 2e-2",
        error / scale
    );
}

// ─── attention ───────────────────────────────────────────────────────────

/// The fused kernel and the eager path must compute the same attention, or the
/// vault's vectors depend on which machine filled them.
#[test]
fn the_fused_and_eager_attention_branches_agree() {
    let Ok(metal) = Device::new_metal(0) else {
        // Not a skip that hides a failure: the fused branch only exists on a
        // Metal device, and on a host without one the eager path is the only
        // path and is covered by every other row here.
        return;
    };
    let (batch, heads, seq, head_dim) = (2usize, 16usize, 7usize, 128usize);
    let kv_heads = 8usize;
    let make = |count: usize, seed: f32| {
        let values: Vec<f32> = (0..batch * count * seq * head_dim)
            .map(|n| ((n as f32 * seed).sin()) * 0.1)
            .collect();
        Tensor::from_vec(values, (batch, count, seq, head_dim), &Device::Cpu).expect("tensor")
    };
    let (q, k, v) = (
        make(heads, 0.013),
        make(kv_heads, 0.017),
        make(kv_heads, 0.019),
    );
    let mask = attention::causal_mask(seq, &Device::Cpu).expect("mask");
    let eager: Vec<f32> =
        attention::eager_attention(&q, &k, &v, &mask, 1.0 / (head_dim as f32).sqrt())
            .and_then(|out| out.flatten_all()?.to_vec1())
            .expect("eager attention");

    let to_metal = |tensor: &Tensor| tensor.to_device(&metal).expect("to metal");
    let fused: Vec<f32> = attention::grouped_causal_attention(
        &to_metal(&q),
        &to_metal(&k),
        &to_metal(&v),
        // The fused kernel masks causally itself, and the model builds no mask
        // for this path at all.
        None,
        1.0 / (head_dim as f32).sqrt(),
    )
    .and_then(|out| out.flatten_all()?.to_vec1())
    .expect("fused attention");

    assert_eq!(eager.len(), fused.len());
    let worst = eager
        .iter()
        .zip(&fused)
        .map(|(a, b)| (a - b).abs())
        .fold(0f32, f32::max);
    assert!(worst < 1e-2, "branches disagree by {worst}");
}

/// The cache is bounded and first-in-first-out, so a long-lived process holds
/// at most [`qwen3_embedding::MASK_CACHE_CAPACITY`] masks however many distinct
/// lengths it has embedded.
#[test]
fn the_mask_cache_holds_a_bounded_window_of_lengths() {
    let mut cache = qwen3_embedding::MaskCache::new();
    let capacity = qwen3_embedding::MASK_CACHE_CAPACITY;
    let seen = capacity + 4;
    for seq in 1..=seen {
        let mask = cache.get_or_build(seq, &Device::Cpu).expect("mask");
        assert_eq!(mask.dims4().expect("mask shape"), (1, 1, seq, seq));
    }
    assert_eq!(
        cache.lengths(),
        (seen - capacity + 1..=seen).collect::<Vec<usize>>(),
        "the cache keeps the newest lengths and drops the oldest"
    );
    // Reading a length it still holds neither rebuilds nor reorders it.
    let held = cache.lengths();
    cache.get_or_build(seen, &Device::Cpu).expect("cached mask");
    assert_eq!(cache.lengths(), held);
}

#[test]
fn the_causal_mask_blocks_only_future_positions() {
    let mask: Vec<f32> = attention::causal_mask(3, &Device::Cpu)
        .and_then(|mask| mask.flatten_all()?.to_vec1())
        .expect("mask");
    assert_eq!(mask[0], 0.0);
    assert_eq!(mask[1], f32::NEG_INFINITY);
    assert_eq!(mask[3], 0.0);
    assert_eq!(mask[4], 0.0);
    assert_eq!(mask[5], f32::NEG_INFINITY);
}

#[test]
fn l2_normalisation_makes_every_row_unit_length() {
    let values = Tensor::from_vec(vec![3.0f32, 4.0, 0.0, 5.0], (2, 2), &Device::Cpu).expect("t");
    let rows: Vec<Vec<f32>> = attention::l2_normalize(&values)
        .and_then(|out| out.to_vec2())
        .expect("normalised");
    for row in &rows {
        let norm = row.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "norm was {norm}");
    }
}

// ─── the model's own declaration ─────────────────────────────────────────

fn config_json(architecture: &str) -> String {
    format!(
        r#"{{"architectures":["{architecture}"],"hidden_size":1024,"num_hidden_layers":28,
            "num_attention_heads":16,"num_key_value_heads":8,"head_dim":128,
            "intermediate_size":3072,"vocab_size":151936,"rope_theta":1000000.0,
            "rms_norm_eps":1e-06,"max_position_embeddings":32768}}"#
    )
}

#[test]
fn both_body_and_causal_lm_class_names_are_accepted() {
    for architecture in ["Qwen3Model", "Qwen3ForCausalLM"] {
        let config = qwen3_embedding::Config::parse(&config_json(architecture))
            .expect("an accepted class parses");
        assert_eq!(config.hidden_size, 1024);
        assert_eq!(config.head_dim(), 128);
    }
}

#[test]
fn an_unsupported_model_class_is_refused_by_name() {
    let error = qwen3_embedding::Config::parse(&config_json("Gemma3TextModel"))
        .expect_err("an unknown class is refused");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(ref message) if message.contains("Gemma3TextModel")),
        "{error:?}"
    );
}

#[test]
fn a_head_count_that_is_not_a_multiple_of_the_kv_count_is_refused() {
    let raw =
        config_json("Qwen3Model").replace("\"num_key_value_heads\":8", "\"num_key_value_heads\":5");
    let error = qwen3_embedding::Config::parse(&raw).expect_err("refused");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(_)),
        "{error:?}"
    );
}

// ─── device and precision ────────────────────────────────────────────────

#[test]
fn quantised_weights_run_in_f32_and_bf16_weights_run_in_bf16() {
    assert_eq!(device::run_dtype(EmbedderQuant::Q8_0), DType::F32);
    assert_eq!(device::run_dtype(EmbedderQuant::None), DType::BF16);
}

#[test]
fn an_explicitly_named_unavailable_device_is_an_error_not_a_downgrade() {
    // `auto` always resolves: the CPU is always there.
    assert!(device::resolve_device(EmbedderDevice::Auto).is_ok());
    assert!(matches!(
        device::resolve_device(EmbedderDevice::Cpu),
        Ok(Device::Cpu)
    ));
    if Device::new_metal(0).is_err() {
        assert!(
            device::resolve_device(EmbedderDevice::Metal).is_err(),
            "a named device this build cannot reach is refused"
        );
    }
}

// ─── the artifact manager ────────────────────────────────────────────────

fn local_config(dir: &std::path::Path) -> crate::config::LocalEmbedderConfig {
    crate::config::LocalEmbedderConfig {
        models_dir: Some(dir.to_path_buf()),
        ..crate::config::LocalEmbedderConfig::default()
    }
}

#[test]
fn the_model_directory_is_root_org_name_revision() {
    let dir = tempfile::tempdir().expect("models dir");
    let path = model_manager::model_dir(&local_config(dir.path())).expect("a configured root");
    assert_eq!(
        path,
        dir.path()
            .join("microsoft")
            .join("harrier-oss-v1-0.6b")
            .join(crate::config::embedder::DEFAULT_LOCAL_REVISION)
    );
}

#[test]
fn a_models_root_without_an_override_follows_the_xdg_data_directory() {
    let root = model_manager::resolve_models_root(
        None,
        Some(std::path::PathBuf::from("/data")),
        Some(std::path::PathBuf::from("/home/someone")),
    )
    .expect("an XDG data directory resolves");
    assert_eq!(
        root,
        std::path::Path::new("/data").join("oneiron").join("models")
    );
}

#[test]
fn a_models_root_falls_back_to_the_home_share_tree() {
    let root = model_manager::resolve_models_root(
        None,
        None,
        Some(std::path::PathBuf::from("/home/someone")),
    )
    .expect("a home directory resolves");
    assert_eq!(
        root,
        std::path::Path::new("/home/someone")
            .join(".local")
            .join("share")
            .join("oneiron")
            .join("models")
    );
}

/// With no data directory to write to, the resolution refuses and names what
/// would fix it. The alternative is a relative path: a gigabyte of model
/// written into whatever directory the server started in, and downloaded again
/// from the next one.
#[test]
fn a_models_root_with_nowhere_to_write_is_refused_by_name() {
    let error = model_manager::resolve_models_root(None, None, None)
        .expect_err("an unresolvable root is refused");
    let oneiron::Error::InvalidConfig(message) = &error else {
        panic!("{error:?}");
    };
    for named in ["XDG_DATA_HOME", "HOME", "models_dir"] {
        assert!(message.contains(named), "{named} is not named: {message}");
    }
    assert!(
        model_manager::resolve_models_root(
            Some(std::path::Path::new("/models")),
            None,
            None,
        )
        .is_ok(),
        "a configured root needs no environment at all"
    );
}

#[test]
fn a_file_whose_digest_does_not_match_is_refused() {
    let dir = tempfile::tempdir().expect("models dir");
    let config = local_config(dir.path());
    let path = model_manager::model_dir(&config)
        .expect("a configured root")
        .join("config.json");
    std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
    // The right size, the wrong bytes: the size check passes and the digest
    // catches it, which is the ordering the verifier promises.
    let pinned = model_manager::HARRIER_06_FILES
        .iter()
        .find(|artifact| artifact.file == "config.json")
        .expect("config.json is pinned");
    std::fs::write(&path, "x".repeat(pinned.bytes as usize)).expect("write a wrong file");
    let error = model_manager::verify(&path, pinned).expect_err("a wrong digest is refused");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(ref message) if message.contains("sha256")),
        "{error:?}"
    );
}

#[test]
fn a_file_of_the_wrong_size_is_refused_before_it_is_hashed() {
    let dir = tempfile::tempdir().expect("models dir");
    let path = dir.path().join("config.json");
    std::fs::write(&path, b"short").expect("write");
    let pinned = model_manager::HARRIER_06_FILES
        .iter()
        .find(|artifact| artifact.file == "config.json")
        .expect("config.json is pinned");
    let error = model_manager::verify(&path, pinned).expect_err("a wrong size is refused");
    assert!(
        matches!(error, oneiron::Error::InvalidConfig(ref message) if message.contains("bytes")),
        "{error:?}"
    );
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

#[test]
fn every_pinned_artifact_carries_a_digest_and_a_size() {
    assert_eq!(model_manager::HARRIER_06_FILES.len(), 6);
    for artifact in &model_manager::HARRIER_06_FILES {
        assert_eq!(
            artifact.sha256.len(),
            64,
            "{} has no sha256 digest",
            artifact.file
        );
        assert!(artifact.bytes > 0, "{} has no pinned size", artifact.file);
    }
    let names: Vec<&str> = model_manager::HARRIER_06_FILES
        .iter()
        .map(|artifact| artifact.file)
        .collect();
    for required in [
        "config.json",
        "modules.json",
        "1_Pooling/config.json",
        "tokenizer.json",
        "model.safetensors",
    ] {
        assert!(names.contains(&required), "{required} is not pinned");
    }
}

/// A repository this build has never measured keeps the file list and drops the
/// digest pins rather than failing every download against the wrong digest.
#[test]
fn an_unpinned_repository_keeps_the_file_list_without_digests() {
    let config = crate::config::LocalEmbedderConfig {
        repo: "someone/else".to_owned(),
        ..crate::config::LocalEmbedderConfig::default()
    };
    let files = model_manager::model_files(&config);
    assert_eq!(files.len(), 6);
    assert!(
        files
            .iter()
            .all(|artifact| artifact.sha256 == model_manager::UNPINNED)
    );
}

// ─── the artifact source, stubbed on loopback ────────────────────────────

/// The bytes the stub serves, and the pin that makes them the right bytes.
const STUB_BODY: &str = "harrier stub artifact\n";
const STUB_ARTIFACT: model_manager::PinnedArtifact = model_manager::PinnedArtifact {
    file: "config.json",
    sha256: "a7f696052a04543b70eb9211a5af7430d87d38d753c0e1c0c8a3655d6a2fe671",
    bytes: STUB_BODY.len() as u64,
};

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
                        paths
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(uri.path().to_owned());
                        STUB_BODY
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
    let path = dir.join(STUB_ARTIFACT.file);
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

/// A verified artifact is not hashed again until it changes.
///
/// The worker retries a failed load on a backoff that tops out at a minute, and
/// the checkpoint is 1.19 GB: re-reading it on every pass is most of that
/// minute spent proving what the last pass proved. What the manager remembers
/// is its own, not the process's, so a second manager repeats the work.
#[test]
fn a_verified_artifact_is_not_hashed_again_until_it_changes() {
    fn overwrite_keeping_the_stamp(path: &std::path::Path, bytes: &str) {
        let modified = std::fs::metadata(path)
            .expect("metadata")
            .modified()
            .expect("modification time");
        std::fs::write(path, bytes).expect("overwrite");
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("reopen")
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .expect("restore the modification time");
    }

    let source = StubSource::start();
    let models = tempfile::tempdir().expect("models dir");
    let config = local_config(models.path());
    let dir = model_manager::model_dir(&config).expect("a configured root");
    std::fs::create_dir_all(&dir).expect("create the model dir");
    let path = dir.join(STUB_ARTIFACT.file);

    let manager = model_manager::ModelManager::with_base_url(&source.base);
    assert!(
        manager
            .ensure_one(&config, &dir, &STUB_ARTIFACT)
            .expect("first pass"),
        "the first pass fetches the artifact"
    );

    // Different bytes, same size and same modification time. Nothing the
    // manager reads on a repeat pass has changed, so it does not read the file.
    overwrite_keeping_the_stamp(&path, &"y".repeat(STUB_BODY.len()));
    assert!(
        !manager
            .ensure_one(&config, &dir, &STUB_ARTIFACT)
            .expect("repeat pass"),
        "an unchanged file is taken as verified"
    );
    assert_eq!(source.paths().len(), 1, "and is not fetched again");

    // A manager that verified nothing hashes the same file and catches it.
    let fresh = model_manager::ModelManager::with_base_url(&source.base);
    assert!(
        fresh
            .ensure_one(&config, &dir, &STUB_ARTIFACT)
            .expect("a fresh manager"),
        "what one manager verified is not what another knows"
    );
    assert_eq!(source.paths().len(), 2);
    assert_eq!(
        std::fs::read_to_string(&path).expect("the refetched artifact"),
        STUB_BODY
    );

    // A file of a different size is a different file whatever was remembered.
    std::fs::write(&path, "truncated").expect("shrink the file");
    assert!(
        fresh
            .ensure_one(&config, &dir, &STUB_ARTIFACT)
            .expect("a changed file"),
        "a file whose size changed is verified again, refused and refetched"
    );
    assert_eq!(source.paths().len(), 3);
    assert_eq!(
        std::fs::read_to_string(&path).expect("the refetched artifact"),
        STUB_BODY
    );
}

// ─── rows that need the checkpoint ───────────────────────────────────────

mod with_model {
    use super::*;
    use crate::config::EmbedderConfig;

    /// The model config as shipped, reachable only when the artifacts are on
    /// this host.
    fn ready_config(device: EmbedderDevice) -> EmbedderConfig {
        EmbedderConfig {
            dimensions: 1024,
            batch_size: 16,
            local: crate::config::LocalEmbedderConfig {
                device,
                ..crate::config::LocalEmbedderConfig::default()
            },
            ..EmbedderConfig::default()
        }
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

    fn reference_chunks() -> Vec<String> {
        std::fs::read_to_string(std::path::Path::new(FIXTURES).join("spec_chunks_64.jsonl"))
            .expect("the committed chunk subset")
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("chunk json")["text"]
                    .as_str()
                    .expect("chunk text")
                    .to_owned()
            })
            .collect()
    }

    fn cosine(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        dot / (na * nb)
    }

    /// The load-bearing row: our rebuilt stack must land in the same place in
    /// the space as the reference runtime's Q8_0 of the same weights.
    #[test]
    #[ignore = "needs the 1.19 GB checkpoint; run with --run-ignored=all"]
    fn the_committed_subset_matches_the_reference_runtime() {
        let embedder =
            LocalEmbedder::load(&ready_config(EmbedderDevice::Auto), &manager()).expect("model loads");
        let chunks = reference_chunks();
        let reference = reference_vectors();
        assert_eq!(chunks.len(), reference.len());
        let measured = embedder.embed_texts(&chunks).expect("embedded");
        let mut worst = 1.0f32;
        for (index, (ours, theirs)) in measured.iter().zip(&reference).enumerate() {
            let score = cosine(ours, theirs);
            assert!(
                score >= 0.99,
                "chunk {index} agrees to only {score} with the reference"
            );
            worst = worst.min(score);
        }
        println!("worst cosine against the reference runtime: {worst}");
    }

    /// The same batch, one at a time and together, must produce the same
    /// vectors: the no-padding grouping is only correct if it is.
    #[test]
    #[ignore = "needs the 1.19 GB checkpoint; run with --run-ignored=all"]
    fn a_batched_input_embeds_exactly_as_it_does_alone() {
        let embedder =
            LocalEmbedder::load(&ready_config(EmbedderDevice::Auto), &manager()).expect("model loads");
        let texts: Vec<String> = reference_chunks().into_iter().take(8).collect();
        let batched = embedder.embed_texts(&texts).expect("batched");
        for (index, text) in texts.iter().enumerate() {
            let alone = embedder
                .embed_texts(std::slice::from_ref(text))
                .expect("single");
            let score = cosine(&batched[index], &alone[0]);
            assert!(
                score >= 0.9999,
                "input {index} differs batched vs alone: cosine {score}"
            );
        }
    }

    /// The tokenizer's own post-processor appends the end-of-text token. A
    /// truncated input keeps it, because last-token pooling reads that row.
    #[test]
    #[ignore = "needs the 1.19 GB checkpoint; run with --run-ignored=all"]
    fn the_tokenizer_appends_one_end_of_text_token_and_truncation_keeps_it() {
        let dir = manager()
            .ensure_all(&ready_config(EmbedderDevice::Auto).local)
            .expect("artifacts present");
        let tokenizer =
            tokenizers::Tokenizer::from_file(dir.join("tokenizer.json")).expect("tokenizer loads");
        let short = batcher::tokenize(&tokenizer, &["hello".to_owned()], 4096).expect("tokenized");
        let ids = &short[0].ids;
        assert_eq!(*ids.last().expect("a final token"), 151_643);
        assert_eq!(
            ids.iter().filter(|id| **id == 151_643).count(),
            1,
            "the end-of-text token appears exactly once"
        );
        assert!(!short[0].truncated);

        let long = "word ".repeat(4000);
        let cut = batcher::tokenize(&tokenizer, &[long], 64).expect("tokenized");
        assert!(cut[0].truncated, "an over-long input is truncated");
        assert_eq!(cut[0].ids.len(), 64);
        assert_eq!(
            *cut[0].ids.last().expect("a final token"),
            151_643,
            "truncation keeps the token last-token pooling reads"
        );
    }

    /// Metal and CPU must agree: a vault filled on one host and queried from
    /// another is one space only if they do.
    #[test]
    #[ignore = "needs the 1.19 GB checkpoint and is slow on CPU"]
    fn the_cpu_and_metal_devices_agree_on_the_same_input() {
        if Device::new_metal(0).is_err() {
            return;
        }
        let texts: Vec<String> = reference_chunks().into_iter().take(4).collect();
        let on_metal = LocalEmbedder::load(&ready_config(EmbedderDevice::Metal), &manager())
            .expect("metal model")
            .embed_texts(&texts)
            .expect("metal vectors");
        let on_cpu = LocalEmbedder::load(&ready_config(EmbedderDevice::Cpu), &manager())
            .expect("cpu model")
            .embed_texts(&texts)
            .expect("cpu vectors");
        for (index, (metal, cpu)) in on_metal.iter().zip(&on_cpu).enumerate() {
            let score = cosine(metal, cpu);
            assert!(score >= 0.999, "input {index} differs by device: {score}");
        }
    }

    /// The full spec corpus, its three query sets, and the throughput numbers
    /// the PR body reports.
    ///
    /// The corpus is 13 MB of measurement data that has no business in the
    /// repository, so the directory holding it is named by
    /// `ONEIRON_EMBED_BENCH_DIR` and the row says so rather than silently
    /// passing when it is unset.
    #[test]
    #[ignore = "needs the checkpoint and ONEIRON_EMBED_BENCH_DIR; reported in the PR body"]
    fn the_full_corpus_reproduces_the_recall_the_blueprint_pins() {
        let Some(bench) = std::env::var_os("ONEIRON_EMBED_BENCH_DIR").map(std::path::PathBuf::from)
        else {
            panic!(
                "set ONEIRON_EMBED_BENCH_DIR to the directory holding chunks.jsonl and q1..q3.json"
            );
        };
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
        let embedder =
            LocalEmbedder::load(&ready_config(EmbedderDevice::Auto), &manager()).expect("model loads");
        let load_ms = load_started.elapsed().as_millis();

        let embed_started = std::time::Instant::now();
        let documents = embedder.embed_texts(&texts).expect("documents embedded");
        let embed_secs = embed_started.elapsed().as_secs_f64();
        println!(
            "load+quantise {load_ms} ms; {} chunks in {embed_secs:.1} s = {:.2} chunks/s",
            texts.len(),
            texts.len() as f64 / embed_secs
        );

        for (name, file, pinned) in [
            ("Q1", "q1.json", 0.9811f32),
            ("Q2", "q2.json", 0.8775),
            ("Q3", "q3.json", 0.9700),
        ] {
            let queries: Vec<serde_json::Value> =
                serde_json::from_str(&std::fs::read_to_string(bench.join(file)).expect(file))
                    .expect("query json");
            let recall = recall_at_10(&embedder, &queries, &chunks, &documents);
            println!("{name} R@10 {recall:.4} (pinned {pinned:.4})");
            assert!(
                (recall - pinned).abs() <= 0.005,
                "{name} R@10 {recall} is more than 0.005 from the pinned {pinned}"
            );
        }
    }

    /// Recall@10 over one query set, scored exactly as the bench scored it:
    /// cosine against every document, relevance by page for Q1 and Q3 and by
    /// chunk index for Q2.
    fn recall_at_10(
        embedder: &LocalEmbedder,
        queries: &[serde_json::Value],
        chunks: &[serde_json::Value],
        documents: &[Vec<f32>],
    ) -> f32 {
        let mut hits = 0usize;
        for query in queries {
            let relevant = relevant_indices(query, chunks);
            let probe = embedder
                .embed_query(query["query"].as_str().expect("query text"))
                .expect("query embedded");
            let mut scored: Vec<(f32, usize)> = documents
                .iter()
                .enumerate()
                .map(|(index, doc)| (cosine(&probe, doc), index))
                .collect();
            scored.sort_by(|a, b| b.0.total_cmp(&a.0));
            if scored
                .iter()
                .take(10)
                .any(|(_, index)| relevant.contains(index))
            {
                hits += 1;
            }
        }
        hits as f32 / queries.len() as f32
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
