//! Local-provider rows.
//!
//! Everything that can be proved without the model's weights runs here and in
//! CI. The rows that need the 1.19 GB checkpoint are marked `#[ignore]` and
//! named in the PR body with their measured numbers: a gate that downloads a
//! gigabyte from the internet is not a gate.

use candle_core::{DType, Device, IndexOp, Tensor};

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

/// A `FlexibleQuantizer` after mean pooling emits `round(tanh(x) · 127)`,
/// clamped to the int8 range, and the provider never adds a Normalize the
/// checkpoint did not declare.
#[test]
fn the_int8_tanh_quantizer_follows_mean_pooling_in_declared_order() {
    let dir = tempfile::tempdir().expect("fixture dir");
    std::fs::write(
        dir.path().join("modules.json"),
        br#"[{"idx":0,"name":"0","path":"","type":"sentence_transformers.models.Transformer"},
             {"idx":1,"name":"1","path":"1_Pooling","type":"sentence_transformers.models.Pooling"},
             {"idx":2,"name":"2","path":"","type":"st_quantize.FlexibleQuantizer","kwargs":["quantization"]}]"#,
    )
    .expect("write modules.json");
    std::fs::create_dir_all(dir.path().join("1_Pooling")).expect("pool dir");
    std::fs::write(
        dir.path().join("1_Pooling").join("config.json"),
        br#"{"word_embedding_dimension":4,"pooling_mode_mean_tokens":true,"include_prompt":true}"#,
    )
    .expect("write pooling config");
    let modules = st_modules::StModules::load(dir.path()).expect("the chain parses");

    // Two rows whose means are [0, 0.5, -0.5, 9] and [0.01, -0.01, 2, -9].
    let hidden = Tensor::from_vec(
        vec![
            0.0f32, 0.0, -1.0, 8.0, 0.0, 1.0, 0.0, 10.0, //
            0.02, 0.0, 2.0, -8.0, 0.0, -0.02, 2.0, -10.0,
        ],
        (2, 2, 4),
        &Device::Cpu,
    )
    .expect("hidden states");
    let pooled: Vec<Vec<f32>> = modules
        .apply(&hidden)
        .and_then(|pooled| pooled.to_vec2())
        .expect("pooled");
    let expected = |means: [f32; 4]| -> Vec<f32> {
        means
            .iter()
            .map(|m| (m.tanh() * 127.0).round().clamp(-128.0, 127.0))
            .collect()
    };
    assert_eq!(pooled[0], expected([0.0, 0.5, -0.5, 9.0]));
    assert_eq!(pooled[1], expected([0.01, -0.01, 2.0, -9.0]));
    assert_eq!(pooled[0], vec![0.0, 59.0, -59.0, 127.0]);
    assert!(
        pooled.iter().flatten().all(|v| v.fract() == 0.0),
        "the quantizer emits integers, not a unit vector"
    );
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

/// The Arch decision needs a measured Q8 matmul vs eager-attention split,
/// not a guess based on a single end-to-end throughput number. Synthetic
/// tensors have the pinned Harrier layer's shapes; run on an idle CPU host.
#[test]
#[ignore = "CPU microbenchmark; run with --ignored --nocapture on the Arch host"]
fn the_cpu_q8_projection_and_eager_attention_report_timings() {
    let cpu = Device::Cpu;
    let weight = Tensor::from_vec(
        (0..3072 * 1024)
            .map(|n| ((n as f32 * 0.01).sin()) * 0.01)
            .collect(),
        (3072, 1024),
        &cpu,
    )
    .expect("projection weight");
    let q8 = candle_core::quantized::QTensor::quantize_onto(
        &weight,
        candle_core::quantized::GgmlDType::Q8_0,
        &cpu,
    )
    .and_then(candle_core::quantized::QMatMul::from_qtensor)
    .expect("Q8_0 projection");
    let inputs =
        Tensor::from_vec(vec![0.1f32; 128 * 1024], (128, 1024), &cpu).expect("layer inputs");
    let make = |heads: usize| {
        Tensor::from_vec(vec![0.01f32; heads * 128 * 128], (1, heads, 128, 128), &cpu)
            .expect("attention input")
    };
    let (q, k, v) = (make(16), make(8), make(8));
    let mask = attention::causal_mask(128, &cpu).expect("mask");
    // Warm both paths, then compare one intermediate MLP projection with one
    // grouped-query attention pass at the same sequence length.
    candle_core::Module::forward(&q8, &inputs).expect("projection warmup");
    attention::eager_attention(&q, &k, &v, Some(&mask), 1.0 / 128f32.sqrt())
        .expect("attention warmup");
    let started = std::time::Instant::now();
    for _ in 0..5 {
        std::hint::black_box(
            candle_core::Module::forward(&q8, &inputs).expect("projection forward"),
        );
    }
    let projection_ms = started.elapsed().as_secs_f64() * 1000.0 / 5.0;
    let started = std::time::Instant::now();
    for _ in 0..5 {
        std::hint::black_box(
            attention::eager_attention(&q, &k, &v, Some(&mask), 1.0 / 128f32.sqrt())
                .expect("attention forward"),
        );
    }
    let attention_ms = started.elapsed().as_secs_f64() * 1000.0 / 5.0;
    println!(
        "Harrier seq=128: one Q8_0 (3072x1024) projection {:.2} ms; one eager GQA attention {:.2} ms; attention/projection {:.2}",
        projection_ms,
        attention_ms,
        attention_ms / projection_ms,
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
    let scale = 1.0 / (head_dim as f32).sqrt();
    let to_metal = |tensor: &Tensor| tensor.to_device(&metal).expect("to metal");
    // Causal: the eager branch takes the mask, the fused kernel masks itself
    // and the model builds no mask for it. Bidirectional: neither takes one.
    for (causal, eager_mask) in [(true, Some(&mask)), (false, None)] {
        let eager: Vec<f32> = attention::eager_attention(&q, &k, &v, eager_mask, scale)
            .and_then(|out| out.flatten_all()?.to_vec1())
            .expect("eager attention");
        let fused: Vec<f32> = attention::grouped_attention(
            &to_metal(&q),
            &to_metal(&k),
            &to_metal(&v),
            None,
            causal,
            scale,
        )
        .and_then(|out| out.flatten_all()?.to_vec1())
        .expect("fused attention");

        assert_eq!(eager.len(), fused.len());
        let worst = eager
            .iter()
            .zip(&fused)
            .map(|(a, b)| (a - b).abs())
            .fold(0f32, f32::max);
        assert!(
            worst < 1e-2,
            "causal={causal}: branches disagree by {worst}"
        );
    }
}

/// Bidirectional attention lets the FIRST position read the last one; causal
/// attention does not. The same inputs through both shapes must therefore
/// agree on the final row, which sees everything either way, and differ on the
/// first.
#[test]
fn bidirectional_attention_reads_later_positions_and_causal_does_not() {
    let (batch, heads, kv_heads, seq, head_dim) = (1usize, 2usize, 1usize, 4usize, 8usize);
    let make = |count: usize, seed: f32| {
        let values: Vec<f32> = (0..batch * count * seq * head_dim)
            .map(|n| ((n as f32 * seed).sin()) * 0.5)
            .collect();
        Tensor::from_vec(values, (batch, count, seq, head_dim), &Device::Cpu).expect("tensor")
    };
    let (q, k, v) = (
        make(heads, 0.31),
        make(kv_heads, 0.17),
        make(kv_heads, 0.23),
    );
    let mask = attention::causal_mask(seq, &Device::Cpu).expect("mask");
    let causal =
        attention::grouped_attention(&q, &k, &v, Some(&mask), true, 0.5).expect("causal attention");
    let bidirectional =
        attention::grouped_attention(&q, &k, &v, None, false, 0.5).expect("bidirectional");
    let row = |tensor: &Tensor, position: usize| -> Vec<f32> {
        tensor
            .i((0, 0, position))
            .and_then(|row| row.to_vec1())
            .expect("row")
    };
    let gap = |a: &[f32], b: &[f32]| {
        a.iter()
            .zip(b)
            .map(|(x, y)| (x - y).abs())
            .fold(0f32, f32::max)
    };
    assert!(gap(&row(&causal, seq - 1), &row(&bidirectional, seq - 1)) < 1e-6);
    assert!(gap(&row(&causal, 0), &row(&bidirectional, 0)) > 1e-3);
    assert!(
        attention::grouped_attention(&q, &k, &v, None, true, 0.5).is_err(),
        "eager causal attention without its mask is refused, not run unmasked"
    );
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
fn every_qwen3_body_class_name_is_accepted() {
    for architecture in ["Qwen3Model", "Qwen3ForCausalLM", "PPLXQwen3Model"] {
        let config = qwen3_embedding::Config::parse(&config_json(architecture))
            .expect("an accepted class parses");
        assert_eq!(config.hidden_size, 1024);
        assert_eq!(config.head_dim(), 128);
    }
}

/// The attention shape is the checkpoint's declaration, not a class name: the
/// key absent means causal, and `true` means bidirectional for any class.
#[test]
fn bidirectional_attention_is_read_from_the_config_and_defaults_to_causal() {
    let causal = qwen3_embedding::Config::parse(&config_json("PPLXQwen3Model")).expect("parses");
    assert!(!causal.use_bidirectional_attention);
    for architecture in ["PPLXQwen3Model", "Qwen3Model"] {
        let raw = config_json(architecture).replace(
            "\"head_dim\":128",
            "\"head_dim\":128,\"use_bidirectional_attention\":true",
        );
        let bidirectional = qwen3_embedding::Config::parse(&raw).expect("parses");
        assert!(bidirectional.use_bidirectional_attention, "{architecture}");
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

/// The same refusal config resolution makes against the default model, made
/// again against whatever window the loaded model declares.
#[test]
fn an_input_cap_above_the_loaded_models_window_is_refused_with_both_numbers() {
    let model_config =
        qwen3_embedding::Config::parse(&config_json("Qwen3Model")).expect("the config parses");
    let over = crate::config::EmbedderConfig {
        max_input_tokens: model_config.max_position_embeddings + 1,
        ..crate::config::EmbedderConfig::default()
    };
    let error = check_input_window(&over, &model_config).expect_err("a cap above the window");
    let oneiron::Error::InvalidConfig(message) = &error else {
        panic!("{error:?}");
    };
    assert!(message.contains("32769"), "{message}");
    assert!(message.contains("32768"), "{message}");

    let at_the_window = crate::config::EmbedderConfig {
        max_input_tokens: model_config.max_position_embeddings,
        ..crate::config::EmbedderConfig::default()
    };
    assert!(check_input_window(&at_the_window, &model_config).is_ok());
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
    assert!(resolve_test_device(EmbedderDevice::Auto).is_ok());
    assert!(matches!(
        resolve_test_device(EmbedderDevice::Cpu),
        Ok(Device::Cpu)
    ));
    if Device::new_metal(0).is_err() {
        assert!(
            resolve_test_device(EmbedderDevice::Metal).is_err(),
            "a named device this build cannot reach is refused"
        );
    }
    if Device::new_metal(0).is_err() && Device::new_cuda(0).is_err() {
        assert!(matches!(
            resolve_test_device(EmbedderDevice::Auto),
            Ok(Device::Cpu)
        ));
    }
}

#[test]
fn a_named_cuda_device_is_an_error_when_unavailable_not_a_cpu_downgrade() {
    if Device::new_cuda(0).is_err() {
        assert!(
            resolve_test_device(EmbedderDevice::Cuda).is_err(),
            "a named unavailable CUDA device must fail closed"
        );
    } else {
        assert!(matches!(
            resolve_test_device(EmbedderDevice::Cuda),
            Ok(Device::Cuda(_))
        ));
    }
}

fn resolve_test_device(configured: EmbedderDevice) -> oneiron::Result<Device> {
    device::resolve_device(
        configured,
        &crate::config::LocalEmbedderConfig::default().auto_devices,
    )
}

#[test]
fn auto_honours_a_vault_narrowed_cpu_only_candidate_set() {
    assert!(matches!(
        device::resolve_device(EmbedderDevice::Auto, &[EmbedderDevice::Cpu]),
        Ok(Device::Cpu)
    ));
    if Device::new_cuda(0).is_err() {
        let error = device::resolve_device(EmbedderDevice::Auto, &[EmbedderDevice::Cuda])
            .expect_err("a disallowed CPU may not become a silent fallback");
        assert!(matches!(error, oneiron::Error::InvalidConfig(_)));
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
            .join("perplexity-ai")
            .join("pplx-embed-v1-0.6b")
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
        model_manager::resolve_models_root(Some(std::path::Path::new("/models")), None, None)
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

/// Every measured model resolves to its own pins, each carrying a digest and a
/// size, and covering every file the provider reads.
#[test]
fn every_measured_model_resolves_to_its_own_digest_pinned_files() {
    use crate::config::embedder_models::{HARRIER_06, KNOWN_MODELS, PPLX_EMBED_V1_06};
    for model in KNOWN_MODELS {
        let files = model_manager::model_files(&crate::config::LocalEmbedderConfig {
            repo: model.repo.to_owned(),
            revision: model.revision.to_owned(),
            ..crate::config::LocalEmbedderConfig::default()
        });
        for artifact in &files {
            assert_eq!(
                artifact.sha256.len(),
                64,
                "{}: {} has no sha256 digest",
                model.model_id,
                artifact.file
            );
            assert!(artifact.bytes > 0, "{} has no pinned size", artifact.file);
        }
        let names: Vec<&str> = files.iter().map(|artifact| artifact.file).collect();
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
    let default = model_manager::model_files(&crate::config::LocalEmbedderConfig::default());
    assert_eq!(default, model_manager::PPLX_EMBED_V1_06_FILES.to_vec());
    assert_eq!(
        model_manager::model_files(&crate::config::LocalEmbedderConfig {
            repo: HARRIER_06.repo.to_owned(),
            revision: HARRIER_06.revision.to_owned(),
            ..crate::config::LocalEmbedderConfig::default()
        }),
        model_manager::HARRIER_06_FILES.to_vec(),
        "a vault pinned to the earlier default still verifies that model's files"
    );
    assert_ne!(PPLX_EMBED_V1_06.model_id, HARRIER_06.model_id);
}

/// A repository this build has never measured needs the files the provider
/// reads, and drops the digest pins rather than failing every download
/// against the wrong digest.
#[test]
fn an_unpinned_repository_keeps_the_file_list_without_digests() {
    let config = crate::config::LocalEmbedderConfig {
        repo: "someone/else".to_owned(),
        ..crate::config::LocalEmbedderConfig::default()
    };
    let files = model_manager::model_files(&config);
    let names: Vec<&str> = files.iter().map(|artifact| artifact.file).collect();
    assert_eq!(
        names,
        [
            "config.json",
            "modules.json",
            "1_Pooling/config.json",
            "tokenizer.json",
            "model.safetensors"
        ]
    );
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

/// A named accelerator refusal must happen before either public model
/// acquisition door reaches an HTTP source or creates the cache directory.
#[test]
fn unavailable_cuda_refuses_prepare_and_load_before_acquiring_any_artifact() {
    if Device::new_cuda(0).is_ok() {
        // On an NVIDIA build, CUDA is available; this refusal is proved on
        // toolchain-less CI and on every host without a CUDA device.
        return;
    }
    let source = StubSource::start();
    let root = tempfile::tempdir().expect("model cache root");
    let mut config = crate::config::EmbedderConfig::default();
    config.local.device = EmbedderDevice::Cuda;
    config.local.models_dir = Some(root.path().to_path_buf());
    let manager = model_manager::ModelManager::with_base_url(&source.base);

    let first = super::prepare_with_manager(&config, &manager).expect_err("CUDA is unavailable");
    let second = LocalEmbedder::load(&config, &manager)
        .err()
        .expect("CUDA is unavailable");
    for error in [first, second] {
        assert!(
            matches!(error, oneiron::Error::InvalidConfig(ref message) if message.contains("cuda")),
            "{error:?}"
        );
    }
    assert!(
        source.paths().is_empty(),
        "no HTTP request reached the source"
    );
    assert_eq!(
        std::fs::read_dir(root.path()).expect("cache root").count(),
        0,
        "no artifact directory was created"
    );
}

/// An auto-selected available fallback still reaches the artifact source.
#[test]
fn auto_fallback_can_prepare_an_uncached_model() {
    let source = StubSource::start();
    let root = tempfile::tempdir().expect("model cache root");
    let mut config = crate::config::EmbedderConfig::default();
    config.local.repo = "fixture/model".to_owned();
    config.local.models_dir = Some(root.path().to_path_buf());
    let manager = model_manager::ModelManager::with_base_url(&source.base);

    let label = super::prepare_with_manager(&config, &manager).expect("auto can prepare");
    assert_eq!(
        label,
        device::device_label(&resolve_test_device(EmbedderDevice::Auto).expect("auto device"))
    );
    let model_dir = model_manager::model_dir(&config.local).expect("model dir");
    assert_eq!(
        std::fs::read_to_string(model_dir.join("config.json")).expect("first artifact"),
        STUB_BODY
    );
    assert_eq!(
        source.paths().len(),
        model_manager::model_files(&config.local).len()
    );
}

/// A vault that removes CPU from auto must not silently use it when its only
/// permitted accelerator is unavailable. This is the same acquisition door
/// the worker uses, not just an isolated device-selector test.
#[test]
fn narrowed_auto_policy_refuses_before_acquiring_artifacts_when_no_candidate_is_available() {
    if Device::new_cuda(0).is_ok() {
        return;
    }
    let source = StubSource::start();
    let root = tempfile::tempdir().expect("model cache root");
    let mut config = crate::config::EmbedderConfig::default();
    config.local.models_dir = Some(root.path().to_path_buf());
    config.local.auto_devices = vec![EmbedderDevice::Cuda];
    let manager = model_manager::ModelManager::with_base_url(&source.base);

    let error = super::prepare_with_manager(&config, &manager)
        .expect_err("CPU fallback was excluded by the vault policy");
    assert!(matches!(error, oneiron::Error::InvalidConfig(_)));
    assert!(
        source.paths().is_empty(),
        "no HTTP request reached the source"
    );
    assert_eq!(
        std::fs::read_dir(root.path()).expect("cache root").count(),
        0,
        "no artifact directory was created"
    );
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
    use crate::config::embedder_models::{HARRIER_06, KnownModel, PPLX_EMBED_V1_06};

    /// A measured model's config as shipped, reachable only when its artifacts
    /// are on this host. Offline GPU hosts can name a directory already holding
    /// the verified checkpoint in `dir_env` without downloading it again or
    /// changing the test fixture.
    fn model_config(model: &KnownModel, dir_env: &str, device: EmbedderDevice) -> EmbedderConfig {
        EmbedderConfig {
            model_id: model.model_id.to_owned(),
            dimensions: model.dimensions,
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
        model_config(&HARRIER_06, "ONEIRON_EMBED_TEST_MODEL_DIR", device)
    }

    fn pplx_config(device: EmbedderDevice) -> EmbedderConfig {
        model_config(
            &PPLX_EMBED_V1_06,
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
        let measured = embedder.embed_texts(&reference_chunks()).expect("embedded");
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
                .embed_texts(&pplx_parity_texts())
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
            .embed_texts(&pplx_parity_texts())
            .expect("embedded");
        let (worst, mean) = agreement(&measured, &pplx_reference_vectors(), 0.99);
        println!("pplx Q8_0 vs sentence-transformers: worst cosine {worst}, mean {mean}");
    }

    /// The same inputs, one at a time and together, must produce the same
    /// vectors: the no-padding grouping is only correct if it is. The default
    /// model's inputs here have uneven lengths, which the reference ran as
    /// padded, masked batches.
    #[test]
    #[ignore = "needs both checkpoints; run with --run-ignored=all"]
    fn a_batched_input_embeds_exactly_as_it_does_alone() {
        for (config, texts) in [
            (
                harrier_config(EmbedderDevice::Auto),
                reference_chunks().into_iter().take(8).collect::<Vec<_>>(),
            ),
            (
                pplx_config(EmbedderDevice::Auto),
                pplx_parity_texts().into_iter().take(18).collect(),
            ),
        ] {
            let embedder = LocalEmbedder::load(&config, &manager()).expect("model loads");
            let batched = embedder.embed_texts(&texts).expect("batched");
            for (index, text) in texts.iter().enumerate() {
                let alone = embedder
                    .embed_texts(std::slice::from_ref(text))
                    .expect("single");
                let score = cosine(&batched[index], &alone[0]);
                assert!(
                    score >= 0.9999,
                    "{}: input {index} differs batched vs alone: cosine {score}",
                    config.model_id
                );
            }
        }
    }

    /// The earlier default's post-processor appends the end-of-text token. A
    /// truncated input keeps it, because last-token pooling reads that row.
    #[test]
    #[ignore = "needs the 1.19 GB checkpoint; run with --run-ignored=all"]
    fn the_tokenizer_appends_one_end_of_text_token_and_truncation_keeps_it() {
        let tokenizer = provider_tokenizer(&harrier_config(EmbedderDevice::Auto), 4096);
        let short = batcher::tokenize(&tokenizer, &["hello".to_owned()]).expect("tokenized");
        let ids = &short[0].ids;
        assert_eq!(*ids.last().expect("a final token"), 151_643);
        assert_eq!(
            ids.iter().filter(|id| **id == 151_643).count(),
            1,
            "the end-of-text token appears exactly once"
        );
        assert!(!short[0].truncated);

        let tokenizer = provider_tokenizer(&harrier_config(EmbedderDevice::Auto), 64);
        let cut = batcher::tokenize(&tokenizer, &["word ".repeat(4000)]).expect("tokenized");
        assert!(cut[0].truncated, "an over-long input is truncated");
        assert_eq!(cut[0].ids.len(), 64);
        assert_eq!(
            *cut[0].ids.last().expect("a final token"),
            151_643,
            "truncation keeps the token last-token pooling reads"
        );
    }

    /// The default model's tokenizer adds nothing around the text, so a
    /// truncated input is exactly the head of the full one. Keeping the final
    /// token, as the earlier default needs, would splice the text's end onto
    /// its start.
    #[test]
    #[ignore = "needs the 2.38 GB pplx-embed-v1 checkpoint; run with --run-ignored=all"]
    fn the_default_tokenizer_appends_nothing_and_truncation_keeps_the_head() {
        let long = "word ".repeat(3999) + "ending";
        let full = batcher::tokenize(
            &provider_tokenizer(&pplx_config(EmbedderDevice::Auto), 32_768),
            &[
                "hello".to_owned(),
                long.clone(),
                " \n hello\t\u{3000}".to_owned(),
            ],
        )
        .expect("tokenized");
        assert_eq!(full[0].ids.len(), 1, "a one-word input is one token");
        assert!(!full[1].truncated);
        assert_eq!(
            full[2].ids, full[0].ids,
            "surrounding whitespace is stripped, as sentence-transformers strips it"
        );

        let cut = batcher::tokenize(
            &provider_tokenizer(&pplx_config(EmbedderDevice::Auto), 64),
            &[long],
        )
        .expect("tokenized");
        assert!(cut[0].truncated, "an over-long input is truncated");
        assert_eq!(cut[0].ids, full[1].ids[..64]);
    }

    fn provider_tokenizer(config: &EmbedderConfig, cap: usize) -> tokenizers::Tokenizer {
        let dir = manager()
            .ensure_all(&config.local)
            .expect("artifacts present");
        let tokenizer =
            tokenizers::Tokenizer::from_file(dir.join("tokenizer.json")).expect("tokenizer loads");
        batcher::for_provider(tokenizer, cap).expect("the cap fits")
    }

    /// Metal and CPU must agree: a vault filled on one host and queried from
    /// another is one space only if they do.
    #[test]
    #[ignore = "needs both checkpoints and is slow on CPU"]
    fn the_cpu_and_metal_devices_agree_on_the_same_input() {
        if Device::new_metal(0).is_err() {
            return;
        }
        for (config, texts) in [
            (
                harrier_config as fn(EmbedderDevice) -> EmbedderConfig,
                reference_chunks().into_iter().take(4).collect::<Vec<_>>(),
            ),
            (
                pplx_config,
                pplx_parity_texts().into_iter().take(17).collect(),
            ),
        ] {
            let on_metal = LocalEmbedder::load(&config(EmbedderDevice::Metal), &manager())
                .expect("metal model")
                .embed_texts(&texts)
                .expect("metal vectors");
            let on_cpu = LocalEmbedder::load(&config(EmbedderDevice::Cpu), &manager())
                .expect("cpu model")
                .embed_texts(&texts)
                .expect("cpu vectors");
            for (index, (metal, cpu)) in on_metal.iter().zip(&on_cpu).enumerate() {
                let score = cosine(metal, cpu);
                assert!(score >= 0.999, "input {index} differs by device: {score}");
            }
        }
    }

    /// A named CUDA build must really load Q8_0 projections onto CUDA and
    /// produce the same embedding space as the featureless CPU build.
    #[test]
    #[ignore = "needs the default checkpoint and a CUDA-enabled NVIDIA host"]
    fn the_cpu_and_cuda_devices_agree_on_the_committed_subset() {
        Device::new_cuda(0).expect("build candle-core/cuda + candle-nn/cuda on an NVIDIA host");
        let texts = pplx_parity_texts();
        let on_cuda = LocalEmbedder::load(&pplx_config(EmbedderDevice::Cuda), &manager())
            .expect("CUDA Q8_0 model loads")
            .embed_texts(&texts)
            .expect("CUDA Q8_0 vectors");
        let on_cpu = LocalEmbedder::load(&pplx_config(EmbedderDevice::Cpu), &manager())
            .expect("CPU Q8_0 model loads")
            .embed_texts(&texts)
            .expect("CPU Q8_0 vectors");
        let mut worst = 1.0f32;
        for (index, (cuda, cpu)) in on_cuda.iter().zip(&on_cpu).enumerate() {
            let score = cosine(cuda, cpu);
            assert!(score >= 0.999, "input {index} differs by device: {score}");
            worst = worst.min(score);
        }
        println!(
            "CUDA vs CPU worst cosine on {} inputs: {worst}",
            texts.len()
        );
    }

    /// Small committed subset for hosts without the out-of-tree full spec
    /// corpus; report both load and forward throughput with an explicit device.
    #[test]
    #[ignore = "needs the default checkpoint; choose ONEIRON_EMBED_BENCH_DEVICE"]
    fn the_committed_subset_reports_load_and_throughput() {
        let device = bench_device();
        let texts = reference_chunks();
        let start = std::time::Instant::now();
        let embedder = LocalEmbedder::load(&pplx_config(device), &manager()).expect("model loads");
        let load_secs = start.elapsed().as_secs_f64();
        let start = std::time::Instant::now();
        let vectors = embedder.embed_texts(&texts).expect("vectors");
        let forward_secs = start.elapsed().as_secs_f64();
        assert_eq!(vectors.len(), texts.len());
        println!(
            "{}: subset {} chunks, load+quantise {:.2}s, forward {:.2}s, {:.2} chunks/s",
            device.as_str(),
            texts.len(),
            load_secs,
            forward_secs,
            texts.len() as f64 / forward_secs
        );
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
    /// retest's own scorer can grade the provider's rankings.
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
        let documents = embedder.embed_texts(&texts).expect("documents embedded");
        let embed_secs = embed_started.elapsed().as_secs_f64();
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
