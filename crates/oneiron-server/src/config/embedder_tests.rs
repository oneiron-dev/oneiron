//! Resolution rows for the `[embedder]` section.

use super::embedder::{EmbedderDevice, EmbedderQuant};
use super::*;

fn config_file(body: &str) -> (tempfile::TempDir, ServeArgs) {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("oneiron.toml");
    std::fs::write(&path, body).expect("write config");
    let args = ServeArgs {
        config: Some(path),
        ..Default::default()
    };
    (dir, args)
}

fn resolve(body: &str) -> anyhow::Result<ServeConfig> {
    let (_dir, args) = config_file(body);
    resolve_serve_config_with_sources(&args, EnvConfig::default(), None)
}

/// No section anywhere means rung 0: nothing to start, nothing to download, and
/// every existing deployment resolves exactly as it did before.
#[test]
fn a_configuration_that_never_mentions_an_embedder_resolves_to_none() {
    let resolved = resolve("dimensions = 1024\n").expect("resolves");
    assert!(resolved.embedder.is_none());
    assert!(resolved.vault_config().embedding_model.is_none());
}

/// Naming the section selects the local provider, and that pins the vault's
/// embedding space.
#[test]
fn an_empty_section_selects_the_local_provider_and_pins_the_space() {
    let resolved = resolve("dimensions = 1024\n\n[embedder]\n").expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert_eq!(embedder.provider, EmbedderProvider::Local);
    assert_eq!(
        embedder.model_id,
        super::embedder::DEFAULT_MODEL_ID,
        "the default local model is the pinned space"
    );
    assert_eq!(
        resolved.vault_config().embedding_model.as_deref(),
        Some(super::embedder::DEFAULT_MODEL_ID)
    );
}

/// `provider = "none"` is the section stated rather than absent: it resolves,
/// and it pins no space.
#[test]
fn an_explicit_none_provider_pins_no_embedding_space() {
    let resolved =
        resolve("dimensions = 1024\n\n[embedder]\nprovider = \"none\"\n").expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert!(!embedder.is_active());
    assert!(resolved.vault_config().embedding_model.is_none());
}

/// One vault, one width. The two numbers disagreeing is a configuration error
/// and not something to discover at the first fill.
#[test]
fn an_embedder_width_that_differs_from_the_vault_width_is_refused() {
    let error = resolve("dimensions = 4096\n\n[embedder]\ndimensions = 1024\n")
        .expect_err("a width mismatch is refused")
        .to_string();
    assert!(error.contains("embedder.dimensions"), "{error}");
    assert!(error.contains("4096"), "{error}");
}

#[test]
fn an_endpoint_provider_without_an_endpoint_is_refused() {
    let error = resolve(
        "dimensions = 1024\n\n[embedder]\nprovider = \"endpoint\"\ndimensions = 1024\nmodel_key = \"k\"\n",
    )
    .expect_err("an endpoint provider needs an endpoint")
    .to_string();
    assert!(error.contains("embedder.endpoint"), "{error}");
}

#[test]
fn an_endpoint_provider_without_a_model_key_is_refused() {
    let error = resolve(
        "dimensions = 1024\n\n[embedder]\nprovider = \"endpoint\"\ndimensions = 1024\nendpoint = \"http://127.0.0.1:1234/v1\"\n",
    )
    .expect_err("an endpoint provider needs a model key")
    .to_string();
    assert!(error.contains("embedder.model_key"), "{error}");
}

/// A third-party embedder is a locality the engine models and this server has no
/// egress predicate for, so it is refused by name rather than silently demoted.
/// `{:#}` reads the whole anyhow chain: the file layer wraps the refusal.
#[test]
fn a_third_party_locality_in_the_file_is_refused_by_name() {
    let error =
        resolve("dimensions = 1024\n\n[embedder]\ndimensions = 1024\nlocality = \"third-party\"\n")
            .expect_err("third-party is refused");
    let chain = format!("{error:#}");
    assert!(chain.contains("third-party"), "{chain}");
    assert!(chain.contains("on-device"), "{chain}");
}

/// The same refusal through the environment, where the server's own parser runs
/// and says why rather than listing alternatives.
#[test]
fn a_third_party_locality_in_the_environment_is_refused_with_the_reason() {
    let env = EnvConfig::from_pairs([("ONEIRON_EMBEDDER_LOCALITY", "third-party")]);
    let error = env.expect_err("third-party is refused").to_string();
    assert!(error.contains("egress predicate"), "{error}");
}

/// bf16 has no CPU matmul path worth running, so the pairing is refused while it
/// is still a configuration error rather than a failure after a download.
#[test]
fn bf16_weights_on_a_cpu_device_are_refused() {
    let error = resolve(
        "dimensions = 1024\n\n[embedder]\ndimensions = 1024\nquant = \"none\"\ndevice = \"cpu\"\n",
    )
    .expect_err("bf16 on the CPU is refused")
    .to_string();
    assert!(error.contains("quant"), "{error}");
}

#[test]
fn a_zero_request_timeout_is_refused_rather_than_timing_out_every_request() {
    let error = resolve(
        "dimensions = 1024\n\n[embedder]\nprovider = \"endpoint\"\ndimensions = 1024\nendpoint = \"http://127.0.0.1:1234/v1\"\nmodel_key = \"k\"\ntimeout_ms = 0\n",
    )
    .expect_err("a zero timeout is refused")
    .to_string();
    assert!(error.contains("timeout_ms"), "{error}");
}

#[test]
fn an_unknown_provider_name_fails_closed() {
    let error = resolve("dimensions = 1024\n\n[embedder]\nprovider = \"magic\"\n")
        .expect_err("an unknown provider is refused");
    let chain = format!("{error:#}");
    assert!(chain.contains("parse config file"), "{chain}");
    assert!(chain.contains("magic"), "{chain}");
}

/// Precedence is defaults, then the file, then the environment, then argv — the
/// same order every other key follows.
#[test]
fn the_environment_overrides_the_file_and_argv_overrides_both() {
    let (_dir, mut args) = config_file(
        "dimensions = 1024\n\n[embedder]\ndimensions = 1024\nbatch_size = 8\nmax_input_tokens = 100\nrevision = \"fromfile\"\n",
    );
    let env = EnvConfig::from_pairs([
        ("ONEIRON_EMBEDDER_BATCH_SIZE", "16"),
        ("ONEIRON_EMBEDDER_MAX_INPUT_TOKENS", "200"),
    ])
    .expect("env");
    args.embedder.embedder_batch_size = Some(32);

    let resolved = resolve_serve_config_with_sources(&args, env, None).expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert_eq!(embedder.batch_size, 32, "argv wins");
    assert_eq!(
        embedder.max_input_tokens, 200,
        "the environment beats the file"
    );
    assert_eq!(
        embedder.local.revision, "fromfile",
        "the file is still read"
    );
}

/// The environment alone is enough to make the section present: an operator who
/// only exports variables still gets a worker.
#[test]
fn the_environment_alone_makes_the_section_present() {
    let env = EnvConfig::from_pairs([
        ("ONEIRON_DIMENSIONS", "1024"),
        ("ONEIRON_EMBEDDER_DEVICE", "cpu"),
    ])
    .expect("env");
    let resolved =
        resolve_serve_config_with_sources(&ServeArgs::default(), env, None).expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert_eq!(embedder.local.device, EmbedderDevice::Cpu);
    assert_eq!(embedder.local.quant, EmbedderQuant::Q8_0);
}

/// An unknown key inside the section fails closed, as it does at the top level.
#[test]
fn an_unknown_key_inside_the_section_fails_closed() {
    let error = resolve("dimensions = 1024\n\n[embedder]\nnot_a_key = 1\n")
        .expect_err("an unknown key is refused");
    let chain = format!("{error:#}");
    assert!(chain.contains("parse config file"), "{chain}");
    assert!(chain.contains("not_a_key"), "{chain}");
}
