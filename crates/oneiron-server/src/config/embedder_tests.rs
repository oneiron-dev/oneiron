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

/// The default space is the default model's files, end to end, and nothing is
/// said about a query instruction: the model's own files decide it.
#[test]
fn the_default_space_is_the_default_models_files() {
    let resolved = resolve("dimensions = 1024\n\n[embedder]\n").expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert_eq!(embedder.model_id, super::embedder::DEFAULT_MODEL_ID);
    assert_eq!(
        embedder.model_id,
        format!("{}@{}", embedder.local.repo, embedder.local.revision),
        "the default space id spells its repository and commit"
    );
    assert_eq!(embedder.dimensions, super::embedder::DEFAULT_DIMENSIONS);
    assert_eq!(embedder.query_instruction, None);
    assert_eq!(embedder.query_prompt_name, None);
    assert_eq!(embedder.local.attention, super::EmbedderAttention::Auto);
    assert_eq!(
        embedder.local.output_quantization,
        super::EmbedderOutputQuantization::Int8
    );
}

const HARRIER: &str = "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee";

/// A config that names a space and not its files means that space's own
/// files. This is the shape `init` writes, so a vault created under the
/// earlier default keeps being filled by the earlier default's weights after
/// the default moves.
#[test]
fn naming_a_space_selects_its_own_files() {
    let resolved = resolve(&format!(
        "dimensions = 1024\n\n[embedder]\nprovider = \"local\"\ndimensions = 1024\nmodel_id = \"{HARRIER}\"\n"
    ))
    .expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert_eq!(embedder.local.repo, "microsoft/harrier-oss-v1-0.6b");
    assert_eq!(
        embedder.local.revision,
        "f9b9dc8d367d443f2479d27aa5d8d2850c0774ee"
    );
    assert_eq!(
        resolved.vault_config().embedding_model.as_deref(),
        Some(HARRIER)
    );
}

/// Files named beside the space must be the space's own, in the same layer or
/// a later one: a vault pinned to one model must never be filled from another
/// model's files under the first one's name.
#[test]
fn files_that_disagree_with_the_named_space_are_refused() {
    let in_config_error = |error: anyhow::Error| {
        matches!(
            error.downcast_ref::<oneiron::Error>(),
            Some(oneiron::Error::InvalidConfig(_))
        )
    };
    let (_dir, args) = config_file(&format!(
        "dimensions = 1024\n\n[embedder]\ndimensions = 1024\nmodel_id = \"{HARRIER}\"\nrepo = \"mirror/harrier\"\n"
    ));
    let error = resolve_serve_config_with_sources(&args, EnvConfig::default(), None)
        .expect_err("a repository other than the space's is refused");
    assert!(in_config_error(error));

    // The default space, with another model's files named from argv.
    let (_dir, mut args) = config_file("dimensions = 1024\n\n[embedder]\ndimensions = 1024\n");
    args.embedder.embedder_model_id = Some(super::embedder::DEFAULT_MODEL_ID.to_owned());
    args.embedder.embedder_repo = Some("microsoft/harrier-oss-v1-0.6b".to_owned());
    args.embedder.embedder_revision = Some("f9b9dc8d367d443f2479d27aa5d8d2850c0774ee".to_owned());
    let error = resolve_serve_config_with_sources(&args, EnvConfig::default(), None)
        .expect_err("another model's files under the default space are refused");
    assert!(in_config_error(error));

    // A later layer's revision alone still has to match the space.
    let (_dir, mut args) = config_file(&format!(
        "dimensions = 1024\n\n[embedder]\ndimensions = 1024\nmodel_id = \"{HARRIER}\"\n"
    ));
    args.embedder.embedder_revision = Some("mirrored".to_owned());
    let error = resolve_serve_config_with_sources(&args, EnvConfig::default(), None)
        .expect_err("another commit under the same space is refused");
    assert!(in_config_error(error));
}

/// Files named without a space name the space they fill; files named with
/// their own space resolve as named.
#[test]
fn named_files_name_their_own_space() {
    let resolved = resolve(
        "dimensions = 1024\n\n[embedder]\ndimensions = 1024\nrepo = \"microsoft/harrier-oss-v1-0.6b\"\nrevision = \"f9b9dc8d367d443f2479d27aa5d8d2850c0774ee\"\n",
    )
    .expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert_eq!(embedder.model_id, HARRIER);
    assert_eq!(
        resolved.vault_config().embedding_model.as_deref(),
        Some(HARRIER)
    );

    let resolved = resolve(&format!(
        "dimensions = 1024\n\n[embedder]\ndimensions = 1024\nmodel_id = \"{HARRIER}\"\nrepo = \"microsoft/harrier-oss-v1-0.6b\"\nrevision = \"f9b9dc8d367d443f2479d27aa5d8d2850c0774ee\"\n"
    ))
    .expect("a space and its own files resolve");
    assert_eq!(
        resolved.embedder.as_ref().expect("section").model_id,
        HARRIER
    );
}

/// An endpoint makes whatever its server makes, so the vault pins only its
/// width beside the model; `none` pins nothing, and a local model whose files
/// are not on this host yet is checked once they arrive.
#[test]
fn the_vault_pins_a_transform_for_what_the_section_can_declare() {
    let endpoint = resolve(
        "dimensions = 1024\n\n[embedder]\nprovider = \"endpoint\"\ndimensions = 1024\nendpoint = \"http://127.0.0.1:1234/v1\"\nmodel_key = \"k\"\nmodel_id = \"test/remote@v1\"\n",
    )
    .expect("resolves");
    assert_eq!(
        endpoint.vault_config().embedding_transform.as_deref(),
        Some("endpoint;dims=1024")
    );
    let none = resolve("dimensions = 1024\n\n[embedder]\nprovider = \"none\"\n").expect("resolves");
    assert_eq!(none.vault_config().embedding_transform, None);
    let dir = tempfile::tempdir().expect("models root");
    let local = resolve(&format!(
        "dimensions = 1024\n\n[embedder]\ndimensions = 1024\nmodels_dir = {:?}\n",
        dir.path()
    ))
    .expect("resolves");
    assert_eq!(local.vault_config().embedding_transform, None);
}

/// The keys that override a checkpoint's own declaration resolve from the
/// file, the environment and argv like every other key.
#[test]
fn the_model_shape_overrides_resolve_through_every_layer() {
    let resolved = resolve(
        "dimensions = 1024\n\n[embedder]\ndimensions = 1024\nattention = \"bidirectional\"\noutput_quantization = \"binary\"\nquery_prompt_name = \"web_search_query\"\nquery_instruction = \"\"\n",
    )
    .expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert_eq!(
        embedder.local.attention,
        super::EmbedderAttention::Bidirectional
    );
    assert_eq!(
        embedder.local.output_quantization,
        super::EmbedderOutputQuantization::Binary
    );
    assert_eq!(
        embedder.query_prompt_name.as_deref(),
        Some("web_search_query")
    );
    assert_eq!(embedder.query_instruction.as_deref(), Some(""));

    let (_dir, mut args) =
        config_file("dimensions = 1024\n\n[embedder]\nattention = \"bidirectional\"\n");
    let env = EnvConfig::from_pairs([
        ("ONEIRON_EMBEDDER_ATTENTION", "causal"),
        ("ONEIRON_EMBEDDER_QUERY_PROMPT_NAME", "query"),
    ])
    .expect("env");
    args.embedder.embedder_output_quantization = Some(super::EmbedderOutputQuantization::Binary);
    let resolved = resolve_serve_config_with_sources(&args, env, None).expect("resolves");
    let embedder = resolved.embedder.as_ref().expect("a section is present");
    assert_eq!(embedder.local.attention, super::EmbedderAttention::Causal);
    assert_eq!(embedder.query_prompt_name.as_deref(), Some("query"));
    assert_eq!(
        embedder.local.output_quantization,
        super::EmbedderOutputQuantization::Binary
    );
    assert!(resolve("dimensions = 1024\n\n[embedder]\nattention = \"sideways\"\n").is_err());
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
    let env = EnvConfig::from_pairs([
        ("ONEIRON_DIMENSIONS", "1024"),
        ("ONEIRON_EMBEDDER_LOCALITY", "third-party"),
    ])
    .expect("locality parses");
    assert!(resolve_serve_config_with_sources(&ServeArgs::default(), env, None).is_err());
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
fn a_cuda_device_resolves_through_the_config_file() {
    let resolved = resolve("dimensions = 1024\n\n[embedder]\ndevice = \"cuda\"\n")
        .expect("cuda is a supported local device");
    assert_eq!(
        resolved.embedder.expect("embedder configured").local.device,
        EmbedderDevice::Cuda
    );
}

#[test]
fn a_cuda_device_resolves_through_the_environment() {
    let env = EnvConfig::from_pairs([
        ("ONEIRON_DIMENSIONS", "1024"),
        ("ONEIRON_EMBEDDER_DEVICE", "cuda"),
    ])
    .expect("cuda parses");
    let resolved = resolve_serve_config_with_sources(&ServeArgs::default(), env, None)
        .expect("cuda is a supported local device");
    assert_eq!(
        resolved.embedder.expect("embedder configured").local.device,
        EmbedderDevice::Cuda
    );
}

#[test]
fn shipped_auto_device_policy_is_an_ordered_manifest_row() {
    let resolved = resolve("dimensions = 1024\n\n[embedder]\n").expect("local default");
    assert_eq!(
        resolved.embedder.expect("embedder").local.auto_devices,
        [
            EmbedderDevice::Metal,
            EmbedderDevice::Cuda,
            EmbedderDevice::Cpu
        ],
    );
}

#[test]
fn vault_policy_may_reorder_and_nested_layers_may_only_narrow_auto_candidates() {
    let resolved = resolve(
        r#"dimensions = 1024
[embedder]
device = "auto"
[embedder.policy]
auto_devices = ["cpu", "cuda"]
"#,
    )
    .expect("vault-local reordered policy");
    assert_eq!(
        resolved.embedder.expect("embedder").local.auto_devices,
        [EmbedderDevice::Cpu, EmbedderDevice::Cuda]
    );

    let (_dir, args) = config_file(
        r#"dimensions = 1024
[embedder]
[embedder.policy]
auto_devices = ["cuda", "cpu"]
"#,
    );
    let env =
        EnvConfig::from_pairs([("ONEIRON_EMBEDDER_AUTO_DEVICES", "cpu")]).expect("narrow env row");
    let resolved = resolve_serve_config_with_sources(&args, env, None).expect("narrowed");
    assert_eq!(
        resolved.embedder.expect("embedder").local.auto_devices,
        [EmbedderDevice::Cpu]
    );

    let (_dir, mut args) = config_file(
        r#"dimensions = 1024
[embedder]
[embedder.policy]
auto_devices = ["cpu"]
"#,
    );
    args.embedder.embedder_auto_devices = vec![EmbedderDevice::Cuda, EmbedderDevice::Cpu];
    let error = resolve_serve_config_with_sources(&args, EnvConfig::default(), None)
        .expect_err("argv cannot re-enable CUDA above a CPU-only vault policy");
    assert!(
        error.to_string().contains("embedder.policy.auto_devices"),
        "{error}"
    );
}

#[test]
fn shipped_policy_declares_nested_narrowing_precedence() {
    let resolved = resolve("dimensions = 1024\n[embedder]\n").expect("local default");
    assert_eq!(
        resolved
            .embedder
            .expect("embedder")
            .local
            .auto_device_precedence,
        super::embedder::AutoDevicePrecedence::NestedNarrowing,
    );
}

#[test]
fn vault_capped_holder_override_can_bypass_environment_but_not_vault() {
    let (_dir, mut args) = config_file(
        r#"dimensions = 1024
[embedder]
[embedder.policy]
auto_devices = ["cuda", "cpu"]
precedence = "vault-capped-holder-override"
"#,
    );
    let env = EnvConfig::from_pairs([("ONEIRON_EMBEDDER_AUTO_DEVICES", "cpu")])
        .expect("environment preference");
    args.embedder.embedder_auto_devices = vec![EmbedderDevice::Cuda];
    let resolved = resolve_serve_config_with_sources(&args, env.clone(), None)
        .expect("the holder selects CUDA inside the vault cap");
    assert_eq!(
        resolved.embedder.expect("embedder").local.auto_devices,
        [EmbedderDevice::Cuda],
    );

    args.embedder.embedder_auto_devices = vec![EmbedderDevice::Metal];
    let error = resolve_serve_config_with_sources(&args, env, None)
        .expect_err("the holder cannot add Metal outside the vault cap");
    assert!(
        error.to_string().contains("embedder.policy.auto_devices"),
        "{error}"
    );
}

#[test]
fn only_the_vault_policy_can_select_device_precedence() {
    let env = EnvConfig::from_pairs([
        ("ONEIRON_DIMENSIONS", "1024"),
        (
            "ONEIRON_EMBEDDER_POLICY_PRECEDENCE",
            "vault-capped-holder-override",
        ),
    ])
    .expect("environment token parses");
    let error = resolve_serve_config_with_sources(&ServeArgs::default(), env, None)
        .expect_err("an environment cannot change vault precedence");
    assert!(
        error.to_string().contains("embedder.policy.precedence"),
        "{error}"
    );
}

#[test]
fn the_auto_policy_cli_flag_parses_one_ordered_row() {
    #[derive(clap::Parser)]
    struct DeviceCli {
        #[command(flatten)]
        args: super::embedder::EmbedderArgs,
    }
    let parsed = <DeviceCli as clap::Parser>::try_parse_from([
        "oneiron-server",
        "--embedder-auto-devices",
        "cpu,cuda",
    ])
    .expect("policy flag parses");
    assert_eq!(
        parsed.args.embedder_auto_devices,
        vec![EmbedderDevice::Cpu, EmbedderDevice::Cuda]
    );
}

#[test]
fn malformed_auto_device_policy_is_refused_before_model_load() {
    for value in ["[]", "[\"auto\", \"cpu\"]", "[\"cpu\", \"cpu\"]"] {
        let body =
            format!("dimensions = 1024\n[embedder]\n[embedder.policy]\nauto_devices = {value}\n");
        let error = resolve(&body).expect_err("invalid auto policy");
        assert!(
            error.to_string().contains("embedder.policy.auto_devices"),
            "{error}"
        );
    }
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

#[test]
fn remote_third_party_requires_host_egress_at_startup() {
    let body = r#"dimensions = 1024
[embedder]
provider = "local"
[embedder.remote]
endpoint = "https://embed.example/v1"
model_key = "harrier"
locality = "third-party"
"#;
    assert!(resolve(body).is_err());
    let allowed = format!("{body}\n[embedder.remote.egress]\nallow_all = false\n");
    let config = resolve(&allowed).unwrap();
    assert_eq!(
        config.embedder.unwrap().remote.unwrap().locality,
        EmbedderLocality::ThirdParty
    );
}
