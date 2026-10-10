//! Which section `embedder serve` serves, and at what width. There is no
//! vault here, so the vault-wide width only has to agree with the model's.

use super::*;
use crate::config::{EmbedderArgs, EmbedderDevice};
use crate::config::embedder::DEFAULT_DIMENSIONS;

fn serve_args(
    config: Option<PathBuf>,
    embedder: EmbedderArgs,
    dimensions: Option<usize>,
) -> EmbedderServeArgs {
    EmbedderServeArgs {
        config,
        embedder,
        dimensions,
        host: std::net::Ipv4Addr::LOCALHOST.into(),
        port: 7399,
        api_key_env: None,
        model_aliases: Vec::new(),
        log_level: "info".to_owned(),
    }
}

fn on_cpu() -> EmbedderArgs {
    EmbedderArgs {
        embedder_device: Some(EmbedderDevice::Cpu),
        ..EmbedderArgs::default()
    }
}

/// Bug repro: with no config file, `embedder serve --embedder-device cpu`
/// was refused because the vault-wide default (4,096) is not the default
/// model's width (1,024).
#[test]
fn with_no_config_file_the_default_model_is_served_at_its_width() {
    let served = served_config_from(
        &serve_args(None, on_cpu(), None),
        &EnvConfig::default(),
        None,
    )
    .expect("served");
    assert_eq!(served.provider, EmbedderProvider::Local);
    assert_eq!(served.dimensions, DEFAULT_DIMENSIONS);
}

/// Review R4-2: the width fallback overrode the environment's widths, which
/// agree, with the default model's.
#[test]
fn widths_the_environment_names_are_served() {
    let env = EnvConfig::from_pairs([
        ("ONEIRON_DIMENSIONS", "2560"),
        ("ONEIRON_EMBEDDER_DIMENSIONS", "2560"),
    ])
    .expect("environment");
    let served =
        served_config_from(&serve_args(None, on_cpu(), None), &env, None).expect("served");
    assert_eq!(served.dimensions, 2560);
}

/// Review R4-2: a config file that names no width was held to the vault-wide
/// default.
#[test]
fn a_config_file_that_names_no_width_serves_the_model_s() {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("oneiron.toml");
    std::fs::write(&path, "[embedder]\nprovider = \"local\"\n").expect("write config");
    let served = served_config_from(
        &serve_args(Some(path), on_cpu(), None),
        &EnvConfig::default(),
        None,
    )
    .expect("served");
    assert_eq!(served.dimensions, DEFAULT_DIMENSIONS);
}

/// Review R5-1: the width was read with the section held inactive, which a
/// remote rung refuses, so a valid section with one fell back to the
/// vault-wide default and was refused.
#[test]
fn a_section_with_a_remote_rung_is_served_at_its_width() {
    let embedder = EmbedderArgs {
        embedder_remote: Some(
            serde_json::from_str(
                r#"{"endpoint":"https://embeddings.example/v1","model_key":"shared","locality":"owner-server","egress":{"allow_all":true}}"#,
            )
            .expect("remote rung"),
        ),
        ..on_cpu()
    };
    let served = served_config_from(
        &serve_args(None, embedder, None),
        &EnvConfig::default(),
        None,
    )
    .expect("served");
    assert_eq!(served.dimensions, DEFAULT_DIMENSIONS);
    assert!(served.remote.is_some());
}

/// Widths named against each other are still refused.
#[test]
fn flags_that_disagree_on_the_width_are_refused() {
    let embedder = EmbedderArgs {
        embedder_dimensions: Some(DEFAULT_DIMENSIONS),
        ..on_cpu()
    };
    let error = served_config_from(
        &serve_args(None, embedder, Some(4096)),
        &EnvConfig::default(),
        None,
    )
    .expect_err("disagreeing widths");
    assert!(format!("{error:#}").contains("must equal"), "{error:#}");
}
