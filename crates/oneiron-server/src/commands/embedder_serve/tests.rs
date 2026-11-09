//! Which section `embedder serve` serves, and at what width. There is no
//! vault here, so the vault-wide width only has to agree with the model's.

use super::*;
use crate::config::embedder::DEFAULT_DIMENSIONS;
use crate::config::{EmbedderArgs, EmbedderDevice};

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
