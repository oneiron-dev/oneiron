//! Resolution rows for the `[embedder]` section.

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

const HARRIER: &str = "microsoft/harrier-oss-v1-0.6b@f9b9dc8d367d443f2479d27aa5d8d2850c0774ee";

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
