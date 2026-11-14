//! Resolution rows for the `[phonetic_embedder]` section.

use super::*;
use std::time::Duration;

fn resolve(body: &str, env: &[(&str, &str)]) -> anyhow::Result<ServeConfig> {
    let dir = tempfile::tempdir().expect("config dir");
    let path = dir.path().join("oneiron.toml");
    std::fs::write(&path, body).expect("write config");
    let args = ServeArgs {
        config: Some(path),
        ..Default::default()
    };
    resolve_serve_config_with_sources(&args, EnvConfig::from_pairs(env.iter().copied())?, None)
}

const ENDPOINT: &str = "[phonetic_embedder]
provider = \"endpoint\"
endpoint = \"http://127.0.0.1:8790/embed-names\"
model_id = \"symphonym-v7\"
dimensions = 128
";

/// No section binds no model, and neither does `provider = "none"`. An
/// endpoint section binds the model it names, on the owner's server and with
/// a one-minute request bound unless it says otherwise.
#[test]
fn phonetic_embedder_section_parses_endpoint_and_none() {
    assert_eq!(resolve("", &[]).unwrap().phonetic_embedder, None);

    let none = resolve("[phonetic_embedder]\nprovider = \"none\"\n", &[])
        .unwrap()
        .phonetic_embedder
        .expect("the section");
    assert_eq!(none.provider, PhoneticEmbedderProvider::None);
    assert_eq!(none.binding().unwrap(), None);

    let endpoint = resolve(ENDPOINT, &[])
        .unwrap()
        .phonetic_embedder
        .expect("the section")
        .binding()
        .unwrap()
        .expect("a bound model");
    assert_eq!(endpoint.url.as_str(), "http://127.0.0.1:8790/embed-names");
    assert_eq!(endpoint.model_id, "symphonym-v7");
    assert_eq!(endpoint.dimensions, 128);
    assert_eq!(endpoint.locality, EmbedderLocality::OwnerServer);
    assert_eq!(endpoint.timeout, Duration::from_secs(60));

    let on_device = resolve(
        &format!("{ENDPOINT}locality = \"on-device\"\ntimeout_ms = 250\n"),
        &[],
    )
    .unwrap()
    .phonetic_embedder
    .expect("the section")
    .binding()
    .unwrap()
    .expect("a bound model");
    assert_eq!(on_device.locality, EmbedderLocality::OnDevice);
    assert_eq!(on_device.timeout, Duration::from_millis(250));
}

/// A provider the section does not know is refused at startup, and so are a
/// key it does not read, an endpoint section missing its endpoint or model, a
/// URL that is not http(s), a width outside 1..=1024, a zero timeout and a
/// third-party model.
#[test]
fn an_unknown_provider_is_refused() {
    let refused = [
        "[phonetic_embedder]\nprovider = \"local\"\n".to_owned(),
        "[phonetic_embedder]\nendpoint = \"http://127.0.0.1:8790/embed-names\"\n".to_owned(),
        format!("{ENDPOINT}batch_size = 4\n"),
        ENDPOINT.replace("endpoint = \"http://127.0.0.1:8790/embed-names\"\n", ""),
        ENDPOINT.replace("model_id = \"symphonym-v7\"\n", ""),
        ENDPOINT.replace("http://127.0.0.1", "ftp://127.0.0.1"),
        ENDPOINT.replace("dimensions = 128", "dimensions = 0"),
        ENDPOINT.replace("dimensions = 128", "dimensions = 1025"),
        format!("{ENDPOINT}timeout_ms = 0\n"),
        format!("{ENDPOINT}locality = \"third-party\"\n"),
    ];
    for body in &refused {
        assert!(resolve(body, &[]).is_err(), "{body}");
    }
}
