//! The slot's laws: configuration, the endpoint's wire and identity probe,
//! the typed refusals, `init`, and the worker against a stub tagger server.

mod support;
mod worker;

use std::io::{Read, Write};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use oneiron::memory::extraction::{EncoderInput, EncoderMessage, ExtractionEncoder};
use serde_json::json;

use super::endpoint::{HttpTagger, ProbeError, ProbeOutcome};
use super::{TaggerNotBuilt, build_slot};
use crate::config::{
    EnvConfig, OneironerConfig, OneironerMode, OneironerProvider, ServeArgs,
    resolve_serve_config_with_sources,
};
use support::{Answer, CHECKPOINT, LABEL_COUNT, StubTagger, card, endpoint_config};

fn input(text: &str) -> EncoderInput {
    EncoderInput {
        turn: "72727272727272727272727272727272".into(),
        messages: vec![EncoderMessage {
            id: "73737373737373737373737373737373".into(),
            text: text.into(),
        }],
    }
}

fn resolve(
    file: &str,
    env: &[(&str, &str)],
    args: ServeArgs,
) -> anyhow::Result<crate::config::ServeConfig> {
    let dir = tempfile::tempdir().expect("dir");
    let path = dir.path().join("oneiron.toml");
    std::fs::write(&path, file).expect("write config");
    resolve_serve_config_with_sources(
        &ServeArgs {
            config: Some(path),
            ..args
        },
        EnvConfig::from_pairs(env.iter().copied()).expect("env"),
        None,
    )
}

// ─── configuration ──────────────────────────────────────────────────────

#[test]
fn an_absent_section_arms_nothing_and_a_named_one_defaults_to_local_save() {
    let absent = resolve("", &[], ServeArgs::default()).expect("absent");
    assert!(absent.oneironer.is_none());
    assert!(absent.vault_config().tagging.is_none());
    let named = resolve("[oneironer]\n", &[], ServeArgs::default()).expect("named");
    let section = named.oneironer.expect("section");
    assert_eq!(section.provider, OneironerProvider::Local);
    assert_eq!(section.mode, OneironerMode::Save);
    // Only an endpoint arms markers: the local provider never serves here.
    assert!(named_vault_tagging("[oneironer]\n").is_none());
}

fn named_vault_tagging(file: &str) -> Option<String> {
    resolve(file, &[], ServeArgs::default())
        .expect("resolve")
        .vault_config()
        .tagging
        .map(|tagging| tagging.checkpoint)
}

#[test]
fn file_environment_and_flags_layer_in_that_order() {
    let file = r#"
[oneironer]
provider = "endpoint"
mode = "shadow"
url = "http://127.0.0.1:9100"
checkpoint_sha16 = "0123456789abcdef"
label_count = 53
[oneironer.labels]
PERSON = "PERSON"
"#;
    let config = resolve(
        file,
        &[
            ("ONEIRON_ONEIRONER_URL", "http://127.0.0.1:9200"),
            ("ONEIRON_ONEIRONER_LABELS", "PERSON=PERSON,PLACE=PLACE"),
        ],
        ServeArgs {
            oneironer: crate::config::OneironerArgs {
                oneironer_url: Some("http://127.0.0.1:9300".into()),
                oneironer_timeout_ms: Some(250),
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .expect("resolve");
    let section = config.oneironer.as_ref().expect("section");
    assert_eq!(section.url.as_deref(), Some("http://127.0.0.1:9300"));
    assert_eq!(section.timeout_ms, 250);
    assert_eq!(section.label_count, Some(53));
    assert_eq!(section.labels.len(), 2);
    assert_eq!(
        section.label_kinds().get("PLACE"),
        Some(&oneiron::registry::ENTITY_TYPE_PLACE)
    );
    assert_eq!(
        config
            .vault_config()
            .tagging
            .map(|tagging| tagging.checkpoint),
        Some("0123456789abcdef".to_owned())
    );
}

#[test]
fn an_endpoint_section_missing_its_identity_or_naming_an_unknown_kind_is_refused() {
    let base = "[oneironer]\nprovider = \"endpoint\"\nmode = \"shadow\"\n";
    let url = "url = \"http://127.0.0.1:9100\"\n";
    let sha = "checkpoint_sha16 = \"0123456789abcdef\"\n";
    let count = "label_count = 3\n";
    for file in [
        format!("{base}{sha}{count}"),
        format!("{base}{url}{count}"),
        format!("{base}{url}{sha}"),
        format!("{base}{url}checkpoint_sha16 = \"0123456789ABCDEF\"\n{count}"),
        format!("{base}{url}{sha}{count}[oneironer.labels]\nPERSON = \"NOT_A_KIND\"\n"),
    ] {
        assert!(resolve(&file, &[], ServeArgs::default()).is_err(), "{file}");
    }
    assert!(
        resolve(
            &format!("{base}{url}{sha}{count}"),
            &[],
            ServeArgs::default()
        )
        .is_ok()
    );
}

#[test]
fn a_zero_first_retry_delay_is_refused() {
    let base = "[oneironer]\nprovider = \"endpoint\"\nmode = \"shadow\"\nurl = \"http://127.0.0.1:9100\"\ncheckpoint_sha16 = \"0123456789abcdef\"\nlabel_count = 3\n";
    let refused = resolve(
        &format!("{base}retry_backoff_secs = 0\n"),
        &[],
        ServeArgs::default(),
    )
    .expect_err("a zero first retry delay");
    assert!(
        refused.to_string().contains("retry_backoff_secs"),
        "{refused}"
    );
    let section = resolve(
        &format!("{base}retry_backoff_secs = 1\n"),
        &[],
        ServeArgs::default(),
    )
    .expect("a one-second first retry delay")
    .oneironer
    .expect("section");
    assert_eq!(section.retry_backoff_secs, 1);
    let zero = OneironerConfig {
        retry_backoff_secs: 0,
        ..section
    };
    assert!(zero.validate().is_err());
}

/// Managed mode builds its configuration from its own flags and never reads
/// the tagger's: each `--oneironer-*` flag is refused by name, not dropped.
#[test]
fn managed_mode_refuses_every_tagger_flag_by_name() {
    #[derive(clap::Parser)]
    struct Probe {
        #[command(flatten)]
        serve: ServeArgs,
    }
    let version = oneiron_vault_contract::CONTRACT_VERSION.to_string();
    for (flag, value) in [
        ("--oneironer-provider", "endpoint"),
        ("--oneironer-mode", "shadow"),
        ("--oneironer-url", "http://127.0.0.1:9100"),
        ("--oneironer-checkpoint-sha16", CHECKPOINT),
        ("--oneironer-label-count", "3"),
        ("--oneironer-labels", "PERSON=PERSON"),
        ("--oneironer-timeout-ms", "250"),
    ] {
        let argv = [
            "oneiron-server",
            "--managed-by-hypnos",
            "--contract-version",
            version.as_str(),
            flag,
            value,
        ];
        let args = <Probe as clap::Parser>::try_parse_from(argv)
            .expect("parse")
            .serve;
        let refused = crate::managed::ManagedArgs::from_serve_args(&args).expect_err(flag);
        assert!(
            matches!(
                &refused,
                crate::managed::ManagedError::ConflictingFlag { flag: named, .. }
                    if *named == flag.trim_start_matches("--")
            ),
            "{flag}: {refused}"
        );
    }
}

// ─── the endpoint ───────────────────────────────────────────────────────

#[test]
fn extract_posts_the_engine_input_and_reads_the_engine_output() {
    let stub = StubTagger::start(Answer::Good);
    let tagger = HttpTagger::from_config(&stub.config()).expect("tagger");
    assert_eq!(
        tagger.locality(),
        oneiron::embed::EmbedderLocality::OnDevice
    );
    let request = input("Ada sailed north");
    let output = tagger.infer(&request).expect("answer");
    assert_eq!(output.spans.len(), 1);
    assert_eq!((output.spans[0].start, output.spans[0].end), (0, 3));
    assert_eq!(output.spans[0].label, "PERSON");
    assert_eq!(
        stub.extracts(),
        vec![serde_json::to_value(&request).expect("input json")]
    );
}

#[test]
fn a_network_tagger_is_refused_and_a_loopback_one_is_on_device() {
    for url in [
        "https://tagger.example",
        "http://10.0.0.7:9100",
        "http://user:pw@127.0.0.1:9100",
        "http://127.0.0.1:9100/?key=x",
    ] {
        let mut config = endpoint_config(url);
        config.url = Some(url.into());
        assert!(HttpTagger::from_config(&config).is_err(), "{url}");
    }
    for url in [
        "http://127.0.0.1:9100",
        "http://localhost:9100",
        "http://[::1]:9100/tagger",
    ] {
        assert!(
            HttpTagger::from_config(&endpoint_config(url)).is_ok(),
            "{url}"
        );
    }
}

#[test]
fn the_probe_accepts_the_configured_tagger_and_refuses_another() {
    let stub = StubTagger::start(Answer::Good);
    let tagger = HttpTagger::from_config(&stub.config()).expect("tagger");
    assert!(
        matches!(tagger.probe(), Ok(ProbeOutcome::Ready(card)) if card.label_count == LABEL_COUNT)
    );

    stub.set_card(card("ffffffffffffffff"));
    assert!(matches!(
        tagger.probe(),
        Err(ProbeError::WrongCheckpoint { .. })
    ));
    let mut wrong = card(CHECKPOINT);
    wrong["contract_version"] = json!(99);
    stub.set_card(wrong);
    assert!(matches!(
        tagger.probe(),
        Err(ProbeError::WrongContract { got: 99, .. })
    ));
    let mut wrong = card(CHECKPOINT);
    wrong["label_count"] = json!(LABEL_COUNT + 1);
    stub.set_card(wrong);
    assert!(matches!(
        tagger.probe(),
        Err(ProbeError::WrongLabelCount { .. })
    ));
    let mut wrong = card(CHECKPOINT);
    wrong["returns"]["mood"] = json!(false);
    stub.set_card(wrong);
    if oneiron::tagging::spans_only_answers_admitted() {
        assert!(matches!(tagger.probe(), Ok(ProbeOutcome::Ready(_))));
    } else {
        assert_eq!(tagger.probe(), Err(ProbeError::NoMood));
    }
    stub.set_card(json!({"name": "something else"}));
    assert_eq!(tagger.probe(), Err(ProbeError::NoModelCard));
}

#[test]
fn an_unreachable_tagger_is_not_fatal() {
    let tagger = HttpTagger::from_config(&endpoint_config("http://127.0.0.1:1")).expect("tagger");
    assert!(matches!(tagger.probe(), Ok(ProbeOutcome::Unreachable(_))));
    let slot = build_slot(Some(&endpoint_config("http://127.0.0.1:1")))
        .expect("an unreachable tagger still builds a slot")
        .expect("slot");
    assert!(slot.card().is_none());
}

#[test]
fn a_failed_call_carries_its_class_and_never_the_turn_text() {
    const SECRET: &str = "the harbour code is 4471";
    let stub = StubTagger::start(Answer::ServerError);
    let tagger = HttpTagger::from_config(&stub.config()).expect("tagger");
    for (answer, class) in [
        (Answer::ServerError, "tagger extract returned HTTP 500"),
        (
            Answer::NotTheContract,
            "tagger extract response is not the contract",
        ),
        (Answer::Slow, "tagger extract timed out"),
    ] {
        stub.set_answer(answer);
        let error = tagger.infer(&input(SECRET)).expect_err("a failed call");
        let shown = format!("{error} {error:?}");
        assert!(!shown.contains("4471"), "{shown}");
        assert!(matches!(
            &error,
            oneiron::Error::UpstreamToolFailure { code, .. } if code == class
        ));
    }
}

/// A model card comes from a tagger that has read vault text: no refusal
/// names the checkpoint it reports, even one in a checkpoint's shape, and the
/// card keeps no other string the tagger reports, so none reaches a log.
#[test]
fn a_model_card_echoing_turn_text_is_refused_without_carrying_it() {
    const SECRET: &str = "the harbour code is 4471";
    const SHORT_SECRET: &str = "alice@example.com";
    const HEX_SECRET: &str = "4471447144714471";
    let stub = StubTagger::start(Answer::Good);
    let tagger = HttpTagger::from_config(&stub.config()).expect("tagger");
    let mut echoed = card(CHECKPOINT);
    echoed["engine"] = json!(SHORT_SECRET);
    stub.set_card(echoed);
    let Ok(ProbeOutcome::Ready(ready)) = tagger.probe() else {
        panic!("the configured checkpoint is still ready");
    };
    assert!(!format!("{ready:?}").contains(SHORT_SECRET), "{ready:?}");
    stub.set_card(card(SECRET));
    let error = tagger.probe().expect_err("an echoed checkpoint is refused");
    assert_eq!(error, ProbeError::MalformedCheckpoint);
    let shown = format!("{error} {error:?}");
    assert!(!shown.contains("4471"), "{shown}");
    stub.set_card(card(HEX_SECRET));
    let error = tagger.probe().expect_err("another checkpoint is refused");
    assert_eq!(
        error,
        ProbeError::WrongCheckpoint {
            expected: CHECKPOINT.to_owned()
        }
    );
    let shown = format!("{error} {error:?}");
    assert!(!shown.contains(HEX_SECRET), "{shown}");
}

const PROXY_CHILD: &str = "ONEIRON_TEST_TAGGER_PROXY_CHILD";
const PROXY_CHECKED: &str = "tagger proxy isolation checked";

/// The tagger client takes no proxy from the environment or the system: with
/// every proxy variable naming a listener and no exclusion, the probe and the
/// extract both reach the local tagger and the listener sees no connection.
/// Only a child process carries the variables, so no sibling test sees them.
#[test]
fn the_tagger_client_never_routes_through_an_inherited_proxy() {
    if std::env::var_os(PROXY_CHILD).is_some() {
        let stub = StubTagger::start(Answer::Good);
        let tagger = HttpTagger::from_config(&stub.config()).expect("tagger");
        assert!(matches!(tagger.probe(), Ok(ProbeOutcome::Ready(_))));
        tagger.infer(&input("Ada sailed north")).expect("answer");
        assert_eq!(stub.extracts().len(), 1);
        println!("{PROXY_CHECKED}");
        return;
    }
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").expect("proxy listener");
    let proxy_url = format!("http://{}", proxy.local_addr().expect("proxy addr"));
    let connections = Arc::new(AtomicUsize::new(0));
    {
        let connections = Arc::clone(&connections);
        std::thread::spawn(move || {
            for stream in proxy.incoming() {
                let Ok(mut stream) = stream else {
                    continue;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                let mut head = [0_u8; 1024];
                let _ = stream.read(&mut head);
                let _ = stream.write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                );
            }
        });
    }
    let mut child = Command::new(std::env::current_exe().expect("test binary"));
    child.args([
        "--exact",
        "oneironer::tests::the_tagger_client_never_routes_through_an_inherited_proxy",
        "--nocapture",
        "--test-threads=1",
    ]);
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        child.env(name, &proxy_url);
    }
    // No exclusion, and no CGI marker that would switch the proxy off.
    for name in ["NO_PROXY", "no_proxy", "REQUEST_METHOD"] {
        child.env_remove(name);
    }
    child.env(PROXY_CHILD, "1");
    let output = child.output().expect("child test process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stdout={stdout} stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    // A mistyped --exact filter exits successfully having run nothing.
    assert!(stdout.contains(PROXY_CHECKED), "{stdout}");
    assert_eq!(
        connections.load(Ordering::SeqCst),
        0,
        "a tagger request went to the proxy"
    );
}

// ─── the slot ───────────────────────────────────────────────────────────

#[test]
fn the_local_provider_and_save_mode_are_refused_by_name_and_none_builds_nothing() {
    let local = OneironerConfig {
        provider: OneironerProvider::Local,
        ..OneironerConfig::default()
    };
    let refused = build_slot(Some(&local)).err().expect("local refused");
    assert_eq!(
        refused.downcast_ref::<TaggerNotBuilt>(),
        Some(&TaggerNotBuilt::LocalProvider)
    );
    let stub = StubTagger::start(Answer::Good);
    let save = OneironerConfig {
        mode: OneironerMode::Save,
        ..stub.config()
    };
    let refused = build_slot(Some(&save)).err().expect("save refused");
    assert_eq!(
        refused.downcast_ref::<TaggerNotBuilt>(),
        Some(&TaggerNotBuilt::SaveMode)
    );
    let none = OneironerConfig {
        provider: OneironerProvider::None,
        ..stub.config()
    };
    assert!(build_slot(Some(&none)).expect("none").is_none());
    assert!(build_slot(None).expect("absent").is_none());
}

#[test]
fn a_wrong_checkpoint_at_startup_refuses_the_tagger() {
    let stub = StubTagger::start(Answer::Good);
    stub.set_card(card("ffffffffffffffff"));
    let refused = build_slot(Some(&stub.config())).err().expect("refused");
    assert!(matches!(
        refused.downcast_ref::<ProbeError>(),
        Some(ProbeError::WrongCheckpoint { .. })
    ));
    stub.set_card(card(CHECKPOINT));
    let slot = build_slot(Some(&stub.config()))
        .expect("built")
        .expect("slot");
    assert_eq!(
        slot.card().map(|card| card.checkpoint_sha16),
        Some(CHECKPOINT.to_owned())
    );
}

// ─── init ───────────────────────────────────────────────────────────────

fn init_args(dir: &std::path::Path) -> crate::cli::InitArgs {
    crate::cli::InitArgs {
        path: dir.join("vault"),
        config: Some(dir.join("oneiron.toml")),
        embedder: Some(crate::config::EmbedderProvider::None),
        dimensions: Some(32),
        map_size: 64 * 1024 * 1024,
        ..Default::default()
    }
}

#[test]
fn init_writes_the_tagger_serve_reads_and_refuses_one_it_cannot_serve() {
    let stub = StubTagger::start(Answer::Good);
    let dir = tempfile::tempdir().expect("dir");
    let args = crate::cli::InitArgs {
        oneironer: Some(OneironerProvider::Endpoint),
        oneironer_url: Some(stub.base.clone()),
        oneironer_checkpoint_sha16: Some(CHECKPOINT.into()),
        oneironer_label_count: Some(LABEL_COUNT),
        oneironer_mode: Some(OneironerMode::Shadow),
        ..init_args(dir.path())
    };
    crate::commands::init(args).expect("init");
    let serve = resolve_serve_config_with_sources(
        &ServeArgs {
            config: Some(dir.path().join("oneiron.toml")),
            ..Default::default()
        },
        EnvConfig::default(),
        None,
    )
    .expect("serve config");
    let section = serve.oneironer.as_ref().expect("section");
    assert_eq!(section.provider, OneironerProvider::Endpoint);
    assert_eq!(section.mode, OneironerMode::Shadow);
    assert_eq!(
        serve
            .vault_config()
            .tagging
            .map(|tagging| tagging.checkpoint),
        Some(CHECKPOINT.to_owned())
    );

    for (provider, mode, refusal) in [
        (
            OneironerProvider::Local,
            None,
            TaggerNotBuilt::LocalProvider,
        ),
        (
            OneironerProvider::Endpoint,
            Some(OneironerMode::Save),
            TaggerNotBuilt::SaveMode,
        ),
    ] {
        let dir = tempfile::tempdir().expect("dir");
        let endpoint = provider == OneironerProvider::Endpoint;
        let args = crate::cli::InitArgs {
            oneironer: Some(provider),
            oneironer_url: endpoint.then(|| stub.base.clone()),
            oneironer_checkpoint_sha16: endpoint.then(|| CHECKPOINT.to_owned()),
            oneironer_label_count: endpoint.then_some(LABEL_COUNT),
            oneironer_mode: mode,
            ..init_args(dir.path())
        };
        let refused = crate::commands::init(args).expect_err("refused");
        assert_eq!(refused.downcast_ref::<TaggerNotBuilt>(), Some(&refusal));
        assert!(!dir.path().join("oneiron.toml").exists());
        assert!(!dir.path().join("vault").exists());
    }
}
