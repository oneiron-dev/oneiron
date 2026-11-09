use super::*;

const PROVIDERS: &str = r#"
[providers.cpa]
kind = "openai-compat"
base_url = "http://127.0.0.1:8317"
key_env = "CPA_API_KEY"

[providers.llama]
kind = "local-openai-compat"
base_url = "http://192.168.1.20:8080/v1"

[providers.claude]
kind = "anthropic-compat"
base_url = "https://api.example.com"
key_env = "CLAUDE_KEY"

[providers.tagger]
kind = "oneironer"
base_url = "http://127.0.0.1:7070"
"#;

fn resolve(extra: &str) -> anyhow::Result<ModelsConfig> {
    let file: ModelsFile = toml::from_str(&format!("{extra}\n{PROVIDERS}"))?;
    file.resolve(None)
}

fn models(ladder: &[Rung]) -> Vec<String> {
    ladder.iter().map(|rung| rung.model.to_string()).collect()
}

#[test]
fn high_level_one_model_fills_every_shorthand_seat() {
    let config = resolve(r#"default = "cpa:owen7/gpt-6.1-sol""#).unwrap();
    for role in SHORTHAND_ROLES {
        assert_eq!(
            models(config.ladder(role).unwrap()),
            ["cpa:owen7/gpt-6.1-sol"]
        );
    }
    assert!(config.ladder(ModelRole::LocalReasoner).is_none());
    assert!(!config.extraction_egress, "egress is an explicit opt-in");
}

fn provider(body: &str) -> anyhow::Result<ProviderConfig> {
    let file: ProviderFile = toml::from_str(body)?;
    file.resolve("p")
}

#[test]
fn provider_entries_never_hold_a_literal_key() {
    assert!(
        provider("kind = \"openai-compat\"\nbase_url = \"https://h\"\nkey_env = \"sk-live-123\"")
            .is_err()
    );
    assert!(
        provider(
            "kind = \"openai-compat\"\nbase_url = \"https://h\"\nheaders = { Authorization = \"Bearer sk\" }"
        )
        .is_err()
    );
    assert!(provider("kind = \"openai-compat\"\nbase_url = \"https://user:pw@h\"").is_err());
    assert!(
        provider("kind = \"openai-compat\"\nbase_url = \"https://h\"\napi_key = \"sk\"").is_err()
    );
    let ok = provider(
        "kind = \"openai-compat\"\nbase_url = \"https://h/\"\nkey_env = \"OPENROUTER_API_KEY\"\nheaders = { X-Title = \"oneiron\" }",
    )
    .unwrap();
    assert_eq!(ok.base_url, "https://h");
    assert_eq!(ok.locality, oneiron::ModelLocality::ThirdParty);
}

/// ARCH-0069 `#broker-design`: a key held in the vault leaves only through
/// the credential broker, which sends to one exact `https` origin.
#[test]
fn a_vault_held_key_goes_out_only_through_the_broker_over_https() {
    let broker = "[broker]\nsocket = \"/run/oneiron-broker/broker.sock\"\nuid = 991\n";
    let held = |provider: &str, broker: &str| -> anyhow::Result<ModelsConfig> {
        let file: ModelsFile = toml::from_str(&format!("[providers.paid]\n{provider}\n{broker}"))?;
        file.resolve(None)
    };
    let https = "kind = \"openai-compat\"\nbase_url = \"https://h\"\nkey_secret = \"provider-key\"";
    let config = held(https, broker).unwrap();
    assert_eq!(
        config.providers["paid"].key_secret.as_deref(),
        Some("provider-key")
    );
    assert_eq!(
        config.broker,
        BrokerConfig::SeparateUser {
            socket: "/run/oneiron-broker/broker.sock".into(),
            uid: 991,
        }
    );
    // With no separate user named, this server starts a same-user child
    // (`#broker-same-user-open`).
    for (broker, program) in [
        ("", None),
        (
            "[broker]\nprogram = \"/opt/oneiron/oneiron-broker\"\n",
            Some("/opt/oneiron/oneiron-broker"),
        ),
    ] {
        assert_eq!(
            held(https, broker).unwrap().broker,
            BrokerConfig::SameUser {
                program: program.map(Into::into),
                extra_roots: Vec::new(),
            }
        );
    }
    for (provider, broker) in [
        // A separate user needs both its socket and its uid.
        (
            https,
            "[broker]\nsocket = \"/run/oneiron-broker/broker.sock\"\n",
        ),
        (https, "[broker]\nuid = 991\n"),
        // A child's flags are not a separate-user broker's.
        (
            https,
            "[broker]\nsocket = \"/run/oneiron-broker/broker.sock\"\nuid = 991\nprogram = \"/opt/oneiron-broker\"\n",
        ),
        (https, "[broker]\nprogram = \"oneiron-broker\"\n"),
        // Two ways to name one key.
        (&*format!("{https}\nkey_env = \"PAID_KEY\""), broker),
        // The broker sends over https only, even on this machine.
        (
            "kind = \"openai-compat\"\nbase_url = \"http://127.0.0.1:8080\"\nkey_secret = \"provider-key\"",
            broker,
        ),
        (
            "kind = \"openai-compat\"\nbase_url = \"https://h\"\nkey_secret = \"a key\"",
            broker,
        ),
        (https, "[broker]\nsocket = \"broker.sock\"\nuid = 991\n"),
    ] {
        assert!(held(provider, broker).is_err(), "{provider}\n{broker}");
    }
}

#[test]
fn plain_http_is_for_this_machine_or_a_local_model_server() {
    assert!(provider("kind = \"openai-compat\"\nbase_url = \"http://api.example.com\"").is_err());
    assert!(provider("kind = \"openai-compat\"\nbase_url = \"http://localhost:8317\"").is_ok());
    assert!(provider("kind = \"openai-compat\"\nbase_url = \"http://10.0.0.5:8000\"").is_err());
    let local =
        provider("kind = \"local-openai-compat\"\nbase_url = \"http://10.0.0.5:8000\"").unwrap();
    assert_eq!(local.locality, oneiron::ModelLocality::OwnServer);
    assert!(provider("kind = \"local-openai-compat\"\nbase_url = \"http://example.com\"").is_err());
}

#[test]
fn two_spellings_that_meet_on_one_engine_id_are_refused() {
    let error = resolve(
        r#"
[roles.checker]
rungs = [{ model = "cpa:org/model" }, { model = "cpa:org.model" }]
"#,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("both become engine id"),
        "{error}"
    );
}

/// TSC-WIRE: the type check is off unless asked for, `enforce` is a reserved
/// name that is not wired, and the backend is one key.
#[test]
fn the_code_check_is_off_by_default_and_enforce_is_refused() {
    use oneiron_code_check::{BackendKind, CheckMode};
    let check = |body: &str| resolve(&format!("[code_mode.check]\n{body}"));
    // Ruled defaults: feedback is on by default (#3903, FIX 8277 CALLS row 1)
    // and tsrs is the default backend (#3788); "shadow" became "feedback",
    // with no alias.
    let default = resolve("").unwrap().code_mode.check;
    assert_eq!(default.mode, CheckMode::Feedback);
    assert_eq!(default.backend, BackendKind::Tsrs);
    let feedback = check("mode = \"feedback\"").unwrap().code_mode.check;
    assert_eq!(feedback.mode, CheckMode::Feedback);
    let error = check("mode = \"enforce\"").unwrap_err();
    assert!(
        error.to_string().contains("code_check_enforce_reserved"),
        "{error}"
    );
    let microsoft =
        check("mode = \"feedback\"\nbackend = \"microsoft\"\nmicrosoft_tsc = \"/opt/tsc\"")
            .unwrap()
            .code_mode
            .check;
    assert_eq!(microsoft.backend, BackendKind::Microsoft);
    assert!(
        check("backend = \"microsoft\"").is_err(),
        "it needs its binary"
    );
}
