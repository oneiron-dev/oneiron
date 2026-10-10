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
    let config = resolve(r#"default = "cpa:olety7/gpt-6.1-sol""#).unwrap();
    for role in SHORTHAND_ROLES {
        assert_eq!(
            models(config.ladder(role).unwrap()),
            ["cpa:olety7/gpt-6.1-sol"]
        );
    }
    assert!(config.ladder(ModelRole::LocalReasoner).is_none());
    assert!(!config.extraction_egress, "egress is an explicit opt-in");
}

#[test]
fn mid_level_orders_local_and_cloud_and_binds_the_local_reasoner() {
    let local_first = resolve(
        r#"
local = "llama:qwen3:8b"
cloud = "cpa:gpt-6.1-sol"
"#,
    )
    .unwrap();
    assert_eq!(
        models(local_first.ladder(ModelRole::DreamerCurrent).unwrap()),
        ["llama:qwen3:8b", "cpa:gpt-6.1-sol"]
    );
    assert_eq!(
        models(local_first.ladder(ModelRole::LocalReasoner).unwrap()),
        ["llama:qwen3:8b"]
    );
    let cloud_first = resolve(
        r#"
local = "llama:qwen3:8b"
cloud = "cpa:gpt-6.1-sol"
prefer_local = false
"#,
    )
    .unwrap();
    assert_eq!(
        models(cloud_first.ladder(ModelRole::GenerativeReasoner).unwrap()),
        ["cpa:gpt-6.1-sol", "llama:qwen3:8b"]
    );
}

#[test]
fn detailed_level_replaces_one_role_and_keeps_rung_prompts() {
    let config = resolve(
        r#"
default = "cpa:gpt-6.1-sol"
prompt = "Answer briefly."

[roles.dreamer_current]
rungs = [
  { model = "llama:qwen3:8b", prompt = "Reply with JSON only." },
  { model = "claude:claude-family-latest" },
]
"#,
    )
    .unwrap();
    let dreamer = config.ladder(ModelRole::DreamerCurrent).unwrap();
    assert_eq!(
        models(dreamer),
        ["llama:qwen3:8b", "claude:claude-family-latest"]
    );
    assert_eq!(dreamer[0].prompt.as_deref(), Some("Reply with JSON only."));
    assert_eq!(dreamer[1].prompt, None);
    let chat = config.ladder(ModelRole::GenerativeReasoner).unwrap();
    assert_eq!(chat[0].prompt.as_deref(), Some("Answer briefly."));
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
