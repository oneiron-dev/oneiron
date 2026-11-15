//! What `load dream` sets up before the server starts: the model check, the
//! `[models]` section that routes every role a consolidation pass calls to
//! that one model, and the owner's stopped-vault grant of the extraction
//! route. The model key is read from its file and goes to the server's
//! environment only: never a command line, a log or the report. The lives
//! screen's dreamed arm sets its Dreamer up the same way.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::super::server::Vault;

/// The environment variable the served config names for the model key.
pub(in crate::load) const MODEL_KEY_ENV: &str = "ONEIRON_DREAM_MODEL_KEY";

/// The one provider entry the config writes.
const PROVIDER: &str = "dream";

/// The host's wording for a declared scope summary (ARCH-0006a): without
/// one the sitting's summary attempt ends unserved.
const SUMMARY_PROMPT: &str = "Summarise what this conversation established, in a few plain \
sentences: who it is about, what they said about their work and plans, and what changed. \
State only what the conversation says.";

/// The key in `path`, trimmed. An error names the file, never its text.
pub(in crate::load) fn read_key(path: &Path) -> Result<String, String> {
    let key = std::fs::read_to_string(path)
        .map_err(|e| format!("--model-key-file {}: {}", path.display(), e.kind()))?;
    let key = key.trim().to_owned();
    if key.is_empty() {
        return Err(format!("--model-key-file {} is empty", path.display()));
    }
    Ok(key)
}

/// What the preflight call answered.
pub(in crate::load) struct Preflight {
    pub(in crate::load) reply_model: String,
    pub(super) ms: f64,
}

/// A JSON scalar as text; empty for null.
fn text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// One tiny chat completion at `<base_url>/chat/completions`, with `key` as
/// its bearer when there is one. Refused unless the reply's `model` contains
/// the requested slug less any `-sub` suffix: a gateway may spell the model
/// its own way, but it may not answer with another one.
pub(in crate::load) fn preflight(
    base_url: &str,
    model: &str,
    key: Option<&str>,
) -> Result<Preflight, String> {
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .map_err(|e| format!("model client: {e}"))?;
    let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let started = Instant::now();
    let request = match key {
        Some(key) => http.post(&url).bearer_auth(key),
        None => http.post(&url),
    };
    let response = request
        .json(&json!({
            "model": model,
            "messages": [{"role": "user", "content": "Reply OK"}],
            "max_tokens": 8,
        }))
        .send()
        .map_err(|e| {
            let kind = if e.is_timeout() {
                "timeout"
            } else {
                "transport"
            };
            format!("model preflight {url}: {kind}")
        })?;
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    let status = response.status();
    let body = response.json::<Value>().unwrap_or(Value::Null);
    if !status.is_success() {
        // Only the error's code and type: a gateway's message can echo part
        // of the key it refused.
        return Err(format!(
            "model preflight {url} answered {} (code `{}`, type `{}`)",
            status.as_u16(),
            text(&body["error"]["code"]),
            text(&body["error"]["type"]),
        ));
    }
    let reply_model = text(&body["model"]);
    let wanted = model.strip_suffix("-sub").unwrap_or(model);
    if !reply_model.contains(wanted) {
        return Err(format!(
            "model preflight: the reply names model `{reply_model}`, not `{wanted}`"
        ));
    }
    Ok(Preflight { reply_model, ms })
}

/// A TOML basic string: JSON's string escapes are TOML's.
fn toml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

/// Where the Dreamer's model runs, for the route checks: a keyed model is a
/// third party's (as `load dream`'s gateway is), and a keyless one the
/// owner's own server (a local model, or a GPU host over a tunnel). The
/// value is `oneiron-server dreamer grant --extraction-route`'s.
pub(in crate::load) fn route(keyed: bool) -> &'static str {
    if keyed { "third_party" } else { "own_server" }
}

/// The `[models]` section's body: one provider at `base_url`, as
/// `ModelsConfig::from_toml` reads it and as a config file holds it under
/// `[models]` (dotted keys, so one text serves both). A keyed provider is
/// `openai-compat`, its key read from [`MODEL_KEY_ENV`]; a keyless one is
/// `local-openai-compat`. The shorthand `default` fills the generative
/// reasoner (the conflict verdict), the checker and `dreamer_current` (the
/// Dreamer's seat and its narrative role); the extraction teacher, which no
/// shorthand fills, is named out. Extraction may leave the device, and the
/// Dreamer runs with a summary instruction. Key names:
/// `config/models/mod.rs` (`ModelsFile`, `DreamerFile`), `provider.rs`
/// (`ProviderFile`), `levels.rs` (`RoleFile`).
pub(in crate::load) fn models_body(
    base_url: &str,
    model: &str,
    context_tokens: Option<u64>,
    keyed: bool,
) -> String {
    let rung = toml_string(&format!("{PROVIDER}:{model}"));
    let provider = format!("providers.{PROVIDER}");
    let mut body = format!("default = {rung}\nextraction_egress = true\n");
    if keyed {
        body.push_str(&format!(
            "{provider}.kind = \"openai-compat\"\n{provider}.key_env = \"{MODEL_KEY_ENV}\"\n"
        ));
    } else {
        body.push_str(&format!("{provider}.kind = \"local-openai-compat\"\n"));
    }
    body.push_str(&format!(
        "{provider}.base_url = {}\n{provider}.timeout_secs = 600\n",
        toml_string(base_url)
    ));
    if let Some(tokens) = context_tokens {
        body.push_str(&format!("{provider}.context_tokens = {tokens}\n"));
    }
    body.push_str(&format!(
        "roles.extraction_teacher.model = {rung}\n\
         dreamer.enabled = true\ndreamer.summary_prompt = {}\n",
        toml_string(SUMMARY_PROMPT)
    ));
    body
}

/// Appends `[models]` ([`models_body`]) to the config `init` wrote.
pub(in crate::load) fn write_models(
    vault: &Vault,
    base_url: &str,
    model: &str,
    context_tokens: Option<u64>,
    keyed: bool,
) -> Result<(), String> {
    let path = &vault.config;
    let existing =
        std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    if existing
        .lines()
        .any(|line| line.trim_start().starts_with("[models"))
    {
        return Err(format!("{} already has a [models] section", path.display()));
    }
    let body = models_body(base_url, model, context_tokens, keyed);
    std::fs::write(path, format!("{existing}\n[models]\n{body}"))
        .map_err(|e| format!("write {}: {e}", path.display()))
}

/// The last `n` characters of `text`.
fn tail(text: &str, n: usize) -> &str {
    let skip = text.chars().count().saturating_sub(n);
    text.char_indices()
        .nth(skip)
        .map_or("", |(at, _)| &text[at..])
}

/// `oneiron-server dreamer grant --extraction-route <route>` on the stopped
/// vault (`commands/dreamer.rs`; it needs the host issuer secret): the
/// Dreamer's policy rows, and the extraction and consolidation defaults
/// routed to where the model runs ([`route`]), the extraction bound raised
/// to it (`ai_host/policy.rs` `route_dreamer_extraction`). Returns the JSON
/// line it printed.
pub(in crate::load) fn grant(bin: &Path, vault: &Vault, route: &str) -> Result<Value, String> {
    let output = Command::new(bin)
        .args(["dreamer", "grant", "--extraction-route", route])
        .arg("--config")
        .arg(&vault.config)
        .arg("--vault-path")
        .arg(&vault.path)
        .env("ONEIRON_AUTH_SECRET", &vault.secret)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("run {} dreamer grant: {e}", bin.display()))?;
    if !output.status.success() {
        return Err(format!(
            "dreamer grant exited {}: {}",
            output.status,
            tail(&String::from_utf8_lossy(&output.stderr), 2000)
        ));
    }
    // Log lines may come first on stdout; the answer is the last line.
    let printed = String::from_utf8_lossy(&output.stdout);
    let last = printed
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("");
    serde_json::from_str(last).map_err(|e| format!("dreamer grant output: {e}"))
}

/// What `<bin> --version` prints, when it prints.
pub(super) fn version(bin: &Path) -> Option<String> {
    let output = Command::new(bin)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}
