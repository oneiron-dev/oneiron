//! The `--models-toml` file as the server reads its `[models]` section.
//!
//! `ModelsConfig::from_toml` takes the section's body. A file written as the
//! server's own config (`[models]`, `[models.providers.x]`, as
//! `deploy/house-model/models.toml` is) has its headers unprefixed first;
//! tables outside `[models]` are dropped. The router serves a model by its
//! own id only when some role's ladder names it, so a file that names the
//! model in no ladder gets one role for it, recorded on every row.

use std::path::Path;

use oneiron::ModelId;
use oneiron::llm::manifest::ModelRole;
use oneiron_server::config::ModelsConfig;
use oneiron_server::config::models::{ModelRef, role_key};

/// The roles a model no ladder names may be placed in, the first free one
/// taken. The chat seat comes first: nothing calls it on an idle server.
const ADDED_ROLES: [ModelRole; 4] = [
    ModelRole::GenerativeReasoner,
    ModelRole::Checker,
    ModelRole::LocalReasoner,
    ModelRole::DreamerCurrent,
];

/// The resolved `--models-toml` and `--model`.
pub(super) struct Models {
    /// BLAKE3 of the file's bytes, as read.
    pub(super) toml_digest: String,
    /// The section body the config was resolved from, with any added role.
    pub(super) body: String,
    pub(super) config: ModelsConfig,
    pub(super) model: ModelRef,
    /// The engine id the router serves the model under.
    pub(super) engine_id: ModelId,
    pub(super) revision: String,
    /// The role key this bench added for the model, when no ladder named it.
    pub(super) role_added: Option<String>,
}

impl Models {
    /// The body as a whole config file's `[models]` section, for the
    /// loopback server's config.
    pub(super) fn server_section(&self) -> String {
        let mut section = String::from("\n[models]\n");
        for line in self.body.lines() {
            match header(line) {
                Some((true, path)) => section.push_str(&format!("[[models.{path}]]")),
                Some((false, path)) => section.push_str(&format!("[models.{path}]")),
                None => section.push_str(line),
            }
            section.push('\n');
        }
        section
    }
}

pub(super) fn load(path: &Path, model: &str) -> Result<Models, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("read --models-toml {}: {e}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| format!("--models-toml {} is not UTF-8", path.display()))?;
    let base = path.parent();
    let resolve = |body: &str| {
        ModelsConfig::from_toml(body, base)
            .map_err(|e| format!("--models-toml {}: {e:#}", path.display()))
    };
    let mut body = section_body(text);
    let mut config = resolve(&body)?;
    let (provider, name) = model
        .split_once(':')
        .filter(|(provider, name)| !provider.is_empty() && !name.trim().is_empty())
        .ok_or_else(|| format!("--model {model:?} must read \"<provider>:<model>\""))?;
    let model = ModelRef {
        provider: provider.to_owned(),
        model: name.trim().to_owned(),
    };
    let revision = config
        .providers
        .get(provider)
        .ok_or_else(|| format!("--models-toml has no provider `{provider}`"))?
        .revision
        .clone();
    let engine_id = model
        .engine_id(&revision)
        .map_err(|e| format!("--model {model}: {e:#}"))?;
    let named = config
        .roles
        .values()
        .flatten()
        .any(|rung| rung.model == model);
    let role_added = if named {
        None
    } else {
        let role = ADDED_ROLES
            .into_iter()
            .find(|role| !config.roles.contains_key(role))
            .ok_or_else(|| {
                format!("no ladder names {model} and every role it could be added to is taken")
            })?;
        let key = role_key(role);
        let quoted = serde_json::Value::String(model.to_string()).to_string();
        body.push_str(&format!("\n[roles.{key}]\nmodel = {quoted}\n"));
        config = resolve(&body)?;
        Some(key)
    };
    Ok(Models {
        toml_digest: blake3::hash(&bytes).to_hex().to_string(),
        body,
        config,
        model,
        engine_id,
        revision,
        role_added,
    })
}

/// `text` as a `[models]` section body: unchanged when no header names
/// `models`, else the lines under `[models]` and `[models.*]` with that prefix
/// taken off the headers.
fn section_body(text: &str) -> String {
    let in_models = |path: &str| path == "models" || path.starts_with("models.");
    if !text
        .lines()
        .any(|line| header(line).is_some_and(|(_, path)| in_models(&path)))
    {
        return text.to_owned();
    }
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        if let Some((array, path)) = header(line) {
            inside = in_models(&path);
            match path.strip_prefix("models.") {
                Some(rest) if array => body.push_str(&format!("[[{rest}]]\n")),
                Some(rest) => body.push_str(&format!("[{rest}]\n")),
                None => {}
            }
        } else if inside {
            body.push_str(line);
            body.push('\n');
        }
    }
    body
}

/// A table header line: whether it opens an array of tables, and its dotted
/// path with the space around each dot taken out. A trailing comment is
/// allowed; any other line is `None`.
fn header(line: &str) -> Option<(bool, String)> {
    let line = line.trim();
    let (array, rest, close) = match line.strip_prefix("[[") {
        Some(rest) => (true, rest, "]]"),
        None => (false, line.strip_prefix('[')?, "]"),
    };
    let end = rest.find(close)?;
    let after = rest[end + close.len()..].trim_start();
    if !(after.is_empty() || after.starts_with('#')) {
        return None;
    }
    let path = rest[..end]
        .split('.')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(".");
    (!path.is_empty()).then_some((array, path))
}
