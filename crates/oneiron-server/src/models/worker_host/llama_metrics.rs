//! Bearer binding for a managed llama.cpp worker's `/metrics` route.
//!
//! At pin d81235049384534c167caea52b85a694f6103d14, env, argv and file
//! handlers append accepted keys. Env keys and a key/file flag at the start
//! of the operator args, or after only the known context/slot prefix, stay
//! valid with any later args. Other argv and preset-only authentication
//! keep the existing unauthenticated GET.
use std::path::Path;

use reqwest::header::{AUTHORIZATION, HeaderValue};
use zeroize::Zeroizing;

pub(super) struct MetricsRoute {
    url: String,
    authorization: Option<HeaderValue>,
}

impl MetricsRoute {
    pub(super) async fn new(
        url: String,
        args: &[String],
        env: &[(String, String)],
        worker_cwd: &Path,
    ) -> Self {
        let args = auth_args(args);
        let authorization = match resolve_key(args, env) {
            Some(key) => bearer(Zeroizing::new(key).as_bytes()),
            None => file_authorization(args, env, worker_cwd).await,
        };
        Self { url, authorization }
    }

    pub(super) fn request(&self, client: &reqwest::Client) -> reqwest::RequestBuilder {
        let builder = client.get(&self.url);
        match &self.authorization {
            Some(value) => builder.header(AUTHORIZATION, value.clone()),
            None => builder,
        }
    }
}

// Skip only the pinned context/slot options, each with exactly one value.
fn auth_args(mut args: &[String]) -> &[String] {
    while let [flag, _, rest @ ..] = args {
        if !matches!(flag.as_str(), "--parallel" | "-np" | "--ctx-size" | "-c") {
            break;
        }
        args = rest;
    }
    args
}

fn resolve_key(args: &[String], env: &[(String, String)]) -> Option<String> {
    env.iter()
        .rev()
        .find(|(name, _)| name == "LLAMA_API_KEY")
        .and_then(|(_, value)| first_nonempty_field(value))
        .or_else(|| match args {
            [flag, value, ..] if flag == "--api-key" || flag == "--api_key" => {
                first_nonempty_field(value)
            }
            _ => None,
        })
}

async fn file_authorization(
    args: &[String],
    env: &[(String, String)],
    worker_cwd: &Path,
) -> Option<HeaderValue> {
    let env_file = env
        .iter()
        .rev()
        .find(|(name, _)| name == "LLAMA_ARG_API_KEY_FILE")
        .map(|(_, value)| value.as_str());
    let arg_file = match args {
        [flag, value, ..] if flag == "--api-key-file" || flag == "--api_key_file" => {
            Some(value.as_str())
        }
        _ => None,
    };
    for path in [env_file, arg_file].into_iter().flatten() {
        let Ok(bytes) = tokio::fs::read(worker_cwd.join(path)).await else {
            continue;
        };
        let bytes = Zeroizing::new(bytes);
        // Pinned getline drops LF only; comments require '#' as the first byte.
        let key = bytes
            .split(|byte| *byte == b'\n')
            .find(|line| !line.is_empty() && line[0] != b'#');
        if let Some(value) = key.and_then(bearer) {
            return Some(value);
        }
    }
    None
}

fn bearer(key: &[u8]) -> Option<HeaderValue> {
    let mut bytes = Zeroizing::new(b"Bearer ".to_vec());
    bytes.extend_from_slice(key);
    let mut value = HeaderValue::from_bytes(&bytes).ok()?;
    value.set_sensitive(true);
    Some(value)
}

/// Matches the pinned `parse_csv_row`: doubled quotes, quoted commas, no trim.
fn first_nonempty_field(value: &str) -> Option<String> {
    let mut chars = value.chars().peekable();
    let mut field = String::new();
    let mut in_quotes = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' if field.is_empty() => in_quotes = true,
            ',' if !in_quotes => {
                if !field.is_empty() {
                    return Some(field);
                }
            }
            _ => field.push(ch),
        }
    }
    (!field.is_empty()).then_some(field)
}
