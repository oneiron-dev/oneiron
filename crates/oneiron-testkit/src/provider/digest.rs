//! The prompt digest a scripted reply is keyed by.
//!
//! The prompt is what the model reads: the request's [`PROMPT_FIELDS`], taken
//! from the JSON body and written as canonical JSON (object keys sorted, no
//! whitespace). Transport and sampling fields (`model`, `stream`,
//! `stream_options`, `max_tokens`, `temperature`, ...) are left out, so the
//! same prompt has the same digest whether it is streamed or buffered and on
//! whichever model. A change to a prompt template changes the digest, and the
//! scripted reply recorded for the old prompt no longer answers: the test
//! fails loudly and the reply is re-recorded.

use std::fmt;

use serde_json::Value;

/// The request fields the digest covers, wherever a protocol carries them.
pub const PROMPT_FIELDS: [&str; 7] = [
    "system",
    "instructions",
    "messages",
    "input",
    "tools",
    "tool_choice",
    "response_format",
];

const DIGEST_DOMAIN: &[u8] = b"oneiron-testkit/prompt-digest/v1\0";

/// A BLAKE3 digest of a request's prompt, as 64 lower-case hex digits.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PromptDigest(String);

impl PromptDigest {
    /// The digest of the prompt in a request body.
    #[must_use]
    pub fn of_request(body: &Value) -> Self {
        Self::of_prompt(&prompt_of(body))
    }

    /// The digest of a prompt already cut from its request (what
    /// [`prompt_of`] returns).
    #[must_use]
    pub fn of_prompt(prompt: &Value) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(canonical_json(prompt).as_bytes());
        Self(hasher.finalize().to_hex().to_string())
    }

    /// A digest written out by an earlier run (the loud-miss report prints
    /// it). `None` unless `hex` is 64 hex digits.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.trim().to_ascii_lowercase();
        (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(Self(hex))
    }

    /// The 64 hex digits.
    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PromptDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for PromptDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PromptDigest({})", &self.0)
    }
}

/// The prompt of a request body: an object holding only its
/// [`PROMPT_FIELDS`] that are present. A body that is not an object is its
/// own prompt.
#[must_use]
pub fn prompt_of(body: &Value) -> Value {
    let Value::Object(fields) = body else {
        return body.clone();
    };
    let mut prompt = serde_json::Map::new();
    for name in PROMPT_FIELDS {
        if let Some(value) = fields.get(name) {
            prompt.insert(name.to_owned(), value.clone());
        }
    }
    Value::Object(prompt)
}

/// `value` as canonical JSON: object keys in byte order at every depth, no
/// whitespace, strings and numbers as `serde_json` writes them.
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<&String> = fields.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                if let Some(field) = fields.get(key) {
                    write_canonical(field, out);
                }
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}
