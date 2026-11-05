//! Bearer binding for a managed llama.cpp worker's `/metrics` route.
//!
//! At pin d81235049384534c167caea52b85a694f6103d14, env, argv and file
//! handlers append accepted keys. An env key remains valid with any argv.
//! Without one, only a complete key-only argv pair is resolved here; other
//! argv and file-only authentication keep the existing unauthenticated GET.
use reqwest::header::{AUTHORIZATION, HeaderValue};

pub(super) struct MetricsRoute {
    url: String,
    authorization: Option<HeaderValue>,
}

impl MetricsRoute {
    pub(super) fn new(url: String, args: &[String], env: &[(String, String)]) -> Self {
        let authorization = resolve_key(args, env).and_then(|key| {
            let mut value = HeaderValue::from_str(&format!("Bearer {key}")).ok()?;
            value.set_sensitive(true);
            Some(value)
        });
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

fn resolve_key(args: &[String], env: &[(String, String)]) -> Option<String> {
    env.iter()
        .rev()
        .find(|(name, _)| name == "LLAMA_API_KEY")
        .and_then(|(_, value)| first_nonempty_field(value))
        .or_else(|| match args {
            [flag, value] if flag == "--api-key" || flag == "--api_key" => {
                first_nonempty_field(value)
            }
            _ => None,
        })
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
