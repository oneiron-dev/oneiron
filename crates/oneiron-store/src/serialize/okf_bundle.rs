//! "Export to OKF" (OF-222): the vault as an Open Knowledge Format v0.1
//! bundle for importing into other tools. Each entity is one markdown concept
//! with YAML frontmatter at `<kind>/<id>.md`; graph edges are bundle-relative
//! markdown links; `index.md` files list each directory. Lossy by design and
//! labelled so: it is not a full copy and does not re-import as one. The
//! whole-vault archive is the full copy. It is cut from the same
//! credential-nulled document as the archive, and carries no custody secret.
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io::{Seek, Write};

use serde_json::{Map, Value};

use crate::batch::export::archive_types::ArchiveRecordKind;
use oneiron_base::error::Error;
use oneiron_base::error::Result;

/// The OKF spec version this bundle follows.
pub const OKF_SPEC_VERSION: &str = "0.1";

const TITLE_KEYS: &[&str] = &["title", "name", "label", "display_name", "predicate"];
const TEXT_KEYS: &[&str] = &["markdown", "md", "text", "content", "body", "summary"];
const DESCRIPTION_CHARS: usize = 160;

/// What every OKF reader is told the bundle drops.
pub const LOSS_DECLARATION: &str = "This bundle is not a full copy of the vault. It is a lossy \
Open Knowledge Format view for other tools. It drops bi-temporal validity (only the time \
each record was learned is kept, as `timestamp`), confidence, approval and lifecycle, \
per-claim provenance beyond the citations listed, typed edge values (weight, valence, \
provenance), resolved entity identity across bundles, code-run results, skill and pack \
source packages, agent bundles and every custody secret. The full copy is the whole-vault \
archive (`oneiron export`), which re-imports into a fresh vault.";

pub struct Concept {
    pub path: String,
    pub kind: String,
    pub id: String,
    pub title: String,
    pub description: String,
    pub timestamp: String,
    pub entity_type: u8,
}

pub fn concept(row: &Value) -> Result<Concept> {
    let id = row
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(encode_failed)?
        .to_owned();
    let entity_type = row
        .get("entity_type")
        .and_then(Value::as_u64)
        .and_then(|byte| u8::try_from(byte).ok())
        .ok_or_else(encode_failed)?;
    let kind = oneiron_base::registry::entity_type_registry_entry(entity_type).map_or_else(
        || format!("type_{entity_type:03}"),
        |entry| entry.kind.to_ascii_lowercase(),
    );
    let body = row.get("body").map(plain_body).unwrap_or(Value::Null);
    let short = id.get(..8).unwrap_or(&id);
    let title = first_text(&body, TITLE_KEYS)
        .map(|title| one_line(&title, 120))
        .unwrap_or_else(|| format!("{} {short}", kind_title(&kind)));
    let description = first_text(&body, TEXT_KEYS)
        .or_else(|| match &body {
            Value::String(text) => Some(text.clone()),
            _ => None,
        })
        .map(|text| one_line(&text, DESCRIPTION_CHARS))
        .unwrap_or_else(|| format!("An Oneiron {kind} record."));
    let learned_at = row.get("learned_at").and_then(Value::as_u64).unwrap_or(0);
    Ok(Concept {
        path: format!("{kind}/{id}.md"),
        kind,
        id,
        title,
        description,
        timestamp: rfc3339(learned_at),
        entity_type,
    })
}

pub fn render_concept(
    concept: &Concept,
    body: &Value,
    links: &[(String, String)],
    citations: &[Value],
    titles: &BTreeMap<&str, (&str, &str)>,
) -> String {
    let entity_type = concept.entity_type.to_string();
    let mut text = frontmatter(
        &format!("Oneiron {}", kind_title(&concept.kind)),
        &concept.title,
        &concept.description,
        &concept.timestamp,
        &[
            ("oneiron_id", concept.id.as_str()),
            ("oneiron_entity_type", entity_type.as_str()),
        ],
    );
    let _ = writeln!(text, "# {}\n", concept.title);
    let main_key = TEXT_KEYS.iter().copied().find(|key| {
        body.get(*key)
            .and_then(Value::as_str)
            .is_some_and(|text| !text.trim().is_empty())
    });
    let main = match body {
        Value::String(body) => Some(body.as_str()),
        body => main_key
            .and_then(|key| body.get(key))
            .and_then(Value::as_str),
    };
    if let Some(main) = main {
        let _ = writeln!(text, "{}\n", main.trim_end());
    }
    if let Value::Object(fields) = body {
        let rest: Vec<_> = fields
            .iter()
            .filter(|(key, value)| !value.is_null() && Some(key.as_str()) != main_key)
            .collect();
        if !rest.is_empty() {
            let _ = writeln!(text, "# Fields\n");
            for (key, value) in rest {
                let _ = writeln!(text, "- **{key}**: {}", inline(value, titles));
            }
            text.push('\n');
        }
    }
    if !links.is_empty() {
        let _ = writeln!(text, "# Links\n");
        for (kind, target) in links {
            match titles.get(target.as_str()) {
                Some((title, path)) => {
                    let _ = writeln!(text, "- {kind}: [{}](/{path})", link_text(title));
                }
                None => {
                    let _ = writeln!(text, "- {kind}: {target}");
                }
            }
        }
        text.push('\n');
    }
    if !citations.is_empty() {
        let _ = writeln!(text, "# Citations\n");
        for (index, citation) in citations.iter().enumerate() {
            let _ = writeln!(text, "[{}] {}", index + 1, inline(citation, titles));
        }
        text.push('\n');
    }
    text
}

/// OKF frontmatter: `type` is the one required key; `title`, `description`
/// and `timestamp` are written too, as Google's reference tooling requires
/// them. Strings are YAML double-quoted scalars.
pub fn frontmatter(
    kind: &str,
    title: &str,
    description: &str,
    timestamp: &str,
    extra: &[(&str, &str)],
) -> String {
    let quote = |text: &str| serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned());
    let mut text = String::from("---\n");
    let _ = writeln!(text, "type: {}", quote(kind));
    let _ = writeln!(text, "title: {}", quote(title));
    let _ = writeln!(text, "description: {}", quote(description));
    let _ = writeln!(text, "timestamp: {}", quote(timestamp));
    let _ = writeln!(text, "tags: [\"oneiron\"]");
    let _ = writeln!(text, "oneiron_copy: \"lossy\"");
    for (key, value) in extra {
        let _ = writeln!(text, "{key}: {}", quote(value));
    }
    text.push_str("---\n\n");
    text
}

/// A body as plain JSON: MessagePack maps become objects, text stays text,
/// and a nulled body is null.
pub fn plain_body(body: &Value) -> Value {
    match body.get("codec").and_then(Value::as_str) {
        Some("message_pack") => body.get("value").map(plain).unwrap_or(Value::Null),
        Some("utf8") => body.get("value").cloned().unwrap_or(Value::Null),
        Some("nulled") | None => Value::Null,
        Some(_) => body.get("value").map(as_okf_shows).unwrap_or(Value::Null),
    }
}

/// A pack or hub-source body as OKF has always shown it (FIX 10097, 10101):
/// each embedded MessagePack body back in its nested tagged value form, and
/// each source file's content back to its text, or null when redacted. A
/// binary file member, which no earlier archive carried, keeps its file
/// reference.
fn as_okf_shows(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            if fields.get("codec").and_then(Value::as_str) == Some("message_pack")
                && let Some(nested) = fields.get("value").and_then(nested_value)
            {
                let mut shown = fields.clone();
                shown.insert("value".to_owned(), nested);
                return Value::Object(shown);
            }
            let source_file = ["path", "content", "sha256"]
                .iter()
                .all(|key| fields.contains_key(*key));
            Value::Object(
                fields
                    .iter()
                    .map(|(key, field)| {
                        let shown = match (source_file && key == "content", field) {
                            (true, Value::Object(content)) => {
                                match content.get("kind").and_then(Value::as_str) {
                                    Some("text") => {
                                        content.get("value").cloned().unwrap_or(Value::Null)
                                    }
                                    Some("redacted") => Value::Null,
                                    _ => field.clone(),
                                }
                            }
                            _ => as_okf_shows(field),
                        };
                        (key.clone(), shown)
                    })
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(as_okf_shows).collect()),
        value => value.clone(),
    }
}

/// One exported value's postorder nodes (FIX 10097) rebuilt as the nested
/// tagged form `{"type", "value"}` it had before: an array holds its items,
/// a map its `[key, value]` pairs, and nil is null. Nodes that form no one
/// value give `None`.
fn nested_value(nodes: &Value) -> Option<Value> {
    let mut built: Vec<Value> = Vec::new();
    for node in nodes.as_array()? {
        let kind = node.get("type").and_then(Value::as_str);
        let len = || {
            node.get("value")
                .and_then(Value::as_u64)
                .and_then(|len| usize::try_from(len).ok())
        };
        let nested = match kind {
            Some("array") => {
                let at = built.len().checked_sub(len()?)?;
                serde_json::json!({ "type": "array", "value": built.split_off(at) })
            }
            Some("map") => {
                let at = built.len().checked_sub(len()?.checked_mul(2)?)?;
                let mut items = built.split_off(at).into_iter();
                let mut pairs = Vec::new();
                while let (Some(key), Some(value)) = (items.next(), items.next()) {
                    pairs.push(Value::Array(vec![key, value]));
                }
                serde_json::json!({ "type": "map", "value": pairs })
            }
            Some(_) => node.clone(),
            None if node.is_null() => Value::Null,
            None => return None,
        };
        built.push(nested);
    }
    match (built.pop(), built.is_empty()) {
        (Some(value), true) => Some(value),
        _ => None,
    }
}

/// One exported MessagePack value as plain JSON, read from its nodes in
/// postorder (FIX 10097): each array or map takes the items before it, and
/// the root is the last node. Nodes that form no one value read as null.
pub fn plain(value: &Value) -> Value {
    let Some(nodes) = value.as_array() else {
        return Value::Null;
    };
    let mut built: Vec<Value> = Vec::new();
    for node in nodes {
        let inner = node.get("value");
        let len = inner
            .and_then(Value::as_u64)
            .and_then(|len| usize::try_from(len).ok());
        let plain = match node.get("type").and_then(Value::as_str) {
            Some("array") => match len.and_then(|len| built.len().checked_sub(len)) {
                Some(at) => Value::Array(built.split_off(at)),
                None => return Value::Null,
            },
            Some("map") => {
                let Some(at) = len
                    .and_then(|len| len.checked_mul(2))
                    .and_then(|items| built.len().checked_sub(items))
                else {
                    return Value::Null;
                };
                let mut items = built.split_off(at).into_iter();
                let mut object = Map::new();
                while let (Some(key), Some(value)) = (items.next(), items.next()) {
                    let key = match key {
                        Value::String(key) => key,
                        key => key.to_string(),
                    };
                    object.insert(key, value);
                }
                Value::Object(object)
            }
            Some("boolean") => inner.cloned().unwrap_or(Value::Null),
            Some("integer") => inner.and_then(Value::as_str).map_or(Value::Null, |digits| {
                digits
                    .parse::<i64>()
                    .map(Value::from)
                    .or_else(|_| digits.parse::<u64>().map(Value::from))
                    .unwrap_or_else(|_| Value::from(digits))
            }),
            Some("f32") => inner
                .and_then(Value::as_u64)
                .and_then(|bits| u32::try_from(bits).ok())
                .map_or(Value::Null, |bits| {
                    Value::from(f64::from(f32::from_bits(bits)))
                }),
            Some("f64") => inner
                .and_then(Value::as_u64)
                .map_or(Value::Null, |bits| Value::from(f64::from_bits(bits))),
            Some("string" | "binary_text") => inner.cloned().unwrap_or(Value::Null),
            Some("entity_reference") => {
                inner
                    .and_then(Value::as_array)
                    .map_or(Value::Null, |bytes| {
                        let bytes: Vec<u8> = bytes
                            .iter()
                            .filter_map(|byte| byte.as_u64().and_then(|b| u8::try_from(b).ok()))
                            .collect();
                        Value::from(oneiron_contracts::entity_id::bytes_to_hex_lower(&bytes))
                    })
            }
            _ => Value::Null,
        };
        built.push(plain);
    }
    match (built.pop(), built.is_empty()) {
        (Some(value), true) => value,
        _ => Value::Null,
    }
}

fn first_text(body: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        body.get(*key)
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned)
    })
}

/// A value inline in markdown: an exported entity's id becomes its link.
fn inline(value: &Value, titles: &BTreeMap<&str, (&str, &str)>) -> String {
    match value {
        Value::String(text) => match titles.get(text.as_str()) {
            Some((title, path)) => format!("[{}](/{path})", link_text(title)),
            None => one_line(text, 400),
        },
        Value::Null => "null".to_owned(),
        value => one_line(&value.to_string(), 400),
    }
}

fn one_line(text: &str, limit: usize) -> String {
    let line: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    match line.char_indices().nth(limit) {
        Some((cut, _)) => format!("{}…", &line[..cut]),
        None => line,
    }
}

pub fn link_text(title: &str) -> String {
    title.replace(['[', ']'], "")
}

pub fn kind_title(kind: &str) -> String {
    let mut chars = kind.chars();
    chars.next().map_or_else(String::new, |first| {
        first
            .to_uppercase()
            .chain(chars)
            .collect::<String>()
            .replace('_', " ")
    })
}

pub fn rfc3339(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map_or_else(
            || "1970-01-01T00:00:00Z".to_owned(),
            |stamp| stamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
}

pub fn encode_failed() -> Error {
    Error::InvariantViolation("OKF bundle encoding failed")
}
