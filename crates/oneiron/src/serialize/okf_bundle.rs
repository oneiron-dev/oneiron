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

use crate::batch::export::{ArchiveRecordKind, RecordSpool};
use crate::error::{Error, Result};

/// The OKF spec version this bundle follows.
pub(crate) const OKF_SPEC_VERSION: &str = "0.1";

const TITLE_KEYS: &[&str] = &["title", "name", "label", "display_name", "predicate"];
const TEXT_KEYS: &[&str] = &["markdown", "md", "text", "content", "body", "summary"];
const DESCRIPTION_CHARS: usize = 160;

/// What every OKF reader is told the bundle drops.
const LOSS_DECLARATION: &str = "This bundle is not a full copy of the vault. It is a lossy \
Open Knowledge Format view for other tools. It drops bi-temporal validity (only the time \
each record was learned is kept, as `timestamp`), confidence, approval and lifecycle, \
per-claim provenance beyond the citations listed, typed edge values (weight, valence, \
provenance), resolved entity identity across bundles, code-run results, skill and pack \
source packages, agent bundles and every custody secret. The full copy is the whole-vault \
archive (`oneiron export`), which re-imports into a fresh vault.";

struct Concept {
    path: String,
    kind: String,
    id: String,
    title: String,
    description: String,
    timestamp: String,
    entity_type: u8,
}

/// The bundle as one ZIP written to `sink`: `index.md`, one `index.md` per
/// kind, and one concept per entity. It is cut from the document's spooled
/// rows (FIX 2766): each concept's row is read back when it is rendered, so
/// only titles, links and citations are held.
pub(super) fn write_okf_bundle<W: Write + Seek>(
    sink: W,
    groups: &mut BTreeMap<String, RecordSpool>,
    exported_at: u64,
) -> Result<W> {
    let mut concepts = Vec::new();
    let mut links: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut citations: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (path, spool) in groups.iter_mut() {
        let kind = spool.kind;
        if !matches!(
            kind,
            ArchiveRecordKind::Entity
                | ArchiveRecordKind::Claim
                | ArchiveRecordKind::Skill
                | ArchiveRecordKind::Edge
                | ArchiveRecordKind::DerivationEnvelope
        ) {
            continue;
        }
        let mut rows = spool.rows()?;
        while let Some((at, row)) = rows.next_row()? {
            match kind {
                ArchiveRecordKind::Edge => {
                    let (Some(source), Some(target), Some(edge_kind)) = (
                        row.get("source").and_then(Value::as_str),
                        row.get("target").and_then(Value::as_str),
                        row.get("kind").and_then(Value::as_u64),
                    ) else {
                        continue;
                    };
                    let name = u8::try_from(edge_kind)
                        .ok()
                        .and_then(crate::edge::EdgeKind::try_from_u8)
                        .map_or_else(
                            || format!("edge {edge_kind}"),
                            |kind| kind.name().replace('_', " "),
                        );
                    links
                        .entry(source.to_owned())
                        .or_default()
                        .push((name, target.to_owned()));
                }
                ArchiveRecordKind::DerivationEnvelope => {
                    if let (Some(id), Some(evidence)) =
                        (row.get("id").and_then(Value::as_str), row.get("evidence"))
                    {
                        match plain(evidence) {
                            Value::Array(items) => {
                                citations.entry(id.to_owned()).or_default().extend(items);
                            }
                            Value::Null => {}
                            item => citations.entry(id.to_owned()).or_default().push(item),
                        }
                    }
                }
                _ => {
                    let entity = if kind == ArchiveRecordKind::Skill {
                        row.get("entity").ok_or_else(encode_failed)?
                    } else {
                        &row
                    };
                    // The body is read again when the concept is rendered.
                    concepts.push((concept(entity)?, path.clone(), at));
                }
            }
        }
    }
    concepts.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    let titles: BTreeMap<&str, (&str, &str)> = concepts
        .iter()
        .map(|(c, _, _)| (c.id.as_str(), (c.title.as_str(), c.path.as_str())))
        .collect();

    let stamp = rfc3339(exported_at);
    let mut zip = zip::ZipWriter::new(sink);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(true);
    let member = |zip: &mut zip::ZipWriter<W>, name: &str, text: &str| -> Result<()> {
        zip.start_file(name, options).map_err(|_| encode_failed())?;
        zip.write_all(text.as_bytes()).map_err(|_| encode_failed())
    };

    let mut kinds: BTreeMap<&str, Vec<&Concept>> = BTreeMap::new();
    for (concept, group, at) in &concepts {
        kinds
            .entry(concept.kind.as_str())
            .or_default()
            .push(concept);
        let spool = groups.get_mut(group).ok_or_else(encode_failed)?;
        let row: Value =
            serde_json::from_slice(&spool.line_at(*at)?).map_err(|_| encode_failed())?;
        let row = if spool.kind == ArchiveRecordKind::Skill {
            row.get("entity").cloned().unwrap_or(Value::Null)
        } else {
            row
        };
        let body = row.get("body").map(plain_body).unwrap_or(Value::Null);
        let text = render_concept(
            concept,
            &body,
            links
                .get(concept.id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default(),
            citations
                .get(concept.id.as_str())
                .map(Vec::as_slice)
                .unwrap_or_default(),
            &titles,
        );
        member(&mut zip, &concept.path, &text)?;
    }
    for (kind, list) in &kinds {
        let mut text = frontmatter(
            "Index",
            &format!("{} ({})", kind_title(kind), list.len()),
            &format!("Every {kind} record in this lossy OKF view of an Oneiron vault."),
            &stamp,
            &[],
        );
        let _ = writeln!(text, "# {}\n", kind_title(kind));
        for concept in list {
            let _ = writeln!(
                text,
                "- [{}](/{}) {}",
                link_text(&concept.title),
                concept.path,
                concept.description
            );
        }
        member(&mut zip, &format!("{kind}/index.md"), &text)?;
    }
    let mut root = frontmatter(
        "Index",
        "Oneiron vault (OKF export, not a full copy)",
        "A lossy Open Knowledge Format view of an Oneiron vault, for other tools.",
        &stamp,
        &[("okf_version", OKF_SPEC_VERSION)],
    );
    let _ = writeln!(
        root,
        "# Not a full copy\n\n{LOSS_DECLARATION}\n\n# Contents\n"
    );
    for (kind, list) in &kinds {
        let _ = writeln!(
            root,
            "- [{}](/{kind}/index.md) {} records",
            kind_title(kind),
            list.len()
        );
    }
    member(&mut zip, "index.md", &root)?;
    zip.finish().map_err(|_| encode_failed())
}

fn concept(row: &Value) -> Result<Concept> {
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
    let kind = crate::registry::entity_type_registry_entry(entity_type).map_or_else(
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

fn render_concept(
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
fn frontmatter(
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
fn plain_body(body: &Value) -> Value {
    match body.get("codec").and_then(Value::as_str) {
        Some("message_pack") => body.get("value").map(plain).unwrap_or(Value::Null),
        Some("utf8") => body.get("value").cloned().unwrap_or(Value::Null),
        Some("nulled") | None => Value::Null,
        Some(_) => body.get("value").cloned().unwrap_or(Value::Null),
    }
}

/// One exported MessagePack value as plain JSON.
fn plain(value: &Value) -> Value {
    let inner = value.get("value");
    match value.get("type").and_then(Value::as_str) {
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
        Some("entity_reference") => inner
            .and_then(Value::as_array)
            .map_or(Value::Null, |bytes| {
                let bytes: Vec<u8> = bytes
                    .iter()
                    .filter_map(|byte| byte.as_u64().and_then(|b| u8::try_from(b).ok()))
                    .collect();
                Value::from(crate::entity_id::bytes_to_hex_lower(&bytes))
            }),
        Some("array") => inner
            .and_then(Value::as_array)
            .map_or(Value::Null, |items| items.iter().map(plain).collect()),
        Some("map") => {
            let mut object = Map::new();
            for entry in inner.and_then(Value::as_array).into_iter().flatten() {
                if let Some([key, value]) = entry.as_array().map(Vec::as_slice) {
                    let key = match plain(key) {
                        Value::String(key) => key,
                        key => key.to_string(),
                    };
                    object.insert(key, plain(value));
                }
            }
            Value::Object(object)
        }
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

fn link_text(title: &str) -> String {
    title.replace(['[', ']'], "")
}

fn kind_title(kind: &str) -> String {
    let mut chars = kind.chars();
    chars.next().map_or_else(String::new, |first| {
        first
            .to_uppercase()
            .chain(chars)
            .collect::<String>()
            .replace('_', " ")
    })
}

fn rfc3339(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map_or_else(
            || "1970-01-01T00:00:00Z".to_owned(),
            |stamp| stamp.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        )
}

fn encode_failed() -> Error {
    Error::InvariantViolation("OKF bundle encoding failed")
}
