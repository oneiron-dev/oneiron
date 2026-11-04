//! Typed record references and bounded record display labels.

use serde::{Deserialize, Serialize};

/// The most characters a [`RecordRef`] label carries.
pub const RECORD_REF_LABEL_MAX_CHARS: usize = 80;

/// The body fields a label is read from; the first one holding text wins.
const LABEL_FIELDS: [&str; 6] = [
    "title",
    "name",
    "label",
    "display_name",
    "predicate",
    "subject",
];
/// The body fields a CLAIM's label is read from: its value.
const CLAIM_LABEL_FIELDS: [&str; 1] = ["val"];
/// The body fields a PERSON's label is read from: the name it shows.
const PERSON_LABEL_FIELDS: [&str; 2] = ["display_name", "name"];

/// One record as the engine names it to a reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecordRef {
    /// Registry kind string (`CLAIM`, `MESSAGE`, `PERSON`, ...).
    pub kind: String,
    /// 32-hex entity id.
    pub id: String,
    /// The vault's short id, when one is assigned. Never revision-pinned: a
    /// ref names a record, not a revision of it.
    pub short_id: Option<String>,
    /// A bounded, single-line display label, from the record's own admitted
    /// body by its kind: a CLAIM's value, a PERSON's display name, any other
    /// record's title or name; else its kind and short id. Display text only,
    /// never authority.
    pub label: String,
}

impl RecordRef {
    /// The ref a producer names from the entity type and id it already
    /// holds, with no read: labelled with its kind and short id. It proves
    /// nothing, neither that a reader may read the record nor who made it;
    /// hover and open re-read it through [`Memory::resolve_record_ref`].
    #[must_use]
    pub fn from_id(
        entity_type: u8,
        id: &crate::entity_id::EntityId,
        short_id: Option<&str>,
    ) -> Self {
        Self::from_body(entity_type, id, short_id, None)
    }

    /// [`Self::from_id`], labelled by its kind from `body`, the JSON body
    /// the producer's own read already admitted, when it holds one.
    #[must_use]
    pub fn from_body(
        entity_type: u8,
        id: &crate::entity_id::EntityId,
        short_id: Option<&str>,
        body: Option<&serde_json::Value>,
    ) -> Self {
        let kind = crate::registry::entity_type_registry_entry(entity_type).map_or_else(
            || format!("TYPE_{entity_type}"),
            |entry| entry.kind.to_owned(),
        );
        let id = id.to_hex();
        let short_id = short_id.map(bare_short_ref);
        let label = body
            .and_then(|body| kind_label(&kind, body))
            .unwrap_or_else(|| fallback_label(&kind, short_id.as_deref(), &id));
        Self {
            kind,
            id,
            short_id,
            label,
        }
    }

    /// This ref labelled with `text`, bounded to one line, when it holds
    /// any: a producer's own served view of the record (a claim's served
    /// value). Display text only.
    #[must_use]
    pub fn with_label(mut self, text: &str) -> Self {
        let label = bounded(text, RECORD_REF_LABEL_MAX_CHARS);
        if !label.is_empty() {
            self.label = label;
        }
        self
    }
}

/// A short ref without the `@<revision>` a pinned read qualifies it with.
pub(crate) fn bare_short_ref(short: &str) -> String {
    short
        .rsplit_once('@')
        .map_or(short, |(bare, _)| bare)
        .to_owned()
}

/// The label a record of `kind` shows from its own admitted body (OF-063
/// per-kind labels): a CLAIM its value, a PERSON the name it shows, any
/// other record its title or name. `None` when the body holds none. A CLAIM
/// whose body reads as a secret shows no value: it falls back to its kind
/// and short id, as every read door serves such a claim redacted.
pub(crate) fn kind_label(kind: &str, body: &serde_json::Value) -> Option<String> {
    let text = match kind {
        "CLAIM" => {
            if crate::batch::secret_scan::release_reads_whole_json(body) {
                return None;
            }
            first_text(body, &CLAIM_LABEL_FIELDS)
        }
        "PERSON" => {
            first_text(body, &PERSON_LABEL_FIELDS).or_else(|| first_text(body, &LABEL_FIELDS))
        }
        _ => first_text(body, &LABEL_FIELDS),
    }?;
    Some(bounded(&text, RECORD_REF_LABEL_MAX_CHARS)).filter(|label| !label.is_empty())
}

/// The first of `fields` in `body` that holds text. A claim's non-text
/// value (`value`, or a CLAIM body's `val`) is shown as its compact JSON.
pub(crate) fn first_text(body: &serde_json::Value, fields: &[&str]) -> Option<String> {
    let object = body.as_object()?;
    fields.iter().find_map(|field| match object.get(*field)? {
        serde_json::Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        serde_json::Value::Null | serde_json::Value::String(_) => None,
        other if matches!(*field, "value" | "val") => Some(other.to_string()),
        _ => None,
    })
}

/// The label a record with no title of its own shows: its kind and short id
/// (the first 8 hex of its id when it has none).
pub(crate) fn fallback_label(kind: &str, short_id: Option<&str>, id_hex: &str) -> String {
    let name = short_id.map_or_else(|| id_hex.chars().take(8).collect(), str::to_owned);
    bounded(&format!("{kind} {name}"), RECORD_REF_LABEL_MAX_CHARS)
}

/// `text` on one line, every run of whitespace or control characters one
/// space, cut to `max_chars` with a closing ellipsis.
pub(crate) fn bounded(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut gap = false;
    for ch in text.chars() {
        if ch.is_whitespace() || ch.is_control() {
            gap = count > 0;
            continue;
        }
        let needed = usize::from(gap) + 1;
        if count + needed > max_chars {
            if count >= max_chars {
                out.pop();
            }
            out.push('…');
            return out;
        }
        if gap {
            out.push(' ');
            count += 1;
            gap = false;
        }
        out.push(ch);
        count += 1;
    }
    out
}
