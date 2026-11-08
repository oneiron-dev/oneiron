//! Core half of `store::record_ref`: its store-layer items live in `oneiron_store::record_ref` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::record_ref::*;

use serde::{Deserialize, Serialize};

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
