//! OF-063: typed, resolvable record refs.
//!
//! The engine names a record to a reader as a [`RecordRef`]: its kind, its
//! 32-hex id, its short id and a bounded display label, all read from one
//! admitted row. A ref is a snapshot, never a capability. Hover and open
//! re-read it through [`Memory::resolve_record_ref`] (`vault.refs.resolve`)
//! under the reader's own scoped read, where a missing record and one the
//! reader may not read give the same one refusal and no preview. How a UI
//! lays a preview out is the UI's; the engine supplies only the typed ref and
//! its resolution.
//!
//! A label and a snippet are display text, never authority: no code path
//! reads either back into a ref ("never parse untrusted prose into
//! authority", ARCH-0040).

use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadResult;
use crate::memory::{
    EntityView, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};

/// The most characters a [`RecordRef`] label carries.
pub const RECORD_REF_LABEL_MAX_CHARS: usize = 80;
/// The most characters a [`RecordRefPreview`] snippet carries.
pub const RECORD_REF_SNIPPET_MAX_CHARS: usize = 280;
/// The longest ref `vault.refs.resolve` reads, in bytes.
pub const RECORD_REF_MAX_BYTES: usize = 256;

/// The body fields a label is read from; the first one holding text wins.
const LABEL_FIELDS: [&str; 6] = [
    "title",
    "name",
    "label",
    "display_name",
    "predicate",
    "subject",
];
/// The body fields a snippet is read from; the first one holding text wins.
const SNIPPET_FIELDS: [&str; 6] = [
    "content",
    "text",
    "summary",
    "description",
    "markdown",
    "value",
];

/// One record as the engine names it to a reader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RecordRef {
    /// Registry kind string (`CLAIM`, `MESSAGE`, `PERSON`, ...).
    pub kind: String,
    /// 32-hex entity id.
    pub id: String,
    /// The vault's short id, when one is assigned.
    pub short_id: Option<String>,
    /// A bounded, single-line display label: the record's own title or name
    /// when its body has one, else its kind and short id. Display text only.
    pub label: String,
}

impl RecordRef {
    /// The ref one admitted view names.
    #[must_use]
    pub fn from_view(view: &EntityView) -> Self {
        let label = view
            .body
            .as_ref()
            .and_then(|body| first_text(body, &LABEL_FIELDS))
            .map(|text| bounded(&text, RECORD_REF_LABEL_MAX_CHARS))
            .filter(|label| !label.is_empty())
            .unwrap_or_else(|| fallback_label(view));
        Self {
            kind: view.kind.clone(),
            id: view.id_hex.clone(),
            short_id: view.short_ref.clone(),
            label,
        }
    }
}

/// `vault.refs.resolve`'s one input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolveRecordRefRequest {
    /// The ref to resolve: a short id or a 32-hex id, either one optionally
    /// pinned as `<ref>@<revision>`.
    pub reference: String,
}

/// The bounded hover/open preview of one record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordRefPreview {
    /// The record, as the reader's own read admitted it.
    pub record: RecordRef,
    /// The revision this preview was read at, lower hex: the pin the ref
    /// named, else the record's live revision when it keeps revisions.
    pub revision: Option<String>,
    /// A bounded, single-line snippet of the record's text, when it has some.
    pub snippet: Option<String>,
}

impl Memory<'_> {
    /// `vault.refs.resolve`: the bounded preview hover and open both read,
    /// through this handle's own scoped read, with that read's receipt.
    ///
    /// A ref that names no record and one naming a record this reader may not
    /// read give the same one `NOT_FOUND` refusal, with no preview and no
    /// receipt, so a refusal says nothing about what exists.
    pub fn resolve_record_ref(
        &self,
        input: &ResolveRecordRefRequest,
    ) -> MemoryResult<ScopedReadResult<RecordRefPreview>> {
        let reference = input.reference.trim();
        if reference.is_empty() || reference.len() > RECORD_REF_MAX_BYTES {
            return Err(MemoryError::bad_request_with(
                format!("a record ref is 1 to {RECORD_REF_MAX_BYTES} bytes"),
                &[
                    "Pass the ref the engine issued: a short id or a 32-hex id, optionally `@<revision>`.",
                ],
            ));
        }
        let read = match self.get_entity(reference) {
            Ok(read) => read,
            Err(error)
                if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
            {
                return Err(unresolved_ref());
            }
            Err(error) => return Err(error),
        };
        let ScopedReadResult { value, receipt } = read;
        let Some(view) = value else {
            return Err(unresolved_ref());
        };
        let revision = match reference.rsplit_once('@') {
            Some((_, pinned)) => Some(pinned.to_ascii_lowercase()),
            None => self.live_revision_hex(&view)?,
        };
        Ok(ScopedReadResult {
            value: RecordRefPreview {
                snippet: view
                    .body
                    .as_ref()
                    .and_then(|body| first_text(body, &SNIPPET_FIELDS))
                    .map(|text| bounded(&text, RECORD_REF_SNIPPET_MAX_CHARS))
                    .filter(|snippet| !snippet.is_empty()),
                record: RecordRef::from_view(&view),
                revision,
            },
            receipt,
        })
    }

    /// The live revision of an admitted record, when it keeps revisions.
    fn live_revision_hex(&self, view: &EntityView) -> MemoryResult<Option<String>> {
        let id = crate::entity_id::EntityId::from_hex(&view.id_hex)?;
        let vault = self.vault();
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        Ok(crate::vault::entity_revision::revision_for_mode_in_txn(
            &vault.store,
            &txn,
            &id,
            crate::vault::ReadMode::Live,
        )?
        .map(crate::vault::RevisionRef::to_hex))
    }
}

/// The one refusal for a ref that does not resolve for this reader.
fn unresolved_ref() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        "the record ref does not resolve",
        &[
            "Refresh the ref from the engine; a missing record and one this reader may not read give this same refusal.",
        ],
    )
}

/// The first of `fields` in `body` that holds text. A claim's non-text
/// `value` is shown as its compact JSON.
fn first_text(body: &serde_json::Value, fields: &[&str]) -> Option<String> {
    let object = body.as_object()?;
    fields.iter().find_map(|field| match object.get(*field)? {
        serde_json::Value::String(text) if !text.trim().is_empty() => Some(text.clone()),
        serde_json::Value::Null | serde_json::Value::String(_) => None,
        other if *field == "value" => Some(other.to_string()),
        _ => None,
    })
}

/// The label a record with no title of its own shows: its kind and short id.
fn fallback_label(view: &EntityView) -> String {
    let name = view
        .short_ref
        .clone()
        .unwrap_or_else(|| view.id_hex.chars().take(8).collect());
    bounded(&format!("{} {name}", view.kind), RECORD_REF_LABEL_MAX_CHARS)
}

/// `text` on one line, every run of whitespace or control characters one
/// space, cut to `max_chars` with a closing ellipsis.
fn bounded(text: &str, max_chars: usize) -> String {
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
