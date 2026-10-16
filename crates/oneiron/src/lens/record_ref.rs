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
//!
//! Prose links (OF-063 prose links: Engine ruling 10-17): a message's
//! Markdown links `[label](oneiron://<ref>)` become typed spans for one
//! reader through [`Memory::record_links`] (`vault.refs.links`). Each link
//! resolves under the reader's own read through the `vault.refs.resolve`
//! door; one the reader cannot read, or an invented one, is its plain label.
//! The spans are display only: no grant, scope or authority path reads them.

use std::collections::BTreeMap;

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

/// The longest text `vault.refs.links` takes, in bytes.
pub const RECORD_LINKS_TEXT_MAX_BYTES: usize = 256 * 1024;

/// `vault.refs.links`'s one input: a text to read for links, or a TURN whose
/// messages this reader may read. Exactly one is named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RecordLinksRequest {
    /// Text to read for `oneiron://` Markdown links.
    #[serde(default)]
    pub text: Option<String>,
    /// A TURN ref (short id or 32-hex): each visible message of it this
    /// reader may read is read for links.
    #[serde(default)]
    pub turn_ref: Option<String>,
}

/// One stretch of a text as one reader sees it. Offsets are UTF-8 byte
/// offsets into the text, end exclusive; the spans cover it in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProseSpan {
    /// Text shown as written. A link the reader cannot follow, missing or
    /// unreadable alike, is this too: its label, without its ref.
    Plain {
        start: usize,
        end: usize,
        text: String,
    },
    /// A link the reader may follow: its label as written and the record it
    /// names, as `vault.refs.resolve` reads it for this reader.
    Link {
        start: usize,
        end: usize,
        label: String,
        record: RecordRef,
    },
}

/// One text read for links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkedText {
    /// The MESSAGE the text is, 32-hex, when it was read from a turn.
    pub message_id: Option<String>,
    /// The text as spans.
    pub spans: Vec<ProseSpan>,
}

/// `vault.refs.links`'s answer: the given text, or the turn's readable
/// visible messages in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordLinks {
    pub texts: Vec<LinkedText>,
}

impl Memory<'_> {
    /// `vault.refs.links`: `text`, or each visible message of `turn_ref` this
    /// reader may read, as typed spans whose links resolve under this
    /// handle's own read. A turn this reader may not read, and one that does
    /// not exist, give the same `NOT_FOUND`.
    pub fn record_links(&self, input: &RecordLinksRequest) -> MemoryResult<RecordLinks> {
        match (input.text.as_deref(), input.turn_ref.as_deref()) {
            (Some(text), None) => {
                if text.len() > RECORD_LINKS_TEXT_MAX_BYTES {
                    return Err(MemoryError::bad_request_with(
                        format!(
                            "a text read for links is at most {RECORD_LINKS_TEXT_MAX_BYTES} bytes"
                        ),
                        &["Read a long text a message at a time."],
                    ));
                }
                Ok(RecordLinks {
                    texts: vec![LinkedText {
                        message_id: None,
                        spans: self.link_spans(text)?,
                    }],
                })
            }
            (None, Some(turn_ref)) => self.turn_links(turn_ref.trim()),
            _ => Err(MemoryError::bad_request_with(
                "name exactly one of `text` and `turn_ref`",
                &["Pass the text to read, or the TURN whose messages to read."],
            )),
        }
    }

    /// `text` as spans for this reader: each `oneiron://` link it may follow
    /// a [`ProseSpan::Link`], everything else plain.
    pub fn link_spans(&self, text: &str) -> MemoryResult<Vec<ProseSpan>> {
        let links = crate::gate::record_references::parse_record_links(text);
        let mut records: BTreeMap<&str, Option<RecordRef>> = BTreeMap::new();
        let mut spans = Vec::with_capacity(links.len() * 2 + 1);
        let mut at = 0;
        for link in &links {
            if link.start > at {
                spans.push(ProseSpan::Plain {
                    start: at,
                    end: link.start,
                    text: text[at..link.start].to_owned(),
                });
            }
            let record = match records.get(link.reference.as_str()) {
                Some(record) => record.clone(),
                None => {
                    let record = self.linked_record(&link.reference)?;
                    records.insert(&link.reference, record.clone());
                    record
                }
            };
            spans.push(match record {
                Some(record) => ProseSpan::Link {
                    start: link.start,
                    end: link.end,
                    label: link.label.clone(),
                    record,
                },
                None => ProseSpan::Plain {
                    start: link.start,
                    end: link.end,
                    text: link.label.clone(),
                },
            });
            at = link.end;
        }
        if at < text.len() {
            spans.push(ProseSpan::Plain {
                start: at,
                end: text.len(),
                text: text[at..].to_owned(),
            });
        }
        Ok(spans)
    }

    /// The record one link names, through the `vault.refs.resolve` door;
    /// `None` when it does not resolve for this reader.
    fn linked_record(&self, reference: &str) -> MemoryResult<Option<RecordRef>> {
        let request = ResolveRecordRefRequest {
            reference: reference.to_owned(),
        };
        match self.resolve_record_ref(&request) {
            Ok(read) => Ok(Some(read.value.record)),
            Err(error)
                if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Each visible message of the TURN `turn_ref` this reader may read, in
    /// message order, as linked text.
    fn turn_links(&self, turn_ref: &str) -> MemoryResult<RecordLinks> {
        let turn = match self.get_entity(turn_ref) {
            Ok(read) => read.value,
            Err(error)
                if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        let turn = turn
            .map(|view| crate::entity_id::EntityId::from_hex(&view.id_hex))
            .transpose()?;
        let Some(members) = turn
            .map(|turn| self.turn_message_ids(&turn))
            .transpose()?
            .flatten()
        else {
            return Err(MemoryError::not_found("turn not found"));
        };
        let mut messages = Vec::new();
        for id in members {
            let Some(view) = self.get_entity(&id.to_hex())?.value else {
                continue;
            };
            let Some(body) = view.body.as_ref() else {
                continue;
            };
            let text = body
                .get("content")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if body.get("is_visible").and_then(serde_json::Value::as_bool) != Some(true)
                || text.is_empty()
            {
                continue;
            }
            let order = body
                .get("order")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            messages.push((order, view.id_hex.clone(), text.to_owned()));
        }
        messages.sort();
        let texts = messages
            .into_iter()
            .map(|(_, id, text)| {
                Ok(LinkedText {
                    spans: self.link_spans(&text)?,
                    message_id: Some(id),
                })
            })
            .collect::<MemoryResult<Vec<_>>>()?;
        Ok(RecordLinks { texts })
    }

    /// The MESSAGE rows `turn` holds, when it is a TURN; `None` otherwise.
    /// The caller reads each through its own lane. Every edge is walked, so
    /// rows this reader may not read never change what it gets.
    fn turn_message_ids(
        &self,
        turn: &crate::entity_id::EntityId,
    ) -> MemoryResult<Option<Vec<crate::entity_id::EntityId>>> {
        use crate::ports::{EdgeStoreRead, EntityStoreRead};
        let vault = self.vault();
        let txn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(crate::Error::from(error)))?;
        let entity_type = |id: &crate::entity_id::EntityId| -> MemoryResult<Option<u8>> {
            Ok(vault
                .store
                .port_entity_raw(&txn, id)?
                .as_deref()
                .and_then(crate::batch::EntityMetadataHeader::parse)
                .map(|header| header.entity_type))
        };
        if entity_type(turn)? != Some(crate::registry::ENTITY_TYPE_TURN) {
            return Ok(None);
        }
        let mut members = Vec::new();
        for edge in vault.store.port_edges(
            &txn,
            turn,
            crate::ports::EdgeDirection::In,
            Some(crate::edge::EdgeKind::PartOf),
            None,
        )? {
            let id = edge?.target;
            if entity_type(&id)? == Some(crate::registry::ENTITY_TYPE_MESSAGE) {
                members.push(id);
            }
        }
        Ok(Some(members))
    }
}
