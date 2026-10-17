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
//! Each span carries its UTF-8 byte offsets and the same points in UTF-16
//! code units, each link the narrowing of the read that admitted its record,
//! and a turn is read a page of messages at a time.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::claim::{ScopedReadReceipt, ScopedReadResult};
use crate::memory::{
    EntityView, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};

/// The most characters a [`RecordRef`] label carries.
pub const RECORD_REF_LABEL_MAX_CHARS: usize = 80;
/// The most characters a [`RecordRefPreview`] snippet carries.
pub const RECORD_REF_SNIPPET_MAX_CHARS: usize = 280;
/// The longest ref `vault.refs.resolve` reads, in bytes.
pub const RECORD_REF_MAX_BYTES: usize = 256;

/// The most messages one `vault.refs.links` page of a turn reads for links,
/// and the page size when the caller names none.
pub const RECORD_LINKS_TURN_PAGE_MAX: usize = 32;

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
    /// The ref one admitted view names, labelled from that view's body: no
    /// other read.
    #[must_use]
    pub fn from_view(view: &EntityView) -> Self {
        let short_id = view.short_ref.as_deref().map(bare_short_ref);
        let label = view
            .body
            .as_ref()
            .and_then(|body| kind_label(&view.kind, body))
            .unwrap_or_else(|| fallback_label(&view.kind, short_id.as_deref(), &view.id_hex));
        Self {
            kind: view.kind.clone(),
            id: view.id_hex.clone(),
            short_id,
            label,
        }
    }

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
fn bare_short_ref(short: &str) -> String {
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
fn kind_label(kind: &str, body: &serde_json::Value) -> Option<String> {
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
/// value (`value`, or a CLAIM body's `val`) is shown as its compact JSON.
fn first_text(body: &serde_json::Value, fields: &[&str]) -> Option<String> {
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
fn fallback_label(kind: &str, short_id: Option<&str>, id_hex: &str) -> String {
    let name = short_id.map_or_else(|| id_hex.chars().take(8).collect(), str::to_owned);
    bounded(&format!("{kind} {name}"), RECORD_REF_LABEL_MAX_CHARS)
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
/// messages this reader may read, a page at a time. Exactly one of `text`
/// and `turn_ref` is named; `after` and `limit` page a turn only.
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
    /// The `next_after` the previous page of the turn gave: this page reads
    /// the turn's messages after it. `None` reads the first page.
    #[serde(default)]
    pub after: Option<String>,
    /// The most messages the page holds, 1 to
    /// [`RECORD_LINKS_TURN_PAGE_MAX`] (also the default).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One stretch of a text as one reader sees it. `start` and `end` are UTF-8
/// byte offsets into the text, end exclusive; `start_utf16` and `end_utf16`
/// are the same points in UTF-16 code units, as a JS UI indexes a string.
/// The spans cover the text in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProseSpan {
    /// Text shown as written. A link the reader cannot follow, missing or
    /// unreadable alike, is this too: its label, without its ref.
    Plain {
        start: usize,
        end: usize,
        start_utf16: usize,
        end_utf16: usize,
        text: String,
    },
    /// A link the reader may follow: its label as written, the record it
    /// names as `vault.refs.resolve` reads it for this reader, and that
    /// read's narrowing.
    Link {
        start: usize,
        end: usize,
        start_utf16: usize,
        end_utf16: usize,
        label: String,
        record: RecordRef,
        narrowing: ScopedReadReceipt,
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

/// `vault.refs.links`'s answer: the given text, or one page of the turn's
/// readable visible messages, in message order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordLinks {
    pub texts: Vec<LinkedText>,
    /// For a turn: the narrowing of the reads that admitted the turn and each
    /// message this page read, folded. `None` for a text, which reads no
    /// record but its links; each link's own read rides its span.
    pub narrowing: Option<ScopedReadReceipt>,
    /// For a turn: the `after` that reads the next page, when the turn holds
    /// messages past this one. It names the last message this page served.
    pub next_after: Option<String>,
}

/// The record a link resolves to for one reader, with that read's
/// narrowing; `None` when it does not resolve.
type LinkedRecord = Option<(RecordRef, ScopedReadReceipt)>;

impl Memory<'_> {
    /// `vault.refs.links`: `text`, or a page of the visible messages of
    /// `turn_ref` this reader may read, as typed spans whose links resolve
    /// under this handle's own read. A turn this reader may not read, and one
    /// that does not exist, give the same `NOT_FOUND`.
    pub fn record_links(&self, input: &RecordLinksRequest) -> MemoryResult<RecordLinks> {
        match (input.text.as_deref(), input.turn_ref.as_deref()) {
            (Some(text), None) => {
                if input.after.is_some() || input.limit.is_some() {
                    return Err(MemoryError::bad_request_with(
                        "`after` and `limit` page a turn's messages; a text is read whole",
                        &["Drop `after` and `limit`, or read a TURN by `turn_ref`."],
                    ));
                }
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
                    narrowing: None,
                    next_after: None,
                })
            }
            (None, Some(turn_ref)) => {
                let limit = match input.limit {
                    Some(0) => {
                        return Err(MemoryError::bad_request_with(
                            "a page of a turn holds at least one message",
                            &["Pass a `limit` of 1 or more, or none for the default page."],
                        ));
                    }
                    Some(limit) => usize::try_from(limit)
                        .unwrap_or(RECORD_LINKS_TURN_PAGE_MAX)
                        .min(RECORD_LINKS_TURN_PAGE_MAX),
                    None => RECORD_LINKS_TURN_PAGE_MAX,
                };
                self.turn_links(turn_ref.trim(), input.after.as_deref(), limit)
            }
            _ => Err(MemoryError::bad_request_with(
                "name exactly one of `text` and `turn_ref`",
                &["Pass the text to read, or the TURN whose messages to read."],
            )),
        }
    }

    /// `text` as spans for this reader: each `oneiron://` link it may follow
    /// a [`ProseSpan::Link`] with its read's narrowing, everything else
    /// plain. A ref the text names twice is read once.
    pub fn link_spans(&self, text: &str) -> MemoryResult<Vec<ProseSpan>> {
        let links = crate::gate::record_references::parse_record_links(text);
        let mut records: BTreeMap<&str, LinkedRecord> = BTreeMap::new();
        let mut spans = Vec::with_capacity(links.len() * 2 + 1);
        let mut utf16 = Utf16Offsets::new(text);
        let mut at = 0;
        for link in &links {
            if link.start > at {
                spans.push(ProseSpan::Plain {
                    start: at,
                    end: link.start,
                    start_utf16: utf16.at(at),
                    end_utf16: utf16.at(link.start),
                    text: text[at..link.start].to_owned(),
                });
            }
            let resolved = match records.get(link.reference.as_str()) {
                Some(resolved) => resolved.clone(),
                None => {
                    let resolved = self.linked_record(&link.reference)?;
                    records.insert(&link.reference, resolved.clone());
                    resolved
                }
            };
            let (start_utf16, end_utf16) = (utf16.at(link.start), utf16.at(link.end));
            spans.push(match resolved {
                Some((record, narrowing)) => ProseSpan::Link {
                    start: link.start,
                    end: link.end,
                    start_utf16,
                    end_utf16,
                    label: link.label.clone(),
                    record,
                    narrowing,
                },
                None => ProseSpan::Plain {
                    start: link.start,
                    end: link.end,
                    start_utf16,
                    end_utf16,
                    text: link.label.clone(),
                },
            });
            at = link.end;
        }
        if at < text.len() {
            spans.push(ProseSpan::Plain {
                start: at,
                end: text.len(),
                start_utf16: utf16.at(at),
                end_utf16: utf16.at(text.len()),
                text: text[at..].to_owned(),
            });
        }
        Ok(spans)
    }

    /// The record one link names, through the `vault.refs.resolve` door, with
    /// that read's narrowing; `None` when it does not resolve for this reader.
    fn linked_record(&self, reference: &str) -> MemoryResult<LinkedRecord> {
        let request = ResolveRecordRefRequest {
            reference: reference.to_owned(),
        };
        match self.resolve_record_ref(&request) {
            Ok(read) => Ok(Some((read.value.record, read.receipt))),
            Err(error)
                if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// One page of the visible messages of the TURN `turn_ref` this reader
    /// may read: at most `limit`, after the message `after` names. Pages go
    /// in the order the vault minted the turn's messages, which is the order
    /// they were said in; a page shows its own by their `order`. Each member
    /// is read through this reader's lane until the page is full, so a page
    /// resolves the links of at most `limit` messages.
    fn turn_links(
        &self,
        turn_ref: &str,
        after: Option<&str>,
        limit: usize,
    ) -> MemoryResult<RecordLinks> {
        let after = after
            .map(|cursor| {
                crate::entity_id::EntityId::from_hex(cursor.trim()).map_err(|_| {
                    MemoryError::bad_request_with(
                        "`after` is not a cursor this read gave",
                        &["Pass the `next_after` of the previous page as it was returned."],
                    )
                })
            })
            .transpose()?;
        let (turn, mut narrowing) = match self.get_entity(turn_ref) {
            Ok(read) => (read.value, Some(read.receipt)),
            Err(error)
                if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
            {
                (None, None)
            }
            Err(error) => return Err(error),
        };
        let turn = turn
            .map(|view| crate::entity_id::EntityId::from_hex(&view.id_hex))
            .transpose()?;
        let Some(mut members) = turn
            .map(|turn| self.turn_message_ids(&turn))
            .transpose()?
            .flatten()
        else {
            return Err(MemoryError::not_found("turn not found"));
        };
        members.sort_unstable();
        members.dedup();
        if let Some(after) = after {
            members.retain(|id| *id > after);
        }
        let mut messages = Vec::new();
        let mut last_served = None;
        let mut read_to = 0;
        for (index, id) in members.iter().enumerate() {
            if messages.len() == limit {
                break;
            }
            read_to = index + 1;
            let read = match self.get_entity(&id.to_hex()) {
                Ok(read) => read,
                Err(error)
                    if error.code == MEMORY_CODE_NOT_FOUND
                        || error.code == MEMORY_CODE_BAD_REQUEST =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            narrowing = Some(match narrowing.take() {
                Some(mut folded) => {
                    folded.restrict_with(&read.receipt);
                    folded
                }
                None => read.receipt,
            });
            let Some(view) = read.value else {
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
            last_served = Some(*id);
        }
        let next_after = last_served
            .filter(|_| messages.len() == limit && read_to < members.len())
            .map(|id| id.to_hex());
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
        Ok(RecordLinks {
            texts,
            narrowing,
            next_after,
        })
    }

    /// The MESSAGE rows `turn` holds, when it is a TURN; `None` otherwise.
    /// Only their ids: the caller reads each through its own lane. Every
    /// edge is walked, so rows this reader may not read never change what it
    /// gets.
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

/// UTF-16 code-unit offsets of byte offsets into one text, read forward:
/// each call counts only the stretch since the last.
struct Utf16Offsets<'t> {
    text: &'t str,
    byte: usize,
    units: usize,
}

impl<'t> Utf16Offsets<'t> {
    const fn new(text: &'t str) -> Self {
        Self {
            text,
            byte: 0,
            units: 0,
        }
    }

    /// The UTF-16 offset of the byte offset `byte`, a character boundary.
    fn at(&mut self, byte: usize) -> usize {
        if byte < self.byte {
            self.byte = 0;
            self.units = 0;
        }
        self.units += self.text[self.byte..byte].encode_utf16().count();
        self.byte = byte;
        self.units
    }
}
