//! OF-063: one check that every record a write names resolves for its writer.
//!
//! The owner's ruling (2026-10-17): check that the records an AI says it
//! created, or cites, really exist; refuse invented ones and log the refusal.
//!
//! A verb-table row declares its typed ref slots as JSON pointers (`refs` in
//! `scripts/sdk/agent-verbs.json`, where `*` takes every item of an array).
//! The row's generated engine fn calls [`admit_row_references`] before the
//! engine call, so every door that reaches the row (the HTTP facade, the MCP
//! dispatch, code mode and the SDK) meets this check once, and no door
//! carries a second, hand-written one.
//!
//! Every named ref must resolve under the WRITER's own scoped read. An
//! invented ref, a missing record and a record the writer may not read are
//! one refusal, so the writer learns nothing it could not read. The refusal
//! names the field pointer, never the ref, and it is receipted on its own
//! write ([`crate::receipt::ReceiptKind::ReferenceRefusal`]) before the
//! caller hears it. The refused write never runs.
//!
//! Only typed slots carry authority. Prose links (OF-063 prose links:
//! Engine ruling 10-17) are the one exception this file reads in text, and
//! only for display: [`parse_record_links`] finds Markdown links
//! `[label](oneiron://<ref>)` outside code spans and fences, bounded in count
//! and length. A reader's link resolves under the reader's own read
//! (`vault.refs.links`, through the `vault.refs.resolve` door); an AI-written
//! link that does not resolve for its writer never refuses or rewrites the
//! text, it leaves the same reference-refusal receipt with the outcome
//! `unlinked` ([`admit_prose_links`]). No grant, scope or authority path
//! reads a prose link.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVENTED_REFERENCE, MEMORY_CODE_NOT_FOUND, Memory,
    MemoryError, MemoryResult,
};
use crate::receipt::{
    ReferenceOutcome, ReferenceRefusalFacts, record_reference_refusal, record_reference_refusals,
};

/// One ref a write names, at the concrete pointer of its slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamedRecordRef {
    /// The slot's concrete JSON pointer (`/edges/2/target_ref`).
    pub(crate) pointer: String,
    /// The ref as the caller wrote it.
    pub(crate) reference: String,
}

/// Why a write's named refs were not admitted.
#[derive(Debug)]
pub(crate) enum ReferenceRefusal {
    /// The ref at `pointer` names no record the writer may read: invented,
    /// missing and unreadable are this one refusal.
    Unresolved { pointer: String },
    /// The writer's read itself failed, so no ref was judged.
    Read(MemoryError),
}

/// Checks that every ref in `refs` resolves under `read`, the writer's own
/// scoped read. The first ref that does not is the refusal; a ref named twice
/// is read once.
pub(crate) fn validate_record_references(
    read: &Memory<'_>,
    refs: &[NamedRecordRef],
) -> Result<(), ReferenceRefusal> {
    let mut judged = BTreeSet::new();
    for named in refs {
        if !judged.insert(named.reference.as_str()) {
            continue;
        }
        let resolves = match read.get_entity(&named.reference) {
            Ok(result) => result.value.is_some(),
            Err(error)
                if error.code == MEMORY_CODE_NOT_FOUND || error.code == MEMORY_CODE_BAD_REQUEST =>
            {
                false
            }
            Err(error) => return Err(ReferenceRefusal::Read(error)),
        };
        if !resolves {
            return Err(ReferenceRefusal::Unresolved {
                pointer: named.pointer.clone(),
            });
        }
    }
    Ok(())
}

/// The string refs `input` holds at `pointers`, in pointer order. A slot that
/// is absent, null or not a string names no ref; `*` takes every item of an
/// array, and its concrete index goes into the slot's pointer.
pub(crate) fn record_references_at(input: &Value, pointers: &[&str]) -> Vec<NamedRecordRef> {
    let mut refs = Vec::new();
    for pointer in pointers {
        let segments: Vec<&str> = pointer.split('/').skip(1).collect();
        collect_at(input, &segments, String::new(), &mut refs);
    }
    refs
}

fn collect_at(value: &Value, segments: &[&str], at: String, refs: &mut Vec<NamedRecordRef>) {
    let Some((head, rest)) = segments.split_first() else {
        if let Value::String(reference) = value {
            refs.push(NamedRecordRef {
                pointer: at,
                reference: reference.clone(),
            });
        }
        return;
    };
    if *head == "*" {
        if let Value::Array(items) = value {
            for (index, item) in items.iter().enumerate() {
                collect_at(item, rest, format!("{at}/{index}"), refs);
            }
        }
        return;
    }
    if let Some(child) = value.as_object().and_then(|members| members.get(*head)) {
        collect_at(child, rest, format!("{at}/{head}"), refs);
    }
}

/// The generated check one verb-table row with `refs` runs before its engine
/// call: every ref `input` names at `pointers` must resolve for `memory`'s
/// writer. A refusal is receipted on its own write, naming the actor, `row`,
/// the field pointer and the time, and only then returned as
/// [`MEMORY_CODE_INVENTED_REFERENCE`]; if the receipt cannot be written the
/// store's error is returned instead, never a refusal claiming it was logged.
pub(crate) fn admit_row_references<T: serde::Serialize>(
    memory: &Memory<'_>,
    row: &'static str,
    input: &T,
    pointers: &[&str],
) -> MemoryResult<()> {
    let value = serde_json::to_value(input).map_err(|_| {
        MemoryError::bad_request("the verb input could not be read for the records it names")
    })?;
    let refs = record_references_at(&value, pointers);
    match validate_record_references(memory, &refs) {
        Ok(()) => Ok(()),
        Err(ReferenceRefusal::Read(error)) => Err(error),
        Err(ReferenceRefusal::Unresolved { pointer }) => {
            record_reference_refusal(
                memory.vault(),
                &ReferenceRefusalFacts {
                    actor: memory.actor(),
                    actor_class: memory.actor_class(),
                    row,
                    field: pointer.clone(),
                    outcome: ReferenceOutcome::Refused,
                },
            )?;
            Err(invented_reference(&pointer))
        }
    }
}

/// The refusal a write naming an unresolved record ref gets: the field
/// pointer, never the ref.
pub(crate) fn invented_reference(pointer: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVENTED_REFERENCE,
        format!(
            "the record named at `{pointer}` does not resolve for this writer; the write was refused and the refusal receipted"
        ),
        &[
            "Name only records this writer can read, by the ref the engine issued (a short id or a 32-hex id).",
            "A missing record and one this writer may not read give this same refusal.",
        ],
    )
}

/// The scheme a prose record link names its ref with.
pub(crate) const PROSE_LINK_SCHEME: &str = "oneiron://";
/// The most links one text is read for; any past them stay plain text.
pub(crate) const MAX_PROSE_LINKS: usize = 64;
/// The most bytes of one text read for links; links past them stay plain text.
pub(crate) const MAX_PROSE_SCAN_BYTES: usize = 128 * 1024;
/// The longest link label read, in bytes.
pub(crate) const MAX_PROSE_LINK_LABEL_BYTES: usize = 512;
/// The most text slots one write is read for links.
const MAX_PROSE_SLOTS: usize = 256;
/// How deep an opaque value is walked for its text.
const MAX_PROSE_DEPTH: usize = 32;

/// One Markdown record link in a text: `[label](oneiron://<ref>)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProseLink {
    /// Byte offset of the link's `[`.
    pub(crate) start: usize,
    /// Byte offset just past the link's `)`.
    pub(crate) end: usize,
    /// The label as written, between the brackets.
    pub(crate) label: String,
    /// The ref after `oneiron://`, as written.
    pub(crate) reference: String,
}

/// The `oneiron://` Markdown links in `text`, in order: at most
/// [`MAX_PROSE_LINKS`], read from its first [`MAX_PROSE_SCAN_BYTES`] bytes.
///
/// Fenced code blocks (```` ``` ```` or `~~~`, indented at most three
/// spaces) and inline code spans are skipped, as are an escaped `[` and an
/// image (`![...](...)`). A label holds
/// no bracket or line break; a ref is 1 to 256 printable ASCII bytes with no
/// parenthesis, angle bracket, quote or backslash. The parse is display data
/// only: nothing it finds is ever authority.
pub(crate) fn parse_record_links(text: &str) -> Vec<ProseLink> {
    let bytes = text.as_bytes();
    let scan_end = bytes.len().min(MAX_PROSE_SCAN_BYTES);
    let mut links = Vec::new();
    // Backtick run lengths with no closing run after a point already tried.
    let mut unclosed = BTreeSet::new();
    let mut fence: Option<(u8, usize)> = None;
    let mut line_start = true;
    let mut at = 0;
    while at < scan_end && links.len() < MAX_PROSE_LINKS {
        if line_start {
            line_start = false;
            let line_end = bytes[at..scan_end]
                .iter()
                .position(|&byte| byte == b'\n')
                .map_or(scan_end, |offset| at + offset);
            let line = &bytes[at..line_end];
            let indent = line.iter().take_while(|&&byte| byte == b' ').count();
            if let Some(next) = fence_line(fence, indent, &line[indent..]) {
                fence = next;
                at = line_end;
                continue;
            }
            if fence.is_some() {
                at = line_end;
                continue;
            }
        }
        match bytes[at] {
            b'\n' => {
                line_start = true;
                at += 1;
            }
            b'\\' => {
                at += if bytes.get(at + 1) == Some(&b'\n') {
                    1
                } else {
                    2
                }
            }
            b'`' => {
                let run = bytes[at..scan_end]
                    .iter()
                    .take_while(|&&byte| byte == b'`')
                    .count();
                let open_end = at + run;
                at = if unclosed.contains(&run) {
                    open_end
                } else if let Some(close_end) = closing_backticks(&bytes[..scan_end], open_end, run)
                {
                    close_end
                } else {
                    unclosed.insert(run);
                    open_end
                };
            }
            b'!' if bytes.get(at + 1) == Some(&b'[') => at += 2,
            b'[' => match link_at(text, at, scan_end) {
                Some(link) => {
                    at = link.end;
                    links.push(link);
                }
                None => at += 1,
            },
            _ => at += 1,
        }
    }
    links
}

/// What a line at a fence boundary does to the open fence: `Some(next)` when
/// it opens or closes one (or sits inside one as a fence-shaped line).
fn fence_line(
    fence: Option<(u8, usize)>,
    indent: usize,
    rest: &[u8],
) -> Option<Option<(u8, usize)>> {
    let &mark = rest.first()?;
    if indent > 3 || (mark != b'`' && mark != b'~') {
        return None;
    }
    let run = rest.iter().take_while(|&&byte| byte == mark).count();
    if run < 3 {
        return None;
    }
    match fence {
        None => Some(Some((mark, run))),
        Some((open, length))
            if open == mark && run >= length && rest[run..].iter().all(u8::is_ascii_whitespace) =>
        {
            Some(None)
        }
        Some(open) => Some(Some(open)),
    }
}

/// The end of the first run of exactly `run` backticks at or after `from`.
fn closing_backticks(bytes: &[u8], from: usize, run: usize) -> Option<usize> {
    let mut at = from;
    while at < bytes.len() {
        if bytes[at] == b'`' {
            let length = bytes[at..].iter().take_while(|&&byte| byte == b'`').count();
            if length == run {
                return Some(at + length);
            }
            at += length;
        } else {
            at += 1;
        }
    }
    None
}

/// The record link that opens at the `[` at `start`, if one does.
fn link_at(text: &str, start: usize, scan_end: usize) -> Option<ProseLink> {
    let bytes = &text.as_bytes()[..scan_end];
    let mut close = start + 1;
    while close < bytes.len() {
        match bytes[close] {
            b'\\' => close += 2,
            b']' => break,
            b'[' | b'\n' => return None,
            _ => close += 1,
        }
        if close - start > MAX_PROSE_LINK_LABEL_BYTES + 1 {
            return None;
        }
    }
    if close >= bytes.len() {
        return None;
    }
    let target = bytes[close + 1..]
        .strip_prefix(b"(")?
        .strip_prefix(PROSE_LINK_SCHEME.as_bytes())?;
    let length = target
        .iter()
        .take(crate::lens::RECORD_REF_MAX_BYTES + 1)
        .position(|&byte| byte == b')')?;
    let reference = &target[..length];
    if reference.is_empty()
        || !reference.iter().all(|&byte| {
            byte.is_ascii_graphic()
                && !matches!(byte, b'(' | b'<' | b'>' | b'[' | b']' | b'"' | b'\\')
        })
    {
        return None;
    }
    let reference_start = close + 2 + PROSE_LINK_SCHEME.len();
    Some(ProseLink {
        start,
        end: reference_start + length + 1,
        label: text[start + 1..close].to_owned(),
        reference: text[reference_start..reference_start + length].to_owned(),
    })
}

/// One text slot a write's prose links are read from.
struct ProseSlot<'v> {
    /// The slot's concrete pointer: the declared one, with array indices.
    pointer: String,
    text: &'v str,
    /// The slot sits behind a `*[key=value]` filter, so its item declares
    /// it AI-written whoever wrote it.
    declared: bool,
}

/// The text `input` holds at `pointers`. A pointer may name a string, or a
/// value whose every string is read (under the declared pointer, never a
/// key the caller chose); `*` takes every array item, and `*[key=value]`
/// only those whose `key` is the string `value`.
fn prose_slots_at<'v>(input: &'v Value, pointers: &[&str]) -> Vec<ProseSlot<'v>> {
    let mut slots = Vec::new();
    for pointer in pointers {
        let segments: Vec<&str> = pointer.split('/').skip(1).collect();
        prose_at(input, &segments, String::new(), false, &mut slots);
    }
    slots
}

fn prose_at<'v>(
    value: &'v Value,
    segments: &[&str],
    at: String,
    declared: bool,
    slots: &mut Vec<ProseSlot<'v>>,
) {
    let Some((head, rest)) = segments.split_first() else {
        texts_in(value, &at, declared, 0, slots);
        return;
    };
    if let Some(filter) = head.strip_prefix('*') {
        let Value::Array(items) = value else {
            return;
        };
        let wanted = filter
            .strip_prefix('[')
            .and_then(|filter| filter.strip_suffix(']'))
            .and_then(|filter| filter.split_once('='));
        for (index, item) in items.iter().enumerate() {
            if let Some((key, expected)) = wanted
                && item.get(key).and_then(Value::as_str) != Some(expected)
            {
                continue;
            }
            prose_at(
                item,
                rest,
                format!("{at}/{index}"),
                declared || wanted.is_some(),
                slots,
            );
        }
        return;
    }
    if let Some(child) = value.as_object().and_then(|members| members.get(*head)) {
        prose_at(child, rest, format!("{at}/{head}"), declared, slots);
    }
}

/// Every string in `value`, each as a slot at `pointer`.
fn texts_in<'v>(
    value: &'v Value,
    pointer: &str,
    declared: bool,
    depth: usize,
    slots: &mut Vec<ProseSlot<'v>>,
) {
    if slots.len() >= MAX_PROSE_SLOTS || depth > MAX_PROSE_DEPTH {
        return;
    }
    match value {
        Value::String(text) => slots.push(ProseSlot {
            pointer: pointer.to_owned(),
            text,
            declared,
        }),
        Value::Array(items) => {
            for item in items {
                texts_in(item, pointer, declared, depth + 1, slots);
            }
        }
        Value::Object(members) => {
            for member in members.values() {
                texts_in(member, pointer, declared, depth + 1, slots);
            }
        }
        _ => {}
    }
}

/// The generated prose-link check a row with `prose_links` runs before its
/// engine call (OF-063 prose links: Engine ruling 10-17).
///
/// Each AI-written text slot (its writer is an agent or a system actor, or
/// its item declares it AI-written through a `*[key=value]` filter) is read
/// for `oneiron://` links, and each link must resolve under the writer's own
/// scoped read. A slot with a link that does not is receipted once, on its
/// own grouped write, as a reference refusal with the outcome `unlinked`:
/// the actor, `row`, the slot's pointer and the time, never the ref. The
/// text is neither refused nor rewritten, and the write goes on; a reader
/// sees such a link as its plain label. If the receipts cannot be written the
/// store's error is returned.
pub(crate) fn admit_prose_links<T: serde::Serialize>(
    memory: &Memory<'_>,
    row: &'static str,
    input: &T,
    pointers: &[&str],
) -> MemoryResult<()> {
    let writer_is_ai = memory.actor_class() != crate::EdgeActorClass::Human;
    if !writer_is_ai && !pointers.iter().any(|pointer| pointer.contains("*[")) {
        return Ok(());
    }
    let value = serde_json::to_value(input).map_err(|_| {
        MemoryError::bad_request("the verb input could not be read for the records its text links")
    })?;
    let mut unlinked: Vec<ReferenceRefusalFacts> = Vec::new();
    for slot in prose_slots_at(&value, pointers) {
        if !(writer_is_ai || slot.declared)
            || unlinked.iter().any(|facts| facts.field == slot.pointer)
        {
            continue;
        }
        let refs: Vec<NamedRecordRef> = parse_record_links(slot.text)
            .into_iter()
            .map(|link| NamedRecordRef {
                pointer: slot.pointer.clone(),
                reference: link.reference,
            })
            .collect();
        match validate_record_references(memory, &refs) {
            Ok(()) => {}
            Err(ReferenceRefusal::Unresolved { pointer }) => unlinked.push(ReferenceRefusalFacts {
                actor: memory.actor(),
                actor_class: memory.actor_class(),
                row,
                field: pointer,
                outcome: ReferenceOutcome::Unlinked,
            }),
            Err(ReferenceRefusal::Read(error)) => return Err(error),
        }
    }
    if !unlinked.is_empty() {
        record_reference_refusals(memory.vault(), &unlinked)?;
    }
    Ok(())
}
