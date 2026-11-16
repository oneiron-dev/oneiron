//! Plain-text artifacts: notes, Markdown, data files and source code kept as
//! blob versions (FIX 7905, OF-511; ARCH-0078 "anchored review across the
//! whole artifact family"). A locator is a character span over the whole
//! decoded file, a unit is one line, and a span moves across a new version
//! by a line diff first and a character diff inside each changed run.

use std::ops::Range;

use similar::{Algorithm, DiffTag, capture_diff_slices};

use super::super::model::{AnnotationThread, Locator, ReanchorOutcome};
use super::{char_occurrences, char_slice};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

/// Media types read as plain text, beside every `text/*` type but HTML
/// (HTML has its own block adapter). Engine call (CALLS.md, FIX 7905): any
/// other `application/*+json` or `application/*+xml` type reads as text too.
const TEXT_APPLICATION_TYPES: &[&str] = &[
    "application/json",
    "application/x-ndjson",
    "application/xml",
    "application/javascript",
    "application/x-javascript",
    "application/ecmascript",
    "application/typescript",
    "application/x-typescript",
    "application/x-sh",
    "application/x-shellscript",
    "application/sql",
    "application/toml",
    "application/yaml",
    "application/x-yaml",
    "application/graphql",
    "application/x-python",
    "application/x-rust",
];

/// True when `media_type` holds text this adapter reads.
pub(super) fn is_text_media_type(media_type: &str) -> bool {
    let base = media_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if let Some(subtype) = base.strip_prefix("text/") {
        return !subtype.is_empty() && subtype != "html";
    }
    if let Some(subtype) = base.strip_prefix("application/") {
        return TEXT_APPLICATION_TYPES.contains(&base.as_str())
            || subtype.ends_with("+json")
            || subtype.ends_with("+xml");
    }
    false
}

/// The file's text: UTF-8 with any leading byte-order mark left out, or
/// `None` when the bytes are not UTF-8. Every offset counts characters of
/// this text.
pub(in crate::anchored_annotation) fn decoded(bytes: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(bytes).ok()?;
    Some(text.strip_prefix('\u{feff}').unwrap_or(text))
}

/// The words under a text span, or `None` when the spot cannot be read.
pub(in crate::anchored_annotation) fn text_span(
    bytes: &[u8],
    char_start: u64,
    char_end: u64,
) -> Option<String> {
    char_slice(decoded(bytes)?, char_start, char_end)
}

/// One unit per line, in file order: the line's span without its line
/// break, and its words when the line holds any. `None` when the bytes are
/// not text.
pub(in crate::anchored_annotation) fn text_units(
    bytes: &[u8],
) -> Option<Vec<(Locator, Option<String>)>> {
    let text = decoded(bytes)?;
    let mut units = Vec::new();
    let mut at = 0u64;
    for line in text.split_inclusive('\n') {
        let width = line.chars().count() as u64;
        let words = line.strip_suffix('\n').unwrap_or(line);
        let words = words.strip_suffix('\r').unwrap_or(words);
        let end = at + words.chars().count() as u64;
        let locator = Locator::text(at, end).ok()?;
        units.push((locator, (end > at).then(|| words.to_owned())));
        at += width;
    }
    Some(units)
}

/// Every place in the file that holds exactly `words`, in file order.
pub(super) fn find_in_text(bytes: &[u8], words: &str) -> Vec<Locator> {
    let Some(text) = decoded(bytes) else {
        return Vec::new();
    };
    char_occurrences(text, words)
        .into_iter()
        .filter_map(|(start, end)| Locator::text(start, end).ok())
        .collect()
}

/// Character offset of each line start, plus the text's length at the end.
fn line_starts(lines: &[&str]) -> Vec<usize> {
    let mut starts = Vec::with_capacity(lines.len() + 1);
    let mut at = 0;
    starts.push(at);
    for line in lines {
        at += line.chars().count();
        starts.push(at);
    }
    starts
}

/// Moves a span over a whole text across an edit, with the rule Word and
/// HTML spans keep ([`super::span_after_edits`]): boundaries inside one
/// changed run move to its edges, a partial delete shrinks the span, and a
/// span whose words were rewritten detaches. Lines are diffed first; only a
/// changed run of lines that touches the span is diffed by character, so a
/// long file costs a line diff plus the runs the span meets.
pub(in crate::anchored_annotation) fn remap_text_span(
    before: &str,
    after: &str,
    start: u64,
    end: u64,
) -> Option<(u64, u64)> {
    let (start, end) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
    let old_lines: Vec<&str> = before.split_inclusive('\n').collect();
    let new_lines: Vec<&str> = after.split_inclusive('\n').collect();
    let (old_at, new_at) = (line_starts(&old_lines), line_starts(&new_lines));
    let old_len = old_at[old_lines.len()];
    if start >= end || end > old_len {
        return None;
    }
    let old_chars: Vec<char> = before.chars().collect();
    let new_chars: Vec<char> = after.chars().collect();
    let mut edits: Vec<(DiffTag, Range<usize>, Range<usize>)> = Vec::new();
    for edit in capture_diff_slices(Algorithm::Myers, &old_lines, &new_lines) {
        let (tag, old, new) = edit.as_tag_tuple();
        let old = old_at[old.start]..old_at[old.end];
        let new = new_at[new.start]..new_at[new.end];
        let touches = old.start <= end && start <= old.end && !old.is_empty();
        if tag == DiffTag::Equal || !touches {
            edits.push((tag, old, new));
            continue;
        }
        for inner in capture_diff_slices(
            Algorithm::Myers,
            &old_chars[old.clone()],
            &new_chars[new.clone()],
        ) {
            let (tag, inner_old, inner_new) = inner.as_tag_tuple();
            edits.push((
                tag,
                old.start + inner_old.start..old.start + inner_old.end,
                new.start + inner_new.start..new.start + inner_new.end,
            ));
        }
    }
    super::span_after_edits(&old_chars, &new_chars, &edits, start, end)
}

/// The text side of one re-anchor sweep: both versions' decoded text.
pub(in crate::anchored_annotation) struct TextReanchor {
    before: Option<String>,
    after: Option<String>,
}

impl TextReanchor {
    /// Reads both versions when a live thread at `from` holds a text span on
    /// a text artifact; `None` otherwise, so other sweeps read nothing more.
    pub(in crate::anchored_annotation) fn load(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        artifact: &EntityId,
        from: u64,
        to: u64,
        threads: &[AnnotationThread],
    ) -> Result<Option<Self>> {
        if !threads.iter().any(|thread| {
            thread.anchor.version == from
                && !thread.is_drifted()
                && matches!(thread.anchor.locator, Locator::Text { .. })
        }) {
            return Ok(None);
        }
        let body = vault
            .get_blob_artifact_in_txn(txn, artifact)?
            .ok_or(Error::EntityNotFound)?;
        if !is_text_media_type(&body.media_type) {
            return Ok(None);
        }
        let read = |version| -> Result<Option<String>> {
            Ok(vault
                .read_blob_artifact_version_in_txn(txn, artifact, version)?
                .and_then(|bytes| decoded(&bytes).map(str::to_owned)))
        };
        Ok(Some(Self {
            before: read(from)?,
            after: read(to)?,
        }))
    }

    /// The span's place in the new version, or drift when none of its
    /// characters survives or either version does not read as text.
    pub(in crate::anchored_annotation) fn rebind(&self, locator: &Locator) -> ReanchorOutcome {
        let Locator::Text {
            char_start,
            char_end,
        } = locator
        else {
            return ReanchorOutcome::Drifted;
        };
        let (Some(before), Some(after)) = (&self.before, &self.after) else {
            return ReanchorOutcome::Drifted;
        };
        match remap_text_span(before, after, *char_start, *char_end)
            .and_then(|(start, end)| Locator::text(start, end).ok())
        {
            Some(locator) => ReanchorOutcome::Mapped(locator),
            None => ReanchorOutcome::Drifted,
        }
    }
}
