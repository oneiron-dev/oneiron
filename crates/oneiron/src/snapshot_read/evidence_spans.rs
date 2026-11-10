//! `vault.evidence.spans`: exact byte spans of one TURN's text, or one
//! source's version, through the caller's scoped read.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::source_version::{SourceVersion, SourceVersionCheck, blake3_ref, source_version_in_txn};
use crate::EntityId;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::dreamer_consolidation::TurnText;
use crate::memory::{Memory, MemoryError, MemoryResult};

/// The most byte ranges one `vault.evidence.spans` request names.
pub const EVIDENCE_SPANS_MAX_RANGES: usize = 64;

/// One `vault.evidence.spans` request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpansRequest {
    /// The source row.
    pub source: EntityId,
    /// The version the caller read the source at. When the row has moved
    /// since, the answer serves no bytes.
    #[serde(default)]
    pub version: Option<SourceVersion>,
    /// Byte ranges over a TURN's projected text, each from `start`
    /// (inclusive) to `end` (exclusive); none reads the whole text. Any other
    /// row takes none: its answer is its version.
    #[serde(default)]
    pub ranges: Vec<EvidenceRange>,
}

/// One byte range over a TURN's projected text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRange {
    /// The first byte, inclusive.
    pub start: u64,
    /// The end, exclusive.
    pub end: u64,
}

/// Whether the source reads for the caller, and at the version asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSourceStatus {
    /// The source reads, at the version asked when one was named.
    Current,
    /// The source reads, but at another version than the one asked: no bytes
    /// are served.
    Moved,
    /// The caller does not read the source, or it is absent.
    Withheld,
}

/// One `vault.evidence.spans` answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceSpans {
    /// Whether the source reads for the caller, and at the version asked.
    pub status: EvidenceSourceStatus,
    /// The source's version as it reads now; `None` when withheld.
    pub version: Option<SourceVersion>,
    /// One span per requested range, or one over the whole text when none
    /// was named; empty unless the status is `current`.
    pub spans: Vec<EvidenceSpan>,
}

/// The exact bytes of one range of a TURN's projected text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceSpan {
    /// The first byte, inclusive.
    pub start: u64,
    /// The end, exclusive.
    pub end: u64,
    /// The range's exact text.
    pub text: String,
    /// `blake3:<hex>` of the range's exact bytes.
    pub content_hash: String,
    /// The MESSAGE-local slices the range covers, for a TURN whose words are
    /// its MESSAGE rows; empty for a TURN that carries its own words.
    pub messages: Vec<EvidenceMessageSlice>,
}

/// One MESSAGE-local slice behind a range of a TURN's text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceMessageSlice {
    /// The MESSAGE row.
    pub message: EntityId,
    /// The first byte within the MESSAGE's own content, inclusive.
    pub start: u64,
    /// The end within the MESSAGE's own content, exclusive.
    pub end: u64,
    /// `blake3:<hex>`: the evidence hash of the MESSAGE revision read.
    pub revision: String,
    /// The MESSAGE's document frontier, in hex, when it has a document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
}

/// The request's shape checks, run before the caller is resolved.
///
/// # Errors
///
/// More than [`EVIDENCE_SPANS_MAX_RANGES`] ranges, an empty range, or a
/// version of another row.
pub fn validate_evidence_spans(input: &EvidenceSpansRequest) -> MemoryResult<()> {
    if input.ranges.len() > EVIDENCE_SPANS_MAX_RANGES {
        return Err(MemoryError::bad_request(format!(
            "at most {EVIDENCE_SPANS_MAX_RANGES} evidence ranges per request"
        )));
    }
    if input.ranges.iter().any(|range| range.start >= range.end) {
        return Err(MemoryError::bad_request(
            "an evidence range needs start < end",
        ));
    }
    if input
        .version
        .as_ref()
        .is_some_and(|version| version.entity != input.source)
    {
        return Err(MemoryError::bad_request("the version names another source"));
    }
    Ok(())
}

/// Reads one source through the caller's scoped read, in one snapshot.
///
/// - A source the caller does not read answers `withheld`, as `vault.get`
///   answers absence. So does a TURN with a MESSAGE row the caller may not
///   read: no partial transcript is served.
/// - With `version`, the version is judged first: when the row has moved,
///   the answer is `moved` with the current version and no bytes.
/// - A TURN serves the exact bytes of each range of its projected text (its
///   own words, or its visible final MESSAGE rows joined with `"\n"`), with
///   the MESSAGE-local slices each covers. Any other row serves its version
///   only.
///
/// # Errors
///
/// A request that fails [`validate_evidence_spans`]; a TURN whose text holds
/// a lifted secret, for a reader other than the owner; ranges over a row that
/// is no TURN, over a TURN with no text, past the text's end, through a
/// UTF-8 character or over only the line breaks between MESSAGE rows; the
/// caller's read lane; and storage errors.
pub fn evidence_spans(
    memory: &Memory<'_>,
    input: &EvidenceSpansRequest,
) -> MemoryResult<ScopedReadResult<EvidenceSpans>> {
    validate_evidence_spans(input)?;
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    read.read_projected(
        &[PointRead::id(input.source)],
        None,
        |txn, _rows| -> MemoryResult<EvidenceSpans> {
            if let Some(asked) = &input.version {
                match asked.recheck_in_txn(&read, txn)? {
                    SourceVersionCheck::Current => {}
                    SourceVersionCheck::Withheld => return Ok(withheld()),
                    SourceVersionCheck::Moved => {
                        let Some((version, _)) = source_version_in_txn(&read, txn, &input.source)?
                        else {
                            return Ok(withheld());
                        };
                        return Ok(EvidenceSpans {
                            status: EvidenceSourceStatus::Moved,
                            version: Some(version),
                            spans: Vec::new(),
                        });
                    }
                }
            }
            let Some((version, text)) = source_version_in_txn(&read, txn, &input.source)? else {
                return Ok(withheld());
            };
            let spans = match text {
                Some(turn) => {
                    // A span is cut from the stored text, so one could cut
                    // through a lifted key: a reader other than the owner
                    // reads such a TURN's words only masked, whole, through
                    // `vault.snapshot.page` (review of #6964).
                    if super::source_version::served_turn_text_in_txn(
                        memory,
                        &read,
                        txn,
                        &input.source,
                        &turn,
                    )?
                    .1
                    {
                        return Err(MemoryError::bad_request(
                            "this TURN's text holds a lifted secret: its byte spans are served to the vault owner only",
                        ));
                    }
                    turn_spans(&turn, &input.ranges)?
                }
                None if input.ranges.is_empty() => Vec::new(),
                None => {
                    return Err(MemoryError::bad_request(
                        "byte ranges are served over a TURN's text only",
                    ));
                }
            };
            Ok(EvidenceSpans {
                status: EvidenceSourceStatus::Current,
                version: Some(version),
                spans,
            })
        },
    )
}

fn withheld() -> EvidenceSpans {
    EvidenceSpans {
        status: EvidenceSourceStatus::Withheld,
        version: None,
        spans: Vec::new(),
    }
}

/// The exact spans of `ranges` over `turn`'s projected text; one over the
/// whole text when `ranges` is empty and the text is not.
fn turn_spans(turn: &TurnText, ranges: &[EvidenceRange]) -> MemoryResult<Vec<EvidenceSpan>> {
    let Some(text) = turn.text() else {
        return if ranges.is_empty() {
            Ok(Vec::new())
        } else {
            Err(MemoryError::bad_request("the turn has no text"))
        };
    };
    let whole = [EvidenceRange {
        start: 0,
        end: u64::try_from(text.len()).unwrap_or(u64::MAX),
    }];
    let ranges = match ranges {
        [] if text.is_empty() => return Ok(Vec::new()),
        [] => &whole[..],
        ranges => ranges,
    };
    ranges
        .iter()
        .map(|range| turn_span(turn, text, *range))
        .collect()
}

fn turn_span(turn: &TurnText, text: &str, range: EvidenceRange) -> MemoryResult<EvidenceSpan> {
    let past_end = || MemoryError::bad_request("an evidence range ends past the turn's text");
    let start = usize::try_from(range.start).map_err(|_| past_end())?;
    let end = usize::try_from(range.end).map_err(|_| past_end())?;
    let bytes = text.as_bytes().get(start..end).ok_or_else(past_end)?;
    let words = std::str::from_utf8(bytes)
        .map_err(|_| MemoryError::bad_request("an evidence range splits a UTF-8 character"))?;
    let messages = turn
        .spans(Some((start, end)))
        .map_err(|error| MemoryError::bad_request(error.to_string()))?
        .into_iter()
        .map(|slice| EvidenceMessageSlice {
            message: slice.message,
            start: u64::try_from(slice.start).unwrap_or(u64::MAX),
            end: u64::try_from(slice.end).unwrap_or(u64::MAX),
            revision: blake3_ref(&slice.revision),
            frontier: slice.frontier.as_deref().map(hex),
        })
        .collect();
    Ok(EvidenceSpan {
        start: range.start,
        end: range.end,
        text: words.to_owned(),
        content_hash: blake3_ref(blake3::hash(bytes).as_bytes()),
        messages,
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
