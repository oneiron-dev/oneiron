//! `vault.evidence.spans`: exact byte spans of one TURN's text, or one
//! source's version, through the caller's scoped read.
//!
//! A reader other than the owner reads a lifted key in a TURN's text as its
//! handle (`[secret sc12]`, OF-067), as `vault.snapshot.page` serves that
//! text. Its spans are cut from that masked text: positions, words and hashes
//! are the masked text's, and the answer says `masked`. A handle's length is
//! its own, so no position tells where a secret was or how long it is (lead
//! 12:4x, FIX-LIST EVIDENCE-SPANS-MASKED-COORDINATES).

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use super::source_version::{SourceVersion, SourceVersionCheck, blake3_ref, source_version_in_txn};
use crate::EntityId;
use crate::batch::secret_scan::LiftedKeys;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadResult};
use crate::dreamer_consolidation::TurnText;
use crate::dreamer_runner::DreamerAttemptBinding;
use crate::memory::{Memory, MemoryError, MemoryResult};

/// The most byte ranges one `vault.evidence.spans` request names.
pub const EVIDENCE_SPANS_MAX_RANGES: usize = 64;

/// The reason code of the refusal a reader other than the owner gets when a
/// lifted key in a TURN's text runs across the line break between two of its
/// MESSAGE rows: masked one row at a time, the text would not read as that
/// reader reads it whole, so no masked span is served.
pub const EVIDENCE_SPANS_MASKED_KEY_CROSSES_MESSAGES: &str =
    "evidence.spans.masked_key_crosses_messages";

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
    /// Byte ranges over a TURN's projected text as the caller reads it, each
    /// from `start` (inclusive) to `end` (exclusive); none reads the whole
    /// text. Any other row takes none: its answer is its version.
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
    /// Whether the spans are cut from the TURN's text as this reader reads
    /// it, with a lifted key as its handle, and not from the stored text:
    /// each span's positions, text and hash are the masked text's, a range
    /// with an end inside a handle is widened to that handle's edge, and a
    /// MESSAGE slice's positions are within that MESSAGE's masked words.
    /// Only a reader other than the owner gets `true`.
    #[serde(default)]
    pub masked: bool,
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
/// - For a reader other than the owner, a TURN whose text holds a lifted key
///   serves its spans over that text masked, as `vault.snapshot.page` serves
///   it, and says `masked`; the owner's spans are the stored text's.
///
/// # Errors
///
/// A request that fails [`validate_evidence_spans`]; ranges over a row that
/// is no TURN, over a TURN with no text, past the text's end, through a
/// UTF-8 character or over only the line breaks between MESSAGE rows; for a
/// reader other than the owner, a TURN whose lifted key runs across two of
/// its MESSAGE rows (reason [`EVIDENCE_SPANS_MASKED_KEY_CROSSES_MESSAGES`]);
/// the caller's read lane; and storage errors.
pub fn evidence_spans(
    memory: &Memory<'_>,
    input: &EvidenceSpansRequest,
) -> MemoryResult<ScopedReadResult<EvidenceSpans>> {
    bound_evidence_spans(memory, input, None)
}

/// Reads the evidence spans after proving the binding in the spans' own
/// read transaction, before any row is read.
///
/// # Errors
///
/// As [`evidence_spans`], and the binding's refusals.
pub(crate) fn evidence_spans_bound(
    memory: &Memory<'_>,
    input: &EvidenceSpansRequest,
    binding: &DreamerAttemptBinding,
) -> MemoryResult<ScopedReadResult<EvidenceSpans>> {
    bound_evidence_spans(memory, input, Some(binding))
}

/// The shared spans body, proving a bound call in its own read transaction.
fn bound_evidence_spans(
    memory: &Memory<'_>,
    input: &EvidenceSpansRequest,
    binding: Option<&DreamerAttemptBinding>,
) -> MemoryResult<ScopedReadResult<EvidenceSpans>> {
    validate_evidence_spans(input)?;
    let vault = memory.vault();
    let read = memory.read_lane(ClaimReadStatus::Recorded)?;
    let _pins = read.prepare_point_read::<MemoryError>()?;
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    if let Some(binding) = binding {
        memory.prove_read_authority_in_txn(&txn)?;
        binding.check_in_txn(&txn)?;
    }
    read.read_projected_in_txn(
        &txn,
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
                            masked: false,
                        });
                    }
                }
            }
            let Some((version, text)) = source_version_in_txn(&read, txn, &input.source)? else {
                return Ok(withheld());
            };
            let (spans, masked) = match text {
                Some(turn) => {
                    let keys = super::source_version::turn_lifted_keys_in_txn(
                        memory,
                        &read,
                        txn,
                        &input.source,
                        &turn,
                    )?;
                    match keys {
                        Some(keys) => masked_turn_spans(&turn, &keys, &input.ranges)?,
                        None => (turn_spans(&turn, &input.ranges)?, false),
                    }
                }
                None if input.ranges.is_empty() => (Vec::new(), false),
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
                masked,
            })
        },
    )
}

fn withheld() -> EvidenceSpans {
    EvidenceSpans {
        status: EvidenceSourceStatus::Withheld,
        version: None,
        spans: Vec::new(),
        masked: false,
    }
}

/// The spans of `ranges` over `turn`'s text as a reader reads it for whom
/// each of `keys` reads as its handle, and whether that text is masked at
/// all. The text is masked piece by piece (the TURN's own words, or each
/// MESSAGE's), so each MESSAGE slice falls within that MESSAGE's masked
/// words; it must read as the whole text masked at once reads, which
/// `vault.snapshot.page` serves. A range with an end inside a handle is
/// widened to that handle's edge (C-ANCHOR), so no span names part of one.
fn masked_turn_spans(
    turn: &TurnText,
    keys: &LiftedKeys,
    ranges: &[EvidenceRange],
) -> MemoryResult<(Vec<EvidenceSpan>, bool)> {
    let whole = turn.text().and_then(|text| keys.masked(text));
    let pieces = turn.masked_by(|words| keys.masked(words))?;
    let (whole, shown) = match (whole, pieces) {
        (None, None) => return Ok((turn_spans(turn, ranges)?, false)),
        (Some(whole), Some(shown)) if shown.text() == Some(whole.as_str()) => (whole, shown),
        _ => {
            let mut refusal = MemoryError::bad_request(
                "spans unavailable: a masked secret in this TURN's text runs across two of its MESSAGE rows",
            );
            refusal
                .reason_codes
                .push(EVIDENCE_SPANS_MASKED_KEY_CROSSES_MESSAGES.to_owned());
            return Err(refusal);
        }
    };
    let handles = keys.handle_ranges(&whole);
    let ranges: Vec<EvidenceRange> = ranges
        .iter()
        .map(|range| widened(*range, &handles))
        .collect();
    Ok((turn_spans(&shown, &ranges)?, true))
}

/// `range` with each end that falls inside one of `handles` (byte ranges of
/// the masked text) moved out to that handle's edge.
fn widened(range: EvidenceRange, handles: &[std::ops::Range<usize>]) -> EvidenceRange {
    let inside = |at: u64, handle: &std::ops::Range<usize>| {
        usize::try_from(at).is_ok_and(|at| handle.start < at && at < handle.end)
    };
    let mut out = range;
    for handle in handles {
        if inside(range.start, handle) {
            out.start = u64::try_from(handle.start).unwrap_or(u64::MAX);
        }
        if inside(range.end, handle) {
            out.end = u64::try_from(handle.end).unwrap_or(u64::MAX);
        }
    }
    out
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
