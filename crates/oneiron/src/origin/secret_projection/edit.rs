//! An agent's edit of a masked repo copy, mapped onto the ORIGINAL (FIX
//! 7608 slice 2b-ii-A, ASK E VisibleDiff).
//!
//! A masked copy is the original with each marked span overwritten in
//! place, byte for byte, so copy offsets are original offsets. The agent's
//! submitted file is aligned with the copy (lines first, then bytes inside
//! each changed run that holds a span): every unchanged line and every
//! unchanged protected span is the original's, so a key the agent did not
//! touch stays as stored; a span the agent deliberately replaced or deleted
//! whole changes as authored. A span edited in part, or an edit that two
//! valid alignments would map onto different original bytes (the
//! alignment taken from the start and the one taken from the end disagree),
//! has no unique mapping: the proposal keeps its typed conflict, never an
//! arbitrary tie-break and never a whole-copy overwrite. An opaque file's
//! placeholder edited in any way is a sealed-file edit. Containers are
//! mapped member by member through the retained rebuild
//! ([`crate::batch::secret_scan::apply_retained_repo_projection_diff`]). No
//! count, byte, depth or time bound is added, and an alignment holds memory
//! linear in its inputs, whatever their edit distance (FIX 9234).

#![allow(
    dead_code,
    reason = "FIX 7608 2b-ii-A: the projected candidate translation calls it in 2b-ii-B"
)]

use super::REPO_OPAQUE_FILE_BYTES;
use crate::batch::secret_scan::{
    RetainedProjectionEdit, apply_retained_repo_projection_diff, is_container,
};
use crate::error::Result;
use crate::secret_custody::KeyPlaces;

/// What mapping an agent's edit of one masked file onto its ORIGINAL came
/// to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RepoProjectionDiffResult {
    /// The submitted bytes are the copy's: the original stays as stored.
    Unchanged,
    /// The edit mapped uniquely: the original with it applied.
    Applied(Vec<u8>),
    /// The sealed-file placeholder was edited (CALL H).
    SealedFileEdited,
    /// The edit has no unique mapping onto the original (ASK E).
    ProjectionEditConflict,
}

/// The copy a masked reader got of one file.
#[derive(Debug, Clone, Copy)]
pub(crate) enum RepoProjectedFileCopy<'c> {
    /// Each marked span overwritten in place: the copy and where its keys
    /// were placed.
    Masked {
        copy: &'c [u8],
        places: &'c KeyPlaces,
    },
    /// The sealed-file placeholder.
    Opaque,
}

/// The agent's `submitted` file mapped onto `original`, of which it was
/// given `copy`.
///
/// # Errors
/// An engine failure in a container reader.
pub(crate) fn apply_repo_projection_diff(
    original: &[u8],
    copy: RepoProjectedFileCopy<'_>,
    submitted: &[u8],
) -> Result<RepoProjectionDiffResult> {
    let (copy, places) = match copy {
        RepoProjectedFileCopy::Opaque if submitted == REPO_OPAQUE_FILE_BYTES => {
            return Ok(RepoProjectionDiffResult::Unchanged);
        }
        RepoProjectedFileCopy::Opaque => return Ok(RepoProjectionDiffResult::SealedFileEdited),
        RepoProjectedFileCopy::Masked { copy, places } => (copy, places),
    };
    if submitted == copy {
        return Ok(RepoProjectionDiffResult::Unchanged);
    }
    let members = places.iter().any(|(at, _)| !at.is_empty());
    if !members || !is_container(original) {
        let spans = places
            .iter()
            .filter(|(at, _)| at.is_empty())
            .flat_map(|(_, spans)| spans.iter().copied())
            .collect::<Vec<_>>();
        return Ok(visible_diff(original, copy, &spans, submitted).map_or(
            RepoProjectionDiffResult::ProjectionEditConflict,
            RepoProjectionDiffResult::Applied,
        ));
    }
    let mut leaf = |original: &[u8], copy: &[u8], submitted: &[u8], spans: &[(u64, u64)]| {
        visible_diff(original, copy, spans, submitted)
    };
    Ok(
        match apply_retained_repo_projection_diff(original, copy, submitted, places, &mut leaf)? {
            RetainedProjectionEdit::Rebuilt(bytes) => RepoProjectionDiffResult::Applied(bytes),
            RetainedProjectionEdit::Unmapped => RepoProjectionDiffResult::ProjectionEditConflict,
        },
    )
}

/// `submitted`, an edit of `copy`, mapped onto `original`, of which `copy`
/// is the in-place masked copy with keys at `spans`: `None` when it has no
/// unique mapping.
fn visible_diff(
    original: &[u8],
    copy: &[u8],
    spans: &[(u64, u64)],
    submitted: &[u8],
) -> Option<Vec<u8>> {
    if original.len() != copy.len() {
        return None;
    }
    let mut protected = Vec::with_capacity(spans.len());
    for &(start, end) in spans {
        let start = usize::try_from(start).ok()?;
        let end = usize::try_from(end).ok()?;
        if start >= end || end > copy.len() {
            return None;
        }
        protected.push((start, end));
    }
    protected.sort_unstable();
    let masked = MaskedFile {
        original,
        copy,
        spans: protected,
    };
    masked.apply(submitted)
}

/// The original, its in-place masked copy and the copy's protected spans,
/// sorted.
struct MaskedFile<'b> {
    original: &'b [u8],
    copy: &'b [u8],
    spans: Vec<(usize, usize)>,
}

impl MaskedFile<'_> {
    /// `submitted` mapped onto the original, when both extreme line
    /// alignments map it onto the same bytes.
    fn apply(&self, submitted: &[u8]) -> Option<Vec<u8>> {
        let copy_lines = line_ranges(self.copy);
        let edit_lines = line_ranges(submitted);
        let copy_tokens: Vec<&[u8]> = copy_lines.iter().map(|&(a, b)| &self.copy[a..b]).collect();
        let edit_tokens: Vec<&[u8]> = edit_lines.iter().map(|&(a, b)| &submitted[a..b]).collect();
        let first = aligned(&copy_tokens, &edit_tokens);
        let last = aligned_from_end(&copy_tokens, &edit_tokens);
        let mapped = self.render(&copy_lines, submitted, &edit_lines, &first)?;
        if first != last && self.render(&copy_lines, submitted, &edit_lines, &last)? != mapped {
            return None;
        }
        Some(mapped)
    }

    /// The original with the line alignment `pairs` applied: each matched
    /// line as stored, each changed run through [`Self::run`].
    fn render(
        &self,
        copy_lines: &[(usize, usize)],
        submitted: &[u8],
        edit_lines: &[(usize, usize)],
        pairs: &[(usize, usize)],
    ) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(submitted.len());
        let (mut copy_at, mut edit_at) = (0, 0);
        let end = (copy_lines.len(), edit_lines.len());
        for &(copy_line, edit_line) in pairs.iter().chain(std::iter::once(&end)) {
            if copy_line > copy_at || edit_line > edit_at {
                let copy_run = span_of(copy_lines, copy_at, copy_line, self.copy.len());
                let edit_run = span_of(edit_lines, edit_at, edit_line, submitted.len());
                out.extend(self.run(copy_run, &submitted[edit_run.0..edit_run.1])?);
            }
            if let Some(&(start, end)) = copy_lines.get(copy_line) {
                out.extend_from_slice(&self.original[start..end]);
            }
            copy_at = copy_line + 1;
            edit_at = edit_line + 1;
        }
        Some(out)
    }

    /// One changed run: the copy's bytes `copy_run` replaced by `edit`.
    /// With no protected span in it, the edit as authored; otherwise each
    /// span kept whole (its original bytes back in place), replaced whole
    /// (as authored), or edited in part (no unique mapping).
    fn run(&self, (start, end): (usize, usize), edit: &[u8]) -> Option<Vec<u8>> {
        let spans: Vec<(usize, usize)> = self
            .spans
            .iter()
            .copied()
            .filter(|&(a, b)| a < end && b > start)
            .collect();
        if spans.is_empty() {
            return Some(edit.to_vec());
        }
        if spans.iter().any(|&(a, b)| a < start || b > end) {
            return None;
        }
        let copy = &self.copy[start..end];
        // A span whose placeholder appears nowhere in the edit was replaced
        // whole by what the agent wrote.
        if !spans.iter().any(|&(a, b)| contains(edit, &self.copy[a..b])) {
            return Some(edit.to_vec());
        }
        let first = aligned(copy, edit);
        let last = aligned_from_end(copy, edit);
        let mapped = self.render_bytes(start, &spans, edit, &first)?;
        if first != last && self.render_bytes(start, &spans, edit, &last)? != mapped {
            return None;
        }
        Some(mapped)
    }

    /// `edit` with each span the byte alignment `pairs` keeps whole given
    /// back its original bytes; `None` for a span edited in part.
    fn render_bytes(
        &self,
        start: usize,
        spans: &[(usize, usize)],
        edit: &[u8],
        pairs: &[(usize, usize)],
    ) -> Option<Vec<u8>> {
        let mut out = edit.to_vec();
        for &(a, b) in spans {
            let kept: Vec<usize> = pairs
                .iter()
                .filter(|&&(copy_at, _)| (a..b).contains(&(start + copy_at)))
                .map(|&(_, edit_at)| edit_at)
                .collect();
            if kept.is_empty() {
                continue;
            }
            let whole = kept.len() == b - a && kept.windows(2).all(|pair| pair[1] == pair[0] + 1);
            if !whole {
                return None;
            }
            out[kept[0]..kept[0] + (b - a)].copy_from_slice(&self.original[a..b]);
        }
        Some(out)
    }
}

/// Each line of `bytes` as its byte range, its newline included.
fn line_ranges(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (at, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            lines.push((start, at + 1));
            start = at + 1;
        }
    }
    if start < bytes.len() {
        lines.push((start, bytes.len()));
    }
    lines
}

/// The bytes lines `from..to` of `lines` cover; an empty range at the start
/// of line `from` (or at `len` past the last line) when none.
fn span_of(lines: &[(usize, usize)], from: usize, to: usize, len: usize) -> (usize, usize) {
    let start = lines.get(from).map_or(len, |&(start, _)| start);
    let end = if to > from {
        lines.get(to - 1).map_or(len, |&(_, end)| end)
    } else {
        start
    };
    (start, end)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// The pairs of equal tokens a shortest edit script keeps, in order (Myers'
/// alignment, a deletion taken before an insertion), in space linear in
/// the inputs (FIX 9234): each run's common prefix and suffix are kept,
/// and what lies between is split at its middle snake, met from both ends,
/// the halves aligned in turn from a heap stack. No step's frontier is
/// kept past the step after it.
fn aligned<T: PartialEq>(a: &[T], b: &[T]) -> Vec<(usize, usize)> {
    let mut pairs = Vec::new();
    let width = a.len() + b.len() + 4;
    let mut forward = vec![0_isize; width];
    let mut backward = vec![0_isize; width];
    let mut pending = vec![Alignment::Run {
        a: (0, a.len()),
        b: (0, b.len()),
    }];
    while let Some(next) = pending.pop() {
        let (a_run, b_run) = match next {
            Alignment::Kept {
                a: a_at,
                b: b_at,
                len,
            } => {
                pairs.extend((0..len).map(|step| (a_at + step, b_at + step)));
                continue;
            }
            Alignment::Run { a, b } => (a, b),
        };
        let prefix = a[a_run.0..a_run.1]
            .iter()
            .zip(&b[b_run.0..b_run.1])
            .take_while(|(left, right)| left == right)
            .count();
        pairs.extend((0..prefix).map(|step| (a_run.0 + step, b_run.0 + step)));
        let (a_start, b_start) = (a_run.0 + prefix, b_run.0 + prefix);
        let suffix = a[a_start..a_run.1]
            .iter()
            .rev()
            .zip(b[b_start..b_run.1].iter().rev())
            .take_while(|(left, right)| left == right)
            .count();
        let (a_end, b_end) = (a_run.1 - suffix, b_run.1 - suffix);
        if suffix > 0 {
            pending.push(Alignment::Kept {
                a: a_end,
                b: b_end,
                len: suffix,
            });
        }
        if a_start == a_end || b_start == b_end {
            continue;
        }
        let Some((x, y)) = middle_snake(
            &a[a_start..a_end],
            &b[b_start..b_end],
            &mut forward,
            &mut backward,
        ) else {
            continue;
        };
        pending.push(Alignment::Run {
            a: (a_start + x, a_end),
            b: (b_start + y, b_end),
        });
        pending.push(Alignment::Run {
            a: (a_start, a_start + x),
            b: (b_start, b_start + y),
        });
    }
    pairs
}

/// One pending piece of an alignment, taken in order from a heap stack.
enum Alignment {
    /// Token ranges of both inputs still to align.
    Run {
        a: (usize, usize),
        b: (usize, usize),
    },
    /// Equal runs of `len` tokens already found, kept in place.
    Kept { a: usize, b: usize, len: usize },
}

/// The start of the middle snake of a shortest edit script of `a` into
/// `b`, both non-empty and differing at their first and last token: the
/// point a script's first half ends at, found by walking forward from the
/// start and backward from the end, one edit a step each, until they meet
/// (Myers 1986, 4b). `forward` and `backward` hold at least
/// `a.len() + b.len() + 4` entries; nothing they held before is read.
fn middle_snake<T: PartialEq>(
    a: &[T],
    b: &[T],
    forward: &mut [isize],
    backward: &mut [isize],
) -> Option<(usize, usize)> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let delta = n - m;
    let odd = delta.rem_euclid(2) == 1;
    let max = (n + m + 1) / 2;
    let at = |k: isize| (k + max + 1) as usize;
    forward[at(1)] = 0;
    backward[at(1)] = 0;
    for d in 0..=max {
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && forward[at(k - 1)] < forward[at(k + 1)]) {
                forward[at(k + 1)]
            } else {
                forward[at(k - 1)] + 1
            };
            let mut y = x - k;
            let start = (x, y);
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            forward[at(k)] = x;
            let reverse = delta - k;
            if odd && reverse.abs() < d && x + backward[at(reverse)] >= n {
                return Some((start.0 as usize, start.1 as usize));
            }
            k += 2;
        }
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && backward[at(k - 1)] < backward[at(k + 1)]) {
                backward[at(k + 1)]
            } else {
                backward[at(k - 1)] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[(n - 1 - x) as usize] == b[(m - 1 - y) as usize] {
                x += 1;
                y += 1;
            }
            backward[at(k)] = x;
            let ahead = delta - k;
            if !odd && ahead.abs() <= d && forward[at(ahead)] + x >= n {
                return Some(((n - x) as usize, (m - y) as usize));
            }
            k += 2;
        }
    }
    None
}

/// [`aligned`] taken from the end: the other extreme of the equally short
/// alignments, so an edit both map alike has one meaning.
fn aligned_from_end<T: PartialEq>(a: &[T], b: &[T]) -> Vec<(usize, usize)> {
    let reversed_a: Vec<&T> = a.iter().rev().collect();
    let reversed_b: Vec<&T> = b.iter().rev().collect();
    let mut pairs: Vec<(usize, usize)> = aligned(&reversed_a, &reversed_b)
        .into_iter()
        .map(|(i, j)| (a.len() - 1 - i, b.len() - 1 - j))
        .collect();
    pairs.reverse();
    pairs
}
