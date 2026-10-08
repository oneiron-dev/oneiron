//! ED-02 (ARCH-0056 §3, ruling r2 — ONE-1758): the reconstructed lane's
//! measuring instrument, a line diff refined to characters, for amendments
//! that arrived with no op log to replay.
//!
//! # When this lane runs
//!
//! r2 pins it as a FALLBACK, never the substrate. An amendment that rode the
//! gated proposal flow has recorded ops, and those see churn — text typed and
//! then retyped — that no endpoint comparison can. Myers runs only when both
//! ends of a window exist and nothing in between does: a human edited the
//! artifact out of band. The precedence itself lives in
//! [`crate::edit_distance::delta::capture_delta_best`]; nothing here decides
//! when it is chosen.
//!
//! # Three passes
//!
//! 1. **Shortest edit script** — classic Myers O(ND) over INTERNED line ids.
//!    Interned rather than hashed: equal ids mean equal lines, so no
//!    collision can make two different lines diff as one. Common leading and
//!    trailing lines are trimmed first; they are survivors by definition, and
//!    the trim is what keeps a one-line edit inside a 10k-line artifact cheap.
//!    The script groups its edits into hunks: the changed regions between
//!    runs of surviving lines.
//! 2. **Move pairing** — a deleted line whose text reappears among the
//!    insertions is one relocation, not two edits, and is charged
//!    [`MOVE_DISCOUNT`] instead of a fresh delete-plus-insert. The pair leaves
//!    `ins`/`del` entirely and lands in [`OpsSummary::moved`], which is the
//!    channel ED-01 reserved for exactly this producer.
//! 3. **Characters inside each hunk** — the lines a hunk still holds are
//!    diffed again character by character (the same Myers walk over
//!    `char`s), so a one-character typo in a long line charges one character,
//!    not the line. A hunk whose characters barely overlap is a rewrite and
//!    is charged whole (`REWRITE_SIMILARITY_PERCENT`), so coincidental shared letters
//!    never discount new text.
//!
//! # Unit and normal form
//!
//! The counts are CHARACTERS of the normalized text, the same unit as the
//! recorded-ops lane. Each line is `collapse_whitespace`d and blank lines
//! are dropped, so re-indenting or re-spacing is not an edit; and pass 3 joins
//! a hunk's lines with spaces, so re-wrapping a paragraph across different
//! line breaks is not an edit either. A line weighs its characters plus one
//! terminator. `\r\n` is `\n`, and a trailing newline is not an edit.
//! Deliberately boring — this lane measures how much a decider changed, not
//! how the text was laid out.
//!
//! # The cap
//!
//! The trace Myers backtracks through costs O(D²) memory, and a Δ is
//! TELEMETRY — no number here is worth an allocation the caller did not
//! choose. Past `MAX_EDIT_SCRIPT` the script is abandoned rather than paid
//! for: the trimmed middle is charged as a whole replacement (an upper bound
//! on the real edit mass), move pairing runs unchanged over it, and
//! [`OpsSummary::approx`] marks the result so a consumer can never read a
//! capped diff as an exact one. Pass 3 keeps the same cap per hunk.
//!
//! # Scope
//!
//! No generic diff trait and no rename detection. r2 says this lane never
//! becomes the substrate, and the cheapest way to keep that true is to leave
//! it not quite good enough to tempt anyone.

use std::collections::HashMap;

use crate::edit_distance::delta::{OpsSummary, u32_saturating};

/// What a relocated line costs against a rewritten one.
///
/// A move-paired character charges `2 · MOVE_DISCOUNT` (0.2) into the edit
/// mass where the delete-plus-insert it replaces would charge 2.0 — the
/// ratified tenth. Compile-time on purpose: this is part of the metric's definition,
/// not a dial an operator turns under a miner that already banked numbers
/// measured with the old one.
pub const MOVE_DISCOUNT: f32 = 0.1;

/// Cap on the shortest-edit-script length `D`.
///
/// The cap IS the memory bound: the backtrackable trace is `(D + 1)²` cells,
/// so 1024 buys ~4 MiB worst case and an exact script for any amendment short
/// of a wholesale rewrite. Past it the diff degrades to a bound and says so.
const MAX_EDIT_SCRIPT: usize = 1024;

/// One reconstructed line diff.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LineDiff {
    /// Character counts of the normalized text, with relocated lines
    /// already split out of `ins`/`del` and into `moved`.
    pub ops: OpsSummary,
    /// The pinned `clamp(edit_mass / (len_before + len_after), 0, 1)`.
    pub d_norm: f32,
}

impl LineDiff {
    /// Whether the script hit `MAX_EDIT_SCRIPT`, leaving `ops` an upper
    /// bound rather than an exact count.
    ///
    /// Reads the flag the Δ itself carries, so a serialized Δ and the diff it
    /// came from cannot disagree about whether they are exact.
    #[must_use]
    pub const fn approximate(self) -> bool {
        self.ops.approx
    }
}

/// Measures the edit between two endpoint texts, in characters of their
/// normalized lines (see the module docs).
///
/// Never fails: every degenerate input has an honest answer. Two empty texts
/// changed nothing (`d_norm == 0`), a wholly rewritten text scores exactly
/// `1`, and a script too long to build is charged as a replacement and
/// flagged approximate.
///
/// Myers breaks ties between equally short line scripts by direction, and
/// once lines weigh their characters two such scripts can cost differently
/// (keep the long block and move the short one, or the reverse). Both
/// directions are measured and the cheaper kept, so the score never depends
/// on which text was called `before`.
#[must_use]
pub fn myers_line_diff(before: &str, after: &str) -> LineDiff {
    // A layout-only edit is settled before any line is paired: a re-wrap can
    // leave one line that happens to equal another, and pairing it would
    // charge a move for text that never went anywhere.
    let collapsed = collapse_whitespace(before);
    if collapsed == collapse_whitespace(after) {
        let len = if collapsed.is_empty() {
            0
        } else {
            u32_saturating(collapsed.chars().count()).saturating_add(1)
        };
        let ops = OpsSummary {
            kept: len,
            ..OpsSummary::default()
        };
        return LineDiff {
            d_norm: ops.d_norm(len, len),
            ops,
        };
    }
    let forward = one_way_diff(before, after);
    let reverse = one_way_diff(after, before);
    if reverse.d_norm < forward.d_norm {
        LineDiff {
            ops: OpsSummary {
                ins: reverse.ops.del,
                del: reverse.ops.ins,
                ..reverse.ops
            },
            d_norm: reverse.d_norm,
        }
    } else {
        forward
    }
}

/// [`myers_line_diff`] in one direction, with Myers' own tie-breaking.
fn one_way_diff(before: &str, after: &str) -> LineDiff {
    let lines = Lines::intern(before, after);
    let (_, mid_before, mid_after) = trim_common_affix(&lines.before, &lines.after);

    let script = shortest_edit_script(mid_before, mid_after)
        .unwrap_or_else(|| EditScript::whole_replacement(mid_before, mid_after));
    let mut hunks = script.hunks;
    let moved = pair_moves(&mut hunks);

    let before_len = lines.weight_of(&lines.before);
    let after_len = lines.weight_of(&lines.after);
    let survived = before_len.saturating_sub(lines.weight_of(mid_before));
    let mut ops = OpsSummary {
        ins: 0,
        del: 0,
        kept: survived.saturating_add(lines.weight_of(&script.kept)),
        moved: lines.weight_of(&moved),
        approx: script.approx,
    };
    for hunk in &hunks {
        let chars = char_pass(&lines, hunk);
        ops.ins = ops.ins.saturating_add(chars.ins);
        ops.del = ops.del.saturating_add(chars.del);
        ops.kept = ops.kept.saturating_add(chars.kept);
        ops.approx |= chars.approx;
    }
    LineDiff {
        d_norm: ops.d_norm(before_len, after_len),
        ops,
    }
}

// ---------------------------------------------------------------------------
// Normalization + interning + affix trim
// ---------------------------------------------------------------------------

/// The format-blind form of a text: every whitespace run, newlines
/// included, becomes one space, and the ends are trimmed.
///
/// Both text lanes measure THIS, never the raw text, so re-indenting,
/// re-spacing or re-wrapping a passage costs nothing.
pub(in crate::edit_distance) fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Both texts' normalized, non-blank lines as dense ids sharing one table,
/// so the diff and the move pairing compare integers while equality stays
/// EXACT. A blank line is format, not content, so it is not a line here.
struct Lines {
    before: Vec<u32>,
    after: Vec<u32>,
    /// `weights[id]`: the line's characters plus its one terminator, so the
    /// lines of a text weigh exactly what its newline-terminated normal form
    /// does.
    weights: Vec<u32>,
    /// `texts[id]`: the normalized line itself, for the character pass.
    texts: Vec<String>,
}

impl Lines {
    fn intern(before: &str, after: &str) -> Self {
        let mut table: HashMap<String, u32> = HashMap::new();
        let mut texts: Vec<String> = Vec::new();
        let mut intern = |text: &str| -> Vec<u32> {
            text.lines()
                .map(collapse_whitespace)
                .filter(|line| !line.is_empty())
                .map(|line| {
                    let next = u32_saturating(texts.len());
                    *table.entry(line).or_insert_with_key(|line| {
                        texts.push(line.clone());
                        next
                    })
                })
                .collect()
        };
        let before = intern(before);
        let after = intern(after);
        let weights = texts
            .iter()
            .map(|line| u32_saturating(line.chars().count()).saturating_add(1))
            .collect();
        Self {
            before,
            after,
            weights,
            texts,
        }
    }

    fn weight_of(&self, ids: &[u32]) -> u32 {
        ids.iter().fold(0, |total: u32, id| {
            total.saturating_add(self.weights[*id as usize])
        })
    }

    /// The characters of `ids`, each line followed by a SPACE rather than a
    /// newline, so a passage re-wrapped across different line breaks reads
    /// as the same characters.
    fn chars_of(&self, ids: &[u32]) -> Vec<u32> {
        ids.iter()
            .flat_map(|id| self.texts[*id as usize].chars().chain([' ']))
            .map(u32::from)
            .collect()
    }
}

/// Splits off the shared head and tail, returning how many lines survived
/// there and the middles Myers actually has to walk.
///
/// The head and tail must not overlap on the shorter side, or a repeated run
/// (`a a a` → `a a a a a`) would count the same line as both.
fn trim_common_affix<'a>(before: &'a [u32], after: &'a [u32]) -> (u32, &'a [u32], &'a [u32]) {
    let prefix = before
        .iter()
        .zip(after)
        .take_while(|(left, right)| left == right)
        .count();
    let budget = before.len().min(after.len()) - prefix;
    let suffix = before
        .iter()
        .rev()
        .zip(after.iter().rev())
        .take(budget)
        .take_while(|(left, right)| left == right)
        .count();
    (
        u32_saturating(prefix + suffix),
        &before[prefix..before.len() - suffix],
        &after[prefix..after.len() - suffix],
    )
}

// ---------------------------------------------------------------------------
// Pass 1 — shortest edit script
// ---------------------------------------------------------------------------

/// The edit script over one trimmed middle: the changed regions it found,
/// and the ids it walked over untouched.
struct EditScript {
    hunks: Vec<Hunk>,
    kept: Vec<u32>,
    approx: bool,
}

/// One changed region: the ids that left and the ids that arrived between
/// two runs of survivors, each in text order.
#[derive(Default)]
struct Hunk {
    deleted: Vec<u32>,
    inserted: Vec<u32>,
}

impl Hunk {
    /// Closes this region, if it holds anything, onto `hunks`. The backtrack
    /// collects ids last-first, so they are put back in text order here.
    fn close_into(&mut self, hunks: &mut Vec<Self>) {
        if self.deleted.is_empty() && self.inserted.is_empty() {
            return;
        }
        let mut done = std::mem::take(self);
        done.deleted.reverse();
        done.inserted.reverse();
        hunks.push(done);
    }
}

impl EditScript {
    /// The bound taken when the exact script costs more than a telemetry
    /// number is worth: everything between the shared affixes is charged as
    /// ONE rewritten region. `ins`/`del` can only overstate from here, never
    /// understate, which is why the flag says APPROXIMATE rather than
    /// unknown.
    fn whole_replacement(before: &[u32], after: &[u32]) -> Self {
        let mut hunks = Vec::new();
        Hunk {
            deleted: before.iter().rev().copied().collect(),
            inserted: after.iter().rev().copied().collect(),
        }
        .close_into(&mut hunks);
        Self {
            hunks,
            kept: Vec::new(),
            approx: true,
        }
    }
}

/// Myers' greedy O(ND) walk, or `None` when `D` passes [`MAX_EDIT_SCRIPT`].
///
/// `trace` holds the frontier as it stood entering each step `d`, packed at
/// offset `d²` because step `d` reaches exactly the `2d + 1` diagonals
/// `-d..=d`. That packing is what makes the cap a real memory bound rather
/// than a promise.
fn shortest_edit_script(before: &[u32], after: &[u32]) -> Option<EditScript> {
    let n = i32::try_from(before.len()).ok()?;
    let m = i32::try_from(after.len()).ok()?;
    // Bounded by MAX_EDIT_SCRIPT, so the cast cannot truncate.
    let max_d = MAX_EDIT_SCRIPT.min(before.len() + after.len()) as i32;

    // One guard cell past each end: the greedy rule reads the neighbours of
    // diagonal `k`, and at `|k| == max_d` one of those is off the board. It
    // reads as `0`, which is what the classic seed `v[1] = 0` means anyway.
    let offset = max_d + 1;
    let mut frontier = vec![0i32; (2 * max_d + 3) as usize];
    let mut trace: Vec<i32> = Vec::new();

    for d in 0..=max_d {
        let row = ((offset - d) as usize)..=((offset + d) as usize);
        trace.extend_from_slice(&frontier[row]);
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d
                || (k != d
                    && frontier[(offset + k - 1) as usize] < frontier[(offset + k + 1) as usize])
            {
                frontier[(offset + k + 1) as usize]
            } else {
                frontier[(offset + k - 1) as usize] + 1
            };
            let mut y = x - k;
            while x < n && y < m && before[x as usize] == after[y as usize] {
                x += 1;
                y += 1;
            }
            frontier[(offset + k) as usize] = x;
            if x >= n && y >= m {
                return Some(backtrack(before, after, &trace, d, (n, m)));
            }
            k += 2;
        }
    }
    None
}

/// Walks the trace back from the corner the forward pass reached, naming
/// every line the script removed or added and counting the diagonals it slid
/// along.
fn backtrack(
    before: &[u32],
    after: &[u32],
    trace: &[i32],
    depth: i32,
    end: (i32, i32),
) -> EditScript {
    let mut script = EditScript {
        hunks: Vec::new(),
        kept: Vec::new(),
        approx: false,
    };
    let mut hunk = Hunk::default();
    let (mut x, mut y) = end;

    for d in (0..=depth).rev() {
        // Step 0 has one predecessor, the origin, and no edit to charge — the
        // frontier row it would read does not hold the diagonal it would ask
        // for.
        let (prev_x, prev_y) = if d == 0 {
            (0, 0)
        } else {
            predecessor(trace, d, x - y)
        };
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            script.kept.push(before[x as usize]);
            hunk.close_into(&mut script.hunks);
        }
        if d > 0 {
            if x == prev_x {
                hunk.inserted.push(after[prev_y as usize]);
            } else {
                hunk.deleted.push(before[prev_x as usize]);
            }
        }
        x = prev_x;
        y = prev_y;
    }
    hunk.close_into(&mut script.hunks);
    script
}

/// Where diagonal `k` at step `d` came from: the neighbour Myers' greedy rule
/// would have extended.
fn predecessor(trace: &[i32], d: i32, k: i32) -> (i32, i32) {
    let start = (d * d) as usize;
    let row = &trace[start..start + (2 * d + 1) as usize];
    let at = |diagonal: i32| row[(diagonal + d) as usize];
    let prev_k = if k == -d || (k != d && at(k - 1) < at(k + 1)) {
        k + 1
    } else {
        k - 1
    };
    let prev_x = at(prev_k);
    (prev_x, prev_x - prev_k)
}

// ---------------------------------------------------------------------------
// Pass 2 — move pairing
// ---------------------------------------------------------------------------

/// Pairs each deleted line against an identical insertion anywhere in the
/// script, takes both out of their hunks, and returns the paired lines.
///
/// Multiplicity is respected: three deletions of one line against two
/// insertions of it are two moves and one real deletion. Anything unpaired
/// stays in its hunk for the character pass, so the discount can only ever
/// apply to content that demonstrably survived.
fn pair_moves(hunks: &mut [Hunk]) -> Vec<u32> {
    let mut pool: HashMap<u32, u32> = HashMap::new();
    for line in hunks.iter().flat_map(|hunk| &hunk.deleted) {
        *pool.entry(*line).or_insert(0) += 1;
    }
    let mut moved = Vec::new();
    for hunk in hunks.iter_mut() {
        hunk.inserted.retain(|line| match pool.get_mut(line) {
            Some(remaining) if *remaining > 0 => {
                *remaining -= 1;
                moved.push(*line);
                false
            }
            _ => true,
        });
    }
    let mut unclaimed: HashMap<u32, u32> = HashMap::new();
    for line in &moved {
        *unclaimed.entry(*line).or_insert(0) += 1;
    }
    for hunk in hunks.iter_mut() {
        hunk.deleted.retain(|line| match unclaimed.get_mut(line) {
            Some(remaining) if *remaining > 0 => {
                *remaining -= 1;
                false
            }
            _ => true,
        });
    }
    moved
}

// ---------------------------------------------------------------------------
// Pass 3 — characters inside each changed region
// ---------------------------------------------------------------------------

/// Below this share of a region's characters surviving, counted on both
/// sides as `200 · kept / (before + after)`, its character diff is
/// coincidence, not an edit, and the region is charged as rewritten.
///
/// Two unrelated English sentences still share ~40-45% of their characters
/// in order (common letters, spaces); a typo or a reworded clause keeps 70%
/// and more. Without the floor a rewritten line would read as a half-edit,
/// and a full rewrite has to keep scoring `1`.
const REWRITE_SIMILARITY_PERCENT: u64 = 60;

/// The character counts of one region.
struct CharCounts {
    ins: u32,
    del: u32,
    kept: u32,
    approx: bool,
}

/// Diffs one region's remaining lines character by character, so a typo in
/// a long line charges the typo rather than the line, and a re-wrapped
/// passage (same characters, different breaks) charges nothing.
fn char_pass(lines: &Lines, hunk: &Hunk) -> CharCounts {
    let before = lines.chars_of(&hunk.deleted);
    let after = lines.chars_of(&hunk.inserted);
    let (common, mid_before, mid_after) = trim_common_affix(&before, &after);
    let (kept, approx) = match shortest_edit_script(mid_before, mid_after) {
        Some(script) => (
            common.saturating_add(u32_saturating(script.kept.len())),
            false,
        ),
        None => (common, true),
    };
    let region = (before.len() + after.len()) as u64;
    let kept = if 200 * u64::from(kept) < REWRITE_SIMILARITY_PERCENT * region {
        0
    } else {
        kept
    };
    CharCounts {
        ins: u32_saturating(after.len()).saturating_sub(kept),
        del: u32_saturating(before.len()).saturating_sub(kept),
        kept,
        approx,
    }
}

#[cfg(test)]
mod tests;
