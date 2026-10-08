//! ED-02 (ARCH-0056 §3, ruling r2 — ONE-1758): the reconstructed lane's
//! measuring instrument, a word diff refined to characters, for amendments
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
//! 1. **Shortest edit script** — classic Myers O(ND) over INTERNED word ids.
//!    Interned rather than hashed: equal ids mean equal words, so no
//!    collision can make two different words diff as one. Words, not lines:
//!    line breaks are layout, so a script over lines could anchor on a line
//!    that a re-wrap merely produced. Common leading and trailing words are
//!    trimmed first; they are survivors by definition, and the trim is what
//!    keeps a one-word edit inside a 10k-line artifact cheap.
//! 2. **Move pairing** — a source line whose words all left, and whose text
//!    reappears as a line whose words all arrived elsewhere, is one
//!    relocation, not two edits, and is charged [`MOVE_DISCOUNT`] instead of
//!    a fresh delete-plus-insert. The pair leaves `ins`/`del` entirely and
//!    lands in [`OpsSummary::moved`]. Whole lines are the move unit, so a
//!    common word deleted in one place and typed in another is not a move.
//! 3. **Characters inside each changed region** — the changed words are
//!    diffed again character by character (the same Myers walk over
//!    `char`s), so a one-character typo in a long line charges one character,
//!    not the line. Changed regions separated by a run of survivors lighter
//!    than either of them are measured as one region, survivors included, and
//!    a region whose characters barely overlap is a rewrite and is charged
//!    whole (`REWRITE_SIMILARITY_PERCENT`), so coincidental shared letters or
//!    words never discount new text.
//!
//! # Unit and normal form
//!
//! The counts are CHARACTERS of the whitespace-collapsed text, the same unit
//! as the recorded-ops lane: each word weighs its characters plus the one
//! space (or terminator) after it. Re-indenting, re-spacing, blank lines and
//! re-wrapping change no word, so they are not edits, alone or next to a
//! real one. Deliberately boring — this lane measures how much a decider
//! changed, not how the text was laid out.
//!
//! # The cap
//!
//! The trace Myers backtracks through costs O(D²) memory, and a Δ is
//! TELEMETRY — no number here is worth an allocation the caller did not
//! choose. Past `MAX_EDIT_SCRIPT` the script is abandoned rather than paid
//! for: the trimmed middle is charged as a whole replacement (an upper bound
//! on the real edit mass), move pairing runs unchanged over it, and
//! [`OpsSummary::approx`] marks the result so a consumer can never read a
//! capped diff as an exact one. Pass 3 keeps the same cap per region.
//!
//! # Scope
//!
//! No generic diff trait and no rename detection. r2 says this lane never
//! becomes the substrate, and the cheapest way to keep that true is to leave
//! it not quite good enough to tempt anyone.

use std::collections::HashMap;
use std::ops::Range;

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

/// One reconstructed diff.
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
/// whitespace-collapsed words (see the module docs).
///
/// Never fails: every degenerate input has an honest answer. Two empty texts
/// changed nothing (`d_norm == 0`), a wholly rewritten text scores exactly
/// `1`, and a script too long to build is charged as a replacement and
/// flagged approximate.
///
/// Myers breaks ties between equally short scripts by direction, and once
/// words weigh their characters two such scripts can cost differently (keep
/// the long block and move the short one, or the reverse). Both directions
/// are measured and the cheaper kept, so the score never depends on which
/// text was called `before`.
#[must_use]
pub fn myers_line_diff(before: &str, after: &str) -> LineDiff {
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
    let words = Words::intern(before, after);
    let (head, tail) = common_affix(&words.before.ids, &words.after.ids);
    let middle = (
        head..words.before.ids.len() - tail,
        head..words.after.ids.len() - tail,
    );
    let script = shortest_edit_script(
        &words.before.ids[middle.0.clone()],
        &words.after.ids[middle.1.clone()],
    );
    let approx = script.is_none();
    let matches: Vec<(usize, usize)> = script
        .unwrap_or_default()
        .into_iter()
        .map(|(x, y)| (x + head, y + head))
        .collect();

    let mut fates = Fates {
        before: vec![Fate::Kept; words.before.ids.len()],
        after: vec![Fate::Kept; words.after.ids.len()],
    };
    fates.before[middle.0.clone()].fill(Fate::Changed);
    fates.after[middle.1.clone()].fill(Fate::Changed);
    for &(x, y) in &matches {
        fates.before[x] = Fate::Kept;
        fates.after[y] = Fate::Kept;
    }
    let moved = pair_moved_lines(&words, &mut fates);

    let after_all = 0..words.after.ids.len();
    let mut ops = OpsSummary {
        ins: 0,
        del: 0,
        kept: words.weight_in(&words.after, &fates.after, after_all, Fate::Kept),
        moved,
        approx,
    };
    for region in changed_regions(&words, &fates, &matches, middle) {
        let inner_kept =
            words.weight_in(&words.after, &fates.after, region.after.clone(), Fate::Kept);
        let chars = char_pass(
            &words.chars_in(&words.before, &fates.before, region.before),
            &words.chars_in(&words.after, &fates.after, region.after),
        );
        ops.ins = ops.ins.saturating_add(chars.ins);
        ops.del = ops.del.saturating_add(chars.del);
        ops.kept = ops
            .kept
            .saturating_sub(inner_kept)
            .saturating_add(chars.kept);
        ops.approx |= chars.approx;
    }
    LineDiff {
        d_norm: ops.d_norm(
            words.weight_of(&words.before.ids),
            words.weight_of(&words.after.ids),
        ),
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

/// Both texts' words as dense ids sharing one table, so the diff and the
/// move pairing compare integers while equality stays EXACT.
struct Words {
    before: Side,
    after: Side,
    /// `weights[id]`: the word's characters plus the one space after it, so
    /// the words of a text weigh exactly what its collapsed form does, plus
    /// one terminator.
    weights: Vec<u32>,
    /// `texts[id]`: the word itself, for the character pass.
    texts: Vec<String>,
}

/// One text as word ids, with the word ranges of its non-blank lines — the
/// unit move pairing relocates.
struct Side {
    ids: Vec<u32>,
    lines: Vec<Range<usize>>,
}

impl Words {
    fn intern(before: &str, after: &str) -> Self {
        let mut table: HashMap<String, u32> = HashMap::new();
        let mut texts: Vec<String> = Vec::new();
        let mut intern = |text: &str| -> Side {
            let mut side = Side {
                ids: Vec::new(),
                lines: Vec::new(),
            };
            for line in text.lines() {
                let start = side.ids.len();
                for word in line.split_whitespace() {
                    let next = u32_saturating(texts.len());
                    side.ids
                        .push(*table.entry(word.to_owned()).or_insert_with_key(|word| {
                            texts.push(word.clone());
                            next
                        }));
                }
                if side.ids.len() > start {
                    side.lines.push(start..side.ids.len());
                }
            }
            side
        };
        let before = intern(before);
        let after = intern(after);
        let weights = texts
            .iter()
            .map(|word| u32_saturating(word.chars().count()).saturating_add(1))
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

    /// The weight of the words in `range` of `side` whose fate is `fate`.
    fn weight_in(&self, side: &Side, fates: &[Fate], range: Range<usize>, fate: Fate) -> u32 {
        range
            .filter(|at| fates[*at] == fate)
            .fold(0, |total: u32, at| {
                total.saturating_add(self.weights[side.ids[at] as usize])
            })
    }

    /// The characters of the words in `range` of `side` that did not move,
    /// each followed by one space.
    fn chars_in(&self, side: &Side, fates: &[Fate], range: Range<usize>) -> Vec<u32> {
        range
            .filter(|at| fates[*at] != Fate::Moved)
            .flat_map(|at| self.texts[side.ids[at] as usize].chars().chain([' ']))
            .map(u32::from)
            .collect()
    }
}

/// What the script did with one word.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Survived: trimmed as a shared affix or matched by the script.
    Kept,
    /// Left (before side) or arrived (after side).
    Changed,
    /// Left or arrived as part of a move-paired line.
    Moved,
}

/// Every word's fate, by position, on each side.
struct Fates {
    before: Vec<Fate>,
    after: Vec<Fate>,
}

/// How many items the two sequences share at the head and at the tail.
///
/// The head and tail must not overlap on the shorter side, or a repeated run
/// (`a a a` → `a a a a a`) would count the same item as both.
fn common_affix(before: &[u32], after: &[u32]) -> (usize, usize) {
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
    (prefix, suffix)
}

// ---------------------------------------------------------------------------
// Pass 1 — shortest edit script
// ---------------------------------------------------------------------------

/// Myers' greedy O(ND) walk: the matched `(before, after)` positions in text
/// order, or `None` when `D` passes [`MAX_EDIT_SCRIPT`].
///
/// `trace` holds the frontier as it stood entering each step `d`, packed at
/// offset `d²` because step `d` reaches exactly the `2d + 1` diagonals
/// `-d..=d`. That packing is what makes the cap a real memory bound rather
/// than a promise.
fn shortest_edit_script(before: &[u32], after: &[u32]) -> Option<Vec<(usize, usize)>> {
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
                return Some(backtrack(&trace, d, (n, m)));
            }
            k += 2;
        }
    }
    None
}

/// Walks the trace back from the corner the forward pass reached, collecting
/// every diagonal step — a matched pair — in text order.
fn backtrack(trace: &[i32], depth: i32, end: (i32, i32)) -> Vec<(usize, usize)> {
    let mut matches = Vec::new();
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
            matches.push((x as usize, y as usize));
        }
        x = prev_x;
        y = prev_y;
    }
    matches.reverse();
    matches
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

/// Pairs each line whose words all left against an identical line whose
/// words all arrived, marks both `Moved`, and returns the paired weight.
///
/// Multiplicity is respected: three departed copies of one line against two
/// arrived copies are two moves and one real deletion. A line the script
/// kept even one word of is not a candidate, so the discount can only ever
/// apply to content that demonstrably went somewhere else whole.
fn pair_moved_lines(words: &Words, fates: &mut Fates) -> u32 {
    let wholly = |fates: &[Fate], line: &Range<usize>| {
        fates[line.clone()]
            .iter()
            .all(|fate| *fate == Fate::Changed)
    };
    let mut departed: HashMap<&[u32], u32> = HashMap::new();
    for line in &words.before.lines {
        if wholly(&fates.before, line) {
            *departed.entry(&words.before.ids[line.clone()]).or_insert(0) += 1;
        }
    }
    let mut paired: HashMap<&[u32], u32> = HashMap::new();
    let mut moved: u32 = 0;
    for line in &words.after.lines {
        let text = &words.after.ids[line.clone()];
        if !wholly(&fates.after, line) {
            continue;
        }
        if let Some(left) = departed.get_mut(text).filter(|left| **left > 0) {
            *left -= 1;
            *paired.entry(text).or_insert(0) += 1;
            fates.after[line.clone()].fill(Fate::Moved);
            moved = moved.saturating_add(words.weight_of(text));
        }
    }
    for line in &words.before.lines {
        let text = &words.before.ids[line.clone()];
        if !wholly(&fates.before, line) {
            continue;
        }
        if let Some(left) = paired.get_mut(text).filter(|left| **left > 0) {
            *left -= 1;
            fates.before[line.clone()].fill(Fate::Moved);
        }
    }
    moved
}

// ---------------------------------------------------------------------------
// Pass 3 — characters inside each changed region
// ---------------------------------------------------------------------------

/// One stretch the character pass measures: word ranges on each side that
/// hold changed words, and any survivors between them.
struct Region {
    before: Range<usize>,
    after: Range<usize>,
    /// The weight of its changed (not moved, not kept) words, both sides.
    changed: u32,
}

/// The script's changed regions in text order, each closed between two runs
/// of survivors.
///
/// A run of survivors lighter than the changed words on either side of it
/// does not separate them: a word two unrelated sentences share by chance
/// joins them into one region, so the rewrite floor in [`char_pass`] judges
/// the whole rewrite rather than its pieces. A long survivor run, or a small
/// edit beside one, keeps its own region.
fn changed_regions(
    words: &Words,
    fates: &Fates,
    matches: &[(usize, usize)],
    middle: (Range<usize>, Range<usize>),
) -> Vec<Region> {
    let mut regions: Vec<Region> = Vec::new();
    let (mut x, mut y) = (middle.0.start, middle.1.start);
    for &(next_x, next_y) in matches.iter().chain([&(middle.0.end, middle.1.end)]) {
        let (before, after) = (x..next_x, y..next_y);
        (x, y) = (next_x + 1, next_y + 1);
        let changed = words
            .weight_in(&words.before, &fates.before, before.clone(), Fate::Changed)
            .saturating_add(words.weight_in(
                &words.after,
                &fates.after,
                after.clone(),
                Fate::Changed,
            ));
        if changed == 0 {
            continue;
        }
        if let Some(last) = regions.last_mut() {
            let between = words.weight_in(
                &words.after,
                &fates.after,
                last.after.end..after.start,
                Fate::Kept,
            );
            if between < last.changed.min(changed) {
                last.before.end = before.end;
                last.after.end = after.end;
                last.changed = last.changed.saturating_add(changed);
                continue;
            }
        }
        regions.push(Region {
            before,
            after,
            changed,
        });
    }
    regions
}

/// Below this share of a region's characters surviving, counted on both
/// sides as `200 · kept / (before + after)`, its character diff is
/// coincidence, not an edit, and the region is charged as rewritten.
///
/// Two unrelated English sentences still share ~40-45% of their characters
/// in order (common letters, spaces); a typo or a reworded clause keeps 70%
/// and more. Without the floor a rewritten line would read as a half-edit,
/// and a full rewrite has to keep scoring `1`. A side that survives WHOLE is
/// never coincidence — text was only added to it, or only removed — so the
/// floor does not apply there.
const REWRITE_SIMILARITY_PERCENT: usize = 60;

/// The character counts of one region.
struct CharCounts {
    ins: u32,
    del: u32,
    kept: u32,
    approx: bool,
}

/// Diffs one region's characters, so a typo in a long line charges the typo
/// rather than the line.
fn char_pass(before: &[u32], after: &[u32]) -> CharCounts {
    let (head, tail) = common_affix(before, after);
    let script = shortest_edit_script(
        &before[head..before.len() - tail],
        &after[head..after.len() - tail],
    );
    let approx = script.is_none();
    let kept = head + tail + script.as_ref().map_or(0, Vec::len);
    let rewritten = kept < before.len().min(after.len())
        && 200 * kept < REWRITE_SIMILARITY_PERCENT * (before.len() + after.len());
    let kept = if rewritten { 0 } else { u32_saturating(kept) };
    CharCounts {
        ins: u32_saturating(after.len()).saturating_sub(kept),
        del: u32_saturating(before.len()).saturating_sub(kept),
        kept,
        approx,
    }
}

#[cfg(test)]
mod tests;
