//! ED-02 (ARCH-0056 §3, ruling r2 — ONE-1758): the reconstructed lane's
//! measuring instrument, a two-pass line diff for amendments that arrived
//! with no op log to replay.
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
//! # Two passes
//!
//! 1. **Shortest edit script** — classic Myers O(ND) over INTERNED line ids.
//!    Interned rather than hashed: equal ids mean equal lines, so no
//!    collision can make two different lines diff as one. Common leading and
//!    trailing lines are trimmed first; they are survivors by definition, and
//!    the trim is what keeps a one-line edit inside a 10k-line artifact cheap.
//! 2. **Move pairing** — a deleted line whose text reappears among the
//!    insertions is one relocation, not two edits, and is charged
//!    [`MOVE_DISCOUNT`] instead of a fresh delete-plus-insert. The pair leaves
//!    `ins`/`del` entirely and lands in [`OpsSummary::moved`], which is the
//!    channel ED-01 reserved for exactly this producer.
//!
//! # The cap
//!
//! The trace Myers backtracks through costs O(D²) memory, and a Δ is
//! TELEMETRY — no number here is worth an allocation the caller did not
//! choose. Past [`MAX_EDIT_SCRIPT`] the script is abandoned rather than paid
//! for: the trimmed middle is charged as a whole replacement (an upper bound
//! on the real edit mass), move pairing runs unchanged over it, and
//! [`OpsSummary::approx`] marks the result so a consumer can never read a
//! capped diff as an exact one.
//!
//! # Line model
//!
//! [`str::lines`]: a trailing newline is not an edit, and `\r\n` is `\n`.
//! Deliberately boring — this lane measures how much a decider changed, not
//! how a file was terminated.
//!
//! # Scope
//!
//! No generic diff trait, no character-level mode, no rename detection. r2
//! says this lane never becomes the substrate, and the cheapest way to keep
//! that true is to leave it not quite good enough to tempt anyone.

use std::collections::HashMap;

use crate::edit_distance::delta::{OpsSummary, u32_saturating};

/// What a relocated line costs against a rewritten one.
///
/// A move-paired line charges `2 · MOVE_DISCOUNT` (0.2) into the edit mass
/// where the delete-plus-insert it replaces would charge 2.0 — the ratified
/// tenth. Compile-time on purpose: this is part of the metric's definition,
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
    /// Line-level op counts, with relocated lines already split out of
    /// `ins`/`del` and into `moved`.
    pub ops: OpsSummary,
    /// The pinned `clamp(edit_mass / (lines_before + lines_after), 0, 1)`.
    pub d_norm: f32,
}

impl LineDiff {
    /// Whether the script hit [`MAX_EDIT_SCRIPT`], leaving `ops` an upper
    /// bound rather than an exact count.
    ///
    /// Reads the flag the Δ itself carries, so a serialized Δ and the diff it
    /// came from cannot disagree about whether they are exact.
    #[must_use]
    pub const fn approximate(self) -> bool {
        self.ops.approx
    }
}

/// Measures the line-level edit between two endpoint texts.
///
/// Never fails: every degenerate input has an honest answer. Two empty texts
/// changed nothing (`d_norm == 0`), a wholly rewritten text scores exactly
/// `1`, and a script too long to build is charged as a replacement and
/// flagged approximate.
#[must_use]
pub fn myers_line_diff(before: &str, after: &str) -> LineDiff {
    let (before_ids, after_ids) = intern_lines(before, after);
    let (survived, mid_before, mid_after) = trim_common_affix(&before_ids, &after_ids);

    let script = shortest_edit_script(mid_before, mid_after)
        .unwrap_or_else(|| EditScript::whole_replacement(mid_before, mid_after));
    let moved = pair_moves(&script.deleted, &script.inserted);

    let ops = OpsSummary {
        ins: u32_saturating(script.inserted.len()).saturating_sub(moved),
        del: u32_saturating(script.deleted.len()).saturating_sub(moved),
        kept: survived.saturating_add(script.kept),
        moved,
        approx: script.approx,
    };
    LineDiff {
        d_norm: ops.d_norm(
            u32_saturating(before_ids.len()),
            u32_saturating(after_ids.len()),
        ),
        ops,
    }
}

// ---------------------------------------------------------------------------
// Interning + affix trim
// ---------------------------------------------------------------------------

/// Maps both texts' lines onto dense ids sharing one table, so the diff and
/// the move pairing both compare integers while equality stays EXACT.
fn intern_lines<'a>(before: &'a str, after: &'a str) -> (Vec<u32>, Vec<u32>) {
    let mut table: HashMap<&'a str, u32> = HashMap::new();
    let mut intern = |text: &'a str| -> Vec<u32> {
        text.lines()
            .map(|line| {
                let next = u32_saturating(table.len());
                *table.entry(line).or_insert(next)
            })
            .collect()
    };
    let before_ids = intern(before);
    let after_ids = intern(after);
    (before_ids, after_ids)
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

/// The edit script over one trimmed middle: which line ids left, which
/// arrived, and how many the script walked over untouched.
struct EditScript {
    deleted: Vec<u32>,
    inserted: Vec<u32>,
    kept: u32,
    approx: bool,
}

impl EditScript {
    /// The bound taken when the exact script costs more than a telemetry
    /// number is worth: everything between the shared affixes is charged as
    /// rewritten. `ins`/`del` can only overstate from here, never understate,
    /// which is why the flag says APPROXIMATE rather than unknown.
    fn whole_replacement(before: &[u32], after: &[u32]) -> Self {
        Self {
            deleted: before.to_vec(),
            inserted: after.to_vec(),
            kept: 0,
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
    let max_d = i32::try_from(MAX_EDIT_SCRIPT.min(before.len() + after.len())).ok()?;

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
                return Some(backtrack(before, after, &trace, d));
            }
            k += 2;
        }
    }
    None
}

/// Walks the trace back from `(n, m)` to the origin, naming every line the
/// script removed or added and counting the diagonals it slid along.
fn backtrack(before: &[u32], after: &[u32], trace: &[i32], depth: i32) -> EditScript {
    let mut script = EditScript {
        deleted: Vec::new(),
        inserted: Vec::new(),
        kept: 0,
        approx: false,
    };
    let mut x = i32::try_from(before.len()).unwrap_or(i32::MAX);
    let mut y = i32::try_from(after.len()).unwrap_or(i32::MAX);

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
            script.kept += 1;
        }
        if d > 0 {
            if x == prev_x {
                script.inserted.push(after[prev_y as usize]);
            } else {
                script.deleted.push(before[prev_x as usize]);
            }
        }
        x = prev_x;
        y = prev_y;
    }
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

/// Pairs each deleted line against an identical insertion, returning how many
/// pairs held.
///
/// Multiplicity is respected: three deletions of one line against two
/// insertions of it are two moves and one real deletion. Anything unpaired
/// stays a genuine insert or delete, so the discount can only ever apply to
/// content that demonstrably survived.
fn pair_moves(deleted: &[u32], inserted: &[u32]) -> u32 {
    let mut pool: HashMap<u32, u32> = HashMap::new();
    for line in deleted {
        *pool.entry(*line).or_insert(0) += 1;
    }
    let mut moved: u32 = 0;
    for line in inserted {
        if let Some(remaining) = pool.get_mut(line)
            && *remaining > 0
        {
            *remaining -= 1;
            moved = moved.saturating_add(1);
        }
    }
    moved
}

#[cfg(test)]
mod tests;
