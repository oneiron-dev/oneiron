//! Context-management strategies. All model-free and deterministic.
//!
//! A strategy sees the stream turn by turn (after the harness appends each
//! turn) and the window budget, and edits the window only through [`Ctx`].
//! It never sees the query set ahead of time or any hidden answer: at the end
//! it is shown one query at a time and may only name references to restore;
//! the fixed reader then answers from the live window plus those restores.

use std::collections::BTreeMap;
use std::ops::Range;

use super::arms::{Grid, Query, Verb, snapshot_lines};
use super::window::{Caps, Ctx, Span, SpanKind};

/// The five named strategies, in report order.
pub(crate) const STRATEGIES: [&str; 5] = [
    "truncate",
    "fifo-fold",
    "recoverable-fold",
    "free-file",
    "engine-board",
];

pub(crate) trait Strategy {
    fn name(&self) -> &'static str;

    /// The operations this strategy may use; the harness refuses the rest.
    fn caps(&self) -> Caps;

    /// One typed agent action that rode the turn just appended (only the
    /// sketchpad's moves are typed).
    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>);

    /// Called once per stream turn, after the turn (and its verb) landed.
    fn on_turn(&mut self, ctx: &mut Ctx<'_>);

    /// References to restore before the reader answers `query`. The live
    /// window is always visible; nothing else is.
    fn on_query(&mut self, query: &Query, ctx: &Ctx<'_>) -> Vec<u32> {
        let _ = (query, ctx);
        Vec::new()
    }
}

pub(crate) fn build(name: &str) -> Option<Box<dyn Strategy>> {
    match name {
        "truncate" => Some(Box::new(Truncate::new(Box::new(OldestFirst)))),
        "fifo-fold" => Some(Box::new(FifoFold::new(Box::new(OldestFirst)))),
        "recoverable-fold" => Some(Box::new(RecoverableFold::new(Box::new(OldestFirst)))),
        "free-file" => Some(Box::new(FreeFile::default())),
        "engine-board" => Some(Box::new(EngineBoard::new(Box::new(OldestFirst)))),
        _ => None,
    }
}

/// The hook where a model-decided policy plugs in later: which spans leave
/// the live window when it must shrink. A policy only chooses; the strategy
/// applies its own operation to the choice (drop, lossy fold, or offload to
/// a harness-minted reference). No model is called anywhere in this bench.
pub(crate) trait Policy {
    fn name(&self) -> &'static str;

    /// Index ranges (ascending, disjoint) to move out so at least `must_free`
    /// tokens leave. `keep` marks spans that must stay. The newest span is
    /// never chosen.
    fn choose(
        &mut self,
        spans: &[Span],
        must_free: u64,
        keep: &dyn Fn(&Span) -> bool,
    ) -> Vec<Range<usize>>;
}

/// Model-free default: oldest spans first.
pub(crate) struct OldestFirst;

impl Policy for OldestFirst {
    fn name(&self) -> &'static str {
        "oldest-first"
    }

    fn choose(
        &mut self,
        spans: &[Span],
        must_free: u64,
        keep: &dyn Fn(&Span) -> bool,
    ) -> Vec<Range<usize>> {
        let mut out: Vec<Range<usize>> = Vec::new();
        let mut freed = 0;
        let newest = spans.len().saturating_sub(1);
        for (i, span) in spans[..newest].iter().enumerate() {
            if freed >= must_free {
                break;
            }
            if keep(span) {
                continue;
            }
            freed += span.tok();
            match out.last_mut() {
                Some(r) if r.end == i => r.end = i + 1,
                _ => out.push(i..i + 1),
            }
        }
        out
    }
}

/// Once the window crosses its budget, frees down to the low-water mark by
/// applying `op` to the policy's choice, newest range first so indices hold.
fn shrink(
    ctx: &mut Ctx<'_>,
    policy: &mut dyn Policy,
    keep: &dyn Fn(&Span) -> bool,
    op: impl FnMut(&mut Ctx<'_>, Range<usize>),
) {
    if ctx.tokens() > ctx.budget() {
        let must_free = ctx.tokens() - ctx.low_water();
        move_out(ctx, policy, keep, must_free, op);
    }
}

/// Asks the policy for `must_free` tokens and applies `op` to its choice,
/// newest range first so indices hold. A choice that breaks the contract
/// (out of bounds, unordered, overlapping, touching a kept span or the
/// newest span) is applied not at all and fails the cell.
fn move_out(
    ctx: &mut Ctx<'_>,
    policy: &mut dyn Policy,
    keep: &dyn Fn(&Span) -> bool,
    must_free: u64,
    mut op: impl FnMut(&mut Ctx<'_>, Range<usize>),
) {
    let ranges = policy.choose(ctx.spans(), must_free, keep);
    let valid = {
        let spans = ctx.spans();
        let newest = spans.len().saturating_sub(1);
        let mut end = 0;
        ranges.iter().all(|r| {
            let ok = !r.is_empty()
                && r.start >= end
                && r.end <= newest
                && !spans[r.clone()].iter().any(keep);
            end = r.end;
            ok
        })
    };
    if !valid {
        ctx.fail("policy choice breaks its contract");
        return;
    }
    for range in ranges.into_iter().rev() {
        op(ctx, range);
    }
}

/// The agent's own view of the sketchpad, kept from its typed moves.
#[derive(Default)]
pub(crate) struct Sketch {
    grid: Option<Grid>,
    version: u32,
}

impl Sketch {
    /// Applies a verb; returns the row it changed (`None` for an init).
    pub(crate) fn apply(&mut self, verb: &Verb) -> Option<usize> {
        match *verb {
            Verb::BoardInit(grid) => {
                self.grid = Some(grid);
                self.version = 0;
                None
            }
            Verb::SetCell { mv, cell, digit } => {
                let grid = self.grid.get_or_insert([0; 81]);
                grid[usize::from(cell)] = digit;
                self.version = mv;
                Some(usize::from(cell) / 9)
            }
        }
    }

    /// The typed state the engine board renders.
    pub(crate) fn typed(&self) -> Option<(&Grid, u32)> {
        self.grid.as_ref().map(|g| (g, self.version))
    }

    pub(crate) fn snapshot(&self) -> Option<Vec<String>> {
        self.grid.as_ref().map(|g| snapshot_lines(g, self.version))
    }
}

/// What every append-only strategy does with a move: no in-place edit is
/// possible, so it regenerates and appends the whole board (CLM's named
/// expensive failure). The init board already sits in the stream.
fn regenerate_board(sketch: &mut Sketch, verb: &Verb, ctx: &mut Ctx<'_>) {
    if sketch.apply(verb).is_some()
        && let Some(lines) = sketch.snapshot()
    {
        ctx.append_note(lines.join("\n"));
    }
}

/// Drops the oldest spans. Nothing is restorable.
pub(crate) struct Truncate {
    policy: Box<dyn Policy>,
    sketch: Sketch,
}

impl Truncate {
    pub(crate) fn new(policy: Box<dyn Policy>) -> Self {
        Self {
            policy,
            sketch: Sketch::default(),
        }
    }
}

impl Strategy for Truncate {
    fn name(&self) -> &'static str {
        "truncate"
    }

    fn caps(&self) -> Caps {
        Caps {
            drop: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>) {
        regenerate_board(&mut self.sketch, verb, ctx);
    }

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        shrink(ctx, self.policy.as_mut(), &|_| false, |ctx, r| {
            ctx.drop_spans(r);
        });
    }
}

/// A fixed-size stub: about 96 tokens.
const STUB_BYTES: usize = 384;
/// Each line a stub keeps is cut to this many bytes.
const STUB_LINE_BYTES: usize = 32;

fn cut(line: &str, max: usize) -> &str {
    let mut end = line.len().min(max);
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    &line[..end]
}

/// The model-free summary stand-in: the newest data-bearing lines (any line
/// holding a digit) of the folded spans, each cut to [`STUB_LINE_BYTES`], as
/// many as fit in [`STUB_BYTES`]. Prose is dropped. Lossy by construction,
/// and a cut line can read back as a needle or value the stream never held.
pub(crate) fn lossy_summary(spans: &[Span]) -> String {
    let lines: Vec<&str> = spans
        .iter()
        .flat_map(|s| s.text().lines())
        .filter(|l| l.bytes().any(|b| b.is_ascii_digit()))
        .map(|l| cut(l, STUB_LINE_BYTES))
        .collect();
    let mut kept = Vec::new();
    let mut used = 0;
    for line in lines.iter().rev() {
        if used + line.len() + 1 > STUB_BYTES {
            break;
        }
        used += line.len() + 1;
        kept.push(*line);
    }
    kept.reverse();
    if kept.is_empty() {
        "(nothing kept)".to_owned()
    } else {
        kept.join("\n")
    }
}

/// Folds the oldest spans (older stubs included) into one fixed-size lossy
/// stub. No restore path.
pub(crate) struct FifoFold {
    policy: Box<dyn Policy>,
    sketch: Sketch,
}

impl FifoFold {
    pub(crate) fn new(policy: Box<dyn Policy>) -> Self {
        Self {
            policy,
            sketch: Sketch::default(),
        }
    }
}

impl Strategy for FifoFold {
    fn name(&self) -> &'static str {
        "fifo-fold"
    }

    fn caps(&self) -> Caps {
        Caps {
            fold_lossy: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>) {
        regenerate_board(&mut self.sketch, verb, ctx);
    }

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        shrink(ctx, self.policy.as_mut(), &|_| false, |ctx, r| {
            let stub = lossy_summary(&ctx.spans()[r.clone()]);
            ctx.fold_lossy(r, stub);
        });
    }
}

/// Folds the oldest spans into an ID-keyed reference the harness mints and
/// restores byte-exactly on demand (Sculptor, OF-190). The reference stubs
/// stay in the window as its index. At query time it searches its own
/// references for the query's key and restores every match.
pub(crate) struct RecoverableFold {
    policy: Box<dyn Policy>,
    sketch: Sketch,
}

impl RecoverableFold {
    pub(crate) fn new(policy: Box<dyn Policy>) -> Self {
        Self {
            policy,
            sketch: Sketch::default(),
        }
    }
}

fn is_ref_stub(span: &Span) -> bool {
    matches!(span.kind(), SpanKind::RefStub(_))
}

impl Strategy for RecoverableFold {
    fn name(&self) -> &'static str {
        "recoverable-fold"
    }

    fn caps(&self) -> Caps {
        Caps {
            offload: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>) {
        regenerate_board(&mut self.sketch, verb, ctx);
    }

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        shrink(ctx, self.policy.as_mut(), &is_ref_stub, |ctx, r| {
            ctx.offload(r);
        });
    }

    fn on_query(&mut self, query: &Query, ctx: &Ctx<'_>) -> Vec<u32> {
        ctx.grep_refs(&query.key)
    }
}

/// A line's shape for free-file's regex surgery. A line with no digit is
/// `prose`; any other line is its first three whitespace tokens, each kept
/// when it is an all-caps word of two or more letters and masked to `#`
/// otherwise (`# INFO #`, `SET # #`, `NEEDLE # #`).
pub(crate) fn shape(line: &str) -> String {
    if !line.bytes().any(|b| b.is_ascii_digit()) {
        return PROSE.to_owned();
    }
    line.split_whitespace()
        .take(3)
        .map(|t| {
            if t.len() >= 2 && t.bytes().all(|b| b.is_ascii_uppercase()) {
                t
            } else {
                "#"
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

const PROSE: &str = "prose";

/// The CLM rung-three analogue: unrestricted rewrite of the window,
/// deletion included, with no restore. Under pressure it runs regex surgery
/// (delete prose lines first, then every line of the most common shape,
/// oldest spans first), and it edits its sketchpad board in place. A measured
/// comparison arm only: it is never wired into the engine, whose compaction
/// never deletes.
#[derive(Default)]
pub(crate) struct FreeFile {
    sketch: Sketch,
    board: Option<u64>,
}

impl FreeFile {
    /// One surgery pass: prose while any is left, else the most common
    /// shape among evictable lines; its lines are deleted oldest span first
    /// until the projection reaches the low-water mark. Returns false when
    /// nothing is left to cut.
    fn surgery(&self, ctx: &mut Ctx<'_>) -> bool {
        let newest = ctx.spans().len().saturating_sub(1);
        let evictable: Vec<&Span> = ctx.spans()[..newest]
            .iter()
            .filter(|s| Some(s.id()) != self.board)
            .collect();
        let mut census: BTreeMap<String, usize> = BTreeMap::new();
        for line in evictable.iter().flat_map(|s| s.text().lines()) {
            *census.entry(shape(line)).or_default() += 1;
        }
        let Some(target) = census
            .iter()
            .max_by_key(|(k, n)| (k.as_str() == PROSE, **n, std::cmp::Reverse(k.as_str())))
            .map(|(k, _)| k.clone())
        else {
            return false;
        };
        let mut projected = ctx.tokens();
        let mut ids = Vec::new();
        for span in evictable {
            if projected <= ctx.low_water() {
                break;
            }
            let cut: usize = span
                .text()
                .lines()
                .filter(|l| shape(l) == target)
                .map(|l| l.len() + 1)
                .sum();
            if cut > 0 {
                projected = projected.saturating_sub(cut as u64 / 4);
                ids.push(span.id());
            }
        }
        ctx.retain_lines(&ids, &target, |l| shape(l) != target);
        true
    }
}

impl Strategy for FreeFile {
    fn name(&self) -> &'static str {
        "free-file"
    }

    fn caps(&self) -> Caps {
        Caps {
            rewrite: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>) {
        let row = self.sketch.apply(verb);
        let Some(lines) = self.sketch.snapshot() else {
            return;
        };
        match (row, self.board.and_then(|id| ctx.index_of(id))) {
            (Some(row), Some(index)) => {
                ctx.patch_lines(
                    index,
                    &[(0, lines[0].clone()), (row + 1, lines[row + 1].clone())],
                );
            }
            _ => self.board = Some(ctx.append_note(lines.join("\n"))),
        }
    }

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        if ctx.tokens() <= ctx.budget() {
            return;
        }
        while ctx.tokens() > ctx.low_water() && self.surgery(ctx) {}
        // Last resort: delete whole oldest spans, never its board.
        while ctx.tokens() > ctx.budget() {
            let Some(index) = ctx.spans()[..ctx.spans().len().saturating_sub(1)]
                .iter()
                .position(|s| Some(s.id()) != self.board)
            else {
                break;
            };
            ctx.delete_spans(index..index + 1);
        }
    }
}

/// The engine's own path: spans leave the message log only into
/// harness-minted references (the engine never deletes), and the Context
/// Board is rendered every turn as the dynamic tail by
/// `oneiron::context_board::render_board_block` from typed state alone (the
/// harness renders it, see `board.rs`): the sketchpad grid from the agent's
/// typed `board.*` verbs and the reference index from the store's metadata.
/// No text is parsed back into state.
pub(crate) struct EngineBoard {
    policy: Box<dyn Policy>,
    sketch: Sketch,
    board_tok: u64,
}

impl EngineBoard {
    pub(crate) fn new(policy: Box<dyn Policy>) -> Self {
        Self {
            policy,
            sketch: Sketch::default(),
            board_tok: 0,
        }
    }
}

impl Strategy for EngineBoard {
    fn name(&self) -> &'static str {
        "engine-board"
    }

    fn caps(&self) -> Caps {
        Caps {
            offload: true,
            board: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>) {
        let call = match *verb {
            Verb::BoardInit(grid) => {
                let digits: String = grid.iter().map(|d| char::from(b'0' + d)).collect();
                format!("board.init {digits}")
            }
            Verb::SetCell { cell, digit, .. } => {
                format!("board.set r{}c{}={digit}", cell / 9 + 1, cell % 9 + 1)
            }
        };
        self.sketch.apply(verb);
        ctx.charge_verb(&call);
    }

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        ctx.clear_board();
        if ctx.tokens() + self.board_tok > ctx.budget() {
            let must_free = ctx.tokens() + self.board_tok - ctx.low_water();
            move_out(
                ctx,
                self.policy.as_mut(),
                &is_ref_stub,
                must_free,
                |ctx, r| {
                    ctx.offload(r);
                },
            );
        }
        self.board_tok = ctx.render_board(self.sketch.typed());
    }

    fn on_query(&mut self, query: &Query, ctx: &Ctx<'_>) -> Vec<u32> {
        ctx.grep_refs(&query.key)
    }
}
