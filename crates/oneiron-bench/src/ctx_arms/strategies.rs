//! Context-management strategies. All model-free and deterministic.
//!
//! A strategy sees the stream turn by turn (after the harness appends each
//! turn) and the window budget, and edits the window only through [`Ctx`].
//! It never sees the query set ahead of time or any hidden answer: at the end
//! it is shown one query at a time and may only name references to restore;
//! the fixed reader then answers from the live window plus those restores.

use std::ops::Range;

use super::arms::{Grid, Query, Verb, snapshot_lines};
use super::window::{Caps, Ctx, Span};

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
    mut op: impl FnMut(&mut Ctx<'_>, Range<usize>),
) {
    if ctx.tokens() <= ctx.budget() {
        return;
    }
    let must_free = ctx.tokens() - ctx.low_water();
    let ranges = policy.choose(ctx.spans(), must_free, keep);
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
