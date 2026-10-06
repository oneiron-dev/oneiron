//! Context-management strategies. All model-free and deterministic.
//!
//! A strategy sees the stream turn by turn (after the harness appends each
//! turn) and the window budget, and edits the window only through [`Ctx`].
//! It never sees the query set ahead of time or any hidden answer: at the end
//! it is shown one query at a time and may only name references to restore;
//! the fixed reader then answers from the live window plus those restores.

use std::collections::BTreeMap;
use std::ops::Range;

use oneiron::context_board::{
    BoardSnapshot, CarrierCoalesceBuffer, FrameKind, ServedLifecycle, SessionReadSet, SkillsSection,
};

use super::arms::{Grid, Query, Verb, snapshot_lines};
use super::board::{CanonBoard, Held, ResRow};
use super::window::{Caps, Ctx, Link, Place, Span, SpanKind, Surface};

/// The named strategies, in report order. Loop 2 adds the placement family
/// (RESIDENT) and the STREAM family.
pub(crate) const STRATEGIES: [&str; 10] = [
    "truncate",
    "fifo-fold",
    "recoverable-fold",
    "free-file",
    "engine-board",
    "canon-placement",
    "board-in-prefix",
    "keyframe-in-tail",
    "stream-truncate",
    "stream-fifo",
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
    /// window is always visible; nothing else is. A query may come
    /// mid-session (loop 2); a strategy holding the capabilities may edit
    /// or fetch here, and the window it leaves is the one read.
    fn on_query(&mut self, query: &Query, ctx: &mut Ctx<'_>) -> Vec<u32> {
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
        "canon-placement" => Some(Box::new(CanonPlacement::new(Layout::Canon))),
        "board-in-prefix" => Some(Box::new(CanonPlacement::new(Layout::BoardInPrefix))),
        "keyframe-in-tail" => Some(Box::new(CanonPlacement::new(Layout::KeyframeInTail))),
        "stream-truncate" => Some(Box::new(StreamBoard::new(
            "stream-truncate",
            Harness::Truncate,
            STREAM_DIALS,
        ))),
        "stream-fifo" => Some(Box::new(StreamBoard::new(
            "stream-fifo",
            Harness::FifoFold,
            STREAM_DIALS,
        ))),
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
            Verb::Read { .. } | Verb::Changed { .. } => None,
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

    fn on_query(&mut self, query: &Query, ctx: &mut Ctx<'_>) -> Vec<u32> {
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
        let Some(call) = board_call(verb) else {
            return;
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

    fn on_query(&mut self, query: &Query, ctx: &mut Ctx<'_>) -> Vec<u32> {
        ctx.grep_refs(&query.key)
    }
}

/// The typed `board.*` call an agent emits for a sketchpad move. Resource
/// events are the session's own tool calls, not context management.
fn board_call(verb: &Verb) -> Option<String> {
    match verb {
        Verb::BoardInit(grid) => {
            let digits: String = grid.iter().map(|d| char::from(b'0' + d)).collect();
            Some(format!("board.init {digits}"))
        }
        Verb::SetCell { cell, digit, .. } => Some(format!(
            "board.set r{}c{}={digit}",
            cell / 9 + 1,
            cell % 9 + 1
        )),
        Verb::Read { .. } | Verb::Changed { .. } => None,
    }
}

/// Where the placement family writes its two harness renders.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Layout {
    /// ARCH-0067 §2: keyframe on the cached prefix, board on the tail.
    Canon,
    /// Wrong-placement control: the board on the prefix too, so each
    /// turn's re-render rewrites the prefix and everything after it.
    BoardInPrefix,
    /// Wrong-placement control: the keyframe on the tail, re-emitted with
    /// the board every turn.
    KeyframeInTail,
}

impl Layout {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Canon => "canon-placement",
            Self::BoardInPrefix => "board-in-prefix",
            Self::KeyframeInTail => "keyframe-in-tail",
        }
    }

    const fn keyframe(self) -> Place {
        match self {
            Self::KeyframeInTail => Place::Tail,
            _ => Place::Prefix,
        }
    }

    const fn board(self) -> Place {
        match self {
            Self::BoardInPrefix => Place::Prefix,
            _ => Place::Tail,
        }
    }
}

/// The prefix inventory's budget in tokens (a strategy knob, tuned on dev:
/// 4096 holds the relink arm's whole working set on every dev seed and
/// beats 2048 on re-prefill, fetched and edit tokens; 8192 changes
/// nothing). Looser than the board's, far under the window's.
pub(crate) const INVENTORY_TOK: u64 = 4_096;

/// What the strategy knows about one resource, from typed events only.
#[derive(Clone, Debug, Default)]
struct Res {
    /// The newest version the session knows exists.
    current: u32,
    /// The newest version whose body the session was served.
    served: u32,
    uses: u32,
    last: usize,
    /// The stream turn whose span held the newest body the stream showed,
    /// with that body's version.
    body_turn: Option<(usize, u32)>,
    /// The span holding the newest body the session saw (a stream turn or
    /// a fetch), with its version.
    live: Option<(u64, u32)>,
    /// The version resident on the prefix inventory, if any.
    resident: Option<u32>,
}

fn not_log(span: &Span) -> bool {
    span.surface() != Surface::Log
}

/// The placement family (OF-546 loop 2, ARCH-0067 §2). An epoch closes when
/// the window would exceed its budget (or every `every` turns): the oldest
/// log spans fold into harness-minted references (byte-exact, never
/// deleted), the prefix inventory is re-selected (pinned + most-used +
/// recent within [`INVENTORY_TOK`]; the harness fetches the resident bodies
/// at their current version, every other resource gets a link row), and the
/// keyframe (the reference index) is rewritten. Within an epoch the prefix
/// never changes. Every turn the board is re-rendered from typed state
/// through `render_board_block`. A need for a resource whose current body is
/// neither live in the log nor resident is met with one `get`: the engine
/// read set's changed line is what flags a resident copy as superseded.
/// The three layouts differ only in where the keyframe and the board land.
pub(crate) struct CanonPlacement {
    layout: Layout,
    policy: Box<dyn Policy>,
    /// Force an epoch close every this many turns (`None`: only when the
    /// window would exceed its budget).
    every: Option<u32>,
    inventory_tok: u64,
    sketch: Sketch,
    epoch: u64,
    since_close: u32,
    /// Every reference minted, with the epoch that minted it.
    minted: Vec<(u32, u64)>,
    res: BTreeMap<String, Res>,
    read_set: SessionReadSet,
    tail_tok: u64,
}

impl CanonPlacement {
    pub(crate) fn new(layout: Layout) -> Self {
        Self::with(layout, Box::new(OldestFirst), None, INVENTORY_TOK)
    }

    pub(crate) fn with(
        layout: Layout,
        policy: Box<dyn Policy>,
        every: Option<u32>,
        inventory_tok: u64,
    ) -> Self {
        Self {
            layout,
            policy,
            every,
            inventory_tok,
            sketch: Sketch::default(),
            epoch: 0,
            since_close: 0,
            minted: Vec::new(),
            res: BTreeMap::new(),
            read_set: SessionReadSet::default(),
            tail_tok: 0,
        }
    }

    /// Epochs closed so far.
    #[cfg(test)]
    pub(crate) const fn epochs(&self) -> u64 {
        self.epoch
    }

    fn serve(&mut self, name: &str, version: u32) {
        if let Some(r) = self.res.get_mut(name) {
            r.served = r.served.max(version);
        }
        self.read_set.served(name, ServedLifecycle::Active);
        if name.starts_with("skill:") {
            self.read_set.loaded_skill(name, format!("v{version}"));
        }
    }

    fn live_now(r: &Res, ctx: &Ctx<'_>) -> bool {
        r.live
            .is_some_and(|(id, v)| v == r.current && ctx.index_of(id).is_some())
    }

    /// Where the current body is, typed: resident, live, inside a
    /// reference (found by the reference's typed turn range), or only in
    /// the environment.
    fn held(r: &Res, ctx: &Ctx<'_>) -> Held {
        if r.resident == Some(r.current) {
            return Held::Prefix;
        }
        if Self::live_now(r, ctx) {
            return Held::Log;
        }
        if let Some((t, v)) = r.body_turn
            && v == r.current
            && let Some(m) = ctx.ref_metas().iter().find(|m| {
                m.turns
                    .is_some_and(|(a, b)| a as usize <= t && t <= b as usize)
            })
        {
            return Held::Ref(m.id);
        }
        Held::Get
    }

    fn rows(&self, ctx: &Ctx<'_>) -> Vec<ResRow> {
        self.res
            .iter()
            .map(|(name, r)| ResRow {
                name: name.clone(),
                current: r.current,
                served: r.served,
                held: Self::held(r, ctx),
            })
            .collect()
    }

    /// Selects the resident set: the most-used, then most recent resources
    /// whose current bodies fit [`Self::inventory_tok`]. Returns the names
    /// and the tokens their bodies take.
    fn select(&self, ctx: &Ctx<'_>) -> (Vec<String>, u64) {
        let mut ranked: Vec<(&String, &Res)> = self.res.iter().collect();
        ranked.sort_by(|(an, a), (bn, b)| {
            b.uses
                .cmp(&a.uses)
                .then(b.last.cmp(&a.last))
                .then(an.cmp(bn))
        });
        let mut resident = Vec::new();
        let mut used = 0;
        for (name, _) in ranked {
            let cost = ctx.fetch_cost(name).unwrap_or(u64::MAX);
            if used + cost <= self.inventory_tok {
                used += cost;
                resident.push(name.clone());
            }
        }
        (resident, used)
    }

    /// Places the prefix inventory: `resident` bodies (fetched by the
    /// harness at their current version) and a link row for every other
    /// resource.
    fn relink(&mut self, ctx: &mut Ctx<'_>, resident: &[String]) {
        if self.res.is_empty() {
            return;
        }
        let links: Vec<(String, u32, Link)> = self
            .res
            .iter()
            .filter(|(name, _)| !resident.contains(name))
            .map(|(name, r)| {
                let link = match Self::held(r, ctx) {
                    Held::Ref(id) => Link::Ref(id),
                    _ => Link::Get,
                };
                (name.clone(), r.current, link)
            })
            .collect();
        let held = ctx.place_inventory(resident, &links);
        for r in self.res.values_mut() {
            r.resident = None;
        }
        for (name, version) in held {
            if let Some(r) = self.res.get_mut(&name) {
                r.resident = Some(version);
                r.current = r.current.max(version);
            }
            self.serve(&name, version);
        }
    }

    /// Closes an epoch: fold the oldest log spans into references until the
    /// window (plus `tail` tokens about to be rendered and `extra` about to
    /// be fetched) sits at the low-water mark, re-select the inventory,
    /// rewrite the keyframe.
    fn close_epoch(&mut self, ctx: &mut Ctx<'_>, tail: u64, extra: u64) {
        self.epoch += 1;
        self.since_close = 0;
        ctx.release_reloads();
        // Reserve only what the re-selected inventory adds over the current
        // one: its bodies plus one row per resource.
        let (resident, bodies) = self.select(ctx);
        let growth = if self.res.is_empty() {
            0
        } else {
            (bodies + 16 * self.res.len() as u64 + 32)
                .saturating_sub(ctx.kind_tok(SpanKind::Inventory))
        };
        let need = ctx.tokens() + tail + extra + growth;
        if need > ctx.low_water() {
            let mut minted = Vec::new();
            move_out(
                ctx,
                self.policy.as_mut(),
                &not_log,
                need - ctx.low_water(),
                |ctx, r| {
                    if let Some(id) = ctx.fold_to_keyframe(r) {
                        minted.push(id);
                    }
                },
            );
            minted.sort_unstable();
            self.minted
                .extend(minted.into_iter().map(|id| (id, self.epoch)));
        }
        self.relink(ctx, &resident);
        if self.layout.keyframe() == Place::Prefix {
            ctx.place_keyframe(Place::Prefix, self.epoch, &self.minted);
        }
    }

    /// Renders this turn's tail (and, for the prefix-board control, the
    /// prefix board) from typed state.
    fn render(&mut self, ctx: &mut Ctx<'_>) {
        let rows = self.rows(ctx);
        let mut tail = 0;
        if self.layout.keyframe() == Place::Tail && self.epoch > 0 {
            tail += ctx.place_keyframe(Place::Tail, self.epoch, &self.minted);
        }
        let state = CanonBoard {
            epoch: self.epoch,
            turn: ctx.turn(),
            sketch: self.sketch.typed(),
            resources: &rows,
            read_set: &self.read_set,
        };
        let board = ctx.place_board(self.layout.board(), &state);
        if self.layout.board() == Place::Tail {
            tail += board;
        }
        self.tail_tok = tail;
    }

    /// Meets a need for `name`: nothing when its current body is live or
    /// resident, else one `get` (closing an epoch first if the body would
    /// not fit).
    fn need(&mut self, name: &str, ctx: &mut Ctx<'_>) {
        let turn = ctx.turn();
        let Some(r) = self.res.get_mut(name) else {
            return;
        };
        r.uses += 1;
        r.last = turn;
        let r = r.clone();
        if r.resident == Some(r.current) || Self::live_now(&r, ctx) {
            return;
        }
        let cost = ctx.fetch_cost(name).unwrap_or(0);
        if ctx.tokens() + cost > ctx.budget() {
            self.close_epoch(ctx, 0, cost);
            if self
                .res
                .get(name)
                .is_some_and(|r| r.resident == Some(r.current))
            {
                return;
            }
        }
        if let Some((version, id)) = ctx.get(name) {
            if let Some(r) = self.res.get_mut(name) {
                r.live = Some((id, version));
                r.current = r.current.max(version);
            }
            self.serve(name, version);
        }
    }
}

impl Strategy for CanonPlacement {
    fn name(&self) -> &'static str {
        self.layout.name()
    }

    fn caps(&self) -> Caps {
        Caps {
            offload: true,
            board: true,
            prefix: true,
            get: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>) {
        match verb {
            Verb::Read { res, version } => {
                let turn = ctx.turn();
                let span = ctx.spans().last().map(Span::id);
                let r = self.res.entry(res.clone()).or_default();
                r.current = r.current.max(*version);
                r.uses += 1;
                r.last = turn;
                r.body_turn = Some((turn, *version));
                r.live = span.map(|id| (id, *version));
                self.serve(res, *version);
            }
            Verb::Changed { res, version } => {
                let r = self.res.entry(res.clone()).or_default();
                r.current = r.current.max(*version);
            }
            Verb::BoardInit(_) | Verb::SetCell { .. } => {
                if let Some(call) = board_call(verb) {
                    self.sketch.apply(verb);
                    ctx.charge_verb(&call);
                }
            }
        }
    }

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        self.since_close += 1;
        ctx.clear_tail();
        let forced = self.every.is_some_and(|k| self.since_close >= k);
        if forced || ctx.tokens() + self.tail_tok > ctx.budget() {
            self.close_epoch(ctx, self.tail_tok, 0);
        }
        self.render(ctx);
        if ctx.tokens() > ctx.budget() {
            ctx.clear_tail();
            self.close_epoch(ctx, self.tail_tok, 0);
            self.render(ctx);
        }
    }

    fn on_query(&mut self, query: &Query, ctx: &mut Ctx<'_>) -> Vec<u32> {
        if let Some(name) = query.key.strip_suffix('@')
            && self.res.contains_key(name)
        {
            self.need(name, ctx);
            return Vec::new();
        }
        self.read_within_budget(&query.key, ctx)
    }
}

impl CanonPlacement {
    /// The references holding `key`, read inside the window: all of them
    /// when they fit beside the live window; else an epoch closes first
    /// (the live log folds into references, byte-exact) and the matching
    /// references are taken newest first while they fit. A model call never
    /// reads past its window, so a query whose pages cannot all fit reads
    /// the newest ones.
    fn read_within_budget(&mut self, key: &str, ctx: &mut Ctx<'_>) -> Vec<u32> {
        let size = |ctx: &Ctx<'_>, ids: &[u32]| -> u64 {
            let metas = ctx.ref_metas();
            ids.iter()
                .filter_map(|id| metas.iter().find(|m| m.id == *id))
                .map(|m| m.tok)
                .sum()
        };
        let matching = ctx.grep_refs(key);
        let need = size(ctx, &matching);
        if ctx.tokens() + need <= ctx.budget() {
            return matching;
        }
        self.close_epoch(ctx, 0, need);
        let metas = ctx.ref_metas();
        let mut room = ctx.budget().saturating_sub(ctx.tokens());
        let mut picked = Vec::new();
        // Newest stream turns first: a reference made only of reloaded
        // copies carries no turn and goes last, whatever its id.
        let mut order = ctx.grep_refs(key);
        order.sort_by_key(|id| {
            std::cmp::Reverse(
                metas
                    .iter()
                    .find(|m| m.id == *id)
                    .and_then(|m| m.turns)
                    .map(|(_, last)| last),
            )
        });
        for id in order {
            let tok = metas
                .iter()
                .find(|m| m.id == id)
                .map_or(u64::MAX, |m| m.tok);
            if tok <= room {
                room -= tok;
                picked.push(id);
            }
        }
        picked
    }
}

/// The foreign harness a STREAM board rides in: it owns the window and
/// compacts on its own schedule (deliverable 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Harness {
    /// Drops the oldest tool results once the window crosses its budget.
    Truncate,
    /// Folds the oldest tool results into a fixed lossy stub.
    FifoFold,
}

/// The STREAM dials.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Dials {
    /// A keyframe every this many turns (`None`: only when forced).
    pub(crate) keyframe_every: Option<u32>,
    /// Fold the deltas sent since the last keyframe into a new keyframe once
    /// they pass this many tokens (`None`: never).
    pub(crate) fold_over: Option<u64>,
    /// A keyframe once this many log tokens (tool results and frames) have
    /// arrived since the last one (`None`: never). The quantity a foreign
    /// compaction eats is log tokens, not turns.
    pub(crate) keyframe_after_tok: Option<u64>,
    /// The agent calls `board.refresh` after each compaction of its harness;
    /// the keyframe rides the next tool result.
    pub(crate) refresh: bool,
}

/// Default dials, tuned on dev with `--stream-sweep` over all arms: the
/// cheapest setting whose board was never wrong on any arm, on both
/// harnesses (a keyframe once 16,384 log tokens arrived since the last; no
/// turn interval, no delta fold, no refresh, which it never needed). A
/// keyframe every 100 turns, the earlier default, broke on every arm whose
/// turns average 300 tokens or more.
pub(crate) const STREAM_DIALS: Dials = Dials {
    keyframe_every: None,
    fold_over: None,
    keyframe_after_tok: Some(16_384),
    refresh: false,
};

#[derive(Clone, Debug, Default)]
struct StreamRes {
    current: u32,
    served: u32,
    /// The newest body the agent saw, by span, with its version.
    live: Option<(u64, u32)>,
}

/// The STREAM board family (ARCH-0067 §5, deliverable 4): a foreign harness
/// owns the context and compacts it its own way; Oneiron never renders into
/// it except as frames. Each turn the engine builds the board from typed
/// state (the same state the RESIDENT board renders) and sends, inside this
/// turn's tool result, a keyframe (`BoardSnapshot::as_keyframe`: the whole
/// board through `render_board_block`, a new epoch) when one is due, else a
/// delta (`BoardSnapshot::frame_since`), coalesced through the engine's
/// `CarrierCoalesceBuffer`. A keyframe is due on the first turn, every
/// `keyframe_every` turns, once the deltas since the last keyframe pass
/// `fold_over` tokens, and on the turn after a refresh. The foreign model
/// holds the board it rebuilds from the frames still in its window, by the
/// engine's own consumer law (`AppliedStreamState`: latest epoch wins, a
/// keyframe replaces, deltas apply inside their epoch), and acts on that.
/// It has no Oneiron references; it can `get` a resource body.
pub(crate) struct StreamBoard {
    name: &'static str,
    harness: Harness,
    dials: Dials,
    policy: Box<dyn Policy>,
    sketch: Sketch,
    res: BTreeMap<String, StreamRes>,
    read_set: SessionReadSet,
    epoch: u64,
    last: Option<BoardSnapshot>,
    since_key: u32,
    delta_tok: u64,
    /// Log tokens since the last keyframe.
    since_tok: u64,
    refresh_pending: bool,
    /// The connection's carrier: frames ride the next tool response,
    /// deltas superseding within a key.
    carrier: CarrierCoalesceBuffer,
}

impl StreamBoard {
    pub(crate) fn new(name: &'static str, harness: Harness, dials: Dials) -> Self {
        Self {
            name,
            harness,
            dials,
            policy: Box::new(OldestFirst),
            sketch: Sketch::default(),
            res: BTreeMap::new(),
            read_set: SessionReadSet::default(),
            epoch: 0,
            last: None,
            since_key: 0,
            delta_tok: 0,
            since_tok: 0,
            refresh_pending: false,
            carrier: CarrierCoalesceBuffer::default(),
        }
    }

    fn live(r: &StreamRes, ctx: &Ctx<'_>) -> Option<u32> {
        r.live
            .filter(|(id, _)| ctx.index_of(*id).is_some())
            .map(|(_, v)| v)
    }

    /// The board as typed rows (one key per row) and as the engine's typed
    /// render state; the two are projections of the same state.
    fn board(&self, ctx: &Ctx<'_>) -> (BTreeMap<String, String>, Vec<ResRow>) {
        let mut rows = BTreeMap::new();
        rows.insert("a.now".to_owned(), format!("turn: {}", ctx.turn()));
        if let Some(lines) = self.sketch.snapshot() {
            for (i, line) in lines.into_iter().enumerate() {
                rows.insert(format!("b.sketch.{i}"), line);
            }
        }
        let mut res_rows = Vec::new();
        for (name, r) in &self.res {
            let held = if Self::live(r, ctx) == Some(r.current) {
                Held::Log
            } else {
                Held::Get
            };
            let at = if held == Held::Log { "log" } else { "get" };
            rows.insert(
                format!("c.res.{name}"),
                format!("{name}: v{},{at}", r.current),
            );
            if r.current > r.served {
                rows.insert(
                    format!("e.changed.{name}"),
                    format!("{name}: superseded:v{}", r.current),
                );
            }
            res_rows.push(ResRow {
                name: name.clone(),
                current: r.current,
                served: r.served,
                held,
            });
        }
        let skills = SkillsSection::project(&[], &self.read_set);
        if self.read_set.loaded_skills().next().is_some() {
            rows.insert("d.skills".to_owned(), skills.loaded);
        }
        (rows, res_rows)
    }

    /// The foreign harness's own compaction: frees `must_free` tokens of the
    /// oldest tool results. Returns whether it compacted.
    fn compact(&mut self, ctx: &mut Ctx<'_>, must_free: u64) -> bool {
        let before = ctx.tokens();
        let harness = self.harness;
        move_out(
            ctx,
            self.policy.as_mut(),
            &|_| false,
            must_free,
            |ctx, r| {
                if harness == Harness::Truncate {
                    ctx.drop_spans(r);
                } else {
                    let stub = lossy_summary(&ctx.spans()[r.clone()]);
                    ctx.fold_lossy(r, stub);
                }
            },
        );
        ctx.tokens() < before
    }

    fn after_compaction(&mut self, ctx: &mut Ctx<'_>) {
        if self.dials.refresh {
            ctx.board_refresh();
            self.refresh_pending = true;
        }
    }

    /// The version the agent's board says is current.
    fn view_version(ctx: &mut Ctx<'_>, name: &str) -> Option<u32> {
        let view = ctx.board_view()?;
        let line = view.get(&format!("c.res.{name}"))?;
        line.strip_prefix(name)?
            .strip_prefix(": v")?
            .split(',')
            .next()?
            .parse()
            .ok()
    }
}

impl Strategy for StreamBoard {
    fn name(&self) -> &'static str {
        self.name
    }

    fn caps(&self) -> Caps {
        Caps {
            drop: self.harness == Harness::Truncate,
            fold_lossy: self.harness == Harness::FifoFold,
            board: true,
            get: true,
            stream: true,
            ..Caps::default()
        }
    }

    fn on_verb(&mut self, verb: &Verb, ctx: &mut Ctx<'_>) {
        match verb {
            Verb::Read { res, version } => {
                let span = ctx.spans().last().map(Span::id);
                let r = self.res.entry(res.clone()).or_default();
                r.current = r.current.max(*version);
                r.served = r.served.max(*version);
                r.live = span.map(|id| (id, *version));
                self.read_set.served(res, ServedLifecycle::Active);
                if res.starts_with("skill:") {
                    self.read_set.loaded_skill(res, format!("v{version}"));
                }
            }
            Verb::Changed { res, version } => {
                let r = self.res.entry(res.clone()).or_default();
                r.current = r.current.max(*version);
            }
            Verb::BoardInit(_) | Verb::SetCell { .. } => {
                if let Some(call) = board_call(verb) {
                    self.sketch.apply(verb);
                    ctx.charge_verb(&call);
                }
            }
        }
    }

    fn on_turn(&mut self, ctx: &mut Ctx<'_>) {
        self.since_key += 1;
        self.since_tok += ctx.spans().last().map_or(0, Span::tok);
        let (rows, res_rows) = self.board(ctx);
        let mut due = self.last.is_none()
            || self.refresh_pending
            || self
                .dials
                .keyframe_every
                .is_some_and(|k| self.since_key >= k)
            || self.dials.fold_over.is_some_and(|f| self.delta_tok >= f)
            || self
                .dials
                .keyframe_after_tok
                .is_some_and(|t| self.since_tok >= t);
        let mut snapshot = BoardSnapshot {
            epoch: self.epoch,
            keyframe: String::new(),
            rows: rows.clone(),
        };
        let mut frame = None;
        if !due {
            // A delta cannot remove a row: the engine answers that with a
            // keyframe, which opens a new epoch here.
            match snapshot.frame_since(self.last.as_ref()) {
                Some(f) if matches!(f.kind, FrameKind::Keyframe(_)) => due = true,
                other => frame = other,
            }
        }
        if due {
            self.epoch += 1;
            let state = CanonBoard {
                epoch: self.epoch,
                turn: ctx.turn(),
                sketch: self.sketch.typed(),
                resources: &res_rows,
                read_set: &self.read_set,
            };
            snapshot.epoch = self.epoch;
            snapshot.keyframe = match super::board::render_canon(&state) {
                Ok(text) => text,
                Err(_) => {
                    ctx.fail("engine board render");
                    String::new()
                }
            };
            frame = Some(snapshot.as_keyframe());
        }
        if let Some(frame) = frame {
            self.carrier.push(frame);
        }
        let frame = self.carrier.drain();
        match frame.as_ref().map(|f| &f.kind) {
            Some(FrameKind::Keyframe(_)) => {
                self.since_key = 0;
                self.delta_tok = 0;
                self.since_tok = 0;
            }
            Some(FrameKind::Delta(rows)) => {
                self.delta_tok += rows
                    .iter()
                    .map(|r| super::window::tokens(&format!("{} = {}\n", r.key, r.line)))
                    .sum::<u64>();
            }
            None => {}
        }
        ctx.emit_frame(rows, frame);
        self.last = Some(snapshot);
        self.refresh_pending = false;
        if ctx.tokens() > ctx.budget() {
            let must = ctx.tokens() - ctx.low_water();
            if self.compact(ctx, must) {
                self.after_compaction(ctx);
            }
        }
    }

    /// A need is met from the body the agent's board says is current when
    /// it is live, from whatever body is live when the agent holds no board
    /// (it cannot tell a stale copy), else with one `get`. Nothing else is
    /// restorable: the foreign harness keeps no references.
    fn on_query(&mut self, query: &Query, ctx: &mut Ctx<'_>) -> Vec<u32> {
        let Some(name) = query.key.strip_suffix('@') else {
            return Vec::new();
        };
        let Some(r) = self.res.get(name).cloned() else {
            return Vec::new();
        };
        let seen = Self::view_version(ctx, name);
        let live = Self::live(&r, ctx);
        match (seen, live) {
            (Some(v), Some(l)) if v == l => return Vec::new(),
            (None, Some(_)) => return Vec::new(),
            _ => {}
        }
        let cost = ctx.fetch_cost(name).unwrap_or(0);
        if ctx.tokens() + cost > ctx.budget() {
            let must = ctx.tokens() + cost - ctx.low_water();
            if self.compact(ctx, must) {
                self.after_compaction(ctx);
            }
        }
        if let Some((version, id)) = ctx.get(name)
            && let Some(r) = self.res.get_mut(name)
        {
            r.live = Some((id, version));
            r.served = r.served.max(version);
            r.current = r.current.max(version);
            self.read_set.served(name, ServedLifecycle::Active);
        }
        Vec::new()
    }
}
