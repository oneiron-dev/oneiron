//! `ctx-arms` — the OF-546 context-management bench arms.
//!
//! Four deterministic arms rebuilt native from CLM's ContextBench (needle
//! retention, sketchpad, KV offload-and-recall, log triage) measure how a
//! context-management strategy keeps, edits, offloads and restores a live
//! window under rising pressure. Nothing here calls a model.
//!
//! ```text
//! oneiron-bench ctx-arms --report --split heldout|dev [--arm NAME]
//!                        [--strategy NAME] [--budget 32768]
//! ```
//!
//! Every (arm, strategy) cell reports score, exact-restore rate, peak and
//! mean live-window tokens, edit tokens the strategy decoded, re-prefill
//! tokens (everything from the first edited cached position to the end of
//! the window, per model call: the prefix-cache loss OF-263 does not price),
//! and elapsed ms. Re-prefill is a bench-local column: the BEAM
//! `CostComponentReport` is `pub(super)` inside `beam/` with struct-literal
//! construction sites across the BEAM reports, so it is not extended here.
//!
//! Tune on `dev` only; the goal reads `heldout` only. Seeds, generators,
//! scorers and the tokenizer stand-in are fixed in code.
//!
//! Loop 2 adds the two-surface window (cached prefix, append-only log,
//! dynamic tail), a `prefix_hit_rate` column (tokens served from an
//! unchanged cached prefix over all prompt tokens, summed over the turns),
//! the placement family (canon-placement and its two wrong-placement
//! controls) and two arms (relink-after-compaction, multi-epoch) whose
//! queries may come mid-session.

mod arms;
mod arms_epoch;
mod board;
mod strategies;
mod window;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::process::ExitCode;
use std::time::Instant;

use arms::{ARMS, Arm, Episode, Score};
use arms_epoch::Extra;
use strategies::{STRATEGIES, Strategy};
use window::{Audit, Caps, Ctx, Ledger, RefStore, SpanKind, TOKENIZER, Window};

pub(crate) const DEV_SEEDS: RangeInclusive<u64> = 1..=20;
pub(crate) const HELDOUT_SEEDS: RangeInclusive<u64> = 1001..=1020;
pub(crate) const DEFAULT_BUDGET: u64 = 32_768;

/// Eviction hysteresis: once over budget, shrink to this share of it. A
/// strategy knob, tuned on dev only.
const LOW_WATER_PERCENT: u64 = 75;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Split {
    Dev,
    Heldout,
}

impl Split {
    const fn seeds(self) -> RangeInclusive<u64> {
        match self {
            Self::Dev => DEV_SEEDS,
            Self::Heldout => HELDOUT_SEEDS,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Heldout => "heldout",
        }
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::Dev => "CTX-DEV",
            Self::Heldout => "CTX-HELDOUT",
        }
    }
}

struct Options {
    split: Split,
    arm: Option<Arm>,
    strategy: Option<String>,
    budget: u64,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        split: Split::Heldout,
        arm: None,
        strategy: None,
        budget: DEFAULT_BUDGET,
    };
    let mut report = false;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--report" => report = true,
            "--split" => {
                opts.split = match value()?.as_str() {
                    "dev" => Split::Dev,
                    "heldout" => Split::Heldout,
                    other => return Err(format!("--split is dev|heldout, got {other}")),
                }
            }
            "--arm" => {
                let name = value()?;
                opts.arm = Some(Arm::parse(name).ok_or_else(|| format!("unknown arm {name}"))?);
            }
            "--strategy" => {
                let name = value()?;
                if !STRATEGIES.contains(&name.as_str()) {
                    return Err(format!("unknown strategy {name}"));
                }
                opts.strategy = Some(name.clone());
            }
            "--budget" => {
                opts.budget = value()?
                    .parse()
                    .ok()
                    .filter(|b| *b > 0)
                    .ok_or("--budget is a positive token count")?;
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }
    if report {
        Ok(opts)
    } else {
        Err("nothing to do: pass --report".to_owned())
    }
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    match parse(args) {
        Ok(opts) => {
            report(&opts);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ctx-arms: {e}");
            eprintln!(
                "usage: oneiron-bench ctx-arms --report --split heldout|dev \
                 [--arm NAME] [--strategy NAME] [--budget 32768]"
            );
            ExitCode::FAILURE
        }
    }
}

/// One episode's measurements.
#[derive(Clone, Debug, Default)]
pub(crate) struct EpisodeResult {
    pub(crate) score: Score,
    pub(crate) audit: Audit,
    /// A reference failed to restore byte-exactly (at query time or audit).
    pub(crate) restore_fail: bool,
    pub(crate) peak: u64,
    pub(crate) mean: f64,
    pub(crate) edit_tok: u64,
    pub(crate) reprefill_tok: u64,
    /// Tokens restored from references at query time.
    pub(crate) restore_tok: u64,
    /// Largest context the reader received for one query: the live window
    /// plus every page restored for it.
    pub(crate) read_peak: u64,
    /// Model calls that saw a window over budget.
    pub(crate) over_budget: u64,
    pub(crate) violations: Vec<&'static str>,
    /// Prompt tokens served from an unchanged cached prefix, summed over
    /// the turns' model calls.
    pub(crate) served_tok: u64,
    /// Every prompt token of those calls.
    pub(crate) prompt_tok: u64,
    /// The strict surface reading of the same (see `window::Call::frozen`).
    pub(crate) frozen_tok: u64,
    /// Resource bodies the harness fetched from the environment.
    pub(crate) fetch_tok: u64,
    /// Stale answers and per-bucket tallies (loop-2 arms).
    pub(crate) extra: Extra,
}

impl EpisodeResult {
    #[cfg(test)]
    pub(crate) fn hit_rate(&self) -> f64 {
        self.served_tok as f64 / self.prompt_tok.max(1) as f64
    }
}

pub(crate) fn low_water(budget: u64) -> u64 {
    budget * LOW_WATER_PERCENT / 100
}

pub(crate) fn run_episode(ep: &Episode, strategy: &mut dyn Strategy, budget: u64) -> EpisodeResult {
    run_episode_with(ep, strategy, budget, |_| {})
}

/// The harness state one episode runs on.
struct Run<'e> {
    ep: &'e Episode,
    win: Window,
    refs: RefStore,
    led: Ledger,
    caps: Caps,
    budget: u64,
    res: EpisodeResult,
    answers: Vec<String>,
}

impl Run<'_> {
    /// Asks query `i` at stream turn `turn`: the strategy may edit or fetch
    /// (mid-session) and names references to restore; the fixed reader
    /// answers from the restores plus the window it left. A mid-session
    /// query is a model call, so its window counts against the budget.
    fn ask(&mut self, strategy: &mut dyn Strategy, i: usize, turn: usize) {
        let q = &self.ep.queries[i];
        let mut ids = {
            let mut ctx = Ctx::new(
                &mut self.win,
                &mut self.refs,
                &mut self.led,
                self.caps,
                self.budget,
                low_water(self.budget),
            )
            .with_env(&self.ep.env, turn);
            strategy.on_query(q, &mut ctx)
        };
        if !self.win.ordered() {
            self.led.violations.push("surface order");
        }
        if self.ep.ask_at[i].is_some() {
            let live = self.win.total();
            self.res.peak = self.res.peak.max(live);
            self.res.over_budget += u64::from(live > self.budget);
        }
        ids.sort_unstable();
        ids.dedup();
        let mut chunks: Vec<&str> = Vec::new();
        let mut read = self.win.total();
        for id in ids {
            match self.refs.restore(id) {
                Ok(spans) => {
                    let tok = self.refs.meta(id).map_or(0, |m| m.tok);
                    self.res.restore_tok += tok;
                    read += tok;
                    chunks.extend(spans.into_iter().map(|(_, text)| text));
                }
                Err(_) => self.res.restore_fail = true,
            }
        }
        self.res.read_peak = self.res.read_peak.max(read);
        chunks.extend(self.win.spans().iter().map(window::Span::text));
        self.answers[i] = arms::read(self.ep.arm, q, &chunks);
    }
}

/// Streams the episode through the strategy, asking each mid-session query
/// right after its turn's model call, then asks the rest. `tamper` runs
/// between the stream and the end-of-session queries (tests corrupt a
/// reference there to prove the arm fails).
pub(crate) fn run_episode_with(
    ep: &Episode,
    strategy: &mut dyn Strategy,
    budget: u64,
    tamper: impl FnOnce(&mut RefStore),
) -> EpisodeResult {
    let mut run = Run {
        ep,
        win: Window::default(),
        refs: RefStore::default(),
        led: Ledger::default(),
        caps: strategy.caps(),
        budget,
        res: EpisodeResult::default(),
        answers: vec![String::new(); ep.queries.len()],
    };
    let mut mid: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, at) in ep.ask_at.iter().enumerate() {
        if let Some(t) = at {
            mid.entry(*t).or_default().push(i);
        }
    }
    let mut window_sum = 0_u64;
    for (n, turn) in ep.turns.iter().enumerate() {
        run.win.push(SpanKind::Turn(n as u32), turn.text.clone());
        {
            let mut ctx = Ctx::new(
                &mut run.win,
                &mut run.refs,
                &mut run.led,
                run.caps,
                budget,
                low_water(budget),
            )
            .with_env(&ep.env, n);
            if let Some(verb) = &turn.verb {
                strategy.on_verb(verb, &mut ctx);
            }
            strategy.on_turn(&mut ctx);
        }
        if !run.win.ordered() {
            run.led.violations.push("surface order");
        }
        let call = run.win.call();
        run.res.reprefill_tok += call.reprefill;
        run.res.served_tok += call.served;
        run.res.prompt_tok += call.total;
        run.res.frozen_tok += call.frozen;
        let live = run.win.total();
        run.res.peak = run.res.peak.max(live);
        window_sum += live;
        run.res.over_budget += u64::from(live > budget);
        for &i in mid.get(&n).map_or(&[][..], Vec::as_slice) {
            run.ask(strategy, i, n);
        }
    }
    run.res.mean = window_sum as f64 / ep.turns.len().max(1) as f64;
    run.res.read_peak = run.res.read_peak.max(run.res.peak);
    tamper(&mut run.refs);
    let last = ep.turns.len().saturating_sub(1);
    for i in 0..ep.queries.len() {
        if ep.ask_at[i].is_none() {
            run.ask(strategy, i, last);
        }
    }

    let Run {
        refs,
        led,
        mut res,
        answers,
        ..
    } = run;
    res.audit = led.audit(&refs);
    res.restore_fail |= res.audit.broken_reference();
    let (score, extra) = ep.score_full(&answers);
    res.score = score;
    res.extra = extra;
    // OF-546 note 3 / OF-190: a reference that cannot restore its span
    // byte-exactly fails the offload arm by construction, and (loop 2) the
    // relink and multi-epoch arms, whose answers ride the same references.
    if matches!(ep.arm, Arm::KvOffload | Arm::Relink | Arm::MultiEpoch) && res.restore_fail {
        res.score.value = 0.0;
        res.score.correct = 0;
    }
    res.edit_tok = led.edit_tok;
    res.fetch_tok = led.fetch_tok;
    res.violations = led.violations;
    res
}

/// One (arm, strategy) cell over a split.
#[derive(Default)]
pub(crate) struct Cell {
    ran: bool,
    episodes: u64,
    score_sum: f64,
    hallucinated: u64,
    exact: u64,
    departed: u64,
    peak: u64,
    mean_sum: f64,
    edit: u64,
    reprefill: u64,
    restore: u64,
    read_peak: u64,
    over_budget: u64,
    restore_fail: u64,
    violations: usize,
    elapsed_ms: f64,
    served: u64,
    prompt: u64,
    frozen: u64,
    fetch: u64,
    stale: u64,
    buckets: Vec<(u64, u64)>,
}

impl Cell {
    pub(crate) fn add(&mut self, r: &EpisodeResult, elapsed_ms: f64) {
        self.ran = true;
        self.episodes += 1;
        self.score_sum += r.score.value;
        self.hallucinated += u64::from(r.score.hallucinated);
        self.exact += r.audit.exact;
        self.departed += r.audit.departed;
        self.peak = self.peak.max(r.peak);
        self.mean_sum += r.mean;
        self.edit += r.edit_tok;
        self.reprefill += r.reprefill_tok;
        self.restore += r.restore_tok;
        self.read_peak = self.read_peak.max(r.read_peak);
        self.over_budget += r.over_budget;
        self.restore_fail += u64::from(r.restore_fail);
        self.violations += r.violations.len();
        self.elapsed_ms += elapsed_ms;
        self.served += r.served_tok;
        self.prompt += r.prompt_tok;
        self.frozen += r.frozen_tok;
        self.fetch += r.fetch_tok;
        self.stale += u64::from(r.extra.stale);
        if self.buckets.len() < r.extra.buckets.len() {
            self.buckets.resize(r.extra.buckets.len(), (0, 0));
        }
        for (cell, (ok, n)) in self.buckets.iter_mut().zip(&r.extra.buckets) {
            cell.0 += u64::from(*ok);
            cell.1 += u64::from(*n);
        }
    }

    /// Tokens served from an unchanged cached prefix over all prompt
    /// tokens, summed over every turn of every episode.
    pub(crate) fn hit_rate(&self) -> f64 {
        self.served as f64 / self.prompt.max(1) as f64
    }

    /// The strict surface reading: prefix-surface tokens on calls whose
    /// prefix surface was byte-identical to the previous call's, over all
    /// prompt tokens.
    pub(crate) fn frozen_rate(&self) -> f64 {
        self.frozen as f64 / self.prompt.max(1) as f64
    }

    /// Every episode ran, no operation was refused, and no model call saw a
    /// window over budget (an unmanaged window would read the whole stream).
    pub(crate) fn valid(&self, seeds: u64) -> bool {
        self.ran && self.episodes == seeds && self.violations == 0 && self.over_budget == 0
    }

    fn score(&self) -> f64 {
        self.score_sum / self.episodes.max(1) as f64
    }

    fn exact_restore(&self) -> f64 {
        if self.departed == 0 {
            1.0
        } else {
            self.exact as f64 / self.departed as f64
        }
    }

    fn per_episode(&self, total: u64) -> u64 {
        total / self.episodes.max(1)
    }
}

/// In-binary self-checks behind the summary line's `tests` field: every
/// generator is deterministic and distinct across seeds, the fixed reader
/// over the stream (up to each query's turn, plus for relink the needed
/// body as the environment holds it) answers every query exactly on every
/// seed, and the loop-2 arms hold their structural invariants (every relink
/// need post-compaction, every multi-epoch segment over budget). `cargo
/// test -p oneiron-bench` is run separately.
fn self_checks(seeds: &RangeInclusive<u64>) -> Result<(), String> {
    for arm in ARMS {
        let mut digests = std::collections::BTreeSet::new();
        for seed in seeds.clone() {
            let ep = Episode::generate(arm, seed);
            if ep.digest() != Episode::generate(arm, seed).digest() {
                return Err(format!(
                    "{} seed {seed}: generator not deterministic",
                    arm.name()
                ));
            }
            digests.insert(ep.digest());
            arms_epoch::check(&ep).map_err(|e| format!("{} seed {seed}: {e}", arm.name()))?;
            let answers = arms_epoch::oracle_answers(&ep);
            let score = ep.score_full(&answers).0;
            if score.correct != score.total {
                return Err(format!(
                    "{} seed {}: full-stream oracle {}/{}",
                    arm.name(),
                    ep.seed,
                    score.correct,
                    score.total
                ));
            }
        }
        if digests.len() as u64 != seeds.clone().count() as u64 {
            return Err(format!(
                "{}: two seeds generate the same episode",
                arm.name()
            ));
        }
    }
    Ok(())
}

fn report(opts: &Options) {
    let seeds = opts.split.seeds();
    let n_seeds = seeds.clone().count() as u64;
    let checks = self_checks(&seeds);
    println!(
        "CTX-ARMS OF-546 | split {} seeds {}..={} | budget {} tok | low-water {} tok",
        opts.split.name(),
        seeds.start(),
        seeds.end(),
        opts.budget,
        low_water(opts.budget)
    );
    println!("tokenizer: {TOKENIZER}");
    println!("re-prefill: bench-local column (beam CostComponentReport not extended)");
    println!(
        "policy hook: strategies::Policy (model-decided policies plug in there; none is called); default {}",
        strategies::Policy::name(&strategies::OldestFirst)
    );
    println!(
        "tests: in-binary self-checks (generator determinism, full-stream oracle exact on every seed): {}",
        checks
            .as_ref()
            .map_or_else(|e| format!("FAIL {e}"), |()| "pass".to_owned())
    );
    let stream: Vec<String> = ARMS
        .iter()
        .map(|&arm| {
            let total: u64 = seeds
                .clone()
                .map(|seed| {
                    let ep = Episode::generate(arm, seed);
                    ep.turns
                        .iter()
                        .map(|t| window::tokens(&t.text))
                        .sum::<u64>()
                })
                .sum();
            format!("{} {}", arm.name(), total / n_seeds.max(1))
        })
        .collect();
    println!(
        "stream tok/episode (turn text, mean): {}",
        stream.join(" | ")
    );
    println!(
        "columns: token columns are per-episode means; peak_tok (live window at a model call) and read_peak (window + all pages restored for one query) are maxima; \
         over, halluc, stale and rfail are totals over the split"
    );
    println!(
        "prefix_hit: tokens served from an unchanged cached prefix / all prompt tokens, summed over every turn's model call. \
         A call's prompt is prefix + log + tail; it is served from cache up to the first byte that differs from the previous call's prompt, \
         and never past where the previous call's dynamic tail began (the tail is never cached). fetch_tok: bodies the harness fetched from the environment"
    );
    println!(
        "frozen (CTX2 lines only): the strict surface reading. A call counts its prefix-surface tokens only when the prefix surface is \
         byte-identical to the previous call's; the append-only log never counts. Loop-1 strategies have no prefix surface, so they read 0"
    );
    println!(
        "{:<23} {:<16} {:>6} {:>9} {:>8} {:>8} {:>9} {:>13} {:>10} {:>11} {:>9} {:>8} {:>5} {:>6} {:>5} {:>5} {:>8}",
        "arm",
        "strategy",
        "score",
        "exact_rst",
        "peak_tok",
        "mean_tok",
        "edit_tok",
        "reprefill_tok",
        "prefix_hit",
        "restore_tok",
        "fetch_tok",
        "read_peak",
        "over",
        "halluc",
        "stale",
        "rfail",
        "ms"
    );

    let mut cells: Vec<(Arm, &str, Cell)> = Vec::new();
    for arm in ARMS {
        for name in STRATEGIES {
            let mut cell = Cell::default();
            let selected = opts.arm.is_none_or(|a| a == arm)
                && opts.strategy.as_deref().is_none_or(|s| s == name);
            if selected && strategies::build(name).is_some() {
                for seed in seeds.clone() {
                    let ep = Episode::generate(arm, seed);
                    let Some(mut strategy) = strategies::build(name) else {
                        break;
                    };
                    debug_assert_eq!(strategy.name(), name);
                    let start = Instant::now();
                    let r = run_episode(&ep, strategy.as_mut(), opts.budget);
                    cell.add(&r, start.elapsed().as_secs_f64() * 1000.0);
                }
            }
            print_cell(arm, name, &cell, selected);
            cells.push((arm, name, cell));
        }
    }

    let engine_cells = cells
        .iter()
        .filter(|(_, name, c)| {
            matches!(
                *name,
                "engine-board" | "canon-placement" | "board-in-prefix" | "keyframe-in-tail"
            ) && c.ran
        })
        .count();
    println!(
        "engine board render: {}",
        if engine_cells > 0 {
            format!(
                "RAN on {engine_cells} cell(s) via oneiron::context_board::render_board_block \
                 (typed state -> board; the placement family adds the engine SessionReadSet changed line and SKILLS section; \
                 zero oneiron-server plumbing)"
            )
        } else {
            "did not run (not selected)".to_owned()
        }
    );
    let valid = |c: &Cell| c.valid(n_seeds);
    let arms_scored = ARMS
        .iter()
        .filter(|a| cells.iter().any(|(arm, _, c)| arm == *a && valid(c)))
        .count();
    let strategies_scored = STRATEGIES
        .iter()
        .filter(|s| cells.iter().any(|(_, name, c)| name == *s && valid(c)))
        .count();
    let cells_valid = cells.iter().filter(|(_, _, c)| valid(c)).count();
    let n_cells = ARMS.len() * STRATEGIES.len();
    let tests = if checks.is_ok() { "pass" } else { "fail" };
    println!(
        "{} | arms {arms_scored}/{} | strategies {strategies_scored} | cells {cells_valid}/{n_cells} | tests {tests}",
        opts.split.tag(),
        ARMS.len()
    );
    println!(
        "CTX2-{} | arms {arms_scored}/{} | strategies {strategies_scored}/{} | cells {cells_valid}/{n_cells} | tests {tests}",
        opts.split.name().to_uppercase(),
        ARMS.len(),
        STRATEGIES.len()
    );
    for name in STRATEGIES {
        let per_arm: Vec<String> = cells
            .iter()
            .filter(|(_, s, c)| *s == name && c.ran)
            .map(|(arm, _, c)| {
                format!(
                    "{} {:.3} er {:.3} rp {} hit {:.3} frozen {:.3}{}",
                    arm.name(),
                    c.score(),
                    c.exact_restore(),
                    c.per_episode(c.reprefill),
                    c.hit_rate(),
                    c.frozen_rate(),
                    if valid(c) { "" } else { " INVALID" }
                )
            })
            .collect();
        if !per_arm.is_empty() {
            println!("CTX2-STRATEGY {name} | {}", per_arm.join(" | "));
        }
    }
    for (arm, name, c) in &cells {
        if !c.ran || c.buckets.is_empty() {
            continue;
        }
        let label = |b: usize| match arm {
            Arm::Relink => ["one-version", "rewritten", "external"]
                .get(b)
                .map_or_else(|| format!("k{b}"), |s| (*s).to_owned()),
            _ => format!("e{}", b + 1),
        };
        let parts: Vec<String> = c
            .buckets
            .iter()
            .enumerate()
            .map(|(b, (ok, n))| {
                format!(
                    "{} {:.3} ({ok}/{n})",
                    label(b),
                    *ok as f64 / (*n).max(1) as f64
                )
            })
            .collect();
        println!(
            "CTX2-BUCKETS {} {name} | {} | stale {}",
            arm.name(),
            parts.join(" | "),
            c.stale
        );
    }
    for arm in ARMS {
        let get = |s: &str| cells.iter().find(|(a, n, c)| *a == arm && *n == s && c.ran);
        if let Some((_, _, canon)) = get("canon-placement") {
            let mut parts = vec![format!(
                "canon rp {} hit {:.3} frozen {:.3}",
                canon.per_episode(canon.reprefill),
                canon.hit_rate(),
                canon.frozen_rate()
            )];
            for control in ["board-in-prefix", "keyframe-in-tail"] {
                if let Some((_, _, c)) = get(control) {
                    parts.push(format!(
                        "{control} rp {} ({:.2}x) hit {:.3} frozen {:.3}",
                        c.per_episode(c.reprefill),
                        c.reprefill as f64 / canon.reprefill.max(1) as f64,
                        c.hit_rate(),
                        c.frozen_rate()
                    ));
                }
            }
            println!("CTX2-PLACEMENT {} | {}", arm.name(), parts.join(" | "));
        }
    }
    let best: Vec<String> = ARMS
        .iter()
        .map(|arm| {
            cells
                .iter()
                .filter(|(a, _, c)| a == arm && valid(c))
                .min_by(|(_, x, a), (_, y, b)| {
                    b.score()
                        .total_cmp(&a.score())
                        .then((a.edit + a.reprefill).cmp(&(b.edit + b.reprefill)))
                        .then(x.cmp(y))
                })
                .map_or_else(
                    || format!("{}=none", arm.name()),
                    |(_, name, c)| format!("{}={name} {:.3}", arm.name(), c.score()),
                )
        })
        .collect();
    println!("CTX-BEST | {}", best.join(" | "));
}

fn print_cell(arm: Arm, name: &str, c: &Cell, selected: bool) {
    if !c.ran {
        let why = if selected {
            "not built yet"
        } else {
            "not selected"
        };
        println!("{:<23} {name:<16} -- not run ({why})", arm.name());
        return;
    }
    println!(
        "{:<23} {name:<16} {:>6.3} {:>9.3} {:>8} {:>8.0} {:>9} {:>13} {:>10.3} {:>11} {:>9} {:>8} {:>5} {:>6} {:>5} {:>5} {:>8.0}{}",
        arm.name(),
        c.score(),
        c.exact_restore(),
        c.peak,
        c.mean_sum / c.episodes.max(1) as f64,
        c.per_episode(c.edit),
        c.per_episode(c.reprefill),
        c.hit_rate(),
        c.per_episode(c.restore),
        c.per_episode(c.fetch),
        c.read_peak,
        c.over_budget,
        c.hallucinated,
        c.stale,
        c.restore_fail,
        c.elapsed_ms,
        if c.violations > 0 {
            format!("  INVALID: {} capability violations", c.violations)
        } else {
            String::new()
        }
    );
}
