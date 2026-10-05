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

mod arms;
mod strategies;
mod window;

#[cfg(test)]
mod tests;

use std::ops::RangeInclusive;
use std::process::ExitCode;
use std::time::Instant;

use arms::{ARMS, Arm, Episode, Score};
use strategies::{STRATEGIES, Strategy};
use window::{Audit, Ctx, Ledger, RefStore, SpanKind, TOKENIZER, Window};

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
    /// Peak of the live window plus one restored reference while reading.
    pub(crate) query_peak: u64,
    /// Model calls that saw a window over budget.
    pub(crate) over_budget: u64,
    pub(crate) violations: Vec<&'static str>,
}

pub(crate) fn low_water(budget: u64) -> u64 {
    budget * LOW_WATER_PERCENT / 100
}

pub(crate) fn run_episode(ep: &Episode, strategy: &mut dyn Strategy, budget: u64) -> EpisodeResult {
    run_episode_with(ep, strategy, budget, |_| {})
}

/// Streams the episode through the strategy, then asks every query.
/// `tamper` runs between the stream and the queries (tests corrupt a
/// reference there to prove the arm fails).
pub(crate) fn run_episode_with(
    ep: &Episode,
    strategy: &mut dyn Strategy,
    budget: u64,
    tamper: impl FnOnce(&mut RefStore),
) -> EpisodeResult {
    let mut win = Window::default();
    let mut refs = RefStore::default();
    let mut led = Ledger::default();
    let caps = strategy.caps();
    let mut res = EpisodeResult::default();
    let mut window_sum = 0_u64;
    for (n, turn) in ep.turns.iter().enumerate() {
        win.push(SpanKind::Turn(n as u32), turn.text.clone());
        let mut ctx = Ctx {
            win: &mut win,
            refs: &mut refs,
            led: &mut led,
            caps,
            budget,
            low_water: low_water(budget),
        };
        if let Some(verb) = &turn.verb {
            strategy.on_verb(verb, &mut ctx);
        }
        strategy.on_turn(&mut ctx);
        res.reprefill_tok += win.checkpoint();
        let live = win.total();
        res.peak = res.peak.max(live);
        window_sum += live;
        res.over_budget += u64::from(live > budget);
    }
    res.mean = window_sum as f64 / ep.turns.len().max(1) as f64;
    res.query_peak = res.peak;
    tamper(&mut refs);

    let mut answers = Vec::with_capacity(ep.queries.len());
    for q in &ep.queries {
        let mut ids = {
            let ctx = Ctx {
                win: &mut win,
                refs: &mut refs,
                led: &mut led,
                caps,
                budget,
                low_water: low_water(budget),
            };
            strategy.on_query(q, &ctx)
        };
        ids.sort_unstable();
        ids.dedup();
        let mut chunks: Vec<&str> = Vec::new();
        for id in ids {
            match refs.restore(id) {
                Ok(spans) => {
                    let tok = refs.meta(id).map_or(0, |m| m.tok);
                    res.restore_tok += tok;
                    res.query_peak = res.query_peak.max(win.total() + tok);
                    chunks.extend(spans.into_iter().map(|(_, text)| text));
                }
                Err(_) => res.restore_fail = true,
            }
        }
        chunks.extend(win.spans().iter().map(window::Span::text));
        answers.push(arms::read(ep.arm, q, &chunks));
    }

    res.audit = led.audit(&refs);
    res.restore_fail |= res.audit.broken_reference();
    res.score = ep.score(&answers);
    // OF-546 note 3 / OF-190: a reference that cannot restore its span
    // byte-exactly fails the offload arm by construction.
    if ep.arm == Arm::KvOffload && res.restore_fail {
        res.score.value = 0.0;
        res.score.correct = 0;
    }
    res.edit_tok = led.edit_tok;
    res.violations = led.violations;
    res
}

/// One (arm, strategy) cell over a split.
#[derive(Default)]
struct Cell {
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
    query_peak: u64,
    over_budget: u64,
    restore_fail: u64,
    violations: usize,
    elapsed_ms: f64,
}

impl Cell {
    fn add(&mut self, r: &EpisodeResult, elapsed_ms: f64) {
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
        self.query_peak = self.query_peak.max(r.query_peak);
        self.over_budget += r.over_budget;
        self.restore_fail += u64::from(r.restore_fail);
        self.violations += r.violations.len();
        self.elapsed_ms += elapsed_ms;
    }

    fn valid(&self, seeds: u64) -> bool {
        self.ran && self.episodes == seeds && self.violations == 0
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
/// generator is deterministic and distinct across seeds, and the fixed reader
/// over the full stream answers every query exactly on every seed. `cargo
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
            let full: Vec<&str> = ep.turns.iter().map(|t| t.text.as_str()).collect();
            let answers: Vec<String> = ep
                .queries
                .iter()
                .map(|q| arms::read(arm, q, &full))
                .collect();
            let score = ep.score(&answers);
            if score.correct != score.total {
                return Err(format!(
                    "{} seed {seed}: full-stream oracle {}/{}",
                    arm.name(),
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
        "tests: in-binary self-checks (generator determinism, full-stream oracle exact on every seed): {}",
        checks
            .as_ref()
            .map_or_else(|e| format!("FAIL {e}"), |()| "pass".to_owned())
    );
    let engine_board_built = strategies::build("engine-board").is_some();
    println!(
        "engine-board: {}",
        if engine_board_built {
            "ran: oneiron::context_board::render_board_block, typed state to dynamic tail, no server plumbing"
        } else {
            "did not run (strategy not built yet)"
        }
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
        "columns: token columns are per-episode means; peak_tok and q_peak are maxima; \
         over, halluc and rfail are totals over the split"
    );
    println!(
        "{:<18} {:<17} {:>6} {:>9} {:>8} {:>8} {:>9} {:>13} {:>11} {:>8} {:>5} {:>6} {:>5} {:>8}",
        "arm",
        "strategy",
        "score",
        "exact_rst",
        "peak_tok",
        "mean_tok",
        "edit_tok",
        "reprefill_tok",
        "restore_tok",
        "q_peak",
        "over",
        "halluc",
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
                    let start = Instant::now();
                    let r = run_episode(&ep, strategy.as_mut(), opts.budget);
                    cell.add(&r, start.elapsed().as_secs_f64() * 1000.0);
                }
            }
            print_cell(arm, name, &cell, selected);
            cells.push((arm, name, cell));
        }
    }

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
    println!(
        "{} | arms {arms_scored}/4 | strategies {strategies_scored} | cells {cells_valid}/20 | tests {}",
        opts.split.tag(),
        if checks.is_ok() { "pass" } else { "fail" }
    );
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
        println!("{:<18} {name:<17} -- not run ({why})", arm.name());
        return;
    }
    println!(
        "{:<18} {name:<17} {:>6.3} {:>9.3} {:>8} {:>8.0} {:>9} {:>13} {:>11} {:>8} {:>5} {:>6} {:>5} {:>8.0}{}",
        arm.name(),
        c.score(),
        c.exact_restore(),
        c.peak,
        c.mean_sum / c.episodes.max(1) as f64,
        c.per_episode(c.edit),
        c.per_episode(c.reprefill),
        c.per_episode(c.restore),
        c.query_peak,
        c.over_budget,
        c.hallucinated,
        c.restore_fail,
        c.elapsed_ms,
        if c.violations > 0 {
            format!("  INVALID: {} capability violations", c.violations)
        } else {
            String::new()
        }
    );
}
