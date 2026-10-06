//! Harness-side audits from the merged designer cases (OF-546 loop 2,
//! "build now"): F-C1 `precog` / `unbacked` / `foreknow`, the F-C15
//! diagnostics (`stale`, `overcount`; `override` is counted where the
//! harness restores), and F-C18 `frames_live`. Each one reads hidden
//! episode data a strategy never sees and applies to every strategy at
//! once. None changes a score.
//!
//! precog: a strategy-written span (Note or Stub) holding an answer atom
//! (a needle phrase, an asked value, an error timestamp or code, a relink
//! body line, a final board row) before the turn that atom arrives.
//! unbacked: an answered query whose evidence line (the line the fixed
//! reader matched; `evidence` mirrors each reader) is byte-equal to no line
//! that had arrived by then: stream lines, the snapshot lines the typed
//! sketchpad moves imply, and the bodies the environment holds. A verbatim
//! note of an arrived line is backed. foreknow (kv-offload-recall): at the
//! last model call before the queries, the share of asked keys whose latest
//! SET line is live minus the share of all keys whose latest SET line is
//! live.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use super::arms::{Arm, Episode, Query, Verb, parse_move, parse_rows, snapshot_lines};
use super::arms_epoch::{Seen, parse_frames};
use super::window::{SpanKind, Window};

/// What the audits know about one episode before any strategy runs.
pub(crate) struct AuditBase {
    /// Every line that arrived, with the first turn it arrived at.
    backing: HashMap<String, usize>,
    /// Answer atoms with the turn each arrives at, sorted by arrival.
    atoms: Vec<(String, usize)>,
    /// Board rows the true board takes, with the first turn it takes each.
    rows: HashMap<String, usize>,
    /// The final board's rows.
    final_rows: BTreeSet<String>,
    /// kv-offload-recall: each key's latest SET line; the asked keys.
    kv_latest: HashMap<String, String>,
    kv_asked: Vec<String>,
    /// stream-frames: the newest epoch the stream reaches.
    max_epoch: u32,
}

fn trimmed_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim)
}

/// Records that `line` arrived at turn `t`, keeping the earliest arrival.
fn arrive(backing: &mut HashMap<String, usize>, line: String, t: usize) {
    backing
        .entry(line)
        .and_modify(|at| *at = (*at).min(t))
        .or_insert(t);
}

fn board_rows(digits: &str) -> BTreeSet<String> {
    (0..9)
        .filter_map(|r| {
            digits
                .get(r * 9..r * 9 + 9)
                .map(|d| format!("r{} {d}", r + 1))
        })
        .collect()
}

impl AuditBase {
    pub(crate) fn new(ep: &Episode) -> Self {
        let mut backing: HashMap<String, usize> = HashMap::new();
        for (t, turn) in ep.turns.iter().enumerate() {
            for line in trimmed_lines(&turn.text) {
                backing.entry(line.to_owned()).or_insert(t);
            }
        }
        let mut rows: HashMap<String, usize> = HashMap::new();
        let mut final_rows = BTreeSet::new();
        match ep.arm {
            Arm::Sketchpad => {
                let mut grid = [0_u8; 81];
                for (t, turn) in ep.turns.iter().enumerate() {
                    let version = match turn.verb {
                        Some(Verb::BoardInit(g)) => {
                            grid = g;
                            0
                        }
                        Some(Verb::SetCell { mv, cell, digit }) => {
                            grid[usize::from(cell)] = digit;
                            mv
                        }
                        _ => continue,
                    };
                    for line in snapshot_lines(&grid, version) {
                        if line.starts_with('r') {
                            rows.entry(line.clone()).or_insert(t);
                        }
                        arrive(&mut backing, line, t);
                    }
                }
                final_rows = board_rows(&ep.expected[0]);
            }
            Arm::StreamFrames => {
                for (t, grid) in &ep.truth {
                    for line in snapshot_lines(grid, 0).into_iter().skip(1) {
                        rows.entry(line).or_insert(*t);
                    }
                }
                final_rows = board_rows(&ep.expected[0]);
            }
            Arm::Relink => {
                for name in ep.env.names() {
                    for (v, t) in ep.env.versions(name) {
                        for line in ep.env.body(name, v).unwrap_or_default().lines() {
                            arrive(&mut backing, line.to_owned(), t);
                        }
                    }
                }
            }
            _ => {}
        }

        let first = |pred: &dyn Fn(&str) -> bool| -> usize {
            backing
                .iter()
                .filter(|(l, _)| pred(l))
                .map(|(_, t)| *t)
                .min()
                .unwrap_or(usize::MAX)
        };
        let mut atoms: Vec<(String, usize)> = Vec::new();
        for (i, q) in ep.queries.iter().enumerate() {
            let want = &ep.expected[i];
            if want.is_empty() {
                continue;
            }
            let t = &q.text;
            if t.starts_with("RECALL NEEDLE") {
                let line = format!("{} {want}", q.key);
                atoms.push((
                    want.clone(),
                    backing.get(&line).copied().unwrap_or(usize::MAX),
                ));
            } else if t.starts_with("GET ") {
                let at = first(&|l: &str| {
                    l.strip_prefix(q.key.as_str())
                        .and_then(|r| r.split_whitespace().next())
                        == Some(want.as_str())
                });
                atoms.push((want.clone(), at));
            } else if t.starts_with("FIRST ") || t.starts_with("LAST ") {
                atoms.push((want.clone(), first(&|l: &str| l.starts_with(want.as_str()))));
            } else if t == "ERRORS" {
                for code in want.split(',') {
                    let token = format!("code={code}");
                    atoms.push((code.to_owned(), first(&|l: &str| l.contains(&token))));
                }
            } else if t.starts_with("NEED ") {
                let name = q.key.trim_end_matches('@');
                let at = ep.ask_at[i].unwrap_or(ep.turns.len());
                if let Some(v) = ep.env.current(name, at)
                    && let Some(body) = ep.env.body(name, v)
                {
                    let arrives = ep.env.version_turn(name, v).unwrap_or(usize::MAX);
                    atoms.extend(body.lines().map(|l| (l.to_owned(), arrives)));
                }
            }
        }
        atoms.sort_by_key(|(_, t)| *t);
        atoms.dedup();

        let mut kv_latest: HashMap<String, (u64, String)> = HashMap::new();
        let mut kv_asked = Vec::new();
        if matches!(ep.arm, Arm::KvOffload | Arm::KvInterleaved) {
            for line in backing.keys() {
                let mut tok = line.split_whitespace();
                if tok.next() != Some("SET") {
                    continue;
                }
                let (Some(key), Some("="), Some(_), Some(seq)) =
                    (tok.next(), tok.next(), tok.next(), tok.next())
                else {
                    continue;
                };
                let seq: u64 = seq.trim_start_matches('#').parse().unwrap_or(0);
                let slot = kv_latest
                    .entry(key.to_owned())
                    .or_insert((0, String::new()));
                if seq >= slot.0 {
                    *slot = (seq, line.clone());
                }
            }
            // The keys asked after the stream (mid-stream asks were seen).
            kv_asked = ep
                .queries
                .iter()
                .zip(&ep.expected)
                .zip(&ep.ask_at)
                .filter(|((_, want), at)| !want.is_empty() && at.is_none())
                .filter_map(|((q, _), _)| q.text.strip_prefix("GET ").map(str::to_owned))
                .collect();
        }
        let max_epoch = if ep.arm == Arm::StreamFrames {
            let lines: Vec<&str> = ep
                .turns
                .iter()
                .flat_map(|t| trimmed_lines(&t.text))
                .collect();
            parse_frames(&lines)
                .iter()
                .filter_map(|s| match s {
                    Seen::Key(e, _, _) => Some(*e),
                    Seen::Delta(..) => None,
                })
                .max()
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            backing,
            atoms,
            rows,
            final_rows,
            kv_latest: kv_latest.into_iter().map(|(k, (_, l))| (k, l)).collect(),
            kv_asked,
            max_epoch,
        }
    }

    /// Whether `line` had arrived by turn `n`.
    fn backed(&self, line: &str, n: usize) -> bool {
        self.backing.get(line).is_some_and(|t| *t <= n)
    }

    /// Whether `text` holds an answer atom or a final board row that has
    /// not arrived by turn `n`.
    fn early(&self, text: &str, n: usize) -> bool {
        let pending = self.atoms.partition_point(|(_, t)| *t <= n);
        if self.atoms[pending..]
            .iter()
            .any(|(atom, _)| text.contains(atom.as_str()))
        {
            return true;
        }
        !self.final_rows.is_empty()
            && trimmed_lines(text)
                .any(|l| self.final_rows.contains(l) && self.rows.get(l).is_none_or(|t| *t > n))
    }

    /// kv-offload-recall: asked keys live minus all keys live, at the last
    /// model call before the queries.
    pub(crate) fn foreknow(&self, win: &Window) -> Option<f64> {
        if self.kv_latest.is_empty() || self.kv_asked.is_empty() {
            return None;
        }
        let live: HashSet<&str> = win
            .spans()
            .iter()
            .flat_map(|s| trimmed_lines(s.text()))
            .collect();
        let is_live = |k: &String| {
            self.kv_latest
                .get(k)
                .is_some_and(|line| live.contains(line.as_str()))
        };
        let asked =
            self.kv_asked.iter().filter(|k| is_live(k)).count() as f64 / self.kv_asked.len() as f64;
        let all = self.kv_latest.keys().filter(|k| is_live(k)).count() as f64
            / self.kv_latest.len() as f64;
        Some(asked - all)
    }

    /// stream-frames: frames of superseded epochs still live.
    pub(crate) fn frames_live(&self, win: &Window) -> u64 {
        if self.max_epoch == 0 {
            return 0;
        }
        let lines: Vec<&str> = win
            .spans()
            .iter()
            .flat_map(|s| trimmed_lines(s.text()))
            .collect();
        parse_frames(&lines)
            .iter()
            .filter(|s| match s {
                Seen::Key(e, _, _) | Seen::Delta(e, ..) => *e < self.max_epoch,
            })
            .count() as u64
    }
}

/// One run's audit state.
pub(crate) struct Checks<'b> {
    base: &'b AuditBase,
    checked: HashSet<(u64, u32)>,
    pub(crate) precog: u64,
    pub(crate) unbacked: u64,
}

impl<'b> Checks<'b> {
    pub(crate) fn new(base: &'b AuditBase) -> Self {
        Self {
            base,
            checked: HashSet::new(),
            precog: 0,
            unbacked: 0,
        }
    }

    /// A model call at turn `n`: every strategy-written span version not
    /// seen before is checked once for early atoms.
    pub(crate) fn on_call(&mut self, n: usize, win: &Window) {
        for span in win.spans() {
            if matches!(span.kind(), SpanKind::Note | SpanKind::Stub)
                && self.checked.insert((span.id(), span.rev()))
                && self.base.early(span.text(), n)
            {
                self.precog += 1;
            }
        }
    }

    /// An answered query at turn `n`: its evidence must have arrived.
    pub(crate) fn on_answer(
        &mut self,
        arm: Arm,
        q: &Query,
        n: usize,
        chunks: &[&str],
        answer: &str,
    ) {
        if answer.is_empty() {
            return;
        }
        if let Some(line) = evidence(arm, q, chunks)
            .iter()
            .find(|line| !self.base.backed(line, n))
        {
            let _ = line;
            self.unbacked += 1;
        }
    }
}

/// The lines the fixed reader matched for `q` over `chunks` (mirrors each
/// reader in `arms.rs` and `arms_epoch.rs`).
pub(crate) fn evidence(arm: Arm, q: &Query, chunks: &[&str]) -> Vec<String> {
    let lines: Vec<&str> = chunks.iter().flat_map(|c| trimmed_lines(c)).collect();
    let own = |v: Vec<&str>| v.into_iter().map(str::to_owned).collect::<Vec<_>>();
    match arm {
        Arm::Needle => own(lines
            .iter()
            .rev()
            .find(|l| l.starts_with(q.key.as_str()))
            .copied()
            .into_iter()
            .collect()),
        Arm::KvOffload => {
            let mut best: Option<(u64, &str)> = None;
            for &line in &lines {
                let Some(rest) = line.strip_prefix(q.key.as_str()) else {
                    continue;
                };
                let mut tokens = rest.split_whitespace();
                if tokens.next().is_none() {
                    continue;
                }
                let seq = tokens
                    .next()
                    .and_then(|t| t.strip_prefix('#'))
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0);
                if best.is_none_or(|(b, _)| seq >= b) {
                    best = Some((seq, line));
                }
            }
            own(best.map(|(_, l)| l).into_iter().collect())
        }
        Arm::LogTriage => {
            let mut errors: BTreeSet<(&str, &str, &str)> = BTreeSet::new();
            for &line in &lines {
                let mut tokens = line.split_whitespace();
                let (Some(ts), Some("ERROR")) = (tokens.next(), tokens.next()) else {
                    continue;
                };
                if let Some(code) = tokens.find_map(|t| t.strip_prefix("code=")) {
                    errors.insert((ts, code, line));
                }
            }
            if q.text == "ERRORS" {
                return own(errors.iter().map(|e| e.2).collect());
            }
            let Some((verb, code)) = q.text.split_once(' ') else {
                return Vec::new();
            };
            let mut of_code = errors.iter().filter(|e| e.1 == code).map(|e| e.2);
            own(match verb {
                "COUNT" => of_code.collect(),
                "FIRST" => of_code.next().into_iter().collect(),
                "LAST" => of_code.last().into_iter().collect(),
                _ => Vec::new(),
            })
        }
        Arm::Sketchpad => {
            let mut best: Option<(u32, usize)> = None;
            let mut moves: BTreeMap<u32, &str> = BTreeMap::new();
            for (i, &line) in lines.iter().enumerate() {
                if let Some(version) = line
                    .strip_prefix("BOARD @m")
                    .and_then(|v| v.parse::<u32>().ok())
                {
                    if parse_rows(&lines[i + 1..]).is_some()
                        && best.is_none_or(|(v, _)| version >= v)
                    {
                        best = Some((version, i));
                    }
                } else if let Some((mv, _, _)) = parse_move(line) {
                    moves.insert(mv, line);
                }
            }
            let version = best.map_or(0, |(v, _)| v);
            let mut out: Vec<&str> = best.map_or_else(Vec::new, |(_, i)| lines[i..i + 10].to_vec());
            out.extend(moves.range(version + 1..).map(|(_, l)| *l));
            own(out)
        }
        Arm::Relink => {
            let mut versions: BTreeMap<u32, (usize, BTreeMap<usize, &str>)> = BTreeMap::new();
            for &line in &lines {
                let Some(rest) = line.strip_prefix(q.key.as_str()) else {
                    continue;
                };
                let Some((v, rest)) = rest.split_once(' ') else {
                    continue;
                };
                let Some((at, _)) = rest.split_once(' ') else {
                    continue;
                };
                let Some((i, n)) = at.split_once('/') else {
                    continue;
                };
                let (Ok(v), Ok(i), Ok(n)) =
                    (v.parse::<u32>(), i.parse::<usize>(), n.parse::<usize>())
                else {
                    continue;
                };
                if i == 0 || i > n {
                    continue;
                }
                let entry = versions.entry(v).or_insert_with(|| (n, BTreeMap::new()));
                if entry.0 == n {
                    entry.1.entry(i).or_insert(line);
                }
            }
            own(versions
                .values()
                .rev()
                .find(|(n, got)| got.len() == *n)
                .map(|(_, got)| got.values().copied().collect())
                .unwrap_or_default())
        }
        Arm::KvInterleaved => evidence(Arm::KvOffload, q, chunks),
        Arm::Obligations | Arm::LateResults | Arm::Transactions | Arm::ToolLoop => {
            own(super::arms_next::read_with(arm, q, &lines).1)
        }
        Arm::MultiEpoch => {
            let inner = if q.text.starts_with("RECALL NEEDLE") {
                Arm::Needle
            } else if q.text.starts_with("GET ") {
                Arm::KvOffload
            } else {
                Arm::LogTriage
            };
            evidence(inner, q, chunks)
        }
        Arm::StreamFrames => {
            let seen = parse_frames(&lines);
            let keys = seen.iter().filter_map(|s| match s {
                Seen::Key(e, _, _) => Some(*e),
                Seen::Delta(..) => None,
            });
            let Some(epoch) = keys.max().or_else(|| {
                seen.iter()
                    .filter_map(|s| match s {
                        Seen::Delta(e, ..) => Some(*e),
                        Seen::Key(..) => None,
                    })
                    .max()
            }) else {
                return Vec::new();
            };
            let mut out: Vec<&str> = seen
                .iter()
                .rev()
                .find_map(|s| match s {
                    Seen::Key(e, _, range) if *e == epoch => Some(lines[range.clone()].to_vec()),
                    _ => None,
                })
                .unwrap_or_default();
            out.extend(seen.iter().filter_map(|s| match s {
                Seen::Delta(e, _, _, i) if *e == epoch => Some(lines[*i]),
                _ => None,
            }));
            own(out)
        }
    }
}

/// F-C15 from the answers: wrong GET answers that are a value the key held
/// earlier (`stale`), and COUNT answers above the truth (`overcount`).
pub(crate) fn diagnose(ep: &Episode, answers: &[String]) -> (u32, u32) {
    let (mut stale, mut overcount) = (0, 0);
    for (i, q) in ep.queries.iter().enumerate() {
        let (got, want) = (answers[i].as_str(), ep.expected[i].as_str());
        if got == want || got.is_empty() {
            continue;
        }
        if q.text.starts_with("GET ") {
            let end = ep.ask_at[i].map_or(ep.turns.len(), |t| t + 1);
            let held = ep.turns[..end]
                .iter()
                .flat_map(|t| trimmed_lines(&t.text))
                .filter_map(|l| l.strip_prefix(q.key.as_str()))
                .filter_map(|r| r.split_whitespace().next())
                .any(|v| v == got);
            stale += u32::from(held);
        } else if q.text.starts_with("COUNT ")
            && let (Ok(g), Ok(w)) = (got.parse::<u64>(), want.parse::<u64>())
        {
            overcount += u32::from(g > w);
        } else if q.text.starts_with("SIG ") {
            // tool-loop: a signature the function had before an edit.
            let held = ep
                .turns
                .iter()
                .flat_map(|t| trimmed_lines(&t.text))
                .any(|l| l.trim_start_matches(['+', '-']) == got);
            stale += u32::from(held);
        } else if q.text == "FINALFAILS" {
            // tool-loop: the failures of an older run.
            let older = ep.turns.iter().any(|t| {
                let lines: Vec<&str> = trimmed_lines(&t.text).collect();
                lines.first().is_some_and(|h| h.starts_with("TEST run #"))
                    && super::arms_next::read_with(Arm::ToolLoop, q, &lines).0 == got
            });
            stale += u32::from(older);
        }
    }
    (stale, overcount)
}
