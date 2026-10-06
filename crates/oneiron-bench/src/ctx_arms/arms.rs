//! The four OF-546 arms: seeded generators, query sets, the fixed reader and
//! the scorer. Rebuilt native from CLM's ContextBench (needle retention, sudoku
//! sketchpad, KV store, log triage).
//!
//! Frozen once committed: a generator, query set, reader or scorer here never
//! changes between rounds. If one is wrong, PROGRESS.md says so and the bench
//! stops (CLAUDE.md, "fix the bench, never the measurement").
//!
//! The reader is the stand-in for a model reading its own context: given one
//! query and the chunks a strategy left visible (live window spans plus any
//! references it restored), it answers deterministically. Every strategy is
//! judged by the same reader, so a score measures what the window kept.

use std::collections::{BTreeMap, BTreeSet};

use super::arms_epoch::{self, Env, Extra};
use super::arms_next;

/// Every arm, in report order. The last three are loop 2's
/// (`arms_epoch.rs`).
pub(crate) const ARMS: [Arm; 12] = [
    Arm::Needle,
    Arm::Sketchpad,
    Arm::KvOffload,
    Arm::LogTriage,
    Arm::Relink,
    Arm::MultiEpoch,
    Arm::StreamFrames,
    Arm::KvInterleaved,
    Arm::Obligations,
    Arm::LateResults,
    Arm::Transactions,
    Arm::ToolLoop,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Arm {
    Needle,
    Sketchpad,
    KvOffload,
    LogTriage,
    Relink,
    MultiEpoch,
    StreamFrames,
    KvInterleaved,
    Obligations,
    LateResults,
    Transactions,
    ToolLoop,
}

impl Arm {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Needle => "needle-retention",
            Self::Sketchpad => "sketchpad",
            Self::KvOffload => "kv-offload-recall",
            Self::LogTriage => "log-triage",
            Self::Relink => "relink-after-compaction",
            Self::MultiEpoch => "multi-epoch",
            Self::StreamFrames => "stream-frames",
            Self::KvInterleaved => "kv-interleaved",
            Self::Obligations => "pending-obligations",
            Self::LateResults => "late-tool-results",
            Self::Transactions => "commit-or-rollback",
            Self::ToolLoop => "tool-loop",
        }
    }

    pub(crate) fn parse(name: &str) -> Option<Self> {
        ARMS.into_iter().find(|arm| arm.name() == name)
    }

    const fn salt(self) -> u64 {
        match self {
            Self::Needle => 1,
            Self::Sketchpad => 2,
            Self::KvOffload => 3,
            Self::LogTriage => 4,
            Self::Relink => 5,
            Self::MultiEpoch => 6,
            Self::StreamFrames => 7,
            Self::KvInterleaved => 8,
            Self::Obligations => 9,
            Self::LateResults => 10,
            Self::Transactions => 11,
            Self::ToolLoop => 12,
        }
    }
}

/// SplitMix64. Written out so the streams never move with a `rand` upgrade.
pub(crate) struct Rng(u64);

impl Rng {
    pub(crate) const fn new(seed: u64, salt: u64) -> Self {
        Self(seed ^ salt.wrapping_mul(0xD1B5_4A32_D192_ED03))
    }

    pub(crate) const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-enough draw in `0..n` (`n > 0`).
    pub(crate) fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// Draw in `lo..=hi`.
    pub(crate) fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    pub(crate) fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    pub(crate) fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.below(i + 1));
        }
    }
}

pub(crate) const WORDS: [&str; 64] = [
    "amber", "basin", "cedar", "delta", "ember", "fable", "glade", "harbor", "island", "juniper",
    "kettle", "lantern", "meadow", "nectar", "orchard", "pebble", "quarry", "river", "saddle",
    "thistle", "umber", "valley", "willow", "yonder", "zephyr", "anchor", "bramble", "canyon",
    "drift", "echo", "fern", "granite", "hollow", "ivory", "jasper", "kelp", "lumen", "marble",
    "nimbus", "onyx", "prairie", "quill", "ridge", "sorrel", "tundra", "upland", "vesper", "wharf",
    "arbor", "birch", "cobalt", "dune", "estuary", "flint", "grove", "heron", "inlet", "jade",
    "knoll", "lagoon", "moss", "north", "ocher", "pine",
];
const HEX: &[u8; 16] = b"0123456789abcdef";
pub(crate) const SERVICES: [&str; 8] = [
    "auth", "billing", "search", "gateway", "ledger", "notify", "storage", "sched",
];

/// Prose filler: lowercase words, never a digit.
pub(crate) fn filler_line(rng: &mut Rng) -> String {
    let n = rng.range(6, 13);
    let mut line = String::new();
    for i in 0..n {
        if i > 0 {
            line.push(' ');
        }
        line.push_str(rng.pick(&WORDS));
    }
    line.push('.');
    line
}

pub(crate) fn filler_lines(rng: &mut Rng, lo: usize, hi: usize) -> Vec<String> {
    let n = rng.range(lo, hi);
    (0..n).map(|_| filler_line(rng)).collect()
}

pub(crate) fn hex(rng: &mut Rng, n: usize) -> String {
    (0..n).map(|_| char::from(HEX[rng.below(16)])).collect()
}

/// An 81-cell board; 0 is an empty cell.
pub(crate) type Grid = [u8; 81];

/// A typed agent action riding a stream turn. Only the sketchpad's own moves
/// are typed: they are what an agent's `board.set` call would record. Every
/// other turn is opaque text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verb {
    BoardInit(Grid),
    SetCell {
        mv: u32,
        cell: u8,
        digit: u8,
    },
    /// The turn carries `res`'s body at `version` (a read, write, open,
    /// rotation or load the session made). Loop 2.
    Read {
        res: String,
        version: u32,
    },
    /// `res` moved to `version` outside the session; the turn carries a
    /// notice and no body. Loop 2.
    Changed {
        res: String,
        version: u32,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct Turn {
    pub(crate) text: String,
    pub(crate) verb: Option<Verb>,
}

/// One question. `key` is the literal a retrieval tool would search for; it
/// is derived from the question, never from the answer.
#[derive(Clone, Debug)]
pub(crate) struct Query {
    pub(crate) text: String,
    pub(crate) key: String,
}

/// One seeded episode. `expected`, `atomic` and `present` are the hidden
/// answers: the harness scores against them and never hands them to a
/// strategy.
pub(crate) struct Episode {
    pub(crate) arm: Arm,
    pub(crate) seed: u64,
    pub(crate) turns: Vec<Turn>,
    pub(crate) queries: Vec<Query>,
    pub(super) expected: Vec<String>,
    /// Whether a wrong non-empty answer to this query can be a hallucination
    /// (an atom the stream never held). Counts cannot.
    pub(super) atomic: Vec<bool>,
    /// Every answerable atom the stream actually held.
    pub(super) present: BTreeSet<String>,
    /// Loop 2: the stream turn after which each query is asked (`None`:
    /// after the stream, as in loop 1). Parallel to `queries`.
    pub(crate) ask_at: Vec<Option<usize>>,
    /// Loop 2: the bucket each query reports under (epoch of origin for
    /// multi-epoch, need kind for relink). Empty for loop-1 arms.
    pub(super) origin: Vec<u8>,
    /// Loop 2: the environment a `get` reads. Empty for loop-1 arms.
    pub(crate) env: Env,
    /// Loop 2 (stream-frames): the true board after each turn that changed
    /// it, `(turn, grid)`. Hidden; the audits date board rows by it.
    pub(super) truth: Vec<(usize, Grid)>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Score {
    /// Fraction correct: queries for the recall arms, cells for the sketchpad.
    pub(crate) value: f64,
    pub(crate) correct: u32,
    pub(crate) total: u32,
    /// Wrong non-empty answers naming an atom the stream never held.
    pub(crate) hallucinated: u32,
}

/// The canonical board snapshot every writer and the reader share:
/// `BOARD @mNNN` (moves applied) then nine `rI ddddddddd` rows.
pub(crate) fn snapshot_lines(grid: &Grid, version: u32) -> Vec<String> {
    let mut lines = vec![format!("BOARD @m{version:03}")];
    lines.extend((0..9).map(|row| row_line(grid, row)));
    lines
}

pub(crate) fn row_line(grid: &Grid, row: usize) -> String {
    let digits: String = grid[row * 9..row * 9 + 9]
        .iter()
        .map(|d| char::from(b'0' + d))
        .collect();
    format!("r{} {digits}", row + 1)
}

pub(crate) fn move_line(mv: u32, cell: u8, digit: u8) -> String {
    format!("MOVE m{mv:03}: r{}c{}={digit}", cell / 9 + 1, cell % 9 + 1)
}

impl Episode {
    pub(crate) fn generate(arm: Arm, seed: u64) -> Self {
        let mut rng = Rng::new(seed, arm.salt());
        let parts = match arm {
            Arm::Needle => gen_needle(&mut rng),
            Arm::Sketchpad => gen_sketchpad(&mut rng),
            Arm::KvOffload => gen_kv(&mut rng),
            Arm::LogTriage => gen_logs(&mut rng),
            Arm::Relink
            | Arm::MultiEpoch
            | Arm::StreamFrames
            | Arm::KvInterleaved
            | Arm::Obligations
            | Arm::LateResults
            | Arm::Transactions
            | Arm::ToolLoop => {
                let g = match arm {
                    Arm::Relink => arms_epoch::gen_relink(&mut rng),
                    Arm::MultiEpoch => arms_epoch::gen_multi_epoch(&mut rng),
                    Arm::KvInterleaved => arms_next::gen_kv_interleaved(&mut rng, seed >= 1001),
                    Arm::Obligations => arms_next::gen_obligations(&mut rng),
                    Arm::LateResults => arms_next::gen_late_results(&mut rng),
                    Arm::Transactions => arms_next::gen_transactions(&mut rng),
                    Arm::ToolLoop => arms_next::gen_tool_loop(&mut rng, seed >= 1001),
                    _ => arms_epoch::gen_stream_frames(&mut rng, seed >= 1001),
                };
                return Self {
                    arm,
                    seed,
                    turns: g.turns,
                    queries: g.queries,
                    expected: g.expected,
                    atomic: g.atomic,
                    present: g.present,
                    ask_at: g.ask_at,
                    origin: g.origin,
                    env: g.env,
                    truth: g.truth,
                };
            }
        };
        let n = parts.queries.len();
        Self {
            arm,
            seed,
            turns: parts.turns,
            queries: parts.queries,
            expected: parts.expected,
            atomic: parts.atomic,
            present: parts.present,
            ask_at: vec![None; n],
            origin: Vec::new(),
            env: Env::default(),
            truth: Vec::new(),
        }
    }

    /// Scores answers and adds the loop-2 breakdown (stale answers, the
    /// per-bucket tallies). Loop-1 arms score exactly as [`Self::score`].
    pub(crate) fn score_full(&self, answers: &[String]) -> (Score, Extra) {
        match self.arm {
            Arm::Relink | Arm::MultiEpoch | Arm::StreamFrames => arms_epoch::score(self, answers),
            Arm::KvInterleaved
            | Arm::Obligations
            | Arm::LateResults
            | Arm::Transactions
            | Arm::ToolLoop => (arms_next::score(self, answers), Extra::default()),
            _ => (self.score(answers), Extra::default()),
        }
    }

    /// Scores answers (one per query, in order) against the hidden answers.
    pub(crate) fn score(&self, answers: &[String]) -> Score {
        if self.arm == Arm::Sketchpad {
            let want = self.expected[0].as_bytes();
            let got = answers.first().map_or(&[][..], |a| a.as_bytes());
            let correct = (0..81).filter(|&i| got.get(i) == Some(&want[i])).count() as u32;
            return Score {
                value: f64::from(correct) / 81.0,
                correct,
                total: 81,
                hallucinated: 0,
            };
        }
        let mut score = Score {
            total: self.queries.len() as u32,
            ..Score::default()
        };
        for (i, want) in self.expected.iter().enumerate() {
            let got = answers.get(i).map_or("", String::as_str);
            if got == want {
                score.correct += 1;
            } else if self.atomic[i]
                && !got.is_empty()
                && got.split(',').any(|atom| !self.present.contains(atom))
            {
                score.hallucinated += 1;
            }
        }
        score.value = f64::from(score.correct) / f64::from(score.total.max(1));
        score
    }

    /// blake3 over everything generated, hidden answers included: the
    /// determinism check compares two generations of one seed.
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for t in &self.turns {
            h.update(t.text.as_bytes());
            h.update(format!("{:?}\0", t.verb).as_bytes());
        }
        for (q, e) in self.queries.iter().zip(&self.expected) {
            h.update(q.text.as_bytes());
            h.update(q.key.as_bytes());
            h.update(e.as_bytes());
            h.update(b"\0");
        }
        // Loop-2 fields only when present, so loop-1 digests are unchanged.
        if self.ask_at.iter().any(Option::is_some) || !self.env.is_empty() || !self.truth.is_empty()
        {
            h.update(format!("{:?}{:?}{:?}", self.ask_at, self.origin, self.truth).as_bytes());
            self.env.hash_into(&mut h);
        }
        *h.finalize().as_bytes()
    }
}

struct Parts {
    turns: Vec<Turn>,
    queries: Vec<Query>,
    expected: Vec<String>,
    atomic: Vec<bool>,
    present: BTreeSet<String>,
}

const NEEDLE_TURNS: usize = 1000;
const NEEDLES: usize = 16;

/// K verbatim needles, one per stream segment, each a line inside a filler
/// turn. Queries ask for each needle verbatim.
fn gen_needle(rng: &mut Rng) -> Parts {
    let mut phrases: Vec<String> = Vec::with_capacity(NEEDLES);
    while phrases.len() < NEEDLES {
        let phrase = format!(
            "{}-{}-{} {} {} {}",
            rng.pick(&WORDS),
            rng.pick(&WORDS),
            rng.pick(&WORDS),
            hex(rng, 6),
            rng.pick(&WORDS),
            rng.pick(&WORDS)
        );
        if !phrases.contains(&phrase) {
            phrases.push(phrase);
        }
    }
    let segment = NEEDLE_TURNS / NEEDLES;
    let at: BTreeMap<usize, usize> = (0..NEEDLES)
        .map(|i| (i * segment + rng.below(segment), i))
        .collect();
    let mut turns = Vec::with_capacity(NEEDLE_TURNS);
    for t in 0..NEEDLE_TURNS {
        let mut lines = filler_lines(rng, 4, 9);
        if let Some(&i) = at.get(&t) {
            let pos = rng.below(lines.len() + 1);
            lines.insert(pos, format!("NEEDLE n{i:02}: {}", phrases[i]));
        }
        turns.push(Turn {
            text: lines.join("\n"),
            verb: None,
        });
    }
    Parts {
        turns,
        queries: (0..NEEDLES)
            .map(|i| Query {
                text: format!("RECALL NEEDLE n{i:02}"),
                key: format!("NEEDLE n{i:02}:"),
            })
            .collect(),
        expected: phrases.clone(),
        atomic: vec![true; NEEDLES],
        present: phrases.into_iter().collect(),
    }
}

const SKETCH_TURNS: usize = 1000;

/// An 81-cell board in turn 0, then one streamed move on every odd turn,
/// filler between. The query asks for the final board.
fn gen_sketchpad(rng: &mut Rng) -> Parts {
    let mut grid: Grid = [0; 81];
    for cell in &mut grid {
        *cell = if rng.below(100) < 45 {
            0
        } else {
            rng.range(1, 9) as u8
        };
    }
    let mut turns = Vec::with_capacity(SKETCH_TURNS);
    let mut lines = snapshot_lines(&grid, 0);
    lines.extend(filler_lines(rng, 2, 2));
    turns.push(Turn {
        text: lines.join("\n"),
        verb: Some(Verb::BoardInit(grid)),
    });
    let mut mv = 0_u32;
    for t in 1..SKETCH_TURNS {
        if t % 2 == 1 {
            mv += 1;
            let cell = rng.below(81) as u8;
            let digit = rng.range(1, 9) as u8;
            grid[usize::from(cell)] = digit;
            let mut lines = filler_lines(rng, 2, 5);
            let pos = rng.below(lines.len() + 1);
            lines.insert(pos, move_line(mv, cell, digit));
            turns.push(Turn {
                text: lines.join("\n"),
                verb: Some(Verb::SetCell { mv, cell, digit }),
            });
        } else {
            turns.push(Turn {
                text: filler_lines(rng, 6, 11).join("\n"),
                verb: None,
            });
        }
    }
    let answer: String = grid.iter().map(|d| char::from(b'0' + d)).collect();
    Parts {
        turns,
        queries: vec![Query {
            text: "BOARD FINAL".to_owned(),
            key: "BOARD @m".to_owned(),
        }],
        expected: vec![answer],
        atomic: vec![false],
        present: BTreeSet::new(),
    }
}

const KV_TURNS: usize = 880;
const KV_PRESENT_QUERIES: usize = 44;
const KV_ABSENT_QUERIES: usize = 4;

/// Versioned SET lines (`#seq` is the global write order), a fifth of them
/// overwriting an earlier key. Queries GET present keys spread across the
/// stream plus a few keys never set (the right answer is an abstention).
fn gen_kv(rng: &mut Rng) -> Parts {
    let mut keys: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut latest: BTreeMap<String, String> = BTreeMap::new();
    let mut present = BTreeSet::new();
    let mut seq = 0_u32;
    let mut turns = Vec::with_capacity(KV_TURNS);
    for _ in 0..KV_TURNS {
        let mut lines = Vec::new();
        for _ in 0..rng.range(6, 10) {
            seq += 1;
            let key = if !keys.is_empty() && rng.below(100) < 20 {
                keys[rng.below(keys.len())].clone()
            } else {
                fresh_key(rng, &mut seen, &mut keys)
            };
            let value = hex(rng, 20);
            lines.push(format!("SET {key} = {value} #{seq:06}"));
            present.insert(value.clone());
            latest.insert(key, value);
        }
        for _ in 0..rng.range(1, 2) {
            let pos = rng.below(lines.len() + 1);
            lines.insert(pos, filler_line(rng));
        }
        turns.push(Turn {
            text: lines.join("\n"),
            verb: None,
        });
    }
    let stride = keys.len() / KV_PRESENT_QUERIES;
    let mut asked: Vec<String> = (0..KV_PRESENT_QUERIES)
        .map(|i| keys[i * stride + rng.below(stride)].clone())
        .collect();
    let present_keys = asked.len();
    while asked.len() < present_keys + KV_ABSENT_QUERIES {
        let key = format!("k-{}", hex(rng, 5));
        if !seen.contains(&key) && !asked.contains(&key) {
            asked.push(key);
        }
    }
    Parts {
        queries: asked
            .iter()
            .map(|key| Query {
                text: format!("GET {key}"),
                key: format!("SET {key} = "),
            })
            .collect(),
        expected: asked
            .iter()
            .map(|key| latest.get(key).cloned().unwrap_or_default())
            .collect(),
        atomic: vec![true; asked.len()],
        turns,
        present,
    }
}

fn fresh_key(rng: &mut Rng, seen: &mut BTreeSet<String>, keys: &mut Vec<String>) -> String {
    loop {
        let key = format!("k-{}", hex(rng, 5));
        if seen.insert(key.clone()) {
            keys.push(key.clone());
            return key;
        }
    }
}

const LOG_TURNS: usize = 320;
const ERROR_COUNTS: [usize; 6] = [1, 2, 3, 5, 8, 13];

pub(crate) fn timestamp(ms: u64) -> String {
    let (h, m, s, milli) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60, ms % 1000);
    format!("2026-10-06T{h:02}:{m:02}:{s:02}.{milli:03}Z")
}

/// Timestamped INFO and WARN traffic with six rare ERROR codes occurring 1,
/// 2, 3, 5, 8 and 13 times at seeded lines. Queries: which errors occurred,
/// and per code how many times, first and last occurrence; plus one code
/// that never occurred.
fn gen_logs(rng: &mut Rng) -> Parts {
    let per_turn: Vec<usize> = (0..LOG_TURNS).map(|_| rng.range(12, 20)).collect();
    let total_lines: usize = per_turn.iter().sum();
    let mut codes: Vec<String> = Vec::new();
    while codes.len() < ERROR_COUNTS.len() + 1 {
        let code = format!("E{}", 1000 + rng.below(1000));
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    let absent = codes.pop().unwrap_or_default();
    let mut order: Vec<usize> = (0..ERROR_COUNTS.len()).collect();
    rng.shuffle(&mut order);
    let mut bag: Vec<String> = order
        .iter()
        .zip(ERROR_COUNTS)
        .flat_map(|(&code, n)| std::iter::repeat_n(codes[code].clone(), n))
        .collect();
    rng.shuffle(&mut bag);
    let mut slots = BTreeSet::new();
    while slots.len() < bag.len() {
        slots.insert(rng.below(total_lines));
    }
    let error_at: BTreeMap<usize, String> = slots.into_iter().zip(bag).collect();
    let warn_codes: Vec<String> = (0..5)
        .map(|_| format!("W{}", 2000 + rng.below(1000)))
        .collect();

    let mut seen: BTreeMap<String, (String, String, usize)> = BTreeMap::new();
    let mut present = BTreeSet::new();
    let mut ms = 0_u64;
    let mut line_no = 0;
    let mut turns = Vec::with_capacity(LOG_TURNS);
    for &n in &per_turn {
        let mut lines = Vec::with_capacity(n);
        for _ in 0..n {
            ms += rng.range(200, 12_000) as u64;
            let ts = timestamp(ms);
            let svc = rng.pick(&SERVICES);
            let req = hex(rng, 6);
            let msg = format!("{}-{}", rng.pick(&WORDS), rng.pick(&WORDS));
            let line = if let Some(code) = error_at.get(&line_no) {
                let entry = seen
                    .entry(code.clone())
                    .or_insert_with(|| (ts.clone(), ts.clone(), 0));
                entry.1.clone_from(&ts);
                entry.2 += 1;
                present.insert(ts.clone());
                format!("{ts} ERROR svc={svc} req={req} code={code} msg={msg}")
            } else if rng.below(100) < 6 {
                let code = rng.pick(&warn_codes);
                format!("{ts} WARN svc={svc} req={req} code={code} msg={msg}")
            } else {
                let lat = rng.range(1, 999);
                format!("{ts} INFO svc={svc} req={req} lat={lat}ms msg={msg}")
            };
            lines.push(line);
            line_no += 1;
        }
        turns.push(Turn {
            text: lines.join("\n"),
            verb: None,
        });
    }

    let mut queries = vec![Query {
        text: "ERRORS".to_owned(),
        key: "ERROR".to_owned(),
    }];
    let mut expected = vec![seen.keys().cloned().collect::<Vec<_>>().join(",")];
    let mut atomic = vec![true];
    for (code, (first, last, count)) in &seen {
        present.insert(code.clone());
        for (verb, answer, is_atom) in [
            ("COUNT", count.to_string(), false),
            ("FIRST", first.clone(), true),
            ("LAST", last.clone(), true),
        ] {
            queries.push(Query {
                text: format!("{verb} {code}"),
                key: format!("code={code}"),
            });
            expected.push(answer);
            atomic.push(is_atom);
        }
    }
    queries.push(Query {
        text: format!("COUNT {absent}"),
        key: format!("code={absent}"),
    });
    expected.push("0".to_owned());
    atomic.push(false);
    Parts {
        turns,
        queries,
        expected,
        atomic,
        present,
    }
}

/// The fixed reader: answers `q` from `chunks` (restored references first,
/// oldest first, then the live window in order). An empty answer abstains.
pub(crate) fn read(arm: Arm, q: &Query, chunks: &[&str]) -> String {
    let lines = chunks.iter().flat_map(|c| c.lines()).map(str::trim);
    match arm {
        Arm::Needle => lines
            .filter_map(|l| l.strip_prefix(q.key.as_str()))
            .last()
            .map(|rest| rest.trim().to_owned())
            .unwrap_or_default(),
        Arm::KvOffload => {
            let mut best: Option<(u64, &str)> = None;
            for rest in lines.filter_map(|l| l.strip_prefix(q.key.as_str())) {
                let mut tokens = rest.split_whitespace();
                let Some(value) = tokens.next() else { continue };
                let seq = tokens
                    .next()
                    .and_then(|t| t.strip_prefix('#'))
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0);
                if best.is_none_or(|(b, _)| seq >= b) {
                    best = Some((seq, value));
                }
            }
            best.map(|(_, v)| v.to_owned()).unwrap_or_default()
        }
        Arm::Sketchpad => read_board(&lines.collect::<Vec<_>>()),
        Arm::LogTriage => read_logs(q, &lines.collect::<Vec<_>>()),
        Arm::Relink => arms_epoch::read_resource(q, &lines.collect::<Vec<_>>()),
        Arm::MultiEpoch => arms_epoch::read_mixed(q, chunks),
        Arm::StreamFrames => arms_epoch::read_frames(&lines.collect::<Vec<_>>()),
        Arm::KvInterleaved => read(Arm::KvOffload, q, chunks),
        Arm::Obligations | Arm::LateResults | Arm::Transactions | Arm::ToolLoop => {
            arms_next::read_with(arm, q, &lines.collect::<Vec<_>>()).0
        }
    }
}

pub(crate) fn parse_rows(lines: &[&str]) -> Option<Grid> {
    let mut grid: Grid = [0; 81];
    for row in 0..9 {
        let digits = lines.get(row)?.strip_prefix(&format!("r{} ", row + 1))?;
        let bytes = digits.as_bytes();
        if bytes.len() != 9 || !bytes.iter().all(u8::is_ascii_digit) {
            return None;
        }
        for (col, b) in bytes.iter().enumerate() {
            grid[row * 9 + col] = b - b'0';
        }
    }
    Some(grid)
}

pub(crate) fn parse_move(line: &str) -> Option<(u32, usize, u8)> {
    let (mv, rest) = line.strip_prefix("MOVE m")?.split_once(": r")?;
    let b = rest.as_bytes();
    if b.len() != 5 || b[1] != b'c' || b[3] != b'=' {
        return None;
    }
    let digit = |x: u8| x.is_ascii_digit().then(|| x - b'0');
    let (r, c, d) = (digit(b[0])?, digit(b[2])?, digit(b[4])?);
    if !(1..=9).contains(&r) || !(1..=9).contains(&c) {
        return None;
    }
    Some((mv.parse().ok()?, usize::from((r - 1) * 9 + (c - 1)), d))
}

/// Latest complete snapshot (highest version), then every visible move
/// past it in move order. Unknown cells read `?`.
fn read_board(lines: &[&str]) -> String {
    let mut best: Option<(u32, Grid)> = None;
    let mut moves: BTreeMap<u32, (usize, u8)> = BTreeMap::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(version) = line
            .strip_prefix("BOARD @m")
            .and_then(|v| v.parse::<u32>().ok())
        {
            if let Some(grid) = parse_rows(&lines[i + 1..])
                && best.is_none_or(|(v, _)| version >= v)
            {
                best = Some((version, grid));
            }
        } else if let Some((mv, cell, digit)) = parse_move(line) {
            moves.insert(mv, (cell, digit));
        }
    }
    let (version, mut cells) = match best {
        Some((v, grid)) => (v, grid.map(Some)),
        None => (0, [None; 81]),
    };
    for (cell, digit) in moves.range(version + 1..).map(|(_, m)| *m) {
        cells[cell] = Some(digit);
    }
    cells
        .iter()
        .map(|c| c.map_or('?', |d| char::from(b'0' + d)))
        .collect()
}

fn read_logs(q: &Query, lines: &[&str]) -> String {
    let mut errors: BTreeSet<(&str, &str, &str)> = BTreeSet::new();
    for &line in lines {
        let mut tokens = line.split_whitespace();
        let (Some(ts), Some("ERROR")) = (tokens.next(), tokens.next()) else {
            continue;
        };
        if let Some(code) = tokens.find_map(|t| t.strip_prefix("code=")) {
            errors.insert((ts, code, line));
        }
    }
    if q.text == "ERRORS" {
        let codes: BTreeSet<&str> = errors.iter().map(|e| e.1).collect();
        return codes.into_iter().collect::<Vec<_>>().join(",");
    }
    let Some((verb, code)) = q.text.split_once(' ') else {
        return String::new();
    };
    let stamps = errors.iter().filter(|e| e.1 == code).map(|e| e.0);
    match verb {
        "COUNT" => stamps.count().to_string(),
        "FIRST" => stamps.min().unwrap_or_default().to_owned(),
        "LAST" => stamps.max().unwrap_or_default().to_owned(),
        _ => String::new(),
    }
}
