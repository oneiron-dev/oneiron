//! The two loop-2 arms: relink-after-compaction and multi-epoch. Seeded
//! generators, the environment a `get` reads, the fixed readers and the
//! scorer.
//!
//! Frozen once committed, like the loop-1 arms: a generator, query set,
//! reader or scorer here never changes between rounds. Both arms ask some
//! queries mid-session (`Episode::ask_at`), at the turn the generator names;
//! a strategy sees a query only when it is asked.
//!
//! relink-after-compaction: a working session reads files, opens handles and
//! loads skills (named bodies, `<name>@<v> <i>/<n> <text>` per line), and
//! later needs each again. Between uses a body may be rewritten in the stream
//! (a new version with its body) or change outside the session (a notice and
//! no body: only the environment holds the new one). Every need sits more
//! than [`GAP_TOK`] stream tokens after that resource's last body in the
//! stream, so no in-budget window still holds it in its log: every need is
//! post-compaction. Answer = the needed body's current content, exactly. An
//! older version's content is a stale answer and fails.
//!
//! multi-epoch: five segments of [`SEG_TOK`] stream tokens each (more than
//! the default budget, so every in-budget strategy compacts inside every
//! segment: at least four compactions, five epochs). Needles, KV writes and
//! log errors are planted across the segments in the loop-1 formats and
//! read by the loop-1 readers. Queries come after segments 2, 3 and 4 about
//! earlier segments (answers as of that moment) and at the end about every
//! segment. Each query reports under its fact's epoch of origin.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use super::arms::{
    Arm, Episode, Grid, Query, Rng, SERVICES, Score, Turn, Verb, WORDS, filler_line, filler_lines,
    hex, parse_rows, read, row_line, timestamp,
};
use super::window::tokens;

/// Stream tokens between a resource's last body and a need for it: 1.25x
/// the default budget.
pub(crate) const GAP_TOK: u64 = 40_960;
/// Stream tokens per multi-epoch segment: 1.25x the default budget.
pub(crate) const SEG_TOK: u64 = 40_960;
pub(crate) const SEGMENTS: usize = 5;

fn body_line(name: &str, v: u32, i: usize, n: usize, text: &str) -> String {
    format!("{name}@{v} {i:02}/{n:02} {text}")
}

/// One named resource: every version's body lines and the turns at which
/// each version became current.
pub(crate) struct Resource {
    name: String,
    /// Body lines per version (index 0 is v1), without the line prefix.
    versions: Vec<Vec<String>>,
    /// `(turn, version)`: `version` is current from `turn` on.
    events: Vec<(usize, u32)>,
}

/// The environment: what a `get` reads (the file system, the skill hub,
/// the handle registry). Strategies reach it only through the harness.
#[derive(Default)]
pub(crate) struct Env {
    resources: Vec<Resource>,
}

impl Env {
    pub(crate) fn is_empty(&self) -> bool {
        self.resources.is_empty()
    }

    fn find(&self, name: &str) -> Option<&Resource> {
        self.resources.iter().find(|r| r.name == name)
    }

    /// The current version of `name` at `turn` (none before it exists).
    pub(crate) fn current(&self, name: &str, turn: usize) -> Option<u32> {
        self.find(name)?
            .events
            .iter()
            .filter(|(t, _)| *t <= turn)
            .map(|(_, v)| *v)
            .max()
    }

    /// The rendered body of `name` at `version`: what a read or a `get`
    /// shows.
    pub(crate) fn body(&self, name: &str, version: u32) -> Option<String> {
        let lines = self
            .find(name)?
            .versions
            .get((version as usize).checked_sub(1)?)?;
        let n = lines.len();
        Some(
            lines
                .iter()
                .enumerate()
                .map(|(i, t)| body_line(name, version, i + 1, n, t))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    }

    /// The content the reader answers with for `version`.
    pub(crate) fn content(&self, name: &str, version: u32) -> Option<String> {
        Some(
            self.find(name)?
                .versions
                .get((version as usize).checked_sub(1)?)?
                .join("\n"),
        )
    }

    /// The first turn at which `version` of `name` became current.
    pub(crate) fn version_turn(&self, name: &str, version: u32) -> Option<usize> {
        self.find(name)?
            .events
            .iter()
            .find(|(_, v)| *v == version)
            .map(|(t, _)| *t)
    }

    /// Every resource name.
    pub(crate) fn names(&self) -> impl Iterator<Item = &str> {
        self.resources.iter().map(|r| r.name.as_str())
    }

    /// Every `(version, turn it became current)` of `name`.
    pub(crate) fn versions(&self, name: &str) -> Vec<(u32, usize)> {
        let mut out: Vec<(u32, usize)> = Vec::new();
        for &(t, v) in self.find(name).map_or(&[][..], |r| r.events.as_slice()) {
            if !out.iter().any(|(x, _)| *x == v) {
                out.push((v, t));
            }
        }
        out
    }

    pub(crate) fn hash_into(&self, h: &mut blake3::Hasher) {
        for r in &self.resources {
            h.update(format!("{}{:?}{:?}", r.name, r.versions, r.events).as_bytes());
        }
    }
}

/// The loop-2 breakdown beside the loop-1 score.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Extra {
    /// Wrong answers that are an older version's content (relink).
    pub(crate) stale: u32,
    /// Per bucket `(correct, total)`: epoch of origin (multi-epoch) or need
    /// kind (relink: 0 only one version ever existed and the stream showed
    /// it, 1 rewritten in the stream, 2 changed outside the session).
    pub(crate) buckets: Vec<(u32, u32)>,
}

/// What the loop-2 generators hand to `Episode::generate`.
pub(crate) struct Generated {
    pub(crate) turns: Vec<Turn>,
    pub(crate) queries: Vec<Query>,
    pub(crate) expected: Vec<String>,
    pub(crate) atomic: Vec<bool>,
    pub(crate) present: BTreeSet<String>,
    pub(crate) ask_at: Vec<Option<usize>>,
    pub(crate) origin: Vec<u8>,
    pub(crate) env: Env,
    pub(crate) truth: Vec<(usize, Grid)>,
}

const FILES: usize = 6;
const SKILLS: usize = 3;
const HANDLES: usize = 3;
/// Stream positions (tokens) of the three change slots and need waves.
const SLOT_AT: [u64; 3] = [9_500, 82_000, 154_000];
const WAVE_AT: [u64; 3] = [62_000, 134_000, 206_000];
const SLOT_STRIDE: u64 = 650;
const NEED_STRIDE: u64 = 1_400;
const HOT: usize = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Skill,
    Handle,
}

fn code_line(rng: &mut Rng) -> String {
    let (a, b, c) = (*rng.pick(&WORDS), *rng.pick(&WORDS), *rng.pick(&WORDS));
    let n = rng.range(1, 9999);
    match rng.below(5) {
        0 => format!("let {a}_{b} = {c}({n}, \"{a}\");"),
        1 => format!("fn {a}_{b}(x: u32) -> u32 {{ x * {n} + {c} }}"),
        2 => format!("if {a} > {n} {{ return {b}_{c}; }}"),
        3 => format!("// {a} {b} {c} {n}"),
        _ => format!("use crate::{a}::{b}_{c};"),
    }
}

fn skill_line(rng: &mut Rng, i: usize) -> String {
    let (a, b, c) = (*rng.pick(&WORDS), *rng.pick(&WORDS), *rng.pick(&WORDS));
    let n = rng.range(1, 999);
    if rng.below(3) == 0 {
        format!("check: {a} {b} must stay under {n}")
    } else {
        format!("step {}: {a} the {b}-{c} with --{a}={n}", i + 1)
    }
}

fn handle_line(rng: &mut Rng, target: &str) -> String {
    format!("token={} target={target}", hex(rng, 24))
}

fn fresh_body(rng: &mut Rng, kind: Kind, target: &str) -> Vec<String> {
    match kind {
        Kind::File => (0..rng.range(16, 32)).map(|_| code_line(rng)).collect(),
        Kind::Skill => (0..rng.range(6, 12)).map(|i| skill_line(rng, i)).collect(),
        Kind::Handle => vec![handle_line(rng, target)],
    }
}

/// A new version: one to three lines rewritten (a handle: a new token).
fn next_body(rng: &mut Rng, kind: Kind, prev: &[String], target: &str) -> Vec<String> {
    if kind == Kind::Handle {
        return vec![handle_line(rng, target)];
    }
    let mut body = prev.to_vec();
    for _ in 0..rng.range(1, 3) {
        let at = rng.below(body.len());
        loop {
            let line = if kind == Kind::File {
                code_line(rng)
            } else {
                skill_line(rng, at)
            };
            if line != body[at] {
                body[at] = line;
                break;
            }
        }
    }
    body
}

#[derive(Clone, Copy)]
enum Ev {
    /// The stream shows the body: `fresh` is the first read, `bump` makes a
    /// new version first (a write), neither re-reads the current one.
    Read {
        res: usize,
        bump: bool,
    },
    /// A new version outside the session: notice only.
    Notice {
        res: usize,
    },
    Need {
        res: usize,
    },
}

/// The relink-after-compaction generator. Twelve resources (six files,
/// three skills, three handles), each read once at the start, then three
/// change slots and three need waves: each slot gives every resource none,
/// a rewrite in the stream, or a change outside the session (and a re-read
/// of the four hot resources); each wave needs every resource once, more
/// than [`GAP_TOK`] tokens after its last body in the stream.
pub(crate) fn gen_relink(rng: &mut Rng) -> Generated {
    let mut kinds = vec![Kind::File; FILES];
    kinds.extend([Kind::Skill; SKILLS]);
    kinds.extend([Kind::Handle; HANDLES]);
    let mut names: Vec<String> = Vec::new();
    let mut targets: Vec<String> = Vec::new();
    for &kind in &kinds {
        loop {
            let (a, b) = (*rng.pick(&WORDS), *rng.pick(&WORDS));
            let name = match kind {
                Kind::File => format!("file:src/{a}_{b}.rs"),
                Kind::Skill => format!("skill:{a}-{b}"),
                Kind::Handle => format!("handle:{}-{a}", rng.pick(&SERVICES)),
            };
            if !names.contains(&name) {
                names.push(name);
                targets.push(format!("{}:{b}", rng.pick(&SERVICES)));
                break;
            }
        }
    }
    let n = names.len();

    let mut plan: Vec<(u64, Ev)> = Vec::new();
    let mut order: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut order);
    for (k, &res) in order.iter().enumerate() {
        plan.push((200 + 700 * k as u64, Ev::Read { res, bump: false }));
    }
    let mut hot: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut hot);
    hot.truncate(HOT);
    for (slot, &base) in SLOT_AT.iter().enumerate() {
        rng.shuffle(&mut order);
        for (k, &res) in order.iter().enumerate() {
            let at = base + SLOT_STRIDE * k as u64;
            match rng.below(100) {
                0..30 => {}
                30..65 => plan.push((at, Ev::Read { res, bump: true })),
                _ => plan.push((at, Ev::Notice { res })),
            }
            if hot.contains(&res) && (slot + res) % 2 == 0 {
                plan.push((at + 300, Ev::Read { res, bump: false }));
            }
        }
        rng.shuffle(&mut order);
        for (k, &res) in order.iter().enumerate() {
            plan.push((WAVE_AT[slot] + NEED_STRIDE * k as u64, Ev::Need { res }));
        }
    }
    plan.sort_by_key(|(at, _)| *at);

    let mut env = Env {
        resources: names
            .iter()
            .zip(&kinds)
            .zip(&targets)
            .map(|((name, &kind), target)| Resource {
                name: name.clone(),
                versions: vec![fresh_body(rng, kind, target)],
                events: Vec::new(),
            })
            .collect(),
    };
    let mut turns: Vec<Turn> = Vec::new();
    let mut queries = Vec::new();
    let mut expected = Vec::new();
    let mut ask_at = Vec::new();
    let mut origin = Vec::new();
    // Versions whose body the stream has shown, per resource.
    let mut shown: Vec<BTreeSet<u32>> = vec![BTreeSet::new(); n];
    let mut pos = 0_u64;
    let mut next = 0;
    while next < plan.len() {
        let t = turns.len();
        let turn = if plan[next].0 <= pos {
            let ev = plan[next].1;
            next += 1;
            match ev {
                Ev::Read { res, bump } => {
                    let r = &mut env.resources[res];
                    let mut version = r.versions.len() as u32;
                    if bump {
                        let body = next_body(
                            rng,
                            kinds[res],
                            &r.versions[version as usize - 1],
                            &targets[res],
                        );
                        r.versions.push(body);
                        version += 1;
                    }
                    let first = r.events.is_empty();
                    r.events.push((t, version));
                    shown[res].insert(version);
                    let verb = match (kinds[res], first, bump) {
                        (Kind::File, _, true) => "WRITE",
                        (Kind::Skill, _, _) => "LOAD",
                        (Kind::Handle, true, _) => "OPEN",
                        (Kind::Handle, _, true) => "ROTATE",
                        (Kind::Handle, _, false) => "INFO",
                        (Kind::File, _, false) => "READ",
                    };
                    let name = names[res].clone();
                    let mut text = format!("{verb} {name} v{version}");
                    text.push('\n');
                    text.push_str(&env.body(&name, version).unwrap_or_default());
                    Turn {
                        text,
                        verb: Some(Verb::Read { res: name, version }),
                    }
                }
                Ev::Notice { res } => {
                    let r = &mut env.resources[res];
                    let prev = r.versions.len();
                    let body = next_body(rng, kinds[res], &r.versions[prev - 1], &targets[res]);
                    r.versions.push(body);
                    let version = prev as u32 + 1;
                    r.events.push((t, version));
                    let mut lines = vec![format!(
                        "NOTICE {} changed outside this session, now v{version}",
                        names[res]
                    )];
                    lines.extend(filler_lines(rng, 1, 2));
                    Turn {
                        text: lines.join("\n"),
                        verb: Some(Verb::Changed {
                            res: names[res].clone(),
                            version,
                        }),
                    }
                }
                Ev::Need { res } => {
                    let name = &names[res];
                    let version = env.current(name, t).unwrap_or(0);
                    let kind = if !shown[res].contains(&version) {
                        2
                    } else if shown[res].len() > 1 {
                        1
                    } else {
                        0
                    };
                    queries.push(Query {
                        text: format!("NEED {name}"),
                        key: format!("{name}@"),
                    });
                    expected.push(env.content(name, version).unwrap_or_default());
                    ask_at.push(Some(t));
                    origin.push(kind);
                    let mut lines = vec![format!("TASK the next step needs {name}")];
                    lines.extend(filler_lines(rng, 2, 4));
                    Turn {
                        text: lines.join("\n"),
                        verb: None,
                    }
                }
            }
        } else {
            Turn {
                text: filler_lines(rng, 8, 16).join("\n"),
                verb: None,
            }
        };
        pos += tokens(&turn.text);
        turns.push(turn);
    }
    let q = queries.len();
    Generated {
        turns,
        queries,
        expected,
        atomic: vec![false; q],
        present: BTreeSet::new(),
        ask_at,
        origin,
        env,
        truth: Vec::new(),
    }
}

const SEG_NEEDLES: usize = 4;
const ERROR_COUNTS: [usize; 6] = [1, 2, 3, 4, 5, 6];

struct LogClock {
    ms: u64,
}

/// The multi-epoch generator: five segments of [`SEG_TOK`] tokens; half the
/// turns prose, a quarter KV writes (a fifth of them overwriting a key from
/// any earlier segment), a quarter log lines. Four needles per segment; six
/// error codes with 1..6 occurrences each, scattered across the stream.
pub(crate) fn gen_multi_epoch(rng: &mut Rng) -> Generated {
    let total = SEG_TOK * SEGMENTS as u64;
    let mut phrases: Vec<String> = Vec::new();
    while phrases.len() < SEG_NEEDLES * SEGMENTS {
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
    let quarter = SEG_TOK / SEG_NEEDLES as u64;
    let mut needle_at: Vec<(u64, usize)> = (0..SEG_NEEDLES * SEGMENTS)
        .map(|i| {
            let (s, k) = ((i / SEG_NEEDLES) as u64, (i % SEG_NEEDLES) as u64);
            (
                s * SEG_TOK + k * quarter + 500 + rng.below((quarter - 2_000) as usize) as u64,
                i,
            )
        })
        .collect();
    needle_at.sort_unstable();
    let mut codes: Vec<String> = Vec::new();
    while codes.len() < ERROR_COUNTS.len() {
        let code = format!("E{}", 1000 + rng.below(1000));
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    let mut counts = ERROR_COUNTS;
    rng.shuffle(&mut counts);
    let mut error_at: Vec<(u64, usize)> = codes
        .iter()
        .enumerate()
        .flat_map(|(c, _)| std::iter::repeat_n(c, counts[c]))
        .map(|c| (1_000 + rng.below((total - 4_000) as usize) as u64, c))
        .collect();
    error_at.sort_unstable();
    let warn_codes: Vec<String> = (0..5)
        .map(|_| format!("W{}", 2000 + rng.below(1000)))
        .collect();

    let mut turns: Vec<Turn> = Vec::new();
    let mut seg_of: Vec<usize> = Vec::new();
    let mut needle_turn = vec![0_usize; phrases.len()];
    // key -> (turn, seq, value) writes in order.
    let mut writes: BTreeMap<String, Vec<(usize, u32, String)>> = BTreeMap::new();
    let mut keys: Vec<String> = Vec::new();
    let mut seen_keys = BTreeSet::new();
    // code -> (turn, timestamp) occurrences in order.
    let mut occurrences: Vec<Vec<(usize, String)>> = vec![Vec::new(); codes.len()];
    let mut present = BTreeSet::new();
    let mut clock = LogClock { ms: 0 };
    let mut seq = 0_u32;
    let (mut pos, mut ni, mut ei) = (0_u64, 0, 0);
    while pos < total || ni < needle_at.len() || ei < error_at.len() {
        let t = turns.len();
        let seg = ((pos / SEG_TOK) as usize).min(SEGMENTS - 1);
        let must_log = pos >= total && ei < error_at.len();
        let roll = if must_log { 80 } else { rng.below(100) };
        let mut lines = if roll < 50 {
            filler_lines(rng, 6, 10)
        } else if roll < 75 {
            let mut lines = Vec::new();
            for _ in 0..rng.range(4, 7) {
                seq += 1;
                let key = if !keys.is_empty() && rng.below(100) < 20 {
                    keys[rng.below(keys.len())].clone()
                } else {
                    loop {
                        let key = format!("k-{}", hex(rng, 5));
                        if seen_keys.insert(key.clone()) {
                            keys.push(key.clone());
                            break key;
                        }
                    }
                };
                let value = hex(rng, 20);
                lines.push(format!("SET {key} = {value} #{seq:06}"));
                present.insert(value.clone());
                writes.entry(key).or_default().push((t, seq, value));
            }
            let at = rng.below(lines.len() + 1);
            lines.insert(at, filler_line(rng));
            lines
        } else {
            let mut lines = Vec::new();
            for _ in 0..rng.range(8, 14) {
                clock.ms += rng.range(200, 12_000) as u64;
                let ts = timestamp(clock.ms);
                let svc = rng.pick(&SERVICES);
                let req = hex(rng, 6);
                let msg = format!("{}-{}", rng.pick(&WORDS), rng.pick(&WORDS));
                let line = if ei < error_at.len() && error_at[ei].0 <= pos {
                    let code = &codes[error_at[ei].1];
                    occurrences[error_at[ei].1].push((t, ts.clone()));
                    present.insert(ts.clone());
                    ei += 1;
                    format!("{ts} ERROR svc={svc} req={req} code={code} msg={msg}")
                } else if rng.below(100) < 6 {
                    let code = rng.pick(&warn_codes);
                    format!("{ts} WARN svc={svc} req={req} code={code} msg={msg}")
                } else {
                    let lat = rng.range(1, 999);
                    format!("{ts} INFO svc={svc} req={req} lat={lat}ms msg={msg}")
                };
                lines.push(line);
            }
            lines
        };
        while ni < needle_at.len() && needle_at[ni].0 <= pos {
            let i = needle_at[ni].1;
            let at = rng.below(lines.len() + 1);
            lines.insert(at, format!("NEEDLE n{i:02}: {}", phrases[i]));
            needle_turn[i] = t;
            ni += 1;
        }
        let text = lines.join("\n");
        pos += tokens(&text);
        turns.push(Turn { text, verb: None });
        seg_of.push(seg);
    }
    for code in &codes {
        present.insert(code.clone());
    }
    present.extend(phrases.iter().cloned());

    let mut queries = Vec::new();
    let mut expected = Vec::new();
    let mut atomic = Vec::new();
    let mut ask_at = Vec::new();
    let mut origin = Vec::new();
    let mut ask = |q: Query, want: String, is_atom: bool, at: Option<usize>, from: usize| {
        queries.push(q);
        expected.push(want);
        atomic.push(is_atom);
        ask_at.push(at);
        origin.push(from as u8);
    };
    let last_turn = |s: usize| seg_of.iter().rposition(|&x| x == s).unwrap_or(0);
    // The newest write of `key` at or before `t`.
    let latest = |key: &str, t: usize| {
        writes
            .get(key)
            .and_then(|w| w.iter().rev().find(|(wt, _, _)| *wt <= t))
            .map(|(wt, _, v)| (seg_of[*wt], v.clone()))
    };
    let needle_q = |i: usize| Query {
        text: format!("RECALL NEEDLE n{i:02}"),
        key: format!("NEEDLE n{i:02}:"),
    };
    let get_q = |key: &str| Query {
        text: format!("GET {key}"),
        key: format!("SET {key} = "),
    };
    let log_q = |verb: &str, code: &str| Query {
        text: format!("{verb} {code}"),
        key: format!("code={code}"),
    };
    let checkpoints: Vec<(Option<usize>, usize)> = (1..SEGMENTS - 1)
        .map(|s| (Some(last_turn(s)), s))
        .chain(std::iter::once((None, SEGMENTS)))
        .collect();
    let mut key_list: Vec<&String> = writes.keys().collect();
    key_list.sort();
    for (at, upto) in checkpoints {
        let t = at.unwrap_or(turns.len() - 1);
        let end = at.is_none();
        for e in 0..upto {
            let ids: Vec<usize> = (e * SEG_NEEDLES..(e + 1) * SEG_NEEDLES).collect();
            let picked: Vec<usize> = if end {
                ids
            } else {
                let mut ids = ids;
                rng.shuffle(&mut ids);
                ids.truncate(2);
                ids.sort_unstable();
                ids
            };
            for i in picked {
                ask(needle_q(i), phrases[i].clone(), true, at, e);
            }
            let mut in_seg: Vec<(&String, String)> = key_list
                .iter()
                .filter_map(|k| latest(k, t).filter(|(s, _)| *s == e).map(|(_, v)| (*k, v)))
                .collect();
            rng.shuffle(&mut in_seg);
            in_seg.truncate(2);
            in_seg.sort();
            for (k, v) in in_seg {
                ask(get_q(k), v, true, at, e);
            }
        }
        let seen: Vec<usize> = (0..codes.len())
            .filter(|&c| occurrences[c].iter().any(|(ot, _)| *ot <= t))
            .collect();
        let chosen: Vec<usize> = if end {
            seen
        } else {
            let mut s = seen;
            rng.shuffle(&mut s);
            s.truncate(2);
            s.sort_unstable();
            s
        };
        for c in chosen {
            let occ: Vec<&(usize, String)> =
                occurrences[c].iter().filter(|(ot, _)| *ot <= t).collect();
            let (first, last) = (occ[0], occ[occ.len() - 1]);
            if end {
                ask(
                    log_q("COUNT", &codes[c]),
                    occ.len().to_string(),
                    false,
                    at,
                    seg_of[first.0],
                );
            }
            ask(
                log_q("FIRST", &codes[c]),
                first.1.clone(),
                true,
                at,
                seg_of[first.0],
            );
            ask(
                log_q("LAST", &codes[c]),
                last.1.clone(),
                true,
                at,
                seg_of[last.0],
            );
        }
    }
    Generated {
        turns,
        queries,
        expected,
        atomic,
        present,
        ask_at,
        origin,
        env: Env::default(),
        truth: Vec::new(),
    }
}

const FRAME_TURNS: usize = 1000;

#[derive(Clone, Copy)]
enum Frame {
    Key(u32, Grid),
    Delta(u32, u8, u8),
}

fn frame_lines(frame: Frame) -> Vec<String> {
    match frame {
        Frame::Key(epoch, grid) => {
            let mut lines = vec![format!("<board epoch={epoch}>")];
            lines.extend((0..9).map(|row| row_line(&grid, row)));
            lines
        }
        Frame::Delta(epoch, cell, digit) => vec![format!(
            "<delta epoch={epoch}> r{}c{}={digit}",
            cell / 9 + 1,
            cell % 9 + 1
        )],
    }
}

/// The stream-frames generator (F-C18, the STREAM-mode law). An 81-cell
/// board evolves elsewhere and arrives inside tool results: a keyframe
/// `<board epoch=N>` with the nine rows opens each epoch (dev: every 45-55
/// turns; held-out: every 20-120), deltas `<delta epoch=N> rIcJ=D` ride
/// 40% of the other turns, filler elsewhere. Stale frames ride some frame
/// turns (dev 5%: a delta of the previous epoch, chosen so that applying it
/// again leaves a cell wrong that no later delta touches; held-out 15%, a
/// third of them a stale keyframe of the previous epoch). The query at the
/// end asks for the board.
pub(crate) fn gen_stream_frames(rng: &mut Rng, heldout: bool) -> Generated {
    let stale_pct = if heldout { 15 } else { 5 };
    let mut grid: Grid = [0; 81];
    for cell in &mut grid {
        *cell = if rng.below(100) < 45 {
            0
        } else {
            rng.range(1, 9) as u8
        };
    }
    let mut keys = BTreeSet::new();
    let mut t = 0;
    while t < FRAME_TURNS {
        keys.insert(t);
        t += if heldout {
            rng.range(20, 120)
        } else {
            rng.range(45, 55)
        };
    }
    let mut frames: Vec<Option<Frame>> = Vec::with_capacity(FRAME_TURNS);
    let mut truth = vec![(0, grid)];
    let mut key_grids: Vec<Grid> = vec![[0; 81]];
    let mut epoch_deltas: Vec<Vec<(u8, u8)>> = vec![Vec::new()];
    let mut last_touch = [0_usize; 81];
    let mut epoch = 0_u32;
    for t in 0..FRAME_TURNS {
        if keys.contains(&t) {
            epoch += 1;
            key_grids.push(grid);
            epoch_deltas.push(Vec::new());
            frames.push(Some(Frame::Key(epoch, grid)));
        } else if rng.below(100) < 40 {
            let cell = rng.below(81) as u8;
            let digit = rng.range(1, 9) as u8;
            grid[usize::from(cell)] = digit;
            last_touch[usize::from(cell)] = t;
            truth.push((t, grid));
            epoch_deltas[epoch as usize].push((cell, digit));
            frames.push(Some(Frame::Delta(epoch, cell, digit)));
        } else {
            frames.push(None);
        }
    }
    let final_grid = grid;

    let mut turns = Vec::with_capacity(FRAME_TURNS);
    let mut epoch_at = 0_u32;
    for (t, frame) in frames.into_iter().enumerate() {
        let mut blocks: Vec<Vec<String>> = filler_lines(rng, 5, 9)
            .into_iter()
            .map(|l| vec![l])
            .collect();
        if let Some(frame) = frame {
            if let Frame::Key(e, _) = frame {
                epoch_at = e;
            }
            let at = rng.below(blocks.len() + 1);
            blocks.insert(at, frame_lines(frame));
            if epoch_at >= 2 && rng.below(100) < stale_pct {
                let prev = epoch_at - 1;
                let stale = if heldout && rng.below(3) == 0 {
                    Some(Frame::Key(prev, key_grids[prev as usize]))
                } else {
                    let fits: Vec<(u8, u8)> = epoch_deltas[prev as usize]
                        .iter()
                        .copied()
                        .filter(|&(c, d)| {
                            last_touch[usize::from(c)] < t && final_grid[usize::from(c)] != d
                        })
                        .collect();
                    (!fits.is_empty()).then(|| {
                        let (c, d) = fits[rng.below(fits.len())];
                        Frame::Delta(prev, c, d)
                    })
                };
                if let Some(stale) = stale {
                    let after = at + 1 + rng.below(blocks.len() - at);
                    blocks.insert(after, frame_lines(stale));
                }
            }
        }
        turns.push(Turn {
            text: blocks.concat().join("\n"),
            verb: None,
        });
    }
    let answer: String = final_grid.iter().map(|d| char::from(b'0' + d)).collect();
    Generated {
        turns,
        queries: vec![Query {
            text: "BOARD FINAL".to_owned(),
            key: "<board epoch=".to_owned(),
        }],
        expected: vec![answer],
        atomic: vec![false],
        present: BTreeSet::new(),
        ask_at: vec![None],
        origin: Vec::new(),
        env: Env::default(),
        truth,
    }
}

/// A visible frame: its epoch, what it carries, and the lines it spans.
pub(crate) enum Seen {
    Key(u32, Grid, Range<usize>),
    Delta(u32, usize, u8, usize),
}

/// Every complete frame among `lines`, in arrival order.
pub(crate) fn parse_frames(lines: &[&str]) -> Vec<Seen> {
    let digit = |x: u8| x.is_ascii_digit().then(|| x - b'0');
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(epoch) = line
            .strip_prefix("<board epoch=")
            .and_then(|r| r.strip_suffix('>'))
            .and_then(|e| e.parse::<u32>().ok())
        {
            if let Some(grid) = parse_rows(&lines[i + 1..]) {
                out.push(Seen::Key(epoch, grid, i..i + 10));
            }
        } else if let Some((epoch, rest)) = line
            .strip_prefix("<delta epoch=")
            .and_then(|r| r.split_once("> "))
            && let Ok(epoch) = epoch.parse::<u32>()
            && let [b'r', r, b'c', c, b'=', d] = rest.as_bytes()
            && let (Some(r), Some(c), Some(d)) = (digit(*r), digit(*c), digit(*d))
            && (1..=9).contains(&r)
            && (1..=9).contains(&c)
        {
            out.push(Seen::Delta(epoch, usize::from((r - 1) * 9 + (c - 1)), d, i));
        }
    }
    out
}

/// The frames reader (the STREAM-mode law): the keyframe with the highest
/// epoch, then the deltas carrying that epoch in arrival order; frames of
/// older epochs are ignored. With no keyframe, the deltas of the highest
/// epoch seen. Unknown cells read `?`.
pub(crate) fn read_frames(lines: &[&str]) -> String {
    let seen = parse_frames(lines);
    let Some(epoch) = seen
        .iter()
        .filter_map(|s| match s {
            Seen::Key(e, _, _) => Some(*e),
            Seen::Delta(..) => None,
        })
        .max()
        .or_else(|| {
            seen.iter()
                .filter_map(|s| match s {
                    Seen::Delta(e, ..) => Some(*e),
                    Seen::Key(..) => None,
                })
                .max()
        })
    else {
        return "?".repeat(81);
    };
    let mut cells: [Option<u8>; 81] = seen
        .iter()
        .rev()
        .find_map(|s| match s {
            Seen::Key(e, grid, _) if *e == epoch => Some(grid.map(Some)),
            _ => None,
        })
        .unwrap_or([None; 81]);
    for s in &seen {
        if let Seen::Delta(e, cell, digit, _) = s
            && *e == epoch
        {
            cells[*cell] = Some(*digit);
        }
    }
    cells
        .iter()
        .map(|c| c.map_or('?', |d| char::from(b'0' + d)))
        .collect()
}

/// The relink reader: the highest version of the keyed resource that is
/// complete among the visible lines (every line `1..=n` present), as its
/// content. A version cut or partly lost is not an answer.
pub(crate) fn read_resource(q: &Query, lines: &[&str]) -> String {
    let mut versions: BTreeMap<u32, (usize, BTreeMap<usize, &str>)> = BTreeMap::new();
    for line in lines {
        let Some(rest) = line.strip_prefix(q.key.as_str()) else {
            continue;
        };
        let Some((v, rest)) = rest.split_once(' ') else {
            continue;
        };
        let Some((at, text)) = rest.split_once(' ') else {
            continue;
        };
        let Some((i, n)) = at.split_once('/') else {
            continue;
        };
        let (Ok(v), Ok(i), Ok(n)) = (v.parse::<u32>(), i.parse::<usize>(), n.parse::<usize>())
        else {
            continue;
        };
        if i == 0 || i > n {
            continue;
        }
        let entry = versions.entry(v).or_insert_with(|| (n, BTreeMap::new()));
        if entry.0 == n {
            entry.1.entry(i).or_insert(text);
        }
    }
    versions
        .values()
        .rev()
        .find(|(n, got)| got.len() == *n)
        .map(|(_, got)| got.values().copied().collect::<Vec<_>>().join("\n"))
        .unwrap_or_default()
}

/// The multi-epoch reader: the loop-1 reader for the query's own fact type.
pub(crate) fn read_mixed(q: &Query, chunks: &[&str]) -> String {
    let arm = if q.text.starts_with("RECALL NEEDLE") {
        Arm::Needle
    } else if q.text.starts_with("GET ") {
        Arm::KvOffload
    } else {
        Arm::LogTriage
    };
    read(arm, q, chunks)
}

/// Scores a loop-2 episode: exact answers, stale answers (an older version's
/// content, relink), hallucinated atoms (multi-epoch, the loop-1 rule) and
/// the per-bucket tallies.
pub(crate) fn score(ep: &Episode, answers: &[String]) -> (Score, Extra) {
    if ep.arm == Arm::StreamFrames {
        let want = ep.expected[0].as_bytes();
        let got = answers.first().map_or(&[][..], |a| a.as_bytes());
        let correct = (0..81).filter(|&i| got.get(i) == Some(&want[i])).count() as u32;
        return (
            Score {
                value: f64::from(correct) / 81.0,
                correct,
                total: 81,
                hallucinated: 0,
            },
            Extra::default(),
        );
    }
    let mut score = Score {
        total: ep.queries.len() as u32,
        ..Score::default()
    };
    let buckets = ep.origin.iter().max().map_or(0, |m| *m as usize + 1);
    let mut extra = Extra {
        stale: 0,
        buckets: vec![(0, 0); buckets],
    };
    for (i, want) in ep.expected.iter().enumerate() {
        let got = answers.get(i).map_or("", String::as_str);
        let bucket = &mut extra.buckets[ep.origin[i] as usize];
        bucket.1 += 1;
        if got == want {
            score.correct += 1;
            bucket.0 += 1;
        } else if ep.arm == Arm::Relink && !got.is_empty() && is_older(ep, i, got) {
            extra.stale += 1;
        } else if ep.atomic[i]
            && !got.is_empty()
            && got.split(',').any(|atom| !ep.present.contains(atom))
        {
            score.hallucinated += 1;
        }
    }
    score.value = f64::from(score.correct) / f64::from(score.total.max(1));
    (score, extra)
}

fn is_older(ep: &Episode, i: usize, got: &str) -> bool {
    let name = ep.queries[i].key.trim_end_matches('@');
    let t = ep.ask_at[i].unwrap_or(ep.turns.len());
    let current = ep.env.current(name, t).unwrap_or(0);
    (1..current).any(|v| ep.env.content(name, v).as_deref() == Some(got))
}

/// The oracle every self-check holds the arm to: each query answered from
/// the stream up to its turn, plus (relink) the needed body as the
/// environment holds it then.
pub(crate) fn oracle_answers(ep: &Episode) -> Vec<String> {
    ep.queries
        .iter()
        .enumerate()
        .map(|(i, q)| {
            let end = ep.ask_at[i].map_or(ep.turns.len(), |t| t + 1);
            let mut chunks: Vec<String> = ep.turns[..end].iter().map(|t| t.text.clone()).collect();
            if ep.arm == Arm::Relink {
                let name = q.key.trim_end_matches('@');
                let t = end - 1;
                if let Some(body) = ep.env.current(name, t).and_then(|v| ep.env.body(name, v)) {
                    chunks.push(body);
                }
            }
            let refs: Vec<&str> = chunks.iter().map(String::as_str).collect();
            read(ep.arm, q, &refs)
        })
        .collect()
}

/// Structural invariants of the loop-2 arms. relink: every need sits more
/// than [`GAP_TOK`] stream tokens after its resource's last body. multi-epoch:
/// every segment holds at least [`SEG_TOK`] stream tokens.
pub(crate) fn check(ep: &Episode) -> Result<(), String> {
    match ep.arm {
        Arm::Relink => {
            for (i, q) in ep.queries.iter().enumerate() {
                let name = q.key.trim_end_matches('@');
                let Some(t) = ep.ask_at[i] else {
                    return Err(format!("need {i} is not mid-session"));
                };
                let last = ep.turns[..t]
                    .iter()
                    .rposition(|turn| turn.text.lines().any(|l| l.starts_with(q.key.as_str())))
                    .ok_or_else(|| format!("need {i}: {name} never shown"))?;
                let gap: u64 = ep.turns[last + 1..=t].iter().map(|x| tokens(&x.text)).sum();
                if gap <= GAP_TOK {
                    return Err(format!(
                        "need {i} ({name}) only {gap} tokens after its body"
                    ));
                }
            }
            Ok(())
        }
        Arm::MultiEpoch => {
            let total: u64 = ep.turns.iter().map(|t| tokens(&t.text)).sum();
            if total < SEG_TOK * SEGMENTS as u64 {
                return Err(format!("stream holds {total} tokens"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
