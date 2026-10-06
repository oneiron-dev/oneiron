//! The "build next" arms of the merged designer cases (OF-546 loop 2):
//! kv-interleaved (F-C10), pending-obligations (A-C5). Seeded generators,
//! fixed readers; each freezes at its first commit, dev seeds 1..=20 and
//! held-out 1001..=1020 like every other arm. Readers return the answer and
//! the evidence lines they used (the unbacked audit reads the second).

use std::collections::{BTreeMap, BTreeSet};

use super::arms::{Arm, Episode, Query, Rng, Score, Turn, WORDS, filler_line, hex};
use super::arms_epoch::{Env, Generated};

fn generated(
    turns: Vec<Turn>,
    queries: Vec<Query>,
    expected: Vec<String>,
    atomic: Vec<bool>,
    present: BTreeSet<String>,
    ask_at: Vec<Option<usize>>,
) -> Generated {
    Generated {
        turns,
        queries,
        expected,
        atomic,
        present,
        ask_at,
        origin: Vec::new(),
        env: Env::default(),
        truth: Vec::new(),
    }
}

const KVI_TURNS: usize = 880;
/// A key asked at turn `t` was last set at least this many turns before.
pub(crate) const KVI_AGE: usize = 150;

/// kv-interleaved (F-C10): the kv-offload-recall grammar, 880 turns, with
/// GETs riding the stream. Dev: one every 32 turns from turn 160 (22
/// mid-stream, two of them for keys never set). Held-out: four bursts of
/// five GETs in five turns, 200 silent turns apart, plus two absent keys,
/// and 70% of the asked keys last set in the first half of the stream.
/// Every asked key was last set at least [`KVI_AGE`] turns before it is
/// asked; the answer is its latest value as of that turn. Then 22 present
/// and two absent GETs at the end. In this arm the harness appends what a
/// mid-stream query restored to the log as reload spans (the delta-load
/// law): a heavy read is paid once and then lives in the window.
pub(crate) fn gen_kv_interleaved(rng: &mut Rng, heldout: bool) -> Generated {
    let mut keys: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut writes: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
    let mut present = BTreeSet::new();
    let mut seq = 0_u32;
    let mut turns = Vec::with_capacity(KVI_TURNS);
    for t in 0..KVI_TURNS {
        let mut lines = Vec::new();
        for _ in 0..rng.range(6, 10) {
            seq += 1;
            let key = if !keys.is_empty() && rng.below(100) < 20 {
                keys[rng.below(keys.len())].clone()
            } else {
                loop {
                    let key = format!("k-{}", hex(rng, 5));
                    if seen.insert(key.clone()) {
                        keys.push(key.clone());
                        break key;
                    }
                }
            };
            let value = hex(rng, 20);
            lines.push(format!("SET {key} = {value} #{seq:06}"));
            present.insert(value.clone());
            writes.entry(key).or_default().push((t, value));
        }
        for _ in 0..rng.range(1, 2) {
            let at = rng.below(lines.len() + 1);
            lines.insert(at, filler_line(rng));
        }
        turns.push(Turn {
            text: lines.join("\n"),
            verb: None,
        });
    }
    let latest = |key: &str, t: usize| -> Option<(usize, String)> {
        writes
            .get(key)?
            .iter()
            .rev()
            .find(|(wt, _)| *wt <= t)
            .cloned()
    };
    let mut slots: Vec<(usize, bool)> = Vec::new();
    if heldout {
        for start in [160, 365, 570, 775] {
            slots.extend((0..5).map(|i| (start + i, false)));
        }
        slots.push((165, true));
        slots.push((575, true));
    } else {
        slots.extend((0..22).map(|i| (160 + 32 * i, matches!(i, 7 | 15))));
    }
    slots.sort_unstable();
    let mut queries = Vec::new();
    let mut expected = Vec::new();
    let mut ask_at = Vec::new();
    let mut asked: BTreeSet<String> = BTreeSet::new();
    let mut absent = |rng: &mut Rng, asked: &mut BTreeSet<String>| loop {
        let key = format!("k-{}", hex(rng, 5));
        if !seen.contains(&key) && asked.insert(key.clone()) {
            break key;
        }
    };
    let mut pick =
        |rng: &mut Rng, t: usize, asked: &mut BTreeSet<String>| -> Option<(String, String)> {
            let eligible: Vec<(&String, usize)> = keys
                .iter()
                .filter(|k| !asked.contains(*k))
                .filter_map(|k| latest(k, t).map(|(wt, _)| (k, wt)))
                .filter(|(_, wt)| wt + KVI_AGE <= t)
                .collect();
            let early: Vec<&(&String, usize)> = eligible
                .iter()
                .filter(|(_, wt)| *wt < KVI_TURNS / 2)
                .collect();
            let chosen = if heldout && !early.is_empty() && rng.below(100) < 70 {
                early[rng.below(early.len())].0
            } else if eligible.is_empty() {
                return None;
            } else {
                eligible[rng.below(eligible.len())].0
            };
            asked.insert(chosen.clone());
            latest(chosen, t).map(|(_, v)| (chosen.clone(), v))
        };
    let mut ask = |key: String, value: String, at: Option<usize>| {
        queries.push(Query {
            text: format!("GET {key}"),
            key: format!("SET {key} = "),
        });
        expected.push(value);
        ask_at.push(at);
    };
    for (t, is_absent) in slots {
        if is_absent {
            let key = absent(rng, &mut asked);
            ask(key, String::new(), Some(t));
        } else if let Some((key, value)) = pick(rng, t, &mut asked) {
            ask(key, value, Some(t));
        }
    }
    let end = KVI_TURNS - 1;
    for _ in 0..22 {
        if let Some((key, value)) = pick(rng, end, &mut asked) {
            ask(key, value, None);
        }
    }
    for _ in 0..2 {
        let key = absent(rng, &mut asked);
        ask(key, String::new(), None);
    }
    let n = queries.len();
    generated(turns, queries, expected, vec![true; n], present, ask_at)
}

const OBLIGATIONS: usize = 64;
const CLOSES: usize = 48;
const OB_NOISE: usize = 80;
const EARLY_OPEN: usize = 12;
/// Bytes each source turn is padded to (about 512 tokens).
const OB_TURN_BYTES: usize = 2_040;

fn pad(rng: &mut Rng, mut lines: Vec<String>, bytes: usize) -> String {
    while lines.iter().map(|l| l.len() + 1).sum::<usize>() < bytes {
        let at = rng.below(lines.len() + 1);
        lines.insert(at, filler_line(rng));
    }
    lines.join("\n")
}

/// pending-obligations (A-C5): 64 OPEN records (one a turn, each with an
/// opaque id, a promised action and a completion token), then 48 matching
/// CLOSE records interleaved with 80 noisy progress turns: 192 turns of
/// about 512 tokens. The 12 earliest obligations never close; 16 stay open
/// at the end. Noise reassures in prose, names near-miss ids, or closes a
/// real id with the wrong token; only a CLOSE with the exact id and token
/// resolves. Queries after turn 96 and at the end: the pending id set, and
/// for each pending obligation its promised action and OPEN span.
pub(crate) fn gen_obligations(rng: &mut Rng) -> Generated {
    let mut ids: Vec<String> = Vec::new();
    while ids.len() < OBLIGATIONS {
        let id = format!("ob-{}", hex(rng, 6));
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let actions: Vec<String> = (0..OBLIGATIONS)
        .map(|_| {
            format!(
                "{} the {}-{}",
                rng.pick(&WORDS),
                rng.pick(&WORDS),
                rng.pick(&WORDS)
            )
        })
        .collect();
    let tokens_: Vec<String> = (0..OBLIGATIONS)
        .map(|_| format!("tk-{}", hex(rng, 6)))
        .collect();
    let mut later: Vec<usize> = (EARLY_OPEN..OBLIGATIONS).collect();
    rng.shuffle(&mut later);
    let closing: Vec<usize> = later[..CLOSES].to_vec();
    let mut present: BTreeSet<String> = ids.iter().cloned().collect();

    let mut turns = Vec::new();
    for i in 0..OBLIGATIONS {
        let line = format!(
            "OPEN {} action=\"{}\" token={} at=s{i:03}",
            ids[i], actions[i], tokens_[i]
        );
        turns.push(Turn {
            text: pad(rng, vec![line], OB_TURN_BYTES),
            verb: None,
        });
    }
    // The tail: closes and noise, shuffled.
    let mut tail: Vec<Option<usize>> = closing.iter().map(|&i| Some(i)).collect();
    tail.extend(std::iter::repeat_n(None, OB_NOISE));
    rng.shuffle(&mut tail);
    let mut closed_at: BTreeMap<usize, usize> = BTreeMap::new();
    for slot in tail {
        let t = turns.len();
        let line = match slot {
            Some(i) => {
                closed_at.insert(i, t);
                format!("CLOSE {} token={} done", ids[i], tokens_[i])
            }
            None => {
                let i = rng.below(OBLIGATIONS);
                match rng.below(3) {
                    0 => format!(
                        "status: {} is basically done, closing it soon, nothing to worry about",
                        ids[i]
                    ),
                    1 => {
                        // A near-miss id: one hex digit changed.
                        let mut near: Vec<char> = ids[i].chars().collect();
                        let at = 3 + rng.below(6);
                        near[at] = if near[at] == 'f' { '0' } else { 'f' };
                        let near: String = near.into_iter().collect();
                        present.insert(near.clone());
                        format!("CLOSE {near} token={} done", tokens_[i])
                    }
                    _ => format!("CLOSE {} token=tk-{} done", ids[i], hex(rng, 6)),
                }
            }
        };
        turns.push(Turn {
            text: pad(rng, vec![line], OB_TURN_BYTES),
            verb: None,
        });
    }
    let mut queries = Vec::new();
    let mut expected = Vec::new();
    let mut atomic = Vec::new();
    let mut ask_at = Vec::new();
    for at in [Some(96), None] {
        let t = at.unwrap_or(turns.len() - 1);
        let pending: Vec<usize> = (0..OBLIGATIONS)
            .filter(|i| *i <= t && closed_at.get(i).is_none_or(|c| *c > t))
            .collect();
        let mut sorted: Vec<&String> = pending.iter().map(|&i| &ids[i]).collect();
        sorted.sort();
        queries.push(Query {
            text: "PENDING".to_owned(),
            key: "ob-".to_owned(),
        });
        expected.push(
            sorted
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(","),
        );
        atomic.push(true);
        ask_at.push(at);
        for i in pending {
            queries.push(Query {
                text: format!("PROMISE {}", ids[i]),
                key: format!("OPEN {} ", ids[i]),
            });
            expected.push(format!("{}|s{i:03}", actions[i]));
            atomic.push(false);
            ask_at.push(at);
        }
    }
    generated(turns, queries, expected, atomic, present, ask_at)
}

/// The obligations reader: an obligation is pending when its OPEN line is
/// visible and no visible CLOSE line carries its exact id and token.
/// PENDING answers the sorted pending ids; PROMISE answers `action|span`
/// from the obligation's OPEN line.
pub(crate) fn read_obligations<'a>(q: &Query, lines: &[&'a str]) -> (String, Vec<&'a str>) {
    let mut opens: BTreeMap<&str, (&str, &str, &str, &'a str)> = BTreeMap::new();
    let mut closes: BTreeMap<(&str, &str), &'a str> = BTreeMap::new();
    for &line in lines {
        if let Some(rest) = line.strip_prefix("OPEN ")
            && let Some((id, rest)) = rest.split_once(" action=\"")
            && let Some((action, rest)) = rest.split_once("\" token=")
            && let Some((token, at)) = rest.split_once(" at=")
        {
            opens.entry(id).or_insert((action, token, at, line));
        } else if let Some(rest) = line.strip_prefix("CLOSE ")
            && let Some((id, rest)) = rest.split_once(" token=")
            && let Some((token, _)) = rest.split_once(' ')
        {
            closes.entry((id, token)).or_insert(line);
        }
    }
    if q.text == "PENDING" {
        let mut evidence = Vec::new();
        let mut pending = Vec::new();
        for (id, (_, token, _, line)) in &opens {
            evidence.push(*line);
            match closes.get(&(*id, *token)) {
                Some(close) => evidence.push(close),
                None => pending.push(*id),
            }
        }
        return (pending.join(","), evidence);
    }
    let Some(id) = q.text.strip_prefix("PROMISE ") else {
        return (String::new(), Vec::new());
    };
    opens.get(id).map_or_else(
        || (String::new(), Vec::new()),
        |(action, _, at, line)| (format!("{action}|{at}"), vec![*line]),
    )
}

/// Scores a "build next" arm: exact per query, hallucinated atoms by the
/// loop-1 rule.
pub(crate) fn score(ep: &Episode, answers: &[String]) -> Score {
    let mut score = Score {
        total: ep.queries.len() as u32,
        ..Score::default()
    };
    for (i, want) in ep.expected.iter().enumerate() {
        let got = answers.get(i).map_or("", String::as_str);
        if got == want {
            score.correct += 1;
        } else if ep.atomic[i]
            && !got.is_empty()
            && got.split(',').any(|atom| !ep.present.contains(atom))
        {
            score.hallucinated += 1;
        }
    }
    score.value = f64::from(score.correct) / f64::from(score.total.max(1));
    score
}

/// The reader for a "build next" arm, with its evidence.
pub(crate) fn read_with<'a>(arm: Arm, q: &Query, lines: &[&'a str]) -> (String, Vec<&'a str>) {
    match arm {
        Arm::Obligations => read_obligations(q, lines),
        _ => (String::new(), Vec::new()),
    }
}
