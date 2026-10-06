//! The "build next" arms of the merged designer cases (OF-546 loop 2):
//! kv-interleaved (F-C10), pending-obligations (A-C5), late-tool-results
//! (A-C7), commit-or-rollback (A-C2). Seeded generators,
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
        Arm::LateResults => read_calls(q, lines),
        Arm::Transactions => read_transactions(q, lines),
        _ => (String::new(), Vec::new()),
    }
}

const CALLS: usize = 40;
const OPS: [&str; 4] = ["fetch_report", "resize_image", "sync_ledger", "send_digest"];
const REQ_BYTES: usize = 1_020;
const RESP_BYTES: usize = 3_060;
const ACCEPT_BYTES: usize = 500;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CallEv {
    Request,
    Response,
    Accept,
}

/// late-tool-results (A-C7): 40 logical calls, two attempts each, four
/// operation display names shared across calls. 80 request turns (about
/// 256 tokens), 80 response turns (about 768, each with an opaque artifact
/// tag and a response id), 40 ACCEPT turns (about 128) naming the
/// authoritative attempt: 200 turns, causally shuffled, so some rejected
/// responses land after their call's ACCEPT. Queries after the 25th ACCEPT
/// (every call accepted so far) and at the end (all 40): the accepted
/// attempt, its artifact and its response id.
pub(crate) fn gen_late_results(rng: &mut Rng) -> Generated {
    let mut ids: Vec<String> = Vec::new();
    while ids.len() < CALLS {
        let id = format!("c-{}", hex(rng, 5));
        if !ids.contains(&id) {
            ids.push(id);
        }
    }
    let ops: Vec<&str> = (0..CALLS).map(|_| *rng.pick(&OPS)).collect();
    // Both first-attempt and retry acceptance, in every seed.
    let accepted: Vec<u8> = (0..CALLS)
        .map(|i| match i {
            0 => 1,
            1 => 2,
            _ => 1 + rng.below(2) as u8,
        })
        .collect();
    let artifacts: Vec<[String; 2]> = (0..CALLS)
        .map(|_| {
            [
                format!("art-{}", hex(rng, 8)),
                format!("art-{}", hex(rng, 8)),
            ]
        })
        .collect();
    let mut events: Vec<(u64, CallEv, usize, u8)> = Vec::new();
    for c in 0..CALLS {
        let req1 = rng.below(4_000) as u64;
        let resp1 = req1 + rng.range(20, 400) as u64;
        let req2 = req1 + rng.range(10, 300) as u64;
        let resp2 = req2 + rng.range(20, 400) as u64;
        let acc_at = if accepted[c] == 1 { resp1 } else { resp2 };
        let accept = acc_at + rng.range(5, 200) as u64;
        events.push((req1, CallEv::Request, c, 1));
        events.push((resp1, CallEv::Response, c, 1));
        events.push((req2, CallEv::Request, c, 2));
        events.push((resp2, CallEv::Response, c, 2));
        events.push((accept, CallEv::Accept, c, accepted[c]));
    }
    events.sort_unstable();
    let mut turns = Vec::new();
    let mut rid = 0_u32;
    let mut rids: BTreeMap<(usize, u8), String> = BTreeMap::new();
    let mut accepts_seen = 0;
    let mut mid_at = 0;
    let mut accepted_by_mid: Vec<usize> = Vec::new();
    let mut present = BTreeSet::new();
    for (_, ev, c, a) in events {
        let (line, bytes) = match ev {
            CallEv::Request => (
                format!("REQUEST call={} attempt=a{a} op={}", ids[c], ops[c]),
                REQ_BYTES,
            ),
            CallEv::Response => {
                rid += 1;
                let r = format!("R{rid:03}");
                rids.insert((c, a), r.clone());
                let art = &artifacts[c][usize::from(a) - 1];
                present.insert(art.clone());
                (
                    format!(
                        "RESPONSE call={} attempt=a{a} op={} rid={r} artifact={art}",
                        ids[c], ops[c]
                    ),
                    RESP_BYTES,
                )
            }
            CallEv::Accept => {
                accepts_seen += 1;
                if accepts_seen <= 25 {
                    accepted_by_mid.push(c);
                }
                if accepts_seen == 25 {
                    mid_at = turns.len();
                }
                (format!("ACCEPT call={} attempt=a{a}", ids[c]), ACCEPT_BYTES)
            }
        };
        turns.push(Turn {
            text: pad(rng, vec![line], bytes),
            verb: None,
        });
    }
    let mut queries = Vec::new();
    let mut expected = Vec::new();
    let mut ask_at = Vec::new();
    let answer = |c: usize| {
        let a = accepted[c];
        format!(
            "a{a} {} {}",
            artifacts[c][usize::from(a) - 1],
            rids.get(&(c, a)).cloned().unwrap_or_default()
        )
    };
    accepted_by_mid.sort_unstable();
    for (at, calls) in [
        (Some(mid_at), accepted_by_mid.clone()),
        (None, (0..CALLS).collect::<Vec<_>>()),
    ] {
        for c in calls {
            queries.push(Query {
                text: format!("CALL {}", ids[c]),
                key: format!("call={} ", ids[c]),
            });
            expected.push(answer(c));
            ask_at.push(at);
        }
    }
    let n = queries.len();
    generated(turns, queries, expected, vec![false; n], present, ask_at)
}

/// The late-results reader: join by call id and the ACCEPT's attempt, never
/// by display name or arrival order. Answers `attempt artifact rid`; the
/// attempt alone when its response is not visible; nothing without an
/// ACCEPT.
pub(crate) fn read_calls<'a>(q: &Query, lines: &[&'a str]) -> (String, Vec<&'a str>) {
    let Some(call) = q.text.strip_prefix("CALL ") else {
        return (String::new(), Vec::new());
    };
    let field = |line: &'a str, name: &str| -> Option<&'a str> {
        line.split_whitespace()
            .find_map(|t| t.strip_prefix(name).and_then(|v| v.strip_prefix('=')))
    };
    let mut accept: Option<(&str, &'a str)> = None;
    for &line in lines {
        if line.starts_with("ACCEPT ") && field(line, "call") == Some(call) {
            if let Some(a) = field(line, "attempt") {
                accept = Some((a, line));
            }
        }
    }
    let Some((attempt, accept_line)) = accept else {
        return (String::new(), Vec::new());
    };
    for &line in lines {
        if line.starts_with("RESPONSE ")
            && field(line, "call") == Some(call)
            && field(line, "attempt") == Some(attempt)
            && let (Some(rid), Some(art)) = (field(line, "rid"), field(line, "artifact"))
        {
            return (format!("{attempt} {art} {rid}"), vec![accept_line, line]);
        }
    }
    (attempt.to_owned(), vec![accept_line])
}

const TX_FILES: usize = 16;
const TXNS: usize = 24;
const TX_COMMITS: usize = 12;
/// Bytes each turn is padded to (about 1,024 tokens).
const TX_TURN_BYTES: usize = 4_080;

#[derive(Clone, Copy)]
enum TxEv {
    Begin,
    Write(usize, usize),
    Terminal,
    Distractor,
}

/// commit-or-rollback (A-C2): one turn defining 16 files, then 24 six-turn
/// transactions (BEGIN, three staged writes to two files, COMMIT or ABORT,
/// a distractor), up to three in flight at once; exactly 12 commit. Every
/// turn is padded to about 1,024 tokens: 145 turns. A file's committed
/// value replays only committed transactions in commit order, each
/// applying its last staged value per file. Queries after every fourth
/// terminal event and at the end: every file's committed value and the
/// outcomes so far.
pub(crate) fn gen_transactions(rng: &mut Rng) -> Generated {
    let files: Vec<String> = (1..=TX_FILES).map(|i| format!("f{i:02}")).collect();
    let initial: Vec<String> = (0..TX_FILES)
        .map(|_| format!("v-{}", hex(rng, 8)))
        .collect();
    let mut order: Vec<usize> = (0..TXNS).collect();
    rng.shuffle(&mut order);
    let commits: BTreeSet<usize> = order[..TX_COMMITS].iter().copied().collect();
    let mut present: BTreeSet<String> = initial.iter().cloned().collect();
    // Each transaction: two files, three writes (A, B, A), its events.
    let mut plans: Vec<Vec<TxEv>> = Vec::new();
    let mut values: Vec<Vec<(usize, String)>> = Vec::new();
    for _ in 0..TXNS {
        let a = rng.below(TX_FILES);
        let b = loop {
            let b = rng.below(TX_FILES);
            if b != a {
                break b;
            }
        };
        let writes = [
            (a, format!("v-{}", hex(rng, 8))),
            (b, format!("v-{}", hex(rng, 8))),
            (a, format!("v-{}", hex(rng, 8))),
        ];
        for (_, v) in &writes {
            present.insert(v.clone());
        }
        plans.push(vec![
            TxEv::Begin,
            TxEv::Write(0, writes[0].0),
            TxEv::Write(1, writes[1].0),
            TxEv::Write(2, writes[2].0),
            TxEv::Terminal,
            TxEv::Distractor,
        ]);
        values.push(writes.to_vec());
    }
    // Interleave: up to three transactions in flight.
    let mut active: Vec<(usize, usize)> = Vec::new();
    let mut next_tx = 0;
    let mut sched: Vec<(usize, TxEv)> = Vec::new();
    while next_tx < TXNS || !active.is_empty() {
        if next_tx < TXNS && (active.is_empty() || (active.len() < 3 && rng.below(2) == 0)) {
            active.push((next_tx, 0));
            next_tx += 1;
            continue;
        }
        let k = rng.below(active.len());
        let (tx, step) = active[k];
        sched.push((tx, plans[tx][step]));
        if step + 1 == plans[tx].len() {
            active.remove(k);
        } else {
            active[k].1 += 1;
        }
    }
    let mut lines0: Vec<String> = files
        .iter()
        .zip(&initial)
        .map(|(f, v)| format!("FILE {f} = {v}"))
        .collect();
    lines0.insert(0, "FILES 16 committed".to_owned());
    let mut turns = vec![Turn {
        text: pad(rng, lines0, TX_TURN_BYTES),
        verb: None,
    }];
    let tx_id = |tx: usize| format!("tx-{:02}", tx + 1);
    let mut committed: Vec<String> = initial.clone();
    let mut outcomes: BTreeMap<String, &str> = BTreeMap::new();
    let mut terminals = 0;
    let mut checkpoints: Vec<(usize, Vec<String>, BTreeMap<String, &str>)> = Vec::new();
    for (tx, ev) in sched {
        let line = match ev {
            TxEv::Begin => format!("BEGIN {}", tx_id(tx)),
            TxEv::Write(w, f) => format!("WRITE {} {} = {}", tx_id(tx), files[f], values[tx][w].1),
            TxEv::Terminal => {
                terminals += 1;
                if commits.contains(&tx) {
                    let mut last: BTreeMap<usize, &String> = BTreeMap::new();
                    for (f, v) in &values[tx] {
                        last.insert(*f, v);
                    }
                    for (f, v) in last {
                        committed[f].clone_from(v);
                    }
                    outcomes.insert(tx_id(tx), "commit");
                    format!("COMMIT {}", tx_id(tx))
                } else {
                    outcomes.insert(tx_id(tx), "abort");
                    format!("ABORT {}", tx_id(tx))
                }
            }
            TxEv::Distractor => {
                let (f, v) = &values[tx][2];
                format!(
                    "PREVIEW {} {} would become {v} once it lands",
                    tx_id(tx),
                    files[*f]
                )
            }
        };
        turns.push(Turn {
            text: pad(rng, vec![line], TX_TURN_BYTES),
            verb: None,
        });
        if matches!(ev, TxEv::Terminal) && terminals % 4 == 0 {
            checkpoints.push((turns.len() - 1, committed.clone(), outcomes.clone()));
        }
    }
    let mut queries = Vec::new();
    let mut expected = Vec::new();
    let mut ask_at = Vec::new();
    let end = (turns.len(), committed.clone(), outcomes.clone());
    for (k, (t, values, outs)) in checkpoints
        .into_iter()
        .chain(std::iter::once(end))
        .enumerate()
    {
        let at = (k < TXNS / 4).then_some(t);
        for (f, v) in files.iter().zip(&values) {
            queries.push(Query {
                text: format!("VALUE {f}"),
                key: format!("{f} "),
            });
            expected.push(v.clone());
            ask_at.push(at);
        }
        queries.push(Query {
            text: "OUTCOMES".to_owned(),
            key: "tx-".to_owned(),
        });
        expected.push(
            outs.iter()
                .map(|(t, o)| format!("{t}:{o}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        ask_at.push(at);
    }
    let n = queries.len();
    generated(turns, queries, expected, vec![false; n], present, ask_at)
}

/// The transactions reader: a file's committed value is its FILE line,
/// overwritten, for each visible COMMIT in arrival order, by that
/// transaction's last visible staged write to the file. ABORTed and
/// unterminated writes never apply; PREVIEW lines are not writes.
/// OUTCOMES lists every visible terminal event by transaction id.
pub(crate) fn read_transactions<'a>(q: &Query, lines: &[&'a str]) -> (String, Vec<&'a str>) {
    let mut terminals: Vec<(&str, &str, &'a str)> = Vec::new();
    for &line in lines {
        if let Some(tx) = line.strip_prefix("COMMIT ") {
            terminals.push((tx, "commit", line));
        } else if let Some(tx) = line.strip_prefix("ABORT ") {
            terminals.push((tx, "abort", line));
        }
    }
    if q.text == "OUTCOMES" {
        let mut outs: BTreeMap<&str, &str> = BTreeMap::new();
        for (tx, o, _) in &terminals {
            outs.insert(tx, o);
        }
        return (
            outs.iter()
                .map(|(t, o)| format!("{t}:{o}"))
                .collect::<Vec<_>>()
                .join(","),
            terminals.iter().map(|t| t.2).collect(),
        );
    }
    let Some(file) = q.text.strip_prefix("VALUE ") else {
        return (String::new(), Vec::new());
    };
    let mut initial: Option<(&str, &'a str)> = None;
    let mut writes: BTreeMap<&str, (&str, &'a str)> = BTreeMap::new();
    for &line in lines {
        if let Some(rest) = line.strip_prefix("FILE ")
            && let Some((f, v)) = rest.split_once(" = ")
            && f == file
            && initial.is_none()
        {
            initial = Some((v, line));
        } else if let Some(rest) = line.strip_prefix("WRITE ")
            && let Some((tx, rest)) = rest.split_once(' ')
            && let Some((f, v)) = rest.split_once(" = ")
            && f == file
        {
            writes.insert(tx, (v, line));
        }
    }
    let mut value = initial.map(|(v, _)| v);
    let mut evidence: Vec<&'a str> = initial.map(|(_, l)| l).into_iter().collect();
    for (tx, o, line) in &terminals {
        if *o == "commit"
            && let Some((v, write)) = writes.get(tx)
        {
            value = Some(v);
            evidence.push(write);
            evidence.push(line);
        }
    }
    value.map_or_else(|| (String::new(), Vec::new()), |v| (v.to_owned(), evidence))
}
