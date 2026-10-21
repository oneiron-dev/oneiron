//! The measured cells: ingest by one and by many callers, recall at each
//! grade and agent count, the mixed and fairness cells, golden rankings and
//! memory per agent.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::client::Agent;
use super::corpus::{Corpus, Query, Record};
use super::embedder::StubEmbedder;
use super::report::{AgentMemory, Cell, Fairness, GoldenQuery};
use super::server::{Running, cpu_seconds};
use super::stats::{Sample, Summary};

/// A recall grade: the effort the caller asks for and its optional raw deadline.
#[derive(Clone, Debug)]
pub(super) struct Grade {
    pub(super) name: String,
    pub(super) effort: String,
    pub(super) deadline_ms: Option<u64>,
    pub(super) limit: usize,
}

impl Grade {
    pub(super) fn named(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            effort: name.to_owned(),
            deadline_ms: None,
            limit: 10,
        }
    }
}

/// Everything a cell needs from the run.
pub(super) struct Ctx<'a> {
    pub(super) corpus: &'a Corpus,
    pub(super) documents: usize,
    pub(super) secret_scan: &'a str,
    pub(super) owner: &'a str,
    pub(super) server: &'a Running,
    pub(super) agents: &'a [Agent],
    pub(super) queries: &'a [Query],
    /// The `as_of` every recall sends.
    pub(super) now: u64,
    pub(super) cell_requests: usize,
    pub(super) cell_seconds: f64,
    /// Cell names, each with a `kill -s` signal sent to the server before and after it.
    pub(super) signal_cells: Vec<(String, String)>,
}

pub(super) fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg").map_or_else(
        |_| "-".to_owned(),
        |s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "),
    )
}

impl Ctx<'_> {
    /// Runs `body`, timing it and wrapping its samples into a named cell.
    fn cell(
        &self,
        name: &str,
        grade: &str,
        agents: usize,
        body: impl FnOnce() -> Vec<(String, Sample)>,
    ) -> Cell {
        let signals = self
            .signal_cells
            .iter()
            .filter(|(cell, _)| cell == name)
            .map(|(_, signal)| signal.as_str())
            .collect::<Vec<_>>();
        for signal in &signals {
            let _ = self.server.signal(signal);
        }
        let load_before = loadavg();
        let cpu_before = cpu_seconds(self.server.pid);
        let started = Instant::now();
        let samples = body();
        let seconds = started.elapsed().as_secs_f64();
        let cpu_after = cpu_seconds(self.server.pid);
        for signal in &signals {
            let _ = self.server.signal(signal);
        }
        let mut by_verb = BTreeMap::<String, Vec<Sample>>::new();
        for (verb, sample) in &samples {
            by_verb
                .entry(verb.clone())
                .or_default()
                .push(sample.clone());
        }
        let all = samples.into_iter().map(|(_, s)| s).collect::<Vec<_>>();
        let summary = |samples: &[Sample]| {
            let summary = Summary::of(samples, seconds);
            if grade == "ingest" {
                summary
            } else {
                summary.below_corpus_floor(self.documents)
            }
        };
        Cell {
            name: name.to_owned(),
            secret_scan: self.secret_scan.to_owned(),
            grade: grade.to_owned(),
            agents,
            summary: summary(&all),
            by_verb: if by_verb.len() > 1 {
                by_verb
                    .iter()
                    .map(|(verb, s)| (verb.clone(), summary(s)))
                    .collect()
            } else {
                BTreeMap::new()
            },
            server_cpu_seconds: cpu_before.zip(cpu_after).map(|(a, b)| b - a),
            load_before,
            load_after: loadavg(),
        }
    }

    fn write_one(&self, agent: &Agent, record: &Record) -> (String, Sample) {
        let verb = match record {
            Record::Turn { .. } => "vault.witness",
            Record::Claim { .. } => "vault.claims.upsert",
        };
        (
            verb.to_owned(),
            agent.write(self.corpus, self.owner, record),
        )
    }

    /// One caller writes `records` in order. Records are made before the cell
    /// starts, as for [`Self::ingest_parallel`].
    pub(super) fn ingest_single(&self, name: &str, records: Range<usize>) -> Cell {
        let records = records.map(|i| self.corpus.record(i)).collect::<Vec<_>>();
        self.cell(name, "ingest", 1, || {
            records
                .iter()
                .map(|record| self.write_one(&self.agents[0], record))
                .collect()
        })
    }

    /// `callers` agents write `records`; each conversation stays with one
    /// caller, so its turns and the claims about it land in order.
    pub(super) fn ingest_parallel(&self, records: Range<usize>, callers: usize) -> Cell {
        let callers = callers.clamp(1, self.agents.len());
        let mut lanes = vec![Vec::new(); callers];
        for i in records {
            let record = self.corpus.record(i);
            lanes[record.conversation() % callers].push(record);
        }
        self.cell("ingest_parallel", "ingest", callers, || {
            std::thread::scope(|scope| {
                // Every caller starts before any is joined.
                let mut handles = Vec::with_capacity(callers);
                for (lane, agent) in lanes.iter().zip(self.agents) {
                    handles.push(scope.spawn(move || {
                        lane.iter()
                            .map(|record| self.write_one(agent, record))
                            .collect::<Vec<_>>()
                    }));
                }
                handles
                    .into_iter()
                    .flat_map(|h| h.join().unwrap_or_default())
                    .collect()
            })
        })
    }

    fn query(&self, agent: usize, k: usize) -> &str {
        &self.queries[(agent * 7 + k) % self.queries.len()].text
    }

    fn recall(&self, agent: usize, k: usize, grade: &Grade) -> Sample {
        self.agents[agent]
            .recall(
                self.query(agent, k),
                &grade.effort,
                grade.limit,
                grade.deadline_ms,
                self.now,
            )
            .sample
    }

    /// One untimed recall by every role at once, before its cell starts.
    fn warm(&self, roles: &[(usize, &Grade)]) {
        std::thread::scope(|scope| {
            for &(agent, grade) in roles {
                let _ = scope.spawn(move || self.recall(agent, 0, grade));
            }
        });
    }

    /// The roles recall in a closed loop, all at once: `total` timed requests
    /// spread evenly over them, each stopping early at the cell's time cap
    /// once it has two.
    fn recall_loop(&self, roles: &[(usize, &Grade)], total: usize) -> Vec<(String, Sample)> {
        let deadline = Instant::now() + Duration::from_secs_f64(self.cell_seconds);
        let (each, extra) = (total / roles.len().max(1), total % roles.len().max(1));
        std::thread::scope(|scope| {
            // Every agent starts before any is joined.
            let mut handles = Vec::with_capacity(roles.len());
            for (slot, &(agent, grade)) in roles.iter().enumerate() {
                let budget = each + usize::from(slot < extra);
                handles.push(scope.spawn(move || {
                    let mut out = Vec::with_capacity(budget);
                    for k in 1..=budget {
                        if k > 2 && Instant::now() > deadline {
                            break;
                        }
                        out.push((grade.name.clone(), self.recall(agent, k, grade)));
                    }
                    out
                }));
            }
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        })
    }

    /// A cell's timed requests: `--cell-requests`, and at least two per agent.
    fn budget(&self, agents: usize) -> usize {
        self.cell_requests.max(2 * agents)
    }

    pub(super) fn recall_cell(&self, grade: &Grade, agents: usize) -> Cell {
        let agents = agents.min(self.agents.len());
        let roles = (0..agents).map(|a| (a, grade)).collect::<Vec<_>>();
        let name = format!("recall_{}_x{agents}", grade.name);
        self.warm(&roles);
        self.cell(&name, &grade.name, agents, || {
            self.recall_loop(&roles, self.budget(agents))
        })
    }

    /// Half the agents at call grade, half at the normal grade, together.
    pub(super) fn mixed_cell(&self, call: &Grade, normal: &Grade, agents: usize) -> Vec<Cell> {
        let agents = agents.min(self.agents.len());
        let roles = (0..agents)
            .map(|a| (a, if a % 2 == 0 { call } else { normal }))
            .collect::<Vec<_>>();
        let name = format!("mixed_x{agents}");
        self.warm(&roles);
        let joint = self.cell(&name, "mixed", agents, || {
            self.recall_loop(&roles, self.budget(agents))
        });
        [call, normal]
            .iter()
            .map(|grade| {
                let mut part = Cell {
                    name: format!("{name}_{}", grade.name),
                    secret_scan: self.secret_scan.to_owned(),
                    grade: grade.name.clone(),
                    agents: roles.iter().filter(|(_, g)| g.name == grade.name).count(),
                    ..Cell::default()
                };
                part.load_before.clone_from(&joint.load_before);
                part.load_after.clone_from(&joint.load_after);
                part.summary = joint.by_verb.get(&grade.name).cloned().unwrap_or_default();
                part
            })
            .collect()
    }

    /// `callers` call-grade agents alone, then beside one agent recalling at
    /// the normal grade from `heavy_threads` threads at once.
    pub(super) fn fairness(
        &self,
        call: &Grade,
        heavy: &Grade,
        callers: usize,
        heavy_threads: usize,
    ) -> Fairness {
        let callers = callers.min(self.agents.len().saturating_sub(1));
        let heavy_agent = self.agents.len() - 1;
        let roles = (0..callers).map(|a| (a, call)).collect::<Vec<_>>();
        let total = self.budget(callers);
        self.warm(&roles);
        let alone = self.cell("fairness_alone", &call.name, callers, || {
            self.recall_loop(&roles, total)
        });
        let stop = AtomicBool::new(false);
        let mut heavy_samples = Vec::new();
        let started = Instant::now();
        let beside = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(heavy_threads);
            for t in 0..heavy_threads {
                let stop = &stop;
                handles.push(scope.spawn(move || {
                    let mut out = Vec::new();
                    let mut k = t;
                    while !stop.load(Ordering::Relaxed) {
                        out.push(self.recall(heavy_agent, k, heavy));
                        k += heavy_threads;
                    }
                    out
                }));
            }
            std::thread::sleep(Duration::from_millis(500));
            let beside = self.cell("fairness_beside_heavy", &call.name, callers, || {
                self.recall_loop(&roles, total)
            });
            stop.store(true, Ordering::Relaxed);
            for handle in handles {
                heavy_samples.extend(handle.join().unwrap_or_default());
            }
            beside
        });
        let heavy_cell = Cell {
            name: "fairness_heavy".to_owned(),
            secret_scan: self.secret_scan.to_owned(),
            grade: heavy.name.clone(),
            agents: 1,
            summary: Summary::of(&heavy_samples, started.elapsed().as_secs_f64())
                .below_corpus_floor(self.documents),
            ..Cell::default()
        };
        Fairness {
            callers,
            heavy_threads,
            alone,
            beside_heavy: beside,
            heavy: heavy_cell,
        }
    }

    /// Every golden query once per grade, by one agent, in order. A targeted
    /// query that fails counts as a miss in its grade's hit@10.
    pub(super) fn golden(&self, grades: &[Grade]) -> (Vec<GoldenQuery>, BTreeMap<String, f64>) {
        let agent = &self.agents[0];
        let golden = self
            .queries
            .iter()
            .map(|query| {
                let mut rankings = BTreeMap::new();
                let mut errors = BTreeMap::new();
                for grade in grades {
                    let r = agent.recall(
                        &query.text,
                        &grade.effort,
                        grade.limit,
                        grade.deadline_ms,
                        self.now,
                    );
                    match r.sample.error {
                        Some(error) => {
                            errors.insert(grade.name.clone(), error);
                        }
                        None => {
                            rankings.insert(grade.name.clone(), r.ranking);
                        }
                    }
                }
                GoldenQuery {
                    query: query.clone(),
                    rankings,
                    errors,
                }
            })
            .collect::<Vec<_>>();
        let hits = grades
            .iter()
            .map(|grade| {
                let targeted = golden
                    .iter()
                    .filter_map(|g| Some((g.query.target?, g.rankings.get(&grade.name))))
                    .collect::<Vec<_>>();
                let hit = targeted
                    .iter()
                    .filter(|(target, ranking)| {
                        ranking.is_some_and(|r| r.iter().take(10).any(|t| *t == Some(*target)))
                    })
                    .count();
                (
                    grade.name.clone(),
                    hit as f64 / targeted.len().max(1) as f64,
                )
            })
            .collect();
        (golden, hits)
    }

    /// Anonymous memory before and after `agents` not yet heard from each
    /// make two light recalls: the server's cost of one more resident agent.
    pub(super) fn agent_memory(&self, agents: Range<usize>) -> AgentMemory {
        let before = self.server.memory().0.anon_mib;
        let light = Grade::named("light");
        let ids = agents.clone().collect::<Vec<_>>();
        for chunk in ids.chunks(16) {
            let roles = chunk.iter().map(|&a| (a, &light)).collect::<Vec<_>>();
            self.warm(&roles);
            let _ = self.recall_loop(&roles, roles.len());
        }
        std::thread::sleep(Duration::from_millis(500));
        let after = self.server.memory().0.anon_mib;
        let count = agents.len();
        AgentMemory {
            agents: count,
            anon_before_mib: before,
            anon_after_mib: after,
            kib_per_agent: (after - before) * 1024.0 / count.max(1) as f64,
        }
    }
}

/// The server's warning when an embedding pass fails and it backs off.
const PASS_FAILED: &str = "embedding reconciliation failed";
/// The server's info line after an embedding pass that leased work, logged
/// once its fills have committed. A pass that finds no work logs nothing.
pub(super) const PASS_DONE: &str = "embedding reconcile pass";

/// Waits for evidence that every written record's vector is stored and
/// published: the stub has answered a text carrying each of the `expected`
/// records' tags, the server has since logged a pass after the count the stub
/// read as the last new tag arrived (that pass stored it), and then `settle`
/// has passed with no further pass (the worker's idle sleep, after which it
/// publishes what it staged). Returns the seconds that took. An error when the
/// server exits, logs a failed pass, or `cap` runs out: the run's vector
/// numbers would not be the filled vault's.
pub(super) fn drain(
    server: &Running,
    stub: &StubEmbedder,
    expected: usize,
    settle: Duration,
    cap: Duration,
) -> Result<f64, String> {
    let started = Instant::now();
    let mut passes = server.log_count(PASS_DONE);
    let mut since_pass = Instant::now();
    let mut seen = stub.records();
    while started.elapsed() < cap {
        std::thread::sleep(Duration::from_secs(1));
        if cpu_seconds(server.pid).is_none() {
            return Err("drain: the server has exited".into());
        }
        if server.logged(PASS_FAILED) {
            return Err(format!("drain: the server logged `{PASS_FAILED}`"));
        }
        seen = stub.records();
        let now = server.log_count(PASS_DONE);
        if now != passes {
            since_pass = Instant::now();
            passes = now;
        }
        let (records, before_last) = seen;
        if records >= expected && passes > before_last && since_pass.elapsed() >= settle {
            return Ok(started.elapsed().as_secs_f64());
        }
    }
    Err(format!(
        "drain: {} of {expected} records embedded, {passes} passes, within {} s",
        seen.0,
        cap.as_secs()
    ))
}
