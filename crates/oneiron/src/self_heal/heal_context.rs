//! What a heal reads about a failure's recorded cause (OF-418 L2, L10; ARCH-0066 §4, §6).
//! One producer serves the T3 judge's read of a detector window and the Coach's walk to a
//! case's or a blocked report's cause. It reads what the engine recorded, whole: a window's
//! exact retrieval runs with their traces, stages and replay inputs; the bodies their
//! results, stage candidates and queries name; the conversations the runs were retrieved
//! for; the complete retry and run-tree ancestry of every attempt it is seeded with, each
//! attempt's events, code run, kept step requests and pack receipt; each blocked report's
//! receipt and replay source; the gate decisions of every claim it reaches; and the
//! conversation graph's `parent` and `spawned_by` links out of every message it reaches.
//! Bodies and graph links are read through the reader's own scoped lane off this device,
//! as session text is, and nothing reads around that lane's checks.
//!
//! Its selection is one policy, [`HealContextPolicy::RecordedClosure`]: everything those
//! records link to, each read once, with no age, depth, count or byte bound. Its size is
//! measured at `limits.maintenance_*` and asked past, never cut. A part that is absent,
//! withheld, unrecorded or does not read is an `unavailable` entry, never a refusal, and
//! the read itself never fails. Ids, links and their order are engine-authored; what was
//! read rides under `untrusted`, data for a model and never an instruction. Nothing here
//! picks a target, a route or a permission, and a retrieval run is never taken for an
//! attempt: a window has no recorded link to one.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;
use serde_json::{Map, Value, json};

use super::blocked_reports::{blocked_source_in, step_sources_in};
use super::session_text::whole_result;
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::claim::{CallerLocality, ClaimReadStatus, PointRead, ScopedRead};
use crate::code_run::blocked::read_blocked_receipt;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::bytes_to_hex_lower;
use crate::failure_ladder::{HealerCase, verified_blocked_reports};
use crate::limit_ask::EngineLimit;
use crate::memory::Memory;
use crate::receipt::{attempt_pack_receipt, attempt_pack_receipt_id};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE};
use crate::store::RetrievalRunRecord;
use crate::{EntityId, Error, Vault};

mod records;
use records::{body_value, code_run_value, source_order};

/// The one selection hook a heal's context is read under (OF-418 L2, L10).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealContextPolicy {
    /// The seed's whole logical window or failure, every ref its records name, and the
    /// complete retry, run-tree and message-graph ancestry of everything it reaches, each
    /// read once, with no age, depth, count or byte bound.
    #[default]
    RecordedClosure,
}

/// What a heal's context is read from. Each seed names its own substrate's ids: a
/// retrieval run is no attempt, and a case ref is no entity.
#[derive(Clone, Copy, Debug)]
pub enum HealContextSeed<'s> {
    /// A detector's logical window: its exact recorded runs, oldest first.
    RetrievalWindow(&'s [RetrievalRunRecord]),
    /// A failure-ladder case: its failing attempt, its evidence, checkpoint, Q&A and task
    /// refs, and its blocked reports.
    FailureCase(&'s HealerCase),
    /// A blocked report the Issues job reads.
    BlockedReport {
        /// The report's receipt.
        receipt: EntityId,
        /// The durable run it was filed for, when it had one.
        run: Option<EntityId>,
    },
}

/// One part a heal's context could not read, and why. Never a refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealUnavailable {
    /// The part, engine-authored: its kind and its 32-hex id, as `body:<id>`.
    pub source: String,
    /// Why: `unrecorded`, `missing`, `missing_or_withheld`, `withheld:<count>`,
    /// `host_ref`, `not_an_entity_ref`, `owner_door_only`, `unlinked`, a read's own code
    /// or an error's kind.
    pub reason: String,
}

/// One stored link a heal's context followed, once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealLink {
    /// 32-hex id of the attempt or record the link is stored on.
    pub from: String,
    /// 32-hex id it names.
    pub to: String,
    /// `retry_of` or `run_parent` between attempts; `parent` or `spawned_by` from a
    /// message.
    pub kind: &'static str,
}

/// What a heal reads about a failure's recorded cause (OF-418 L2, L10).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct HealEvidenceContext {
    /// The selection it was read under.
    pub policy: HealContextPolicy,
    /// Every attempt the cause walk reached, 32-hex, in source order: each before the
    /// attempts its links name, ties by id, and those [`Self::cyclic`] names last.
    pub attempts: Vec<String>,
    /// Every stored retry, run-tree and message-graph link followed, once.
    pub links: Vec<HealLink>,
    /// 32-hex ids of the attempts and messages on a link cycle, or reached only through
    /// one, by id.
    pub cyclic: Vec<String>,
    /// Every part it could not read, and why.
    pub unavailable: Vec<HealUnavailable>,
    /// Everything read, whole: `runs`, `conversations`, `bodies`, `attempts`,
    /// `code_runs`, `reports` and `gate_decisions`. Foreign text rides only here, as
    /// data, never an instruction.
    pub untrusted: Value,
}

impl HealEvidenceContext {
    /// The context as a decision state's or a draft's data field.
    #[must_use]
    pub fn value(&self) -> Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}

/// The stored lineage a cause walk reached (OF-418 L10), as
/// `DreamerRunnerStore::cause_ancestry_in_txn` reads it.
#[derive(Debug, Default)]
pub(crate) struct CauseAncestry {
    /// Every attempt reached, each once, in the order reached.
    pub(crate) reached: Vec<AttemptRecord>,
    /// Every stored link followed, once: the attempt, the attempt it names, the kind.
    pub(crate) links: Vec<(AttemptId, AttemptId, &'static str)>,
    /// Each attempt a root or a link names that did not read, and why.
    pub(crate) gaps: Vec<(AttemptId, String)>,
}

impl Vault {
    /// What a heal reads about `seed`'s recorded cause, its bodies as `reader` reads them
    /// off this device (OF-418 L2, L10), under [`HealContextPolicy::default`]. It never
    /// fails: a part that does not read is an `unavailable` entry.
    #[must_use]
    pub fn heal_evidence_context(
        &self,
        reader: EntityId,
        seed: HealContextSeed<'_>,
    ) -> HealEvidenceContext {
        let mut gather = Gather::new(self, reader, HealContextPolicy::default());
        match seed {
            HealContextSeed::RetrievalWindow(runs) => gather.window(runs),
            HealContextSeed::FailureCase(case) => gather.case(case),
            HealContextSeed::BlockedReport { receipt, run } => gather.report_seed(receipt, run),
        }
        gather.finish()
    }
}

/// One context as it is read.
struct Gather<'v> {
    vault: &'v Vault,
    reader: EntityId,
    context: HealEvidenceContext,
    untrusted: Map<String, Value>,
    /// Attempts the cause walk starts from.
    roots: Vec<AttemptId>,
    /// Each blocked report read, with its entry.
    reports: Vec<(EntityId, Map<String, Value>)>,
    /// Each attempt reached, in source order, with its entry.
    attempts: Vec<(AttemptId, Map<String, Value>)>,
    /// Code runs to read: each reached attempt's and each report source's.
    code_runs: Vec<EntityId>,
    /// Entities whose bodies to read, in first-reference order.
    refs: Vec<EntityId>,
    /// Every entity named for a body or met as a conversation's message: each once.
    known: BTreeSet<EntityId>,
    /// The conversations' messages, whose graph links are walked.
    messages: Vec<EntityId>,
    /// Claims reached, whose gate decisions are read.
    claims: Vec<EntityId>,
    /// Attempts and messages the walks visited: the scan the context measures.
    walked: usize,
}

impl<'v> Gather<'v> {
    fn new(vault: &'v Vault, reader: EntityId, policy: HealContextPolicy) -> Self {
        Self {
            vault,
            reader,
            context: HealEvidenceContext {
                policy,
                ..HealEvidenceContext::default()
            },
            untrusted: Map::new(),
            roots: Vec::new(),
            reports: Vec::new(),
            attempts: Vec::new(),
            code_runs: Vec::new(),
            refs: Vec::new(),
            known: BTreeSet::new(),
            messages: Vec::new(),
            claims: Vec::new(),
            walked: 0,
        }
    }

    fn unavailable(&mut self, source: String, reason: impl Into<String>) {
        self.context.unavailable.push(HealUnavailable {
            source,
            reason: reason.into(),
        });
    }

    /// Names `id` for a body read, once.
    fn refer(&mut self, id: EntityId) {
        if self.known.insert(id) {
            self.refs.push(id);
        }
    }

    /// Names an entity ref's body for a read; a ref that is no entity id is marked.
    fn refer_hex(&mut self, part: &str, raw: &str) {
        match EntityId::from_hex(raw) {
            Ok(id) => self.refer(id),
            Err(_) => self.unavailable(part.to_owned(), "not_an_entity_ref"),
        }
    }

    /// A window's exact runs, whole, each with the bodies its results, its trace's stage
    /// candidates and its replay refs name, and the conversations the runs were retrieved
    /// for, read by the session judge's own recipe.
    fn window(&mut self, runs: &[RetrievalRunRecord]) {
        let mut shown = Vec::with_capacity(runs.len());
        for run in runs {
            let id = run.run_id.to_hex();
            match &run.trace {
                Some(trace) => {
                    let stages = trace
                        .per_channel
                        .iter()
                        .map(|channel| &channel.candidates)
                        .chain([
                            &trace.fused.candidates,
                            &trace.blended.candidates,
                            &trace.reranked.candidates,
                            &trace.final_stage.candidates,
                        ]);
                    for candidate in stages.flatten() {
                        if let Ok(entity) = EntityId::from_bytes(candidate.result_id) {
                            self.refer(entity);
                        }
                    }
                }
                None => self.unavailable(format!("trace:{id}"), "unrecorded"),
            }
            for result in &run.result_ids {
                if let Ok(entity) = EntityId::from_bytes(*result) {
                    self.refer(entity);
                }
            }
            match &run.replay_inputs {
                Some(inputs) => {
                    for (part, at) in [
                        ("query", &inputs.query_ref),
                        ("corpus", &inputs.corpus_snapshot_ref),
                    ] {
                        match at.as_deref().map(EntityId::from_hex) {
                            Some(Ok(entity)) => self.refer(entity),
                            Some(Err(_)) => self.unavailable(format!("{part}:{id}"), "host_ref"),
                            None => self.unavailable(format!("{part}:{id}"), "unrecorded"),
                        }
                    }
                }
                None => self.unavailable(format!("replay_inputs:{id}"), "unrecorded"),
            }
            shown.push(json!({
                "run": id,
                "record": serde_json::to_value(run).unwrap_or_default(),
            }));
        }
        self.untrusted.insert("runs".into(), Value::Array(shown));
        if runs.iter().all(|run| run.turn.is_none()) {
            self.unavailable("conversations".into(), "unrecorded");
            return;
        }
        match self.vault.session_judge_context(self.reader, runs) {
            Ok(text) => {
                for line in &text.lines {
                    if let Some(message) = &line.message
                        && let Ok(message) = EntityId::from_hex(message)
                    {
                        self.known.insert(message);
                        self.messages.push(message);
                    }
                }
                let text = serde_json::to_value(&text).unwrap_or_default();
                self.untrusted.insert("conversations".into(), text);
            }
            Err(error) => self.unavailable("conversations".into(), kind(&error)),
        }
    }

    /// A case's failing attempt, its refs and its blocked reports.
    fn case(&mut self, case: &HealerCase) {
        self.roots.push(case.failing_attempt_id);
        for (part, raw) in [
            ("case.evidence", &case.evidence_ref),
            ("case.checkpoint", &case.pre_fail_checkpoint_ref),
            ("case.qa_thread", &case.qa_thread_ref),
        ] {
            self.refer_hex(part, raw);
        }
        if let Some(task) = &case.task_ref {
            self.refer_hex("case.task", task);
        }
        for report in &case.blocked_reports {
            match EntityId::from_hex(&report.receipt_ref) {
                Ok(receipt) => self.report(receipt),
                Err(_) => self.unavailable("case.report".into(), "not_an_entity_ref"),
            }
        }
    }

    /// A report, its run's attempt and every other verified report its run filed.
    fn report_seed(&mut self, receipt: EntityId, run: Option<EntityId>) {
        self.report(receipt);
        let Some(run) = run else {
            return;
        };
        if let Ok(attempt) = AttemptId::from_bytes(run.as_bytes()) {
            self.roots.push(attempt);
        }
        let filed = self
            .vault
            .blocked_reports_of_run(run)
            .and_then(|refs| verified_blocked_reports(self.vault, &refs));
        match filed {
            Ok(filed) => {
                for other in filed {
                    if let Ok(other) = EntityId::from_hex(&other.receipt_ref) {
                        self.report(other);
                    }
                }
            }
            Err(error) => self.unavailable(format!("run_reports:{}", run.to_hex()), kind(&error)),
        }
    }

    /// One blocked report's receipt, whole, and the attempt it was bound to.
    fn report(&mut self, receipt: EntityId) {
        if self.reports.iter().any(|(read, _)| *read == receipt) {
            return;
        }
        let id = receipt.to_hex();
        let mut entry = Map::new();
        match read_blocked_receipt(self.vault, &receipt) {
            Ok(Some(body)) => {
                if let Some(attempt) = body
                    .attempt
                    .as_deref()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .and_then(|attempt| AttemptId::from_bytes(attempt.as_bytes()).ok())
                {
                    self.roots.push(attempt);
                }
                entry.insert(
                    "report".into(),
                    serde_json::to_value(&body).unwrap_or_default(),
                );
            }
            Ok(None) => self.unavailable(format!("report:{id}"), "missing"),
            Err(error) => self.unavailable(format!("report:{id}"), kind(&error)),
        }
        entry.insert("receipt".into(), Value::String(id));
        self.reports.push((receipt, entry));
    }

    /// Reads, in one snapshot, each report's replay source, the cause walk with every
    /// attempt's kept step requests, and every code run named.
    fn recorded(&mut self) {
        let vault = self.vault;
        let txn = match vault.store.env.read_txn() {
            Ok(txn) => txn,
            Err(error) => {
                self.unavailable("records".into(), kind(&Error::from(error)));
                return;
            }
        };
        for (receipt, entry) in &mut self.reports {
            let id = receipt.to_hex();
            match blocked_source_in(vault, &txn, receipt) {
                Ok(Some(source)) => {
                    self.code_runs.extend(source.code_run);
                    let source = serde_json::to_value(&source).unwrap_or_default();
                    entry.insert("source".into(), source);
                }
                Ok(None) => self.context.unavailable.push(HealUnavailable {
                    source: format!("report_source:{id}"),
                    reason: "unrecorded".into(),
                }),
                Err(error) => self.context.unavailable.push(HealUnavailable {
                    source: format!("report_source:{id}"),
                    reason: kind(&error),
                }),
            }
        }
        if self.roots.is_empty() {
            self.unavailable("ancestry".into(), "unlinked");
        } else {
            self.ancestry(&txn);
        }
        let mut runs = BTreeSet::new();
        let named = std::mem::take(&mut self.code_runs);
        let mut shown = Vec::new();
        for run in named.into_iter().filter(|run| runs.insert(*run)) {
            let id = run.to_hex();
            match vault.get_code_run_replay_record_in_txn(&txn, &run) {
                Ok(Some(record)) => {
                    for output in &record.outputs {
                        self.unavailable(
                            format!("output_body:{id}:{}", output.handle),
                            "owner_door_only",
                        );
                    }
                    shown.push(code_run_value(&record));
                }
                Ok(None) => self.unavailable(format!("code_run:{id}"), "unrecorded"),
                Err(error) => self.unavailable(format!("code_run:{id}"), kind(&error)),
            }
        }
        self.untrusted
            .insert("code_runs".into(), Value::Array(shown));
    }

    /// The complete stored ancestry of the roots, in source order, each attempt whole
    /// with the requests its steps kept.
    fn ancestry(&mut self, txn: &heed::RoTxn<'_>) {
        let vault = self.vault;
        let walk = DreamerRunnerStore::new(vault).cause_ancestry_in_txn(txn, &self.roots);
        self.walked += walk.reached.len() + walk.gaps.len();
        for (id, why) in walk.gaps {
            self.unavailable(
                format!("attempt:{}", bytes_to_hex_lower(id.as_bytes())),
                why,
            );
        }
        let ids: Vec<AttemptId> = walk.reached.iter().map(|record| record.id).collect();
        let (order, cyclic) = source_order(&ids, &walk.links);
        let hex = |id: &AttemptId| bytes_to_hex_lower(id.as_bytes());
        self.context.attempts = order.iter().map(hex).collect();
        self.context.cyclic.extend(cyclic.iter().map(hex));
        self.context
            .links
            .extend(walk.links.iter().map(|&(from, to, kind)| HealLink {
                from: hex(&from),
                to: hex(&to),
                kind,
            }));
        let mut records: BTreeMap<AttemptId, AttemptRecord> = walk
            .reached
            .into_iter()
            .map(|record| (record.id, record))
            .collect();
        for id in order {
            let Some(record) = records.remove(&id) else {
                continue;
            };
            let attempt = hex(&id);
            if let Some(task) = &record.task_ref {
                self.refer_hex(&format!("task:{attempt}"), task);
            }
            if let Ok(run) = EntityId::from_bytes(*id.as_bytes()) {
                self.code_runs.push(run);
            }
            let mut entry = Map::new();
            match step_sources_in(vault, txn, id) {
                Ok(steps) => {
                    let mut kept = Vec::with_capacity(steps.len());
                    for (key, source) in steps {
                        self.claims.extend(source.claim);
                        kept.push(json!({
                            "step": bytes_to_hex_lower(&key.step),
                            "lease": key.lease,
                            "call": key.call,
                            "source": serde_json::to_value(&source).unwrap_or_default(),
                        }));
                    }
                    entry.insert("kept_requests".into(), Value::Array(kept));
                }
                Err(error) => self.unavailable(format!("kept_requests:{attempt}"), kind(&error)),
            }
            entry.insert("attempt".into(), Value::String(attempt));
            entry.insert(
                "record".into(),
                serde_json::to_value(&record).unwrap_or_default(),
            );
            self.attempts.push((id, entry));
        }
    }

    /// Each reached attempt's terminal pack receipt, whole; a live one has none yet.
    fn pack_receipts(&mut self) {
        let mut missing = Vec::new();
        for (id, entry) in &mut self.attempts {
            let attempt = bytes_to_hex_lower(id.as_bytes());
            match attempt_pack_receipt(self.vault, &attempt_pack_receipt_id(id)) {
                Ok(Some(receipt)) => {
                    let receipt = serde_json::to_value(&receipt).unwrap_or_default();
                    entry.insert("pack_receipt".into(), receipt);
                }
                Ok(None) => missing.push((attempt, "unrecorded".to_owned())),
                Err(error) => missing.push((attempt, kind(&error))),
            }
        }
        for (attempt, why) in missing {
            self.unavailable(format!("pack_receipt:{attempt}"), why);
        }
    }

    /// Every body named, through the reader's scoped lane, then canon §6's walk to
    /// cause over the conversation graph: the `parent` and `spawned_by` links out of
    /// every message reached, through the lane's receipted edge read, each message once,
    /// to the end. No other edge kind is read.
    fn bodies_and_graph(&mut self) {
        if self.refs.is_empty() && self.messages.is_empty() {
            return;
        }
        let vault = self.vault;
        let memory = vault
            .memory(self.reader, EdgeActorClass::Human)
            .at(CallerLocality::OffDevice);
        let lane = match memory.read_lane(ClaimReadStatus::Recorded) {
            Ok(lane) => lane,
            Err(error) => {
                for id in std::mem::take(&mut self.refs) {
                    self.unavailable(format!("body:{}", id.to_hex()), error.code.clone());
                }
                self.unavailable("message_graph".into(), error.code);
                return;
            }
        };
        let mut walk: VecDeque<EntityId> = std::mem::take(&mut self.messages).into();
        let refs = std::mem::take(&mut self.refs);
        self.read_bodies(&memory, &lane, &refs, &mut walk);
        let mut walked = BTreeSet::new();
        let mut nodes = Vec::new();
        let mut links = Vec::new();
        while let Some(message) = walk.pop_front() {
            if !walked.insert(message) {
                continue;
            }
            nodes.push(message);
            let id = message.to_hex();
            let mut named = Vec::new();
            for (kind_of, name) in [
                (EdgeKind::Parent, "parent"),
                (EdgeKind::SpawnedBy, "spawned_by"),
            ] {
                let read = match lane.edges_out_of_kind(&message, kind_of) {
                    Ok(read) => read,
                    Err(error) => {
                        self.unavailable(format!("{name}:{id}"), kind(&error));
                        continue;
                    }
                };
                if read.receipt.suppressed_count > 0 {
                    let withheld = format!("withheld:{}", read.receipt.suppressed_count);
                    self.unavailable(format!("{name}:{id}"), withheld);
                }
                let Some(edges) = read.value else {
                    self.unavailable(format!("message:{id}"), "missing_or_withheld");
                    break;
                };
                for edge in edges {
                    links.push((message, edge.target, name));
                    self.context.links.push(HealLink {
                        from: id.clone(),
                        to: edge.target.to_hex(),
                        kind: name,
                    });
                    if self.known.insert(edge.target) {
                        named.push(edge.target);
                    }
                }
            }
            self.read_bodies(&memory, &lane, &named, &mut walk);
        }
        self.walked += nodes.len();
        let (_, cyclic) = source_order(&nodes, &links);
        self.context
            .cyclic
            .extend(cyclic.iter().map(EntityId::to_hex));
    }

    /// The bodies of `ids` in one lane read, each whole, a MESSAGE's result attachment
    /// beside its words. A MESSAGE read joins the graph `walk`; a CLAIM read has its gate
    /// decisions read.
    fn read_bodies(
        &mut self,
        memory: &Memory<'_>,
        lane: &ScopedRead<'_>,
        ids: &[EntityId],
        walk: &mut VecDeque<EntityId>,
    ) {
        if ids.is_empty() {
            return;
        }
        let reads: Vec<_> = ids.iter().copied().map(PointRead::id).collect();
        let rows = match lane.read(&reads, None) {
            Ok(read) => read.value,
            Err(error) => {
                for id in ids {
                    self.unavailable(format!("body:{}", id.to_hex()), kind(&error));
                }
                return;
            }
        };
        let mut shown = Vec::with_capacity(rows.len());
        for (id, row) in ids.iter().zip(rows) {
            let Some(row) = row else {
                self.unavailable(format!("body:{}", id.to_hex()), "missing_or_withheld");
                continue;
            };
            let message = row.entity_type == ENTITY_TYPE_MESSAGE;
            if message {
                walk.push_back(row.id);
            }
            if row.entity_type == ENTITY_TYPE_CLAIM {
                self.claims.push(row.id);
            }
            let result = if message {
                whole_result(memory, &row.id)
            } else {
                None
            };
            shown.push(json!({
                "id": row.id.to_hex(),
                "entity_type": row.entity_type,
                "occurred": [row.occurred.start, row.occurred.end],
                "learned_at": row.learned_at,
                "body": row.body.as_deref().map(body_value),
                "result": result,
            }));
        }
        if let Some(Value::Array(bodies)) = self.untrusted.get_mut("bodies") {
            bodies.extend(shown);
        } else {
            self.untrusted.insert("bodies".into(), Value::Array(shown));
        }
    }

    /// The exact gate decision rows of every claim reached, whole.
    fn gate_decisions(&mut self) {
        if self.claims.is_empty() {
            return;
        }
        let vault = self.vault;
        let txn = match vault.store.env.read_txn() {
            Ok(txn) => txn,
            Err(error) => {
                self.unavailable("gate_decisions".into(), kind(&Error::from(error)));
                return;
            }
        };
        let mut seen = BTreeSet::new();
        let mut shown = Vec::new();
        for claim in std::mem::take(&mut self.claims) {
            if !seen.insert(claim) {
                continue;
            }
            match vault
                .store
                .gate_decisions_for_claim_in_txn(&txn, claim.as_bytes())
            {
                Ok(records) => shown.extend(records.iter().map(|record| {
                    json!({
                        "claim": claim.to_hex(),
                        "decision": serde_json::to_value(record).unwrap_or_default(),
                    })
                })),
                Err(error) => {
                    self.unavailable(format!("gate_decisions:{}", claim.to_hex()), kind(&error));
                }
            }
        }
        self.untrusted
            .insert("gate_decisions".into(), Value::Array(shown));
    }

    /// Reads what the seed named, in order, and measures the whole (Rule 5).
    fn finish(mut self) -> HealEvidenceContext {
        self.recorded();
        self.pack_receipts();
        self.bodies_and_graph();
        self.gate_decisions();
        let reports = std::mem::take(&mut self.reports);
        let attempts = std::mem::take(&mut self.attempts);
        self.untrusted.insert(
            "reports".into(),
            reports
                .into_iter()
                .map(|(_, entry)| Value::Object(entry))
                .collect(),
        );
        self.untrusted.insert(
            "attempts".into(),
            attempts
                .into_iter()
                .map(|(_, entry)| Value::Object(entry))
                .collect(),
        );
        let items: usize = self
            .untrusted
            .values()
            .map(|part| match part {
                Value::Array(rows) => rows.len(),
                other => other["lines"].as_array().map_or(0, Vec::len),
            })
            .sum();
        let vault = self.vault;
        let walked = self.walked;
        let mut context = self.context;
        context.untrusted = Value::Object(self.untrusted);
        // The context goes whole: past each row the read asks and reads on.
        let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, walked as u64);
        let _ = vault.measure_limit(EngineLimit::MaintenanceRowItems, items as u64);
        let bytes = serde_json::to_vec(&context).map_or(0, |bytes| bytes.len());
        let _ = vault.measure_limit(EngineLimit::MaintenanceTextBytes, bytes as u64);
        context
    }
}

/// An error by its kind only: its message can quote the vault.
fn kind(error: &Error) -> String {
    format!("{:?}", error.kind())
}
