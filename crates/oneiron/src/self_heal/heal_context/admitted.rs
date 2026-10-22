//! The reader's admission of a heal context's recorded trace (FIX 10093). Every trace
//! part is read and admitted in one snapshot of the reader's own scoped lane, and only
//! what that lane admits is copied, with its receipt. A part whose recorded source rows or
//! worlds the reader may not read is `withheld`. A part that records no complete set of
//! the rows it was read from is copied whole only to the vault owner's key, revalidated in
//! that snapshot; to any other reader it is `unprovable`. Each is an `unavailable` entry,
//! never a refusal of the context. The raw getters below run only inside that admission.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use super::records::{code_run_value, source_order};
use super::{Gather, HealLink, kind};
use crate::attempt_queue::{AttemptId, AttemptRecord};
use crate::claim::{PointRead, ScopedRead, ScopedReadReceipt};
use crate::code_run::blocked::read_blocked_receipt;
use crate::dreamer_runner::DreamerRunnerStore;
use crate::entity_id::bytes_to_hex_lower;
use crate::receipt::{ReceiptRecord, attempt_pack_receipt_id};
use crate::self_heal::blocked_reports::{RunWorlds, blocked_source_in, step_sources_in};
use crate::self_heal::centroid_evidence::run_sources;
use crate::side_table::{self, Named, SideTable};
use crate::store::RetrievalRunRecord;
use crate::{EntityId, Error, Result};

/// The attempt pack receipt ledger, read in the admission's own snapshot: a second typed
/// binding of the receipt ledger's table, for reading only.
const PACK_RECEIPT: SideTable<String, ReceiptRecord, Named> =
    SideTable::new(&side_table::ATTEMPT_PACK_RECEIPT);

/// A part's recorded rows or worlds hold one the reader may not read.
const WITHHELD: &str = "withheld";
/// A part records no complete set of the rows it was read from, and the reader is not
/// the vault owner.
const UNPROVABLE: &str = "unprovable";

/// One snapshot of the reader's lane, judging trace parts.
struct Admit<'a, 'l, 't> {
    lane: &'a ScopedRead<'l>,
    txn: &'a heed::RoTxn<'t>,
    /// The reader reads as the vault owner, its key revalidated in this snapshot.
    owner: bool,
}

impl Admit<'_, '_, '_> {
    /// `None` when the reader may have a part that records it was read from `rows` (every
    /// such row when `complete`) in `worlds`; else why not.
    fn part(
        &self,
        rows: &[EntityId],
        complete: bool,
        worlds: &[EntityId],
    ) -> Result<Option<&'static str>> {
        if !complete && !self.owner {
            return Ok(Some(UNPROVABLE));
        }
        if self
            .lane
            .entities_readable_in_txn(self.txn, rows)?
            .contains(&false)
        {
            return Ok(Some(WITHHELD));
        }
        for world in worlds {
            if !self.lane.world_readable_in(self.txn, Some(*world))? {
                return Ok(Some(WITHHELD));
            }
        }
        Ok(None)
    }
}

impl Gather<'_> {
    /// Conjoins one lane read's receipt into the context's narrowing.
    pub(super) fn narrow(&mut self, receipt: &ScopedReadReceipt) {
        match &mut self.context.narrowing {
            Some(narrowing) => narrowing.restrict_with(receipt),
            None => self.context.narrowing = Some(receipt.clone()),
        }
    }

    /// Each report's receipt MESSAGE through the reader's lane; a receipt it admits is
    /// decoded whole, and the attempt it was bound to is followed.
    pub(super) fn report_bodies(&mut self, lane: &ScopedRead<'_>) {
        if self.reports.is_empty() {
            return;
        }
        let reads: Vec<_> = self
            .reports
            .iter()
            .map(|(receipt, _)| PointRead::id(*receipt))
            .collect();
        let rows = match lane.read(&reads, None) {
            Ok(read) => {
                self.narrow(&read.receipt);
                read.value
            }
            Err(error) => {
                let why = kind(&error);
                let parts: Vec<_> = self
                    .reports
                    .iter()
                    .map(|(receipt, _)| format!("report:{}", receipt.to_hex()))
                    .collect();
                for part in parts {
                    self.unavailable(part, why.clone());
                }
                return;
            }
        };
        let vault = self.vault;
        let mut missing = Vec::new();
        for ((receipt, entry), row) in self.reports.iter_mut().zip(rows) {
            let part = format!("report:{}", receipt.to_hex());
            if row.is_none() {
                missing.push((part, "missing_or_withheld".to_owned()));
                continue;
            }
            // The lane admitted the witnessed MESSAGE; its receipt decodes from that same
            // immutable row.
            match read_blocked_receipt(vault, receipt) {
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
                Ok(None) => missing.push((part, "missing".to_owned())),
                Err(error) => missing.push((part, kind(&error))),
            }
        }
        for (part, why) in missing {
            self.unavailable(part, why);
        }
    }

    /// The recorded trace, read and admitted in one snapshot of the reader's lane: the
    /// window's runs, each report's replay source, the cause walk with every attempt's
    /// kept step requests, every code run named and each reached attempt's pack receipt.
    pub(super) fn recorded(&mut self, lane: &ScopedRead<'_>) {
        let read = lane.read_projected(&[], None, |txn, _| {
            let admit = Admit {
                lane,
                txn,
                owner: lane.actor_key().reads_as_vault_owner(),
            };
            self.runs_in(&admit);
            self.report_sources_in(&admit);
            if self.roots.is_empty() {
                self.unavailable("ancestry".into(), "unlinked");
            } else {
                self.ancestry_in(&admit);
            }
            self.code_runs_in(&admit);
            self.pack_receipts_in(&admit);
            Ok::<_, Error>(())
        });
        match read {
            Ok(read) => self.narrow(&read.receipt),
            Err(error) => {
                let why = kind(&error);
                if let Some(runs) = self.runs.take() {
                    for run in runs {
                        self.unavailable(format!("run:{}", run.run_id.to_hex()), why.clone());
                    }
                }
                self.unavailable("records".into(), why);
            }
        }
    }

    /// The window's runs. A run's state, counts and config record no source rows, so a
    /// run is the owner's alone; the owner's copy leaves out every result, candidate and
    /// ref the lane does not admit.
    fn runs_in(&mut self, admit: &Admit<'_, '_, '_>) {
        let Some(runs) = self.runs.take() else {
            return;
        };
        let mut shown = Vec::with_capacity(runs.len());
        for mut run in runs {
            let id = run.run_id.to_hex();
            let part = format!("run:{id}");
            if !admit.owner {
                self.unavailable(part, UNPROVABLE);
                continue;
            }
            let sources: Vec<EntityId> = run_sources(&run)
                .into_iter()
                .filter_map(|source| EntityId::from_bytes(source).ok())
                .collect();
            let readable = match admit.lane.entities_readable_in_txn(admit.txn, &sources) {
                Ok(readable) => readable,
                Err(error) => {
                    self.unavailable(part, kind(&error));
                    continue;
                }
            };
            let denied: BTreeSet<[u8; 16]> = sources
                .iter()
                .zip(readable)
                .filter(|(_, readable)| !readable)
                .map(|(source, _)| *source.as_bytes())
                .collect();
            if !denied.is_empty() {
                withhold_run_sources(&mut run, &denied);
                self.unavailable(part, format!("withheld:{}", denied.len()));
            }
            shown.push(json!({
                "run": id,
                "record": serde_json::to_value(&run).unwrap_or_default(),
            }));
        }
        self.untrusted.insert("runs".into(), Value::Array(shown));
    }

    /// Each report's replay source. It records the worlds its run was scoped to and read,
    /// but not every row its request was built from: the owner's alone, and only when the
    /// lane admits its receipt and every world it records.
    fn report_sources_in(&mut self, admit: &Admit<'_, '_, '_>) {
        let vault = self.vault;
        let mut missing = Vec::new();
        for (receipt, entry) in &mut self.reports {
            let part = format!("report_source:{}", receipt.to_hex());
            if !admit.owner {
                missing.push((part, UNPROVABLE.to_owned()));
                continue;
            }
            let source = match blocked_source_in(vault, admit.txn, receipt) {
                Ok(Some(source)) => source,
                Ok(None) => {
                    missing.push((part, "unrecorded".to_owned()));
                    continue;
                }
                Err(error) => {
                    missing.push((part, kind(&error)));
                    continue;
                }
            };
            let mut worlds = match &source.worlds {
                RunWorlds::Scoped { worlds } => worlds.clone(),
                RunWorlds::Unscoped | RunWorlds::Unproved => Vec::new(),
            };
            if let Some(read) = &source.read_worlds {
                worlds.extend(read.worlds.iter().copied());
            }
            match admit.part(&[*receipt], false, &worlds) {
                Ok(None) => {
                    self.code_runs.extend(source.code_run);
                    entry.insert(
                        "source".into(),
                        serde_json::to_value(&source).unwrap_or_default(),
                    );
                }
                Ok(Some(why)) => missing.push((part, why.to_owned())),
                Err(error) => missing.push((part, kind(&error))),
            }
        }
        for (part, why) in missing {
            self.unavailable(part, why);
        }
    }

    /// The complete stored ancestry of the roots, in source order. An attempt's record
    /// is admitted against the complete source rows it recorded, else it is the owner's
    /// alone; each kept step request is admitted on its own.
    fn ancestry_in(&mut self, admit: &Admit<'_, '_, '_>) {
        let vault = self.vault;
        let walk = DreamerRunnerStore::new(vault).cause_ancestry_in_txn(admit.txn, &self.roots);
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
            let mut entry = Map::new();
            let rows = record.source_rows();
            match admit.part(rows.unwrap_or_default(), rows.is_some(), &[]) {
                Ok(None) => {
                    if let Some(task) = &record.task_ref {
                        self.refer_hex(&format!("task:{attempt}"), task);
                    }
                    if let Ok(run) = EntityId::from_bytes(*id.as_bytes()) {
                        self.code_runs.push(run);
                    }
                    entry.insert(
                        "record".into(),
                        serde_json::to_value(&record).unwrap_or_default(),
                    );
                }
                Ok(Some(why)) => self.unavailable(format!("attempt_record:{attempt}"), why),
                Err(error) => self.unavailable(format!("attempt_record:{attempt}"), kind(&error)),
            }
            self.kept_requests_in(admit, id, &attempt, &mut entry);
            entry.insert("attempt".into(), Value::String(attempt));
            self.attempts.push((id, entry));
        }
    }

    /// An attempt's kept step requests. A request records the actor, subject and claim it
    /// served, not the rows it was built from: the owner's alone, and only when the lane
    /// admits the subject and claim it names.
    fn kept_requests_in(
        &mut self,
        admit: &Admit<'_, '_, '_>,
        id: AttemptId,
        attempt: &str,
        entry: &mut Map<String, Value>,
    ) {
        let steps = match step_sources_in(self.vault, admit.txn, id) {
            Ok(steps) => steps,
            Err(error) => {
                self.unavailable(format!("kept_requests:{attempt}"), kind(&error));
                return;
            }
        };
        let mut kept = Vec::with_capacity(steps.len());
        for (key, source) in steps {
            let step = bytes_to_hex_lower(&key.step);
            let anchors: Vec<EntityId> = source.subject.into_iter().chain(source.claim).collect();
            match admit.part(&anchors, false, &[]) {
                Ok(None) => {
                    self.claims.extend(source.claim);
                    kept.push(json!({
                        "step": step,
                        "lease": key.lease,
                        "call": key.call,
                        "source": serde_json::to_value(&source).unwrap_or_default(),
                    }));
                }
                Ok(Some(why)) => self.unavailable(format!("kept_request:{attempt}:{step}"), why),
                Err(error) => {
                    self.unavailable(format!("kept_request:{attempt}:{step}"), kind(&error));
                }
            }
        }
        entry.insert("kept_requests".into(), Value::Array(kept));
    }

    /// Every code run named. A replay record keeps its bridge calls, checkpoints and
    /// output previews with no rows they were read from: the owner's alone. Output bodies
    /// are read only through the owner's result doors.
    fn code_runs_in(&mut self, admit: &Admit<'_, '_, '_>) {
        let vault = self.vault;
        let mut runs = BTreeSet::new();
        let named = std::mem::take(&mut self.code_runs);
        let mut shown = Vec::new();
        for run in named.into_iter().filter(|run| runs.insert(*run)) {
            let id = run.to_hex();
            match admit.part(&[], false, &[]) {
                Ok(None) => {}
                Ok(Some(why)) => {
                    self.unavailable(format!("code_run:{id}"), why);
                    continue;
                }
                Err(error) => {
                    self.unavailable(format!("code_run:{id}"), kind(&error));
                    continue;
                }
            }
            match vault.get_code_run_replay_record_in_txn(admit.txn, &run) {
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

    /// Each reached attempt's terminal pack receipt, admitted against the complete source
    /// rows its terminal transition froze into it, else the owner's alone; a live attempt
    /// has none yet.
    fn pack_receipts_in(&mut self, admit: &Admit<'_, '_, '_>) {
        let vault = self.vault;
        let mut missing = Vec::new();
        for (id, entry) in &mut self.attempts {
            let attempt = bytes_to_hex_lower(id.as_bytes());
            let receipt =
                match PACK_RECEIPT.get(&vault.store, admit.txn, &attempt_pack_receipt_id(id)) {
                    Ok(Some(receipt)) => receipt,
                    Ok(None) => {
                        missing.push((attempt, "unrecorded".to_owned()));
                        continue;
                    }
                    Err(error) => {
                        missing.push((attempt, kind(&error)));
                        continue;
                    }
                };
            let rows = receipt.pack_source_rows();
            match admit.part(rows.as_deref().unwrap_or_default(), rows.is_some(), &[]) {
                Ok(None) => {
                    entry.insert(
                        "pack_receipt".into(),
                        serde_json::to_value(&receipt).unwrap_or_default(),
                    );
                }
                Ok(Some(why)) => missing.push((attempt, why.to_owned())),
                Err(error) => missing.push((attempt, kind(&error))),
            }
        }
        for (attempt, why) in missing {
            self.unavailable(format!("pack_receipt:{attempt}"), why);
        }
    }

    /// The exact gate decision rows of every claim reached, each claim admitted in the
    /// snapshot its rows are read in.
    pub(super) fn gate_decisions(&mut self, lane: &ScopedRead<'_>) {
        if self.claims.is_empty() {
            return;
        }
        let mut seen = BTreeSet::new();
        let claims: Vec<EntityId> = std::mem::take(&mut self.claims)
            .into_iter()
            .filter(|claim| seen.insert(*claim))
            .collect();
        let vault = self.vault;
        let read = lane.read_projected(&[], None, |txn, _| {
            let readable = lane.entities_readable_in_txn(txn, &claims)?;
            let mut shown = Vec::new();
            let mut missing = Vec::new();
            for (claim, readable) in claims.iter().zip(readable) {
                let part = format!("gate_decisions:{}", claim.to_hex());
                if !readable {
                    missing.push((part, WITHHELD.to_owned()));
                    continue;
                }
                match vault
                    .store
                    .gate_decisions_for_claim_in_txn(txn, claim.as_bytes())
                {
                    Ok(records) => shown.extend(records.iter().map(|record| {
                        json!({
                            "claim": claim.to_hex(),
                            "decision": serde_json::to_value(record).unwrap_or_default(),
                        })
                    })),
                    Err(error) => missing.push((part, kind(&error))),
                }
            }
            Ok::<_, Error>((shown, missing))
        });
        match read {
            Ok(read) => {
                self.narrow(&read.receipt);
                let (shown, missing) = read.value;
                for (part, why) in missing {
                    self.unavailable(part, why);
                }
                self.untrusted
                    .insert("gate_decisions".into(), Value::Array(shown));
            }
            Err(error) => self.unavailable("gate_decisions".into(), kind(&error)),
        }
    }
}

/// Leaves out of a run every id the reader may not read: its results, scored results,
/// every trace stage's candidates, and a query or corpus ref.
fn withhold_run_sources(run: &mut RetrievalRunRecord, denied: &BTreeSet<[u8; 16]>) {
    run.result_ids.retain(|id| !denied.contains(id));
    run.score_breakdown
        .retain(|row| !denied.contains(&row.result_id));
    if let Some(trace) = &mut run.trace {
        let stages = trace
            .per_channel
            .iter_mut()
            .map(|channel| &mut channel.candidates)
            .chain([
                &mut trace.fused.candidates,
                &mut trace.blended.candidates,
                &mut trace.reranked.candidates,
                &mut trace.final_stage.candidates,
            ]);
        for candidates in stages {
            candidates.retain(|candidate| !denied.contains(&candidate.result_id));
        }
    }
    if let Some(inputs) = &mut run.replay_inputs {
        for at in [&mut inputs.query_ref, &mut inputs.corpus_snapshot_ref] {
            if at
                .as_deref()
                .and_then(|raw| EntityId::from_hex(raw).ok())
                .is_some_and(|id| denied.contains(id.as_bytes()))
            {
                *at = None;
            }
        }
    }
}
