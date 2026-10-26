//! The Coach's browser programs (CUA E8, FIX 7605): each night, fixed code
//! reads the solved-run evidence that library runs and TASK runs left and the
//! library's failure index, and proposes programs. No model call, skill or
//! browser. Two runs of one exact group that no live program covers make a
//! pair candidate. A program whose runs failed, live or retired, makes a
//! repair from its group's runs that are not its own or its successor's.
//! Each candidate is one Proposed finding. An aligned one also queues one
//! admission job in the same write, and the host's admission worker replays
//! it: the Coach never admits or files. The Coach reads as itself, never as
//! the source caller or the owner. A group is marked processed in the write
//! that proposed from it, and only when the Coach read every row of it.
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use super::coach::COACH_BROWSER_PROGRAMS_FACET;
use super::proposals;
use crate::browser_library::{
    DirtySolvedGroup, ProgramAdmissionJob, ProgramFailureRef, ProgramSeen, ScopedSolvedGroupKey,
    SolvedGroupKey, SolvedRunEvidence, SolvedSource, WorkflowRecord, dirty_solved_groups,
    enqueue_program_admission_in_txn, mark_group_clean, mark_program_seen_in_txn,
    program_admission_queued, program_seen, programs_with_failures, retired_workflow,
    site_workflows, solved_group_coverage, solved_runs_in_group,
};
use crate::claim::{ScopedRead, ScopedReadActorKey, ScopedReadReceipt};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::entity_id::bytes_to_hex_lower;
use crate::write_envelope::WriteEnvelope;
use crate::{EntityId, Error, Result, Vault};

mod induction;

use induction::{Candidate, INDUCTION_VERSION, Predecessor};

/// The predicate a browser-program finding is filed under.
pub const COACH_BROWSER_PROGRAMS_PREDICATE: &str = "coach.browser_programs.proposal";

/// What one browser-programs pass read and proposed.
#[derive(Debug, Clone, Default)]
pub struct CoachBrowserProgramsReport {
    /// Dirty groups read.
    pub groups: usize,
    /// Groups marked processed through their changed generation.
    pub groups_cleaned: usize,
    /// Groups a live program covers: no pair candidate.
    pub groups_covered: usize,
    /// Groups and repairs with a row or source the Coach could not read:
    /// a group among them stays dirty.
    pub withheld: usize,
    /// Evidence rows read.
    pub evidence: usize,
    /// Failed programs read, live or retired.
    pub failed_programs: usize,
    pub candidates: usize,
    /// Findings filed, the diagnostics among them.
    pub findings: usize,
    pub diagnostics: usize,
    /// Candidates an earlier pass proposed.
    pub already_seen: usize,
    /// Admission jobs queued, one-time catch-ups for proposal-only marks
    /// among them.
    pub jobs: usize,
    /// Repairs with no evidence a finding can cite, reported only.
    pub repairs_pending: Vec<CoachBrowserRepairPending>,
    /// Groups and programs whose write rolled back, and why.
    pub errors: Vec<String>,
    /// Each evidence page's narrowing receipt.
    pub receipts: Vec<ScopedReadReceipt>,
}

/// A failed program the pass could not propose a repair for, and why.
#[derive(Debug, Clone)]
pub struct CoachBrowserRepairPending {
    pub program: EntityId,
    pub reason: &'static str,
}

impl Vault {
    /// One `coach.browser_programs` pass under its leased attempt: every
    /// dirty group's pair candidates, then every failed program's repairs,
    /// each group's or program's findings, admission jobs and seen marks in
    /// one write. A write that fails rolls back and is reported; the pass
    /// goes on.
    ///
    /// # Errors
    ///
    /// A lease that is not this facet's Coach attempt, and storage errors
    /// reading the indexes.
    pub fn run_coach_browser_programs(
        &self,
        attempt: &DreamerAdmittedAttempt,
        now: u64,
    ) -> Result<CoachBrowserProgramsReport> {
        self.require_coach_attempt(attempt, COACH_BROWSER_PROGRAMS_FACET)?;
        let envelope = proposals::run_tray_envelope(
            self,
            COACH_BROWSER_PROGRAMS_FACET,
            attempt.status.attempt.id,
        )?;
        let coach = self.coach_authority()?.entity_ref();
        let key = ScopedReadActorKey::with_actor_class(coach.to_hex(), "system")
            .ok_or_else(|| Error::InvalidConfig("invalid Coach read key".into()))?
            .require_relationship_grants(Some(coach));
        let read = self.scoped_read(key);
        let mut pass = Pass {
            vault: self,
            read: &read,
            coach,
            envelope: &envelope,
            now,
            report: CoachBrowserProgramsReport::default(),
        };
        let mut dirty = Vec::new();
        let mut after = None;
        loop {
            let page = dirty_solved_groups(self, after.as_ref())?;
            dirty.extend(page.items);
            let Some(next) = page.next else { break };
            after = Some(next);
        }
        for group in &dirty {
            if let Err(error) = pass.group(group) {
                let digest = bytes_to_hex_lower(&group.digest);
                pass.report.errors.push(format!("group {digest}: {error}"));
            }
        }
        let mut live = BTreeMap::new();
        let mut after = None;
        loop {
            let page = programs_with_failures(self, after.as_ref())?;
            for failed in page.items.iter().filter(|failed| failed.failures > 0) {
                if let Err(error) = pass.repair(failed, &mut live) {
                    let program = failed.id.to_hex();
                    pass.report
                        .errors
                        .push(format!("program {program}: {error}"));
                }
            }
            let Some(next) = page.next else { break };
            after = Some(next);
        }
        Ok(pass.report)
    }
}

/// One pass's reader, finding envelope and tally.
struct Pass<'a> {
    vault: &'a Vault,
    read: &'a ScopedRead<'a>,
    coach: EntityId,
    envelope: &'a WriteEnvelope,
    now: u64,
    report: CoachBrowserProgramsReport,
}

/// One write's work: the candidates of one group or one failed program.
struct GroupWrite<'k> {
    key: &'k ScopedSolvedGroupKey,
    digest: [u8; 32],
    candidates: Vec<Candidate>,
    /// The generation each seen mark records: the group's changed one, or
    /// the program's failure count.
    generation: u64,
    predecessor: Option<EntityId>,
    failure_generation: u64,
    /// The generation to mark the group processed through, for a pair
    /// group the Coach read whole.
    clean: Option<u64>,
    /// Whether a page of the group withheld a row.
    withheld: bool,
}

impl GroupWrite<'_> {
    fn job(&self, candidate: &Candidate, finding: EntityId) -> ProgramAdmissionJob {
        ProgramAdmissionJob {
            finding,
            fingerprint: candidate.fingerprint,
            group: self.digest,
            scope: self.key.scope.clone(),
            proposal: candidate.proposal.clone(),
            from_runs: candidate.from_runs.clone(),
            source_evidence: candidate.source_evidence.clone(),
            predecessor: self.predecessor,
            failure_generation: self.failure_generation,
            induction_version: INDUCTION_VERSION,
        }
    }
}

/// What one write did.
#[derive(Default)]
struct Tally {
    findings: usize,
    diagnostics: usize,
    seen: usize,
    jobs: usize,
    withheld: bool,
    covered: bool,
    cleaned: bool,
}

impl Pass<'_> {
    /// A dirty group: with no live program covering it, every pair of its
    /// evidence from two distinct runs.
    fn group(&mut self, dirty: &DirtySolvedGroup) -> Result<()> {
        self.report.groups += 1;
        let (evidence, withheld) = self.drain(&dirty.key)?;
        let covered = !solved_group_coverage(self.vault, &dirty.digest)?.is_empty();
        let candidates = if covered {
            Vec::new()
        } else {
            self.pairs(&dirty.digest, evidence, None)?
        };
        self.commit(&GroupWrite {
            key: &dirty.key,
            digest: dirty.digest,
            candidates,
            generation: dirty.changed,
            predecessor: None,
            failure_generation: 0,
            clean: (!withheld).then_some(dirty.changed),
            withheld,
        })
    }

    /// A failed program: its exact record, live or retired, and its group's
    /// runs that are not its own or its successor's.
    fn repair(
        &mut self,
        failed: &ProgramFailureRef,
        live: &mut BTreeMap<String, Vec<WorkflowRecord>>,
    ) -> Result<()> {
        self.report.failed_programs += 1;
        let site = &failed.refs.site;
        let records = match live.entry(site.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(site_workflows(self.vault, site, None, None)?),
        };
        let record = match records.iter().find(|record| record.id == failed.id) {
            Some(record) => Some(record.clone()),
            None => retired_workflow(self.vault, failed.id)?.map(|retired| retired.record),
        };
        let Some(record) = record else {
            self.pending(failed.id, "its record is gone");
            return Ok(());
        };
        let Some(filed) = record.filed_scope else {
            self.pending(failed.id, "it was filed with no caller scope");
            return Ok(());
        };
        let key = ScopedSolvedGroupKey {
            scope: filed.scope,
            group: SolvedGroupKey {
                site: record.site,
                origin: filed.origin,
                type_ref: record.type_ref,
                subgoal: record.program.subgoal,
            },
        };
        let (evidence, withheld) = self.drain(&key)?;
        let changed: Vec<SolvedRunEvidence> = evidence
            .into_iter()
            .filter(|evidence| !own_run(evidence, failed))
            .collect();
        let predecessor = Predecessor {
            id: failed.id.to_hex(),
            failures: failed.failures,
            retired: failed.retired,
            retire_reason: failed.retire_reason.clone(),
            supersedes: failed.refs.supersedes.as_ref().map(EntityId::to_hex),
            successor: failed.refs.successor.as_ref().map(EntityId::to_hex),
        };
        let digest = key.digest();
        let distinct = changed
            .iter()
            .any(|evidence| evidence.run_id != changed[0].run_id);
        let candidates = if changed.is_empty() {
            self.report.withheld += usize::from(withheld);
            let reason = if withheld {
                "its group's other runs are withheld from the Coach"
            } else {
                "no run but its own or its successor's"
            };
            self.pending(failed.id, reason);
            return Ok(());
        } else if distinct {
            self.pairs(&digest, changed, Some(&predecessor))?
        } else {
            let singles = changed
                .iter()
                .map(|evidence| induction::induce(&digest, evidence, None, Some(&predecessor)))
                .collect::<Result<Vec<_>>>()?;
            self.report.candidates += singles.len();
            singles
        };
        self.commit(&GroupWrite {
            key: &key,
            digest,
            candidates,
            generation: failed.failures,
            predecessor: Some(failed.id),
            failure_generation: failed.failures,
            clean: None,
            withheld,
        })
    }

    /// Every page of `key`'s evidence the Coach reads, and whether a page
    /// withheld a row; each page's receipt goes in the report.
    fn drain(&mut self, key: &ScopedSolvedGroupKey) -> Result<(Vec<SolvedRunEvidence>, bool)> {
        let mut evidence = Vec::new();
        let mut withheld = false;
        let mut after = None;
        loop {
            let page = solved_runs_in_group(self.read, key, after.as_ref())?;
            withheld |= page.receipt.suppressed_count > 0;
            self.report.receipts.push(page.receipt);
            evidence.extend(page.value.items);
            let Some(next) = page.value.next else { break };
            after = Some(next);
        }
        self.report.evidence += evidence.len();
        Ok((evidence, withheld))
    }

    /// One candidate for each unordered pair of `evidence` from distinct
    /// runs, in (run id, evidence id) order: the first supplies the
    /// arguments, the second the held-out ones.
    fn pairs(
        &mut self,
        digest: &[u8; 32],
        mut evidence: Vec<SolvedRunEvidence>,
        predecessor: Option<&Predecessor>,
    ) -> Result<Vec<Candidate>> {
        evidence.sort_by_key(|evidence| (evidence.run_id, evidence.id));
        let mut candidates = Vec::new();
        for (at, first) in evidence.iter().enumerate() {
            for second in evidence.iter().skip(at + 1) {
                if first.run_id != second.run_id {
                    candidates.push(induction::induce(digest, first, Some(second), predecessor)?);
                }
            }
        }
        self.report.candidates += candidates.len();
        Ok(candidates)
    }

    fn pending(&mut self, program: EntityId, reason: &'static str) {
        self.report
            .repairs_pending
            .push(CoachBrowserRepairPending { program, reason });
    }

    /// `write`'s one transaction: each candidate whose sources the Coach
    /// still reads, and that no seen mark already names with a job, gets
    /// its finding, its job when it is eligible and its seen mark; then a
    /// pair group read whole is marked processed. A proposal-only mark of
    /// an eligible candidate gets its one job here. The admission worker
    /// wakes once the write commits.
    fn commit(&mut self, write: &GroupWrite<'_>) -> Result<()> {
        let (vault, read, coach, envelope, now) =
            (self.vault, self.read, self.coach, self.envelope, self.now);
        let tally = vault.with_write_txn_grouped(|txn| {
            let mut tally = Tally::default();
            let policy = read.live_policy_manifest_in(txn)?;
            tally.covered = write.predecessor.is_none()
                && !solved_group_coverage(vault, &write.digest)?.is_empty();
            let candidates: &[Candidate] = if tally.covered {
                &[]
            } else {
                &write.candidates
            };
            let mut marked = BTreeSet::new();
            for candidate in candidates {
                let mut readable = true;
                for id in &candidate.source_evidence {
                    readable &= read.is_entity_readable_with_policy_in(txn, &policy, id)?;
                }
                if !readable {
                    tally.withheld = true;
                    continue;
                }
                if !marked.insert(candidate.fingerprint) {
                    continue;
                }
                let eligible = candidate.status.eligible();
                let finding = match program_seen(vault, &candidate.fingerprint)? {
                    Some(seen) if seen.job.is_some() || !eligible => {
                        tally.seen += 1;
                        continue;
                    }
                    Some(seen) => {
                        tally.seen += 1;
                        seen.finding
                    }
                    None => {
                        tally.findings += 1;
                        tally.diagnostics += usize::from(!eligible);
                        proposals::emit_in_txn(
                            vault,
                            txn,
                            coach,
                            COACH_BROWSER_PROGRAMS_PREDICATE,
                            &candidate.value,
                            &candidate.source_evidence,
                            envelope,
                            now,
                        )?
                    }
                };
                let job = if eligible {
                    tally.jobs += 1;
                    let job = write.job(candidate, finding);
                    Some(enqueue_program_admission_in_txn(vault, txn, &job, now)?)
                } else {
                    None
                };
                let seen = ProgramSeen {
                    finding,
                    job,
                    generation: write.generation,
                };
                mark_program_seen_in_txn(vault, txn, &candidate.fingerprint, &seen)?;
            }
            if let Some(through) = write.clean.filter(|_| !tally.withheld) {
                mark_group_clean(vault, txn, write.key, through)?;
                tally.cleaned = true;
            }
            Ok(tally)
        })?;
        if tally.jobs > 0 {
            program_admission_queued(vault);
        }
        let report = &mut self.report;
        report.findings += tally.findings;
        report.diagnostics += tally.diagnostics;
        report.already_seen += tally.seen;
        report.jobs += tally.jobs;
        report.withheld += usize::from(write.withheld || tally.withheld);
        report.groups_covered += usize::from(tally.covered);
        report.groups_cleaned += usize::from(tally.cleaned);
        Ok(())
    }
}

/// Whether `evidence` is a run of the failed program or of its successor:
/// neither is a changed trace.
fn own_run(evidence: &SolvedRunEvidence, failed: &ProgramFailureRef) -> bool {
    matches!(
        evidence.source,
        SolvedSource::LibraryRun { workflow }
            if workflow == failed.id || Some(workflow) == failed.refs.successor
    )
}
