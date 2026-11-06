//! Owner cohort setup through the caller's original Memory source authority.

use super::super::super::cut_audit::prepare_cut_audit_scoped_listing;
use super::*;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryResult};

impl Memory<'_> {
    /// Set up cohorts as the authenticated owner, using this handle's original
    /// credential, locality, destination and room for Repair source reads.
    /// The owner proof permits the setup write; it grants no source access.
    /// Receipt/Synthetic audits keep their existing purpose-limited reader.
    pub fn setup_eval_cohorts(
        &self,
        owner: &AuthenticatedOwner,
        setup: EvalCohortSetup,
        now: u64,
    ) -> MemoryResult<EvalAuthoringReport> {
        self.setup_eval_cohorts_listing(owner, setup, now).0
    }

    /// [`Self::setup_eval_cohorts`], also listing the rows each audit actually
    /// read text from. Missing/withheld Repair sources are coverage gaps, never
    /// clean comparisons or exposures. A refusal retains the preceding list.
    pub fn setup_eval_cohorts_listing(
        &self,
        owner: &AuthenticatedOwner,
        setup: EvalCohortSetup,
        now: u64,
    ) -> (MemoryResult<EvalAuthoringReport>, Vec<EntityId>) {
        let mut rows = Vec::new();
        let answer =
            setup_scoped(self, owner, setup, &[], now, &mut rows).map(|report| report.authoring);
        rows.sort_unstable();
        rows.dedup();
        (answer, rows)
    }

    /// Record explicit Repair recipes under this handle's original source
    /// authority after inventory validation and before the scoped cohort cuts.
    pub fn setup_eval_repair_cohorts(
        &self,
        owner: &AuthenticatedOwner,
        input: EvalRepairCohortSetup,
        now: u64,
    ) -> MemoryResult<EvalRepairCohortReport> {
        self.setup_eval_repair_cohorts_listing(owner, input, now).0
    }

    /// [`Self::setup_eval_repair_cohorts`], retaining actual Repair source
    /// rows and cut-audit rows even when a later stage fails. Stages keep
    /// their existing separate transactions; this is not an atomic batch.
    pub fn setup_eval_repair_cohorts_listing(
        &self,
        owner: &AuthenticatedOwner,
        input: EvalRepairCohortSetup,
        now: u64,
    ) -> (MemoryResult<EvalRepairCohortReport>, Vec<EntityId>) {
        let mut rows = Vec::new();
        let answer = setup_scoped(self, owner, input.setup, &input.repairs, now, &mut rows);
        rows.sort_unstable();
        rows.dedup();
        (answer, rows)
    }
}

fn setup_scoped(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    setup: EvalCohortSetup,
    repairs: &[super::super::super::EvalRepairCaseRequest],
    now: u64,
    rows: &mut Vec<EntityId>,
) -> MemoryResult<EvalRepairCohortReport> {
    let vault = memory.vault();
    let (plan, provenance, mut report) = prepare_setup(vault, owner, setup, now)?;
    let mut repair_results = Vec::with_capacity(repairs.len());
    for input in repairs {
        let read = memory.record_eval_repair_case(owner, input)?;
        if let Some(source_rows) = read
            .case
            .as_ref()
            .and_then(|case| case.source_rows.as_deref())
        {
            rows.extend_from_slice(source_rows);
        }
        repair_results.push(super::super::super::EvalRepairCaseReference::from(read));
    }
    if !plan.cuts.is_empty() {
        let lineage = LineageReader::read(vault)?;
        for cut in &plan.cuts {
            let read = prepare_cut_audit_scoped_listing(
                memory,
                &lineage,
                &cut.seat,
                (cut.from, cut.until),
                provenance.clone(),
                rows,
            )?;
            report.source_receipts.extend(read.receipts);
            apply_cut(vault, cut, read.audit, now, &mut report)?;
        }
    }
    Ok(EvalRepairCohortReport {
        authoring: report,
        repairs: repair_results,
    })
}
