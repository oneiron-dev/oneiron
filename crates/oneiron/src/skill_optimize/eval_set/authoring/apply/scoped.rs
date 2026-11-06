//! Owner cohort setup through the caller's original Memory source authority.

use super::super::super::cut_audit::prepare_cut_audit_scoped_listing;
use super::*;
use crate::claim::ScopedReadReceipt;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryResult};

/// The ordinary setup report and every Repair source admission used by its
/// audits. No source text or expected response is returned or kept in the rows.
#[derive(Debug, Clone)]
pub struct EvalCohortSetupRead {
    pub report: EvalAuthoringReport,
    pub receipts: Vec<ScopedReadReceipt>,
}

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
    ) -> MemoryResult<EvalCohortSetupRead> {
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
    ) -> (MemoryResult<EvalCohortSetupRead>, Vec<EntityId>) {
        let mut rows = Vec::new();
        let answer = setup_scoped(self, owner, setup, now, &mut rows);
        rows.sort_unstable();
        rows.dedup();
        (answer, rows)
    }
}

fn setup_scoped(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    setup: EvalCohortSetup,
    now: u64,
    rows: &mut Vec<EntityId>,
) -> MemoryResult<EvalCohortSetupRead> {
    let vault = memory.vault();
    let (plan, provenance, mut report) = prepare_setup(vault, owner, setup, now)?;
    let mut receipts = Vec::new();
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
            receipts.extend(read.receipts);
            apply_cut(vault, cut, read.audit, now, &mut report)?;
        }
    }
    Ok(EvalCohortSetupRead { report, receipts })
}
