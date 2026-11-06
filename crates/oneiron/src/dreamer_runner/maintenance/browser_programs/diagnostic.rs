//! A failed program without a changed trace may still leave a Proposed
//! diagnostic. Its native failure-index snapshot is the observation; the
//! scoped filing claim only associates the program with its group. No
//! candidate program, replay or admission job is manufactured.

use serde::Serialize;

use super::induction::{INDUCTION_VERSION, Status};
use super::{COACH_BROWSER_PROGRAMS_PREDICATE, Pass, Predecessor, proposals};
use crate::browser_library::{
    ScopedSolvedGroupKey, WorkflowFiling, filing_anchor_in, mark_program_seen_in_txn,
    program_seen_in, workflow_filing_id,
};
use crate::dreamer_runner::maintenance::browser_candidate::{CANDIDATE_DOMAIN, ProgramSeen};
use crate::entity_id::bytes_to_hex_lower;
use crate::{EntityId, Result};

#[derive(Serialize)]
struct NoTraceDiagnostic<'a> {
    version: u32,
    kind: &'static str,
    status: Status,
    group: String,
    site: &'a str,
    filing: WorkflowFiling,
    filing_evidence_role: &'static str,
    source_evidence: [String; 1],
    failure_basis: &'static str,
    predecessor: &'a Predecessor,
    reason: &'static str,
}

enum Landing {
    Pending,
    Seen,
    Written,
}

impl Pass<'_> {
    /// True only when a scoped, Gate-eligible filing anchors a diagnostic
    /// already seen or written here. Otherwise the repair stays pending.
    pub(super) fn diagnose_no_trace(
        &mut self,
        key: &ScopedSolvedGroupKey,
        workflow: EntityId,
        predecessor: &Predecessor,
    ) -> Result<bool> {
        let digest = key.digest();
        let anchor = workflow_filing_id(&workflow, &digest)?;
        let landing = self.vault.with_write_txn_grouped(|txn| {
            let Some(filing) = filing_anchor_in(self.read, txn, &workflow, &digest)? else {
                return Ok(Landing::Pending);
            };
            if !crate::gate::claim_consolidation_eligible_in_txn(
                &self.vault.store,
                txn,
                &anchor,
                crate::gate::ConsolidationReader::PrecommitEvidence,
            )? {
                return Ok(Landing::Pending);
            }
            let body = NoTraceDiagnostic {
                version: INDUCTION_VERSION,
                kind: "repair_no_trace",
                status: Status::Diagnostic,
                group: bytes_to_hex_lower(&digest),
                site: &key.group.site,
                filing,
                filing_evidence_role: "association",
                source_evidence: [anchor.to_hex()],
                failure_basis: "library_failure_index",
                predecessor,
                reason: "no run but its own or its successor's",
            };
            let mut value = serde_json::to_value(body).map_err(|_| super::super::invalid())?;
            let bytes = serde_json::to_vec(&value).map_err(|_| super::super::invalid())?;
            let version = INDUCTION_VERSION.to_be_bytes();
            let mut hasher = blake3::Hasher::new();
            hasher.update(CANDIDATE_DOMAIN);
            for part in [version.as_slice(), digest.as_slice(), bytes.as_slice()] {
                let len = u64::try_from(part.len()).unwrap_or(u64::MAX);
                hasher.update(&len.to_be_bytes());
                hasher.update(part);
            }
            let fingerprint = *hasher.finalize().as_bytes();
            value["fingerprint"] = bytes_to_hex_lower(&fingerprint).into();
            if program_seen_in(self.vault, txn, &fingerprint)?.is_some() {
                return Ok(Landing::Seen);
            }
            let finding = proposals::emit_in_txn(
                self.vault,
                txn,
                self.coach,
                COACH_BROWSER_PROGRAMS_PREDICATE,
                &value,
                &[anchor],
                self.envelope,
                self.now,
            )?;
            mark_program_seen_in_txn(
                self.vault,
                txn,
                &fingerprint,
                &ProgramSeen {
                    finding,
                    job: None,
                    generation: predecessor.failures,
                },
            )?;
            Ok(Landing::Written)
        })?;
        match landing {
            Landing::Pending => Ok(false),
            Landing::Seen => {
                self.report.already_seen += 1;
                Ok(true)
            }
            Landing::Written => {
                self.report.findings += 1;
                self.report.diagnostics += 1;
                Ok(true)
            }
        }
    }
}
