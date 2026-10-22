//! The Coach's feedback triage findings (OF-420 T1). One triaged revision's
//! typed answer lands Proposed in the owner's run tray under the job that
//! ran it, each finding citing the note's evidence ASSET; the revision's
//! result and its acknowledgement commit in that same write. An empty answer
//! is a result: it commits with no finding. No review state moves here, and
//! no note is closed. The sweep's lease on a long GitHub walk is the `lease`
//! child's (FIX 7628).
mod lease;

use super::proposals;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::feedback::{
    COACH_FEEDBACK_TRIAGE_FACET, FEEDBACK_TRIAGE_FINDING_PREDICATE, FeedbackTriageOutput,
    FeedbackTriageResult, acknowledge_feedback_triage_in_txn, check_feedback_triage_findings,
    job_handoff_in_txn,
};
use crate::limit_ask::EngineLimit;
use crate::{EntityId, Result, Vault};

impl Vault {
    /// Files one triaged revision's answer as the Coach, under its leased
    /// `coach.feedback_triage` job: each finding Proposed in the owner's run
    /// tray, then the revision's result and acknowledgement, in one write.
    /// `skill` is the SKILL entity and version the job loaded and
    /// `served_model` the model of the rung that answered. A revision
    /// acknowledged already answers its stored result and files nothing.
    ///
    /// # Errors
    ///
    /// An attempt that is not this facet's Coach attempt or not the
    /// revision's current job; a finding that cites anything but the note it
    /// was given or names no problem (nothing is filed, and the revision
    /// stays unacknowledged); [`crate::Error::Refused`] once the owner erased the
    /// revision's evidence (nothing is filed, and the next sweep settles it
    /// erased); storage errors.
    pub fn run_coach_feedback_triage(
        &self,
        attempt: &DreamerAdmittedAttempt,
        output: &FeedbackTriageOutput,
        skill: (EntityId, String),
        served_model: &str,
        now: u64,
    ) -> Result<FeedbackTriageResult> {
        self.require_coach_attempt(attempt, COACH_FEEDBACK_TRIAGE_FACET)?;
        // The run-tray envelope reads the attempt's stamp in a write of its
        // own, so it is taken before this one.
        let envelope = proposals::run_tray_envelope(
            self,
            COACH_FEEDBACK_TRIAGE_FACET,
            attempt.status.attempt.id,
        )?;
        self.with_write_txn_grouped(|txn| {
            record_feedback_triage_findings_in_txn(
                self,
                txn,
                attempt,
                output,
                &skill,
                served_model,
                &envelope,
                now,
            )
        })
    }
}

/// [`Vault::run_coach_feedback_triage`]'s write, in the caller's
/// transaction: every finding under `envelope`, then the result and the
/// acknowledgement. Never closes a review item or a note.
#[expect(
    clippy::too_many_arguments,
    reason = "one revision's job, answer, provenance and write envelope"
)]
pub(crate) fn record_feedback_triage_findings_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
    output: &FeedbackTriageOutput,
    skill: &(EntityId, String),
    served_model: &str,
    envelope: &crate::WriteEnvelope,
    now: u64,
) -> Result<FeedbackTriageResult> {
    let handoff = job_handoff_in_txn(vault, txn, attempt)?;
    if let Some(result) = &handoff.result {
        return Ok(result.clone());
    }
    let job = EntityId::from_bytes(*attempt.status.attempt.id.as_bytes())?;
    if handoff.attempt != job {
        return Err(super::invalid());
    }
    // Every finding is kept; how many is measured (Rule 5).
    let _ = vault.measure_limit(
        EngineLimit::MaintenanceRowItems,
        output.findings.len() as u64,
    );
    let own = &handoff.source_ref;
    check_feedback_triage_findings(output, own)?;
    let mut findings = Vec::new();
    for finding in &output.findings {
        let problem = finding.problem.trim();
        let fix = finding
            .proposed_fix
            .as_deref()
            .map(str::trim)
            .filter(|fix| !fix.is_empty());
        let value = serde_json::json!({
            "source_refs": [{"source": own.source, "id": own.id, "revision": own.revision}],
            "problem": problem,
            "proposed_fix": fix,
            "skill": skill.0.to_hex(),
            "skill_version": skill.1,
            "served_model": served_model,
        });
        let id = proposals::emit_in_txn(
            vault,
            txn,
            handoff.evidence,
            FEEDBACK_TRIAGE_FINDING_PREDICATE,
            &value,
            &[handoff.evidence],
            envelope,
            now,
        )?;
        if !findings.contains(&id) {
            findings.push(id);
        }
    }
    let result = FeedbackTriageResult {
        attempt: job,
        findings,
        skill: skill.0,
        skill_version: skill.1.clone(),
        served_model: served_model.to_owned(),
        recorded_at: now,
    };
    acknowledge_feedback_triage_in_txn(vault, txn, &handoff, result.clone())?;
    Ok(result)
}
