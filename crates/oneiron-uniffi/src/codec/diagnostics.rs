//! Owned diagnostic and Coach inspection outputs (FIX 12936).

use oneiron::claim::ScopedReadResult;
use oneiron::memory as engine;
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<engine::DiagnosticEventView> for crate::DiagnosticEventView {
    fn lift(view: engine::DiagnosticEventView) -> Result<Self, OneironError> {
        let engine::DiagnosticEventView {
            diagnostic_ref,
            detector_id,
            event_class,
            signal,
            actor_class,
            actor_ref,
            source,
            criticality,
            expected,
            actual,
            delta,
            replay_content_hash,
            replay_run_ref,
            replay_checkpoint_ref,
            evidence_refs,
            untrusted_detail,
            valid_from,
            valid_to,
        } = view;
        // Consume all opaque leaves before propagating an encoding error.
        let expected = WireJson::lift(expected);
        let actual = WireJson::lift(actual);
        let delta = WireJson::lift(delta);
        let expected = expected?;
        let actual = actual?;
        let delta = delta?;
        Ok(Self {
            diagnostic_ref,
            detector_id,
            event_class,
            signal,
            actor_class,
            actor_ref,
            source,
            criticality,
            expected,
            actual,
            delta,
            replay_content_hash,
            replay_run_ref,
            replay_checkpoint_ref,
            evidence_refs,
            untrusted_detail,
            valid_from,
            valid_to,
        })
    }
}

impl Lift<engine::CoachProposalView> for crate::CoachProposalView {
    fn lift(proposal: engine::CoachProposalView) -> Result<Self, OneironError> {
        let engine::CoachProposalView {
            claim,
            route,
            decided,
            repair,
            settled_at,
        } = proposal;
        let repair = match repair {
            None | Some(Value::Null) => Ok(None),
            Some(repair) => WireJson::lift(repair).map(Some),
        };
        let claim = crate::WireClaimView::lift(claim);
        let repair = repair?;
        let claim = claim?;
        Ok(Self {
            claim,
            route,
            decided,
            repair,
            settled_at,
        })
    }
}

impl Lift<engine::CoachInspectionView> for crate::CoachInspectionView {
    fn lift(view: engine::CoachInspectionView) -> Result<Self, OneironError> {
        let engine::CoachInspectionView {
            receipt_ref,
            state,
            report,
            diagnostic,
            working_set,
            proposal,
        } = view;
        let diagnostic = diagnostic.map(crate::DiagnosticEventView::lift).transpose();
        let proposal = proposal.map(crate::CoachProposalView::lift).transpose();
        let diagnostic = diagnostic?;
        let proposal = proposal?;
        Ok(Self {
            receipt_ref,
            state,
            report: lift_record("vault.coach.inspect:report", &report)?,
            diagnostic,
            working_set: lift_record("vault.coach.inspect:working_set", &working_set)?,
            proposal,
        })
    }
}

impl Lift<ScopedReadResult<Vec<engine::DiagnosticEventView>>>
    for crate::ScopedReadResultDiagnosticEventViewList
{
    fn lift(
        read: ScopedReadResult<Vec<engine::DiagnosticEventView>>,
    ) -> Result<Self, OneironError> {
        let ScopedReadResult { value, receipt } = read;
        let value: Vec<_> = value
            .into_iter()
            .map(crate::DiagnosticEventView::lift)
            .collect();
        let value = value.into_iter().collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            value,
            narrowing: lift_record("vault.diagnostics.list:narrowing", &receipt)?,
        })
    }
}

impl Lift<ScopedReadResult<Option<engine::DiagnosticEventView>>>
    for crate::ScopedReadResultOptionalDiagnosticEventView
{
    fn lift(
        read: ScopedReadResult<Option<engine::DiagnosticEventView>>,
    ) -> Result<Self, OneironError> {
        let ScopedReadResult { value, receipt } = read;
        let value = value.map(crate::DiagnosticEventView::lift).transpose()?;
        Ok(Self {
            value,
            narrowing: lift_record("vault.diagnostics.get:narrowing", &receipt)?,
        })
    }
}

impl Lift<ScopedReadResult<engine::CoachInspectionView>>
    for crate::ScopedReadResultCoachInspectionView
{
    fn lift(read: ScopedReadResult<engine::CoachInspectionView>) -> Result<Self, OneironError> {
        let ScopedReadResult { value, receipt } = read;
        let value = crate::CoachInspectionView::lift(value)?;
        Ok(Self {
            value,
            narrowing: lift_record("vault.coach.inspect:narrowing", &receipt)?,
        })
    }
}
