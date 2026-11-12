//! Door for `tests/check_in_fanout_modes.rs` (ROLES-CHECKIN PR 1): one
//! fan-out admission under a mode named by its wire token, so the same test
//! runs before and after the check-in rename and shows that admission did
//! not change.

use std::cell::Cell;

use crate::check_in::CheckInMode;
use crate::error::{Error, Result};
use crate::outbound_chokepoint::{
    FanoutAdmission, FanoutApprovalRow, FanoutAutoDecider, FanoutAutoDisposition, FanoutEstimate,
    FanoutHistory, FanoutPlan, FanoutPlanEdge, FanoutSurfaceSink, admit_fanout_with_history,
};
use crate::receipt::ReceiptRecord;

const NOW_MS: u64 = 1_770_000_000_000;

/// What the injected `auto` classifier answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Classifier {
    /// It allows the plan.
    Allow,
    /// It hands the plan to a person.
    SurfaceHuman,
    /// It fails, as a missing model does.
    Fails,
}

/// One admission, as the test compares it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionOutcome {
    /// `paused` or `proceed`.
    pub outcome: &'static str,
    /// How many times the classifier was asked.
    pub classifier_calls: usize,
    /// How many rows the surface persisted: pause rows and width-question rows.
    pub rows: usize,
}

struct CountingSink {
    rows: usize,
}

impl FanoutSurfaceSink for CountingSink {
    fn persist_pause_row(&mut self, row: &FanoutApprovalRow) -> Result<String> {
        self.rows += 1;
        Ok(format!("durable:{}", row.row_ref))
    }

    fn persist_choice_receipt(&mut self, receipt: &ReceiptRecord) -> Result<String> {
        Ok(format!("receipt:{}", receipt.receipt_id))
    }
}

struct CountingClassifier {
    answer: Classifier,
    calls: Cell<usize>,
}

impl FanoutAutoDecider for CountingClassifier {
    fn decide(&self, _: &FanoutPlan, _: &FanoutEstimate) -> Result<FanoutAutoDisposition> {
        self.calls.set(self.calls.get() + 1);
        match self.answer {
            Classifier::Allow => Ok(FanoutAutoDisposition::Allow),
            Classifier::SurfaceHuman => Ok(FanoutAutoDisposition::SurfaceHuman),
            Classifier::Fails => Err(Error::InvalidConfig("classifier unavailable".to_owned())),
        }
    }
}

/// Admits a plan of `total` consults over one edge, under the mode whose
/// wire token is `mode` (`auto`, `full-access` or `manual`), with the width
/// threshold `threshold`.
///
/// # Errors
///
/// An unknown mode token, or an admission error.
pub fn admit_one(
    mode: &str,
    classifier: Classifier,
    total: u32,
    threshold: u32,
) -> Result<AdmissionOutcome> {
    let mode: CheckInMode = serde_json::from_value(serde_json::Value::String(mode.to_owned()))
        .map_err(|error| Error::InvalidConfig(format!("mode token: {error}")))?;
    let edges = if total == 0 {
        Vec::new()
    } else {
        vec![FanoutPlanEdge {
            from_peer_ref: "peer_a".to_owned(),
            to_peer_ref: "peer_b".to_owned(),
            count: total,
        }]
    };
    let plan = FanoutPlan {
        plan_ref: "plan-1".to_owned(),
        brief_ref: "brief-1".to_owned(),
        actor_ref: "actor-1".to_owned(),
        mode,
        edges,
    };
    let classifier = CountingClassifier {
        answer: classifier,
        calls: Cell::new(0),
    };
    let mut sink = CountingSink { rows: 0 };
    let admission = admit_fanout_with_history(
        &plan,
        Some(threshold),
        FanoutHistory {
            edges: &[],
            peer_rates: &[],
        },
        &classifier,
        &mut sink,
        NOW_MS,
    )?;
    let outcome = match admission {
        FanoutAdmission::Proceed { .. } => "proceed",
        FanoutAdmission::Paused { .. } => "paused",
    };
    Ok(AdmissionOutcome {
        outcome,
        classifier_calls: classifier.calls.get(),
        rows: sink.rows,
    })
}
