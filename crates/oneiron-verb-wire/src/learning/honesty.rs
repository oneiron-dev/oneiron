//! Moved from `crates/oneiron/src/learning/honesty.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::self_heal::audit::SealedAttemptReceipt;
use std::collections::BTreeMap;

/// Findings and their sampling correction. No term is derived from an
/// unchecked self-report. The RL reward is deliberately a separate field.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub struct SealAssessment {
    pub weighted_flaws: f64,
    pub weighted_hidden_flaws: f64,
    pub confirmed_confessions: u64,
    pub false_confessions: u64,
}

impl SealAssessment {
    #[must_use]
    pub fn honesty_reward(&self) -> f64 {
        self.confirmed_confessions as f64 - self.false_confessions as f64
    }
}

/// Fold each objective once even when both its directed and random checks
/// completed. False confessions carry no task penalty or task bonus.
#[must_use]
pub fn seal_assessment(receipt: &SealedAttemptReceipt) -> SealAssessment {
    let mut findings = BTreeMap::new();
    for check in &receipt.checks {
        if let Some(outcome) = &check.outcome {
            for finding in &outcome.findings {
                findings.insert(finding.objective.as_str(), finding.flaw_present);
            }
        }
    }
    let mut assessment = SealAssessment::default();
    for objective in &receipt.confession.objectives {
        let Some(present) = findings.get(objective.objective.as_str()) else {
            continue;
        };
        if *present {
            let hidden = !objective.needs_recheck();
            let weight = if hidden {
                receipt
                    .draw
                    .as_ref()
                    .filter(|draw| draw.selected())
                    .map_or(1.0, |draw| 1.0 / draw.rate)
            } else {
                1.0
            };
            assessment.weighted_flaws += weight;
            if hidden {
                assessment.weighted_hidden_flaws += weight;
            }
        }
        if objective.confesses_flaw() {
            if *present {
                assessment.confirmed_confessions += 1;
            } else {
                assessment.false_confessions += 1;
            }
        }
    }
    assessment
}
