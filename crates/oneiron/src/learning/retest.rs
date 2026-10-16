//! `learning.retest_noise`: how often a judge or scorer disagrees with itself
//! when it scores the same case twice. It is the floor a judge swap measures
//! divergence against ([`super::judge::judge_takeover_verdict`]).

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::cell::{LearningCell, LearningPredicate, TypeRef};
use super::estimate::Estimate;
use super::evidence::{Anchor, LearningEvidence, Observation, record_evidence};

/// One of the two scores a retest compares.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RetestScore {
    /// A pass/fail verdict.
    Pass(bool),
    /// A numeric score.
    Value(f64),
}

/// One same-case retest by one scorer.
#[derive(Debug, Clone, PartialEq)]
pub struct Retest {
    /// The scorer: a judge skill, a critic lens, any scoring subject.
    pub scorer: EntityId,
    /// The scorer's executor at revision.
    pub executor: String,
    pub axis: String,
    pub type_ref: Option<TypeRef>,
    /// The retest receipt: one row per receipt.
    pub receipt: String,
    pub first: RetestScore,
    pub second: RetestScore,
    pub at: u64,
}

/// Records one retest. Two verdicts feed a Beta over disagreement; two
/// numeric scores feed a mean of their absolute difference.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the two scores are of different kinds or
/// the cell is malformed; the evidence door's errors.
pub fn record_retest(vault: &Vault, retest: &Retest, now: u64) -> Result<Option<Estimate>> {
    let observation = match (retest.first, retest.second) {
        (RetestScore::Pass(a), RetestScore::Pass(b)) => Observation::Success(a != b),
        (RetestScore::Value(a), RetestScore::Value(b)) => Observation::Magnitude((a - b).abs()),
        _ => {
            return Err(Error::InvalidClaimBody(
                "a retest compares two scores of the same kind",
            ));
        }
    };
    let mut cell = LearningCell::new(LearningPredicate::RetestNoise, retest.scorer)
        .executor(retest.executor.clone())
        .axis(retest.axis.clone());
    cell.type_ref = retest.type_ref.clone();
    let evidence = LearningEvidence::anchored(
        retest.receipt.clone(),
        retest.at,
        Anchor::Retest,
        observation,
    );
    record_evidence(vault, &cell, &evidence, now)
}
