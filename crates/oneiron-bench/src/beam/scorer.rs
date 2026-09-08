//! BeamScorer trait and fixed scorer.

use super::model::{ArmKind, CompetitorConfig, FixtureCase};
use super::report::{completed_ability_scores, mean_score, not_ready_ability_scores};
use super::report_model::{
    AbilityKind, ArmOutcome, ArmReport, LoadedDataset, ScoreReport, ScorerReport,
};
use super::{BEAM_COMPARATOR_VERSION, BEAM_SCORER_VERSION, BeamResult};
use oneiron::Vault;

pub(super) trait BeamArmAdapter {
    fn kind(&self) -> ArmKind;
    fn run(
        &self,
        vault: &Vault,
        loaded: &LoadedDataset,
        case: &FixtureCase,
    ) -> BeamResult<ArmReport>;
}
pub(super) trait BeamScorer {
    fn metadata(&self) -> ScorerReport;
    fn score(
        &self,
        case: &FixtureCase,
        competitor: &CompetitorConfig,
        arm: &ArmReport,
    ) -> ScoreReport;
}
pub(super) struct FixedBeamScorer;
impl BeamScorer for FixedBeamScorer {
    fn metadata(&self) -> ScorerReport {
        ScorerReport {
            scorer_id: "beam-fixed-scorer".to_owned(),
            version: BEAM_SCORER_VERSION.to_owned(),
            comparator_version: BEAM_COMPARATOR_VERSION.to_owned(),
            abilities: vec![
                AbilityKind::RetrievalCoverage,
                AbilityKind::BudgetDiscipline,
                AbilityKind::Readiness,
                AbilityKind::AbstentionGate,
                AbilityKind::NoRegressionGate,
            ],
        }
    }

    fn score(
        &self,
        case: &FixtureCase,
        competitor: &CompetitorConfig,
        arm: &ArmReport,
    ) -> ScoreReport {
        let abilities = match &arm.outcome {
            ArmOutcome::Completed { context_pack } => completed_ability_scores(case, context_pack),
            ArmOutcome::NotReady { not_ready } => not_ready_ability_scores(competitor, not_ready),
            // Retrieval-only measurements have their own aggregate gate, not an LLM score.
            ArmOutcome::RetrievalSweep { .. } => Vec::new(),
        };
        let overall_score = mean_score(&abilities);

        ScoreReport {
            scorer_version: BEAM_SCORER_VERSION.to_owned(),
            overall_score,
            abilities,
        }
    }
}
