//! Moved from `crates/oneiron/src/llm/decision/questions/records.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::llm::decision::questions::criteria::MAX_CRITERION_BYTES;
pub use oneiron_store::model_decision::questions::CalibrationPair;
pub use oneiron_store::model_decision::questions::DecisionRoute;
pub use oneiron_store::model_decision::questions::OmittedNeighbor;
pub use oneiron_store::model_decision::questions::OutcomeBinding;
pub use oneiron_store::model_decision::questions::OutcomeLabel;
pub use oneiron_store::model_decision::questions::OutcomeSource;
pub use oneiron_store::model_decision::questions::OutcomeWindowClose;
pub use oneiron_store::model_decision::questions::QuestionActivation;
pub use oneiron_store::model_decision::questions::QuestionAudience;
pub use oneiron_store::model_decision::questions::QuestionMedia;
pub use oneiron_store::model_decision::questions::QuestionScheduleHead;
pub use oneiron_store::model_decision::questions::RefreshPolicy;
pub use oneiron_store::model_decision::questions::RoutingPolicy;
pub use oneiron_store::model_decision::questions::SourceConflict;
pub use oneiron_store::model_decision::questions::WindowOutcome;
use oneiron_store::setting_seed::SettingSpec;

/// The adapter of a standing question over artifact units, asked on each artifact's head
/// as it changes ([`QuestionDefinition::artifacts`]).
pub const ARTIFACT_ADAPTER: &str = "artifact";

/// The vault's question call budget (ARCH-0076): each decision call's clock,
/// in milliseconds, when neither the question nor the ask names one. It
/// ships at a graph ask's default, within the asks' own bounds.
pub const QUESTION_CALL_BUDGET_MS: SettingSpec = SettingSpec {
    key: "question_call_budget_ms",
    min: 1.0,
    max: oneiron_base::request_limits::MAX_RECALL_DEADLINE_MS as f64,
    seed: crate::receipt::questions::GRAPH_ASK_UNIT_DEADLINE_MS as f64,
};
