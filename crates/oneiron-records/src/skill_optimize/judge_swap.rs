//! Moved from `crates/oneiron/src/skill_optimize/judge_swap.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::model_decision::DecisionAnswer;
pub use oneiron_verb_wire::skill_optimize::judge_swap::JudgeSwapPick;
pub use oneiron_verb_wire::skill_optimize::judge_swap::JudgeSwapPolicy;
pub use oneiron_verb_wire::skill_optimize::judge_swap::JudgeTieBreaker;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::Entry;

/// A judge's answer to a kept case, asked again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeShadowAnswer {
    /// The judge that answered, `model@version`.
    pub judge: String,
    pub answer: DecisionAnswer,
}

/// The judge whose scale the kept history reads on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeIncumbent {
    pub judge: String,
    pub since: u64,
    /// The judge this one took over from: later picks and outcomes on the
    /// takeover's disagreements can still re-pin it back.
    pub previous: Option<String>,
    /// The takeover's receipt, 32 hex.
    pub takeover: Option<String>,
}

/// What decided one disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeSwapSettledBy {
    /// The owner's hand-test pick.
    Pick,
    /// The held-out receipts' settled outcome.
    Outcome,
    /// The third judge.
    TieBreaker,
    /// Nothing yet: the case is open.
    Open,
}

/// Where a disagreement's settled outcome is read, by the question it asked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JudgeOutcomeLink {
    /// A whole-skill or task-success score: the share of these held-out
    /// receipts the skill won.
    HeldOut {
        skill: String,
        receipts: Vec<String>,
    },
    /// A named or live goal axis: the share of these receipts whose anchored
    /// observation on the axis succeeded, measured under the goal revision
    /// the question was asked under.
    Axis {
        skill: String,
        axis: String,
        receipts: Vec<String>,
        /// The goal revision frozen with the question; `None` when it was
        /// asked under no goal.
        goal_revision: Option<String>,
    },
    /// An honesty finding: whether the run's sealed audit found a flaw its
    /// confession hid.
    Audit { receipt: String },
    /// A tradeoff call: the responsible person's or role's answer to the ask
    /// on exactly this question.
    Tradeoff { proposal: String, digest: String },
    /// A blind preference: the owner's pick between exactly this pair's two
    /// responses.
    ResponsePair { pair_ref: String },
}

/// One case the two judges answered differently.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeSwapDisagreement {
    pub case_ref: String,
    /// The typed question, as hex, its wording key, and when it was asked.
    pub question: String,
    pub kind: Option<String>,
    pub asked_at: u64,
    pub source_family: String,
    /// The case judged a floor axis.
    pub floor: bool,
    /// The skill the case judged, as hex: a pick on it is a label in that
    /// skill's judge anchor.
    pub skill: Option<String>,
    /// Each judge's answer, the incumbent's first.
    pub answers: Vec<JudgeShadowAnswer>,
    /// Where the settled outcome is read; `None` when the case's question
    /// has none.
    pub outcome_link: Option<JudgeOutcomeLink>,
    /// The settled outcome, as an answer to the case's question, once it
    /// settled.
    pub outcome: Option<DecisionAnswer>,
    /// The third judge's answer, when the tie-breaker asked one.
    pub tie_breaker: Option<JudgeShadowAnswer>,
    /// The judge whose answer the case sided with; `None` while open.
    pub sided_with: Option<String>,
    pub settled_by: JudgeSwapSettledBy,
}

/// One shadow pass's ruling, or a re-pin, kept whatever it found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JudgeSwapReceipt {
    /// The receipt's id, 32 hex: a hand-test pick names it.
    pub id: String,
    pub from_judge: String,
    pub to_judge: String,
    /// `take_over`, `hold`, `unknown` or `re_pin`.
    pub verdict: String,
    /// The disagreements decided the verdict: the divergence was known and
    /// wider than the threshold.
    pub arbitrated: bool,
    pub cases: u32,
    pub diverged: u32,
    pub families: u32,
    /// The threshold in force: `retest_noise` or `owner_pinned`.
    pub threshold_source: String,
    /// Its value; `None` while the incumbent's noise is unmeasured.
    pub threshold: Option<f64>,
    /// The incumbent's own retest runs behind a noise threshold.
    pub noise_runs: f64,
    /// The overlap fitted a score conversion, or a re-pin withdrew one.
    pub converted: bool,
    pub disagreements: Vec<JudgeSwapDisagreement>,
    pub at: u64,
}
