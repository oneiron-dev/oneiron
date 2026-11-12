//! Moved from `crates/oneiron/src/skill_optimize/judge_swap.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::Entry;

/// Who settles a disagreement that no pick and no settled outcome decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JudgeTieBreaker {
    /// A third judge from another model family.
    ThirdFamily,
    /// Nobody: the incumbent holds until a pick or an outcome arrives.
    IncumbentHolds,
}

/// The vault's judge-swap policy, which the owner sets. Each field the owner
/// leaves out takes canon's default (ARCH-0079 #model-swaps, ARCH-0003).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct JudgeSwapPolicy {
    /// Disagreements on a case of any other axis. Default: a third judge.
    pub tie_breaker: JudgeTieBreaker,
    /// Disagreements on a floor-axis case. Default: the incumbent holds.
    pub floor_tie_breaker: JudgeTieBreaker,
    /// A fixed divergence rate in `[0, 1]` the takeover is read against, in
    /// place of the incumbent's retest noise. Default: none.
    pub pinned_divergence: Option<f64>,
    /// Every swap asks the owners to rate its disagreements, rather than
    /// telling them. Default: off.
    pub hands_on: bool,
}

impl Default for JudgeSwapPolicy {
    fn default() -> Self {
        Self {
            tie_breaker: JudgeTieBreaker::ThirdFamily,
            floor_tie_breaker: JudgeTieBreaker::IncumbentHolds,
            pinned_divergence: None,
            hands_on: false,
        }
    }
}

/// The owner's hand-test answer to one disagreement: the judge whose answer
/// is right. It overrides any outcome or tie-breaker on the case, and like
/// every calibration label it is final.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JudgeSwapPick {
    pub case_ref: String,
    pub judge: String,
    /// The person who picked, 32 hex.
    pub by: String,
    pub at: u64,
}
