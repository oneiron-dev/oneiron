//! Moved from `crates/oneiron/src/autoreason_campaign/report.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::autoreason_campaign::judge::CampaignTaste;
pub use oneiron_verb_wire::autoreason_campaign::report::CampaignCost;
pub use oneiron_verb_wire::autoreason_campaign::report::CampaignEvaluationSplit;
pub use oneiron_verb_wire::autoreason_campaign::report::CampaignSmokeOutcome;
use serde::Deserialize;
use serde::Serialize;

pub fn effective_taste_score(smoke: &CampaignSmokeOutcome, taste: &CampaignTaste) -> f64 {
    if smoke_is_killed(smoke) {
        0.0
    } else {
        taste.score
    }
}

pub fn smoke_is_killed(smoke: &CampaignSmokeOutcome) -> bool {
    matches!(smoke, CampaignSmokeOutcome::Killed { .. })
}
