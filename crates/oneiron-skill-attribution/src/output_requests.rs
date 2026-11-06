//! Independently requested placement for the attribution pass's new outputs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::read_position::{AttributionJudgmentReadPosition, SkillEditProposalReadPosition};

/// Each key addresses one persisted evidence sequence in this vault. The two
/// maps are independent: judgment placement never supplies proposal placement.
/// Missing keys leave placement unknown; these declarations grant no read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionOutputReadRequests {
    pub judgments: BTreeMap<u64, AttributionJudgmentReadPosition>,
    pub proposals: BTreeMap<u64, SkillEditProposalReadPosition>,
}
