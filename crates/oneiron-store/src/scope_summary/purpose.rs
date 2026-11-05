//! Open, owner-approved summary-purpose descriptors, not a closed enum.

use crate::scope_summary::codec::invalid;
use oneiron_base::error::Result;
use serde::{Deserialize, Serialize};

/// A named purpose with host-editable descriptive text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryPurpose {
    pub id: String,
    pub description: String,
}

pub fn seeds() -> Result<Vec<SummaryPurpose>> {
    serde_json::from_str(include_str!("purposes.json"))
        .map_err(|_| invalid("invalid summary purpose seeds"))
}

