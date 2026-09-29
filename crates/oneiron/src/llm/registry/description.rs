//! Ranked, source-attributed model descriptions; absent evidence stays absent.
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ModelDescription {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_line: Option<DescriptionContribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_measurements: Option<DescriptionContribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_benchmarks: Option<DescriptionContribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_copy: Option<DescriptionContribution>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DescriptionContribution {
    pub text: String,
    /// Attribution of this exact contribution (e.g. owner identity or source URL).
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptionClass {
    OwnerLine,
    VaultMeasurements,
    PublicBenchmarks,
    VendorCopy,
}

impl ModelDescription {
    /// Routing evidence in precedence order. No missing class is synthesized.
    pub fn ranked(&self) -> impl Iterator<Item = (DescriptionClass, &DescriptionContribution)> {
        [
            (DescriptionClass::OwnerLine, self.owner_line.as_ref()),
            (
                DescriptionClass::VaultMeasurements,
                self.vault_measurements.as_ref(),
            ),
            (
                DescriptionClass::PublicBenchmarks,
                self.public_benchmarks.as_ref(),
            ),
            (DescriptionClass::VendorCopy, self.vendor_copy.as_ref()),
        ]
        .into_iter()
        .filter_map(|(class, contribution)| contribution.map(|text| (class, text)))
    }

    pub(super) fn validate(&self) -> Result<()> {
        for (_, contribution) in self.ranked() {
            if [&contribution.text, &contribution.source]
                .iter()
                .any(|value| {
                    value.trim().is_empty()
                        || value.len() > 4096
                        || value.chars().any(char::is_control)
                })
            {
                return Err(Error::InvalidConfig(
                    "invalid model description provenance".into(),
                ));
            }
        }
        Ok(())
    }
}
