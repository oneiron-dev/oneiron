//! Seven independent comparability axes and per-number publication decisions.
use super::{BeamError, BeamResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ComparabilityAxes {
    pub tier: TierAxis,
    pub regime: Regime,
    pub native_scale: String,
    pub backbone: BackboneAxis,
    pub judge: JudgeAxis,
    pub retrieval_k: usize,
    pub provenance: ProvenanceAxis,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TierAxis {
    pub row: String,
    pub reference: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Regime {
    Full,
    Oracle,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct BackboneAxis {
    pub model_pin: String,
    pub solo_row: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct JudgeAxis {
    pub identity: String,
    pub in_family: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProvenanceAxis {
    pub source: String,
    pub independent: bool,
    pub caveat: Option<String>,
    pub withdrawn: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum CitationDisposition {
    Cite,
    CiteWithCaveat,
    WalledAppendix,
    Dropped,
}
impl ComparabilityAxes {
    pub(super) fn validate(&self) -> BeamResult<()> {
        if [
            &self.tier.row,
            &self.tier.reference,
            &self.native_scale,
            &self.backbone.model_pin,
            &self.backbone.solo_row,
            &self.judge.identity,
            &self.provenance.source,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
            || !self
                .backbone
                .model_pin
                .split_once('@')
                .is_some_and(|(id, rev)| !id.is_empty() && !rev.is_empty())
        {
            return Err(BeamError::Comparability {
                reason: "every axis must be disclosed, including backbone pin and solo row".into(),
            });
        }
        Ok(())
    }
    pub(super) fn disposition(&self) -> CitationDisposition {
        if self.provenance.withdrawn {
            CitationDisposition::Dropped
        } else if self.tier.row != self.tier.reference
            || self.regime == Regime::Oracle
            || self.judge.in_family
        {
            CitationDisposition::WalledAppendix
        } else if !self.provenance.independent || self.provenance.caveat.is_some() {
            CitationDisposition::CiteWithCaveat
        } else {
            CitationDisposition::Cite
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn axes() -> serde_json::Value {
        serde_json::json!({"tier":{"row":"128K","reference":"128K"},"regime":"full","nativeScale":"128K",
            "backbone":{"modelPin":"openai/gpt-4.1@2025-04-14","soloRow":"backbone-solo"},
            "judge":{"identity":"gpt-4.1-mini@2025-04-14","inFamily":false},"retrievalK":5,
            "provenance":{"source":"fixture://card","independent":true,"caveat":null,"withdrawn":false}})
    }
    #[test]
    fn comparability_rejects_each_missing_axis_and_walls_nonclearing_rows() {
        for key in [
            "tier",
            "regime",
            "nativeScale",
            "backbone",
            "judge",
            "retrievalK",
            "provenance",
        ] {
            let mut row = axes();
            row.as_object_mut().unwrap().remove(key);
            assert!(
                serde_json::from_value::<ComparabilityAxes>(row).is_err(),
                "{key}"
            );
        }
        let mut row: ComparabilityAxes = serde_json::from_value(axes()).unwrap();
        row.validate().unwrap();
        assert_eq!(row.disposition(), CitationDisposition::Cite);
        row.provenance.caveat = Some("self-report".into());
        assert_eq!(row.disposition(), CitationDisposition::CiteWithCaveat);
        row.regime = Regime::Oracle;
        assert_eq!(row.disposition(), CitationDisposition::WalledAppendix);
        row.regime = Regime::Full;
        row.judge.in_family = true;
        assert_eq!(row.disposition(), CitationDisposition::WalledAppendix);
        row.provenance.withdrawn = true;
        assert_eq!(row.disposition(), CitationDisposition::Dropped);
    }
}
