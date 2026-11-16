//! The setting keys `skill_scan` declares (Setting stage 1): the crate's build script lists each
//! row in the setting catalogue.

use super::DEFAULT_ACTIVATION_RISK_THRESHOLD;
use crate::setting::Kind;
use crate::skill_hub::ScanRiskLevel;

const fn default_activation_risk_threshold() -> ScanRiskLevel {
    DEFAULT_ACTIVATION_RISK_THRESHOLD
}

crate::setting::setting_keys! {
    /// The scan risk at which a skill's activation stops being automatic and waits for the
    /// owner's tap: a stored risk at or above it escalates `auto` to `proposed`. `high` unless
    /// the owner sets it, which is where the static pass places an embedded credential.
    pub(crate) ACTIVATION_RISK_THRESHOLD: ScanRiskLevel = "skills.scan_activation_risk_threshold" {
        kind: Kind::new(default_activation_risk_threshold),
    };
}
