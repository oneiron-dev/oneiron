//! Consent bundle values are defined in the authority layer.

pub(super) use crate::consent::bundle_projection::gate_consent_bundle_name;
pub use crate::consent::bundle_projection::{
    GATE_CONSENT_BUNDLE_DOMAIN, GATE_CONSENT_BUNDLE_FALLBACK_LABEL,
    GATE_CONSENT_BUNDLE_SCHEMA_VERSION, GateConsentBundle, GateConsentBundleAction,
    GateConsentBundleMember, GateConsentBundleReceipt,
};
