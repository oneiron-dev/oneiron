//! Gate consent-bundle projection: naming, receipt view, and hex serde helpers.

use serde::{Deserialize, Serialize};

use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::store::GateDecisionId;

/// Schema version of the [`GateConsentBundle`] projection and its receipt.
pub const GATE_CONSENT_BUNDLE_SCHEMA_VERSION: u8 = 1;

/// Domain separator for the content-bound consent-bundle digest.
pub const GATE_CONSENT_BUNDLE_DOMAIN: &[u8] = b"oneiron/gate/consent-bundle/v1";

/// Engine label used when a run tree exposes no dispatched root agent.
pub const GATE_CONSENT_BUNDLE_FALLBACK_LABEL: &str = "agent run";

/// Separator between the agent label and the bundle-id fragment.
const GATE_CONSENT_BUNDLE_NAME_SEPARATOR: &str = " · ";

/// Bundle-id hex characters carried by the display name.
const GATE_CONSENT_BUNDLE_NAME_ID_CHARS: usize = 8;

#[doc(hidden)]
pub use oneiron_records::consent::bundle_projection::{
    GateConsentBundle, GateConsentBundleAction, GateConsentBundleMember, GateConsentBundleReceipt,
};

/// `"{agent label} · {id8}"`, with the engine fallback for an unlabelled run.
pub(crate) fn gate_consent_bundle_name(agent_label: Option<&str>, bundle_id: &[u8; 32]) -> String {
    let id8: String = bytes_to_hex_lower(bundle_id)
        .chars()
        .take(GATE_CONSENT_BUNDLE_NAME_ID_CHARS)
        .collect();
    let label = agent_label.unwrap_or(GATE_CONSENT_BUNDLE_FALLBACK_LABEL);
    format!("{label}{GATE_CONSENT_BUNDLE_NAME_SEPARATOR}{id8}")
}
