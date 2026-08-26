use std::sync::OnceLock;

use serde::Serialize;
use serde_json::Value;

use super::manifests::build_outbound_capability_manifests;
use crate::delivery_window::DeliveryWindowVerbClass;

/// Stable manifest shape advertised to agents.
pub const OUTBOUND_CAPABILITY_MANIFEST_VERSION: &str = "outbound.capability_manifest.v1";

/// Closed field names every outbound verb contract carries.
pub const OUTBOUND_VERB_FIELD_CONTRACT: &[&str] = &[
    "kind",
    "channel_call",
    "params",
    "interruption_class",
    "delivery_semantics",
    "retry_class",
    "capability_vs_permission",
];

/// Common outbound vocabulary connectors map onto where supported.
///
/// The verb kind remains data in each connector manifest so connector-specific
/// verbs can coexist with the common vocabulary without changing engine core.
pub const COMMON_OUTBOUND_VERB_KINDS: &[&str] = &[
    "send",
    "send_media",
    "react",
    "edit",
    "retract",
    "replace",
    "mark_read",
    "presence",
    "push",
    "call",
    "schedule_native",
];

/// Whether a verb may interrupt the recipient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundInterruptionClass {
    Ambient,
    Interrupt,
}

impl From<OutboundInterruptionClass> for DeliveryWindowVerbClass {
    fn from(value: OutboundInterruptionClass) -> Self {
        match value {
            OutboundInterruptionClass::Ambient => Self::Ambient,
            OutboundInterruptionClass::Interrupt => Self::Interrupt,
        }
    }
}

/// Retry class consumed by the later dispatch/retry policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundRetryClass {
    IdempotentNative,
    IdempotentEmulated,
    NonIdempotentInterrupt,
    ReplaceIdempotent,
}

/// Delivery semantics consumed by edit/retract/dedupe routing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundDeliverySemanticsKind {
    FireAndForget,
    Editable,
    Retractable,
    Replaceable,
    ReactionTarget,
    Ephemeral,
}

/// Delivery behavior for one verb.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutboundDeliverySemantics {
    pub kind: OutboundDeliverySemanticsKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<&'static str>,
}

/// Platform permission status for a capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundPermissionState {
    Allowed,
    Conditional,
    ProviderReview,
}

/// The OF-327 capability-vs-permission split for one verb.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutboundCapabilityPermission {
    pub capability: bool,
    pub permission: OutboundPermissionState,
    pub policy_risk: bool,
    pub verified_at: &'static str,
    pub note: &'static str,
}

/// Seven-field outbound verb contract.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutboundVerbContract {
    pub kind: String,
    pub channel_call: String,
    pub params: Value,
    pub interruption_class: OutboundInterruptionClass,
    pub delivery_semantics: OutboundDeliverySemantics,
    pub retry_class: OutboundRetryClass,
    #[serde(rename = "capability_vs_permission")]
    pub capability_vs_permission: OutboundCapabilityPermission,
}

/// Per-connector capability manifest.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutboundCapabilityManifest {
    pub manifest_version: &'static str,
    pub connector: String,
    pub connector_family: String,
    pub verified_at: &'static str,
    pub schema_on_demand: String,
    pub foreign_content_posture: &'static str,
    pub verbs: Vec<OutboundVerbContract>,
}

/// Typed unsupported-capability error. Callers must surface this instead of
/// treating unsupported connector verbs as successful no-ops.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedOutboundCapability {
    connector: String,
    verb: Option<String>,
    connector_known: bool,
    supported_connectors: Vec<String>,
    supported_verbs: Vec<String>,
    recovery_suggestions: Vec<String>,
}

impl UnsupportedOutboundCapability {
    #[must_use]
    pub fn connector(&self) -> &str {
        &self.connector
    }

    #[must_use]
    pub fn verb(&self) -> Option<&str> {
        self.verb.as_deref()
    }

    #[must_use]
    pub fn connector_known(&self) -> bool {
        self.connector_known
    }

    #[must_use]
    pub fn supported_connectors(&self) -> &[String] {
        &self.supported_connectors
    }

    #[must_use]
    pub fn supported_verbs(&self) -> &[String] {
        &self.supported_verbs
    }

    #[must_use]
    pub fn recovery_suggestions(&self) -> &[String] {
        &self.recovery_suggestions
    }
}

impl std::fmt::Display for UnsupportedOutboundCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.connector_known, self.verb.as_deref()) {
            (true, Some(verb)) => write!(
                f,
                "outbound verb {verb:?} is not supported by connector {:?}",
                self.connector
            ),
            (false, Some(verb)) => write!(
                f,
                "outbound connector {:?} is not registered for verb {verb:?}",
                self.connector
            ),
            (_, None) => {
                write!(
                    f,
                    "outbound connector {:?} is not registered",
                    self.connector
                )
            }
        }
    }
}

impl std::error::Error for UnsupportedOutboundCapability {}

/// Returns the built-in outbound capability manifest registry.
#[must_use]
pub fn outbound_capability_manifests() -> &'static [OutboundCapabilityManifest] {
    static MANIFESTS: OnceLock<Vec<OutboundCapabilityManifest>> = OnceLock::new();
    MANIFESTS.get_or_init(build_outbound_capability_manifests)
}

/// Returns one connector manifest by stable connector key.
#[must_use]
pub fn outbound_capability_manifest(
    connector: &str,
) -> Option<&'static OutboundCapabilityManifest> {
    let connector = normalize_key(connector);
    outbound_capability_manifests()
        .iter()
        .find(|manifest| manifest.connector == connector)
}

/// Resolves one verb contract or returns a typed unsupported-capability error.
pub fn outbound_verb_contract(
    connector: &str,
    verb: &str,
) -> Result<&'static OutboundVerbContract, Box<UnsupportedOutboundCapability>> {
    let connector_key = normalize_key(connector);
    let verb_key = normalize_key(verb);
    let Some(manifest) = outbound_capability_manifest(&connector_key) else {
        return Err(Box::new(unsupported_outbound_capability(
            connector_key,
            Some(verb_key),
            None,
        )));
    };

    manifest
        .verbs
        .iter()
        .find(|entry| entry.kind == verb_key)
        .ok_or_else(|| {
            Box::new(unsupported_outbound_capability(
                connector_key,
                Some(verb_key),
                Some(manifest),
            ))
        })
}

/// Returns a typed unsupported-capability error for connector-only discovery.
#[must_use]
pub fn unsupported_outbound_connector(connector: &str) -> UnsupportedOutboundCapability {
    unsupported_outbound_capability(normalize_key(connector), None, None)
}

fn unsupported_outbound_capability(
    connector: String,
    verb: Option<String>,
    manifest: Option<&OutboundCapabilityManifest>,
) -> UnsupportedOutboundCapability {
    let supported_connectors = outbound_capability_manifests()
        .iter()
        .map(|manifest| manifest.connector.clone())
        .collect::<Vec<_>>();
    let supported_verbs = manifest
        .map(|manifest| {
            manifest
                .verbs
                .iter()
                .map(|entry| entry.kind.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let recovery_suggestions = if manifest.is_some() {
        vec![
            format!(
                "Use one of {connector}'s supported outbound verbs: {}.",
                supported_verbs.join(", ")
            ),
            format!(
                "Fetch /v1/core/outbound/capabilities/{connector} before planning connector-specific actions."
            ),
        ]
    } else {
        vec![
            format!(
                "Choose a registered outbound connector: {}.",
                supported_connectors.join(", ")
            ),
            "Fetch /v1/core/outbound/capabilities before selecting a connector.".to_owned(),
        ]
    };

    UnsupportedOutboundCapability {
        connector,
        verb,
        connector_known: manifest.is_some(),
        supported_connectors,
        supported_verbs,
        recovery_suggestions,
    }
}

pub(super) fn normalize_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}
