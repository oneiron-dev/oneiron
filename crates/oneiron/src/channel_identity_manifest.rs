//! Channel identity capability manifests (OF-347 CID-4).
//!
//! The R8 seed matrix is stored as JSON data and loaded through this typed
//! schema. Provider adapters and policy enforcement consume this surface; they
//! do not add per-channel capability branches here.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::channel_identity::ChannelIdentityShape;

/// Stable schema version for channel identity capability manifests.
pub const CHANNEL_IDENTITY_CAPABILITY_MATRIX_VERSION: &str =
    "channel_identity.capability_matrix.v1";

const CHANNEL_IDENTITY_CAPABILITY_MATRIX_JSON: &str =
    include_str!("data/channel_identity_capability_matrix.v1.json");

/// Built-in channel identity capability matrix.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChannelIdentityCapabilityMatrix {
    pub manifest_version: String,
    pub verified_at: String,
    pub source_design: String,
    pub manifests: Vec<ChannelIdentityManifest>,
}

/// One per-channel identity capability manifest.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChannelIdentityManifest {
    pub channel: String,
    pub display_name: String,
    pub mintability: ChannelIdentityMintability,
    pub shapes: Vec<ChannelIdentityShape>,
    pub cold_contact: bool,
    pub receive_capabilities: ChannelIdentityReceiveCapabilities,
    pub cost_model: String,
    pub hard_limits: Vec<String>,
    pub policy_risk: ChannelIdentityPolicyRisk,
    pub policy_risk_notes: Vec<String>,
    pub verification_tiers: Vec<String>,
    pub disclosure_class: ChannelIdentityDisclosureClass,
    pub reputation_signal_sources: Vec<ChannelIdentityReputationSignal>,
    pub conservative_floor: bool,
}

impl ChannelIdentityManifest {
    /// Stable gate-facing policy-risk string for OF-060/OF-333 consumers.
    #[must_use]
    pub const fn gate_policy_risk(&self) -> &'static str {
        self.policy_risk.as_gate_scope_value()
    }

    /// Whether this channel exposes no concrete identity health signals.
    #[must_use]
    pub fn reputation_blind(&self) -> bool {
        self.reputation_signal_sources.is_empty()
    }

    /// Whether OF-327 reputation floors should use the conservative channel floor.
    #[must_use]
    pub const fn uses_conservative_floor(&self) -> bool {
        self.conservative_floor
    }
}

/// How an identity for this channel is minted or fulfilled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentityMintability {
    Ours,
    Api,
    Console,
    Manual,
    Review,
    SelfHostedBridge,
    HostedBridge,
}

/// Inbound/receive capability surface for an identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ChannelIdentityReceiveCapabilities {
    pub messaging: bool,
    pub sms: bool,
    pub otp: bool,
    pub voice: bool,
    pub push: bool,
    pub webhook: bool,
}

/// Policy-risk tier surfaced to gate and disclosure consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentityPolicyRisk {
    Normal,
    HoldToProposal,
}

impl ChannelIdentityPolicyRisk {
    #[must_use]
    pub const fn as_gate_scope_value(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::HoldToProposal => "hold_to_proposal",
        }
    }
}

/// Platform/legal presentation floor for OF-333.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentityDisclosureClass {
    OwnerHomeChannel,
    AgentSenderDisclosure,
    BotOrAppIdentity,
    PlatformBridgeDisclosure,
    AppleMfbAgentDisclosure,
    AiVoiceDisclosure,
    BusinessAgentDisclosure,
}

/// Health/reputation signal classes that the channel actually exposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentityReputationSignal {
    AppDeliveryReceipts,
    DeviceTokenFeedback,
    EspComplaintWebhook,
    EspBounceWebhook,
    EspPlacementMonitoring,
    ProviderDeliveryReceipt,
    CarrierSpamLookup,
    AttestationTier,
    BusinessQualityRating,
    TemplateQualityRating,
}

/// Validation failure for a channel identity manifest fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelIdentityManifestError {
    reason: String,
}

impl ChannelIdentityManifestError {
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for ChannelIdentityManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for ChannelIdentityManifestError {}

/// Returns the built-in R8 channel identity capability matrix.
#[must_use]
pub fn channel_identity_capability_matrix() -> &'static ChannelIdentityCapabilityMatrix {
    static MATRIX: OnceLock<ChannelIdentityCapabilityMatrix> = OnceLock::new();
    MATRIX.get_or_init(|| {
        parse_channel_identity_capability_matrix(CHANNEL_IDENTITY_CAPABILITY_MATRIX_JSON)
            .expect("built-in channel identity capability matrix must validate")
    })
}

/// Returns all built-in per-channel identity manifests.
#[must_use]
pub fn channel_identity_manifests() -> &'static [ChannelIdentityManifest] {
    &channel_identity_capability_matrix().manifests
}

/// Returns one per-channel identity manifest by stable channel key.
#[must_use]
pub fn channel_identity_manifest(channel: &str) -> Option<&'static ChannelIdentityManifest> {
    let channel = normalize_channel_key(channel);
    channel_identity_manifests()
        .iter()
        .find(|manifest| manifest.channel == channel)
}

/// Parses and validates a channel identity capability matrix fixture.
pub fn parse_channel_identity_capability_matrix(
    json: &str,
) -> Result<ChannelIdentityCapabilityMatrix, ChannelIdentityManifestError> {
    let matrix = serde_json::from_str::<ChannelIdentityCapabilityMatrix>(json)
        .map_err(|err| manifest_error(format!("invalid channel identity manifest JSON: {err}")))?;
    validate_channel_identity_capability_matrix(&matrix)?;
    Ok(matrix)
}

fn validate_channel_identity_capability_matrix(
    matrix: &ChannelIdentityCapabilityMatrix,
) -> Result<(), ChannelIdentityManifestError> {
    if matrix.manifest_version != CHANNEL_IDENTITY_CAPABILITY_MATRIX_VERSION {
        return Err(manifest_error(
            "unexpected channel identity manifest version",
        ));
    }
    validate_non_empty("verified_at", &matrix.verified_at)?;
    validate_non_empty("source_design", &matrix.source_design)?;
    if matrix.manifests.is_empty() {
        return Err(manifest_error("channel identity manifest matrix is empty"));
    }

    let mut channels = BTreeSet::new();
    for manifest in &matrix.manifests {
        validate_manifest(manifest)?;
        if !channels.insert(manifest.channel.as_str()) {
            return Err(manifest_error(format!(
                "duplicate channel identity manifest {}",
                manifest.channel
            )));
        }
    }
    Ok(())
}

fn validate_manifest(
    manifest: &ChannelIdentityManifest,
) -> Result<(), ChannelIdentityManifestError> {
    validate_channel_key(&manifest.channel)?;
    validate_non_empty("display_name", &manifest.display_name)?;
    validate_non_empty("cost_model", &manifest.cost_model)?;
    if manifest.shapes.is_empty() {
        return Err(manifest_error(format!(
            "{} must declare at least one shape",
            manifest.channel
        )));
    }
    ensure_unique("shape", &manifest.shapes)?;
    ensure_unique("hard_limit", &manifest.hard_limits)?;
    ensure_unique("policy_risk_note", &manifest.policy_risk_notes)?;
    ensure_unique("verification_tier", &manifest.verification_tiers)?;
    ensure_unique(
        "reputation_signal_source",
        &manifest.reputation_signal_sources,
    )?;
    if manifest.reputation_blind() && !manifest.conservative_floor {
        return Err(manifest_error(format!(
            "{} is reputation-blind but does not set conservative_floor",
            manifest.channel
        )));
    }
    Ok(())
}

fn validate_channel_key(channel: &str) -> Result<(), ChannelIdentityManifestError> {
    validate_non_empty("channel", channel)?;
    if normalize_channel_key(channel) != channel {
        return Err(manifest_error(format!(
            "channel identity manifest key {channel:?} must be normalized"
        )));
    }
    Ok(())
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), ChannelIdentityManifestError> {
    if value.trim().is_empty() {
        Err(manifest_error(format!("{field} must be non-empty")))
    } else {
        Ok(())
    }
}

fn ensure_unique<T>(field: &str, values: &[T]) -> Result<(), ChannelIdentityManifestError>
where
    T: Ord + std::fmt::Debug,
{
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(manifest_error(format!(
                "{field} value {value:?} is duplicated"
            )));
        }
    }
    Ok(())
}

fn normalize_channel_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn manifest_error(reason: impl Into<String>) -> ChannelIdentityManifestError {
    ChannelIdentityManifestError {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r8_seed_matrix_loads_from_data_and_round_trips() {
        let matrix =
            parse_channel_identity_capability_matrix(CHANNEL_IDENTITY_CAPABILITY_MATRIX_JSON)
                .expect("built-in R8 matrix parses");
        let encoded = serde_json::to_string_pretty(&matrix).expect("matrix serializes");
        let reparsed =
            parse_channel_identity_capability_matrix(&encoded).expect("serialized matrix parses");

        assert_eq!(reparsed, matrix);
        assert_eq!(
            matrix.manifest_version,
            CHANNEL_IDENTITY_CAPABILITY_MATRIX_VERSION
        );
    }

    #[test]
    fn r8_seed_matrix_covers_all_required_channels() {
        let channels = channel_identity_manifests()
            .iter()
            .map(|manifest| manifest.channel.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(
            channels,
            BTreeSet::from([
                "discord",
                "email",
                "imessage_hosted_bridge",
                "imessage_mfb",
                "imessage_self_host_bridge",
                "line",
                "own_app",
                "phone_jp",
                "phone_us",
                "slack",
                "telegram",
                "whatsapp",
            ])
        );
    }

    #[test]
    fn policy_risk_and_disclosure_are_available_to_consumers() {
        let phone = channel_identity_manifest("phone-us").expect("phone US manifest");

        assert_eq!(phone.gate_policy_risk(), "hold_to_proposal");
        assert_eq!(
            phone.disclosure_class,
            ChannelIdentityDisclosureClass::AiVoiceDisclosure
        );
        assert!(phone.receive_capabilities.sms);
        assert!(phone.receive_capabilities.voice);
    }

    #[test]
    fn reputation_blind_channels_use_conservative_floor() {
        for manifest in channel_identity_manifests() {
            if manifest.reputation_blind() {
                assert!(
                    manifest.uses_conservative_floor(),
                    "{} must use conservative floor when reputation-blind",
                    manifest.channel
                );
            }
        }

        let line = channel_identity_manifest("line").expect("LINE manifest");
        assert!(line.reputation_blind());
        assert!(line.uses_conservative_floor());

        let email = channel_identity_manifest("email").expect("email manifest");
        assert!(!email.reputation_blind());
        assert!(!email.uses_conservative_floor());
    }

    #[test]
    fn schema_validation_rejects_bad_seed_data() {
        let mut matrix = channel_identity_capability_matrix().clone();
        matrix.manifest_version = "channel_identity.capability_matrix.v0".to_owned();
        let encoded = serde_json::to_string(&matrix).expect("bad matrix serializes");

        let err = parse_channel_identity_capability_matrix(&encoded)
            .expect_err("bad schema version must fail validation");
        assert!(
            err.reason()
                .contains("unexpected channel identity manifest version")
        );
    }
}
