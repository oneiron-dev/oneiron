//! Outbound action capability manifests for the OF-327 O1 contract.
//!
//! This module intentionally stops at schema-on-demand capability discovery.
//! Dispatch, delivery windows, receipts, and adapter execution live in later
//! SURF-ENG-06 tickets.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

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

/// Version for the intent field contract consumed by the later dispatcher.
pub const OUTBOUND_INTENT_SCHEMA_VERSION: &str = "outbound.intent.v1";

/// Outbound intent spine shared by OF-327 dispatch and receipt projection.
///
/// `job_ref` is optional so older ad-hoc or commitment-triggered intents remain
/// valid. Brief-rooted runs stamp it to make receipt rollups an indexed lookup
/// instead of a render-time chain walk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundIntent {
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub intent_source: String,
    pub trigger_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
}

/// Whether a verb may interrupt the recipient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundInterruptionClass {
    Ambient,
    Interrupt,
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

fn build_outbound_capability_manifests() -> Vec<OutboundCapabilityManifest> {
    vec![
        manifest(
            "line",
            "chat",
            "LINE Messaging API outbound schema; adapter may require channel review for narrowcast.",
            vec![
                verb(
                    "reply",
                    "reply_message",
                    json!({
                        "replyToken": "string",
                        "messages": [{"type": "text", "text": "string"}],
                        "quota": {
                            "plan_tier": "all",
                            "metered": false,
                            "quota_debit": false,
                            "notes": "Reactive replies are free and require a live reply token."
                        }
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Allowed,
                    false,
                    "LINE reply messages are reactive, free, and bounded by reply-token validity.",
                ),
                verb(
                    "push",
                    "push_message",
                    json!({
                        "to": "line_user_id | line_group_id",
                        "messages": [{"type": "text", "text": "string"}],
                        "quota": {
                            "plan_tier": "free_or_paid",
                            "metered": true,
                            "quota_debit": true,
                            "free_monthly_allowance": crate::channel_identity_provider::DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE,
                            "overage_policy": "requires_metered_plan"
                        }
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    false,
                    "LINE push messages debit the monthly push quota and require plan-tier checks before dispatch.",
                ),
                verb(
                    "send",
                    "reply_message | push_message",
                    json!({
                        "to": "line_user_id | line_group_id",
                        "messages": [{"type": "text", "text": "string"}],
                        "replyToken": "optional string"
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Allowed,
                    false,
                    "LINE supports reply and push text sends when account permissions allow recipient reachability.",
                ),
                verb(
                    "send_media",
                    "reply_message | push_message",
                    json!({
                        "to": "line_user_id | line_group_id",
                        "messages": [{"type": "image|video|audio|file", "originalContentUrl": "https://..."}]
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Allowed,
                    true,
                    "Media sends require hosted content and may be subject to platform content checks.",
                ),
                verb(
                    "narrowcast",
                    "narrowcast",
                    json!({
                        "messages": [{"type": "text", "text": "string"}],
                        "recipient": {"type": "operator", "and": []}
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::ProviderReview,
                    true,
                    "LINE narrowcast is a connector-specific capability and can require plan/review constraints.",
                ),
            ],
        ),
        manifest(
            "telegram",
            "chat",
            "Telegram Bot API outbound schema; permissions depend on bot membership and chat policies.",
            vec![
                verb(
                    "send",
                    "sendMessage",
                    json!({"chat_id": "integer|string", "text": "string", "parse_mode": "optional string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Allowed,
                    false,
                    "Bot sends are supported when the bot may message the target chat.",
                ),
                verb(
                    "send_media",
                    "sendPhoto | sendVideo | sendAudio | sendDocument",
                    json!({"chat_id": "integer|string", "media": "file_id|URL|multipart", "caption": "optional string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Allowed,
                    true,
                    "Media calls require a supported media transport and target chat permission.",
                ),
                verb(
                    "react",
                    "setMessageReaction",
                    json!({"chat_id": "integer|string", "message_id": "integer", "reaction": [{"type": "emoji", "emoji": "string"}]}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::ReactionTarget,
                    Some("provider-defined message reaction window"),
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::Conditional,
                    false,
                    "Reaction availability depends on chat type and bot permissions.",
                ),
                verb(
                    "edit",
                    "editMessageText | editMessageCaption | editMessageMedia",
                    json!({"chat_id": "integer|string", "message_id": "integer", "text": "string"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Editable,
                    Some("provider-defined edit window"),
                    OutboundRetryClass::ReplaceIdempotent,
                    OutboundPermissionState::Conditional,
                    false,
                    "Edits are supported for editable bot-originated messages.",
                ),
            ],
        ),
        manifest(
            "slack",
            "workspace_chat",
            "Slack Web API outbound schema; OAuth scopes and workspace policies are distinct from capability.",
            vec![
                verb(
                    "send",
                    "chat.postMessage",
                    json!({"channel": "channel_id", "text": "string", "blocks": "optional block kit array", "thread_ts": "optional string", "username": "persona display name", "icon_url": "optional persona avatar URL", "icon_emoji": "optional persona emoji", "metadata": "optional app-level-token identity metadata"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires chat:write, chat:write.customize for persona attribution, and channel posting permission; Slack message metadata is app-level-token only.",
                ),
                verb(
                    "react",
                    "reactions.add",
                    json!({"channel": "channel_id", "timestamp": "message_ts", "name": "emoji_name"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::ReactionTarget,
                    None,
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires reactions:write and visibility to the message.",
                ),
                verb(
                    "edit",
                    "chat.update",
                    json!({"channel": "channel_id", "ts": "message_ts", "text": "string", "blocks": "optional block kit array"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Editable,
                    None,
                    OutboundRetryClass::ReplaceIdempotent,
                    OutboundPermissionState::Conditional,
                    false,
                    "Updates are limited to messages the app can edit.",
                ),
                verb(
                    "retract",
                    "chat.delete",
                    json!({"channel": "channel_id", "ts": "message_ts"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Retractable,
                    None,
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Conditional,
                    false,
                    "Deletes require permission over the target message.",
                ),
            ],
        ),
        manifest(
            "discord",
            "community_chat",
            "Discord Bot API outbound schema; guild/channel permissions control usable capability.",
            vec![
                verb(
                    "send",
                    "create_message",
                    json!({"channel_id": "snowflake", "content": "string", "embeds": "optional array", "message_reference": "optional reply"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires Send Messages in the target channel.",
                ),
                verb(
                    "react",
                    "create_reaction",
                    json!({"channel_id": "snowflake", "message_id": "snowflake", "emoji": "unicode|custom"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::ReactionTarget,
                    None,
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires message visibility and reaction permission.",
                ),
                verb(
                    "edit",
                    "edit_message",
                    json!({"channel_id": "snowflake", "message_id": "snowflake", "content": "string", "embeds": "optional array"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Editable,
                    None,
                    OutboundRetryClass::ReplaceIdempotent,
                    OutboundPermissionState::Conditional,
                    false,
                    "Bots can edit messages they authored.",
                ),
                verb(
                    "retract",
                    "delete_message",
                    json!({"channel_id": "snowflake", "message_id": "snowflake"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Retractable,
                    None,
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Conditional,
                    false,
                    "Deletes depend on channel moderation permissions or authorship.",
                ),
            ],
        ),
        manifest(
            "apns",
            "push",
            "Apple Push Notification service schema; device tokens and entitlements are permission data.",
            vec![verb(
                "push",
                "apns_push",
                json!({"device_token": "hex", "topic": "bundle id", "aps": {"alert": "string|object", "badge": "optional integer", "sound": "optional string"}}),
                OutboundInterruptionClass::Interrupt,
                OutboundDeliverySemanticsKind::FireAndForget,
                None,
                OutboundRetryClass::NonIdempotentInterrupt,
                OutboundPermissionState::Conditional,
                true,
                "APNs can interrupt users and depends on app entitlement, token validity, and user notification permission.",
            )],
        ),
        manifest(
            "imessage_mfb",
            "apple_messages_for_business",
            "Apple Messages for Business schema; capability is distinct from brand approval and conversation state.",
            vec![
                verb(
                    "send",
                    "messages_for_business_send",
                    json!({"conversation_id": "string", "text": "string", "rich_link": "optional object"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::ProviderReview,
                    true,
                    "Messages for Business requires brand/channel approval and an active conversation.",
                ),
                verb(
                    "invite",
                    "messages_for_business_invite",
                    json!({"recipient": "phone|apple_business_chat_id", "intent": "string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::ProviderReview,
                    true,
                    "Invite is connector-specific and gated by Apple approval and recipient eligibility.",
                ),
            ],
        ),
        manifest(
            "imessage_bridge",
            "local_bridge",
            "Local iMessage bridge schema; capability is local and should be treated as permission-sensitive.",
            vec![
                verb(
                    "send",
                    "local_messages_send",
                    json!({"chat_id": "string", "text": "string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Local bridge sends require host-device consent and OS-level Messages availability.",
                ),
                verb(
                    "send_media",
                    "local_messages_send_attachment",
                    json!({"chat_id": "string", "attachment_path": "string", "caption": "optional string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Media sends require explicit file access and host-device consent.",
                ),
            ],
        ),
        manifest(
            "email",
            "email",
            "SMTP/provider email schema; deliverability and recipient consent are permissions, not raw capability.",
            vec![
                verb(
                    "send",
                    "send_email",
                    json!({"to": ["addr@example.com"], "subject": "string", "body": "text/html|string", "headers": "optional object"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Email sends require verified sender, deliverability policy, and recipient consent checks.",
                ),
                verb(
                    "replace",
                    "send_correction_or_superseding_email",
                    json!({"original_message_id": "optional string", "to": ["addr@example.com"], "subject": "string", "body": "string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::Replaceable,
                    None,
                    OutboundRetryClass::ReplaceIdempotent,
                    OutboundPermissionState::Conditional,
                    true,
                    "Email cannot edit in place; replace means sending a superseding message.",
                ),
            ],
        ),
        manifest(
            "voice",
            "voice_call",
            "Voice call schema; dialing is interruption-heavy and permission-sensitive.",
            vec![verb(
                "call",
                "start_voice_call",
                json!({"to": "e164", "script_ref": "optional string", "recording_disclosure": "required string"}),
                OutboundInterruptionClass::Interrupt,
                OutboundDeliverySemanticsKind::FireAndForget,
                None,
                OutboundRetryClass::NonIdempotentInterrupt,
                OutboundPermissionState::ProviderReview,
                true,
                "Voice calls require recipient consent, jurisdictional compliance, and provider approval.",
            )],
        ),
    ]
}

fn manifest(
    connector: &'static str,
    connector_family: &'static str,
    foreign_content_posture: &'static str,
    verbs: Vec<OutboundVerbContract>,
) -> OutboundCapabilityManifest {
    OutboundCapabilityManifest {
        manifest_version: OUTBOUND_CAPABILITY_MANIFEST_VERSION,
        connector: connector.to_owned(),
        connector_family: connector_family.to_owned(),
        verified_at: "2026-07-06",
        schema_on_demand: format!("/v1/core/outbound/capabilities/{connector}"),
        foreign_content_posture,
        verbs,
    }
}

#[allow(clippy::too_many_arguments)]
fn verb(
    kind: &'static str,
    channel_call: &'static str,
    params: Value,
    interruption_class: OutboundInterruptionClass,
    delivery_kind: OutboundDeliverySemanticsKind,
    delivery_window: Option<&'static str>,
    retry_class: OutboundRetryClass,
    permission: OutboundPermissionState,
    policy_risk: bool,
    note: &'static str,
) -> OutboundVerbContract {
    OutboundVerbContract {
        kind: kind.to_owned(),
        channel_call: channel_call.to_owned(),
        params,
        interruption_class,
        delivery_semantics: OutboundDeliverySemantics {
            kind: delivery_kind,
            window: delivery_window,
        },
        retry_class,
        capability_vs_permission: OutboundCapabilityPermission {
            capability: true,
            permission,
            policy_risk,
            verified_at: "2026-07-06",
            note,
        },
    }
}

fn normalize_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_outbound_verb_declares_the_closed_seven_field_contract() {
        assert_eq!(
            OUTBOUND_VERB_FIELD_CONTRACT,
            [
                "kind",
                "channel_call",
                "params",
                "interruption_class",
                "delivery_semantics",
                "retry_class",
                "capability_vs_permission",
            ]
        );

        for manifest in outbound_capability_manifests() {
            assert_eq!(
                manifest.manifest_version, OUTBOUND_CAPABILITY_MANIFEST_VERSION,
                "{} uses an unexpected manifest version",
                manifest.connector
            );
            assert!(
                !manifest.verbs.is_empty(),
                "{} must expose at least one outbound verb",
                manifest.connector
            );
            for verb in &manifest.verbs {
                let value = serde_json::to_value(verb).expect("serialize outbound verb");
                let object = value.as_object().expect("verb serializes as object");
                let fields = object.keys().map(String::as_str).collect::<Vec<_>>();
                assert_eq!(
                    fields, OUTBOUND_VERB_FIELD_CONTRACT,
                    "{}.{} drifted from the closed field contract",
                    manifest.connector, verb.kind
                );
                assert!(
                    verb.capability_vs_permission.capability,
                    "{}.{} must describe a capability",
                    manifest.connector, verb.kind
                );
            }
        }
    }

    #[test]
    fn outbound_intent_job_ref_is_optional_for_legacy_intents() {
        let intent: OutboundIntent = serde_json::from_str(
            r#"{
                "actor": "agent-alpha",
                "verb": "send",
                "channel": "email",
                "target": "counterparty:kenji",
                "intent_source": "agent_immediate",
                "trigger_ref": "run:planning"
            }"#,
        )
        .expect("legacy intent without job_ref remains valid");

        assert_eq!(intent.job_ref, None);

        let brief_rooted = OutboundIntent {
            job_ref: Some("brief:party".to_owned()),
            ..intent
        };
        let value = serde_json::to_value(&brief_rooted).expect("serialize intent");
        assert_eq!(value["job_ref"], "brief:party");
    }

    #[test]
    fn unsupported_connector_verb_is_typed_and_actionable() {
        let error = outbound_verb_contract("line", "edit").expect_err("line edit unsupported");

        assert_eq!(error.connector(), "line");
        assert_eq!(error.verb(), Some("edit"));
        assert!(error.connector_known());
        assert!(
            error.supported_verbs().contains(&"send".to_owned()),
            "known connector errors should include supported verbs"
        );
        assert!(
            error
                .recovery_suggestions()
                .iter()
                .any(|suggestion| suggestion.contains("/v1/core/outbound/capabilities/line")),
            "unsupported errors must tell clients how to recover"
        );

        let error = outbound_verb_contract("unknown-connector", "send")
            .expect_err("unknown connector unsupported");
        assert!(!error.connector_known());
        assert!(error.supported_verbs().is_empty());
        assert!(
            error.supported_connectors().contains(&"slack".to_owned()),
            "unknown connector errors should include registered connectors"
        );
    }

    #[test]
    fn connector_only_discovery_errors_do_not_fabricate_a_verb() {
        let error = unsupported_outbound_connector("unknown-connector");

        assert_eq!(error.connector(), "unknown_connector");
        assert_eq!(error.verb(), None);
        assert!(!error.connector_known());
        assert!(error.supported_verbs().is_empty());
        assert!(
            error
                .recovery_suggestions()
                .iter()
                .any(|suggestion| suggestion.contains("/v1/core/outbound/capabilities")),
            "connector-only unsupported errors should advertise the manifest index"
        );
    }

    #[test]
    fn connector_specific_verbs_live_as_manifest_data() {
        let line_narrowcast =
            outbound_verb_contract("line", "narrowcast").expect("line narrowcast manifest");
        assert_eq!(line_narrowcast.kind, "narrowcast");
        assert_eq!(
            line_narrowcast.capability_vs_permission.permission,
            OutboundPermissionState::ProviderReview
        );

        let mfb_invite =
            outbound_verb_contract("imessage-mfb", "invite").expect("mfb invite manifest");
        assert_eq!(mfb_invite.kind, "invite");
        assert!(
            !COMMON_OUTBOUND_VERB_KINDS.contains(&mfb_invite.kind.as_str()),
            "connector-specific verbs should not expand the common vocabulary"
        );
    }

    #[test]
    fn line_reply_and_push_manifests_separate_quota_semantics() {
        let line_reply = outbound_verb_contract("line", "reply").expect("line reply manifest");
        assert_eq!(line_reply.channel_call, "reply_message");
        assert_eq!(
            line_reply.capability_vs_permission.permission,
            OutboundPermissionState::Allowed
        );
        assert_eq!(line_reply.params["quota"]["quota_debit"], false);
        assert_eq!(line_reply.params["quota"]["metered"], false);
        assert_eq!(line_reply.params["quota"]["plan_tier"], "all");

        let line_push = outbound_verb_contract("line", "push").expect("line push manifest");
        assert_eq!(line_push.channel_call, "push_message");
        assert_eq!(
            line_push.capability_vs_permission.permission,
            OutboundPermissionState::Conditional
        );
        assert_eq!(line_push.params["quota"]["quota_debit"], true);
        assert_eq!(line_push.params["quota"]["metered"], true);
        assert_eq!(
            line_push.params["quota"]["free_monthly_allowance"],
            crate::channel_identity_provider::DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE
        );
        assert_eq!(
            line_push.params["quota"]["overage_policy"],
            "requires_metered_plan"
        );
    }

    #[test]
    fn manifests_emit_concrete_schema_on_demand_links() {
        let slack = outbound_capability_manifest("slack").expect("slack manifest");

        assert_eq!(
            slack.schema_on_demand,
            "/v1/core/outbound/capabilities/slack"
        );
    }
}
