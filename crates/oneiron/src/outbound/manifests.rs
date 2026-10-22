//! Built-in outbound capability manifests.
//! Entry: `build_outbound_capability_manifests`.
//! Defines its own items.

use serde_json::{Value, json};

use super::capability::{
    OUTBOUND_CAPABILITY_MANIFEST_VERSION, OutboundCapabilityManifest, OutboundCapabilityPermission,
    OutboundDeliverySemantics, OutboundDeliverySemanticsKind, OutboundInterruptionClass,
    OutboundPermissionState, OutboundRetryClass, OutboundVerbContract,
};

mod channels;

use self::channels::{
    apns_manifest, calendar_manifest, discord_manifest, email_manifest, esign_manifest,
    imessage_bridge_manifest, imessage_mfb_manifest, line_manifest, linkedin_manifest,
    slack_manifest, telegram_manifest,
};

fn line_reply_quota() -> Value {
    json!({
        "plan_tier": "all",
        "metered": false,
        "quota_debit": false,
        "notes": "Reactive replies are free and require a live reply-token handle."
    })
}

fn line_push_quota() -> Value {
    json!({
        "plan_tier": "free_or_paid",
        "metered": true,
        "quota_debit": true,
        "free_monthly_allowance": crate::channel_identity_provider::DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE,
        "overage_policy": "requires_metered_plan"
    })
}

pub(super) fn build_outbound_capability_manifests() -> Vec<OutboundCapabilityManifest> {
    let mut manifests = vec![
        feedback_manifest("feedback_cloud"),
        feedback_manifest("feedback_collector"),
        feedback_manifest("feedback_github"),
        failure_signals_manifest(),
        linear_manifest(),
        esign_manifest(),
        line_manifest(),
        telegram_manifest(),
        slack_manifest(),
        discord_manifest(),
        apns_manifest(),
        in_app_reaction_manifest(),
        imessage_mfb_manifest(),
        imessage_bridge_manifest(),
        linkedin_manifest(),
        email_manifest(),
        calendar_manifest(),
        voice_manifest(),
    ];
    // Email is a provider family, not one retry guarantee. SES and Postmark
    // must never inherit Resend's provider-native idempotency guarantee.
    manifests.extend([
        email_provider_manifest("email_resend", Some("Idempotency-Key"), "emails.send"),
        email_provider_manifest("email_ses", None, "SendEmail"),
        email_provider_manifest("email_postmark", None, "POST /email"),
    ]);
    manifests
}

fn voice_manifest() -> OutboundCapabilityManifest {
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
            OutboundRetryClass::IdempotentEmulated,
            OutboundPermissionState::ProviderReview,
            true,
            "Voice calls require recipient consent, jurisdictional compliance, and provider approval.",
        )],
    )
}

fn email_provider_manifest(
    provider: &'static str,
    native_key: Option<&'static str>,
    channel_call: &'static str,
) -> OutboundCapabilityManifest {
    message_manifest(
        manifest(
            provider,
            "email",
            "Verified sender, recipient consent and account limits are separate from send capability.",
            vec![verb(
                "send",
                channel_call,
                json!({
                    "to": ["addr@example.com"], "subject": "string", "body": "string",
                    "provider_idempotency_header": native_key,
                }),
                OutboundInterruptionClass::Interrupt,
                OutboundDeliverySemanticsKind::FireAndForget,
                None,
                if native_key.is_some() {
                    OutboundRetryClass::IdempotentNative
                } else {
                    OutboundRetryClass::IdempotentEmulated
                },
                OutboundPermissionState::Conditional,
                true,
                "Verified sender and recipient consent required; queue dedupe cannot make an ambiguous send safe to retry.",
            )],
        ),
        &["send"],
    )
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
        family: (connector_family == "workspace_bot").then_some("workspace_bot"),
        verified_at: "2026-07-06",
        schema_on_demand: format!("/v1/core/outbound/capabilities/{connector}"),
        foreign_content_posture,
        message_verbs: Vec::new(),
        verbs,
    }
}

fn message_manifest(
    mut manifest: OutboundCapabilityManifest,
    kinds: &[&str],
) -> OutboundCapabilityManifest {
    manifest.message_verbs = kinds.iter().map(|kind| (*kind).to_owned()).collect();
    manifest
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

// In-app reactions target an existing message visible to the actor's
// audience; the app adapter enforces that scope at the write door.
fn in_app_reaction_manifest() -> OutboundCapabilityManifest {
    manifest(
        "in_app",
        "first_party_chat",
        "First-party conversation messages; reaction targets retain their message audience.",
        vec![verb(
            "react",
            "reaction.put",
            json!({
                "message_id": "visible message ref",
                "glyph": "Unicode emoji",
                "emoji_vocabulary": "unicode_emoji"
            }),
            OutboundInterruptionClass::Ambient,
            OutboundDeliverySemanticsKind::ReactionTarget,
            None,
            OutboundRetryClass::IdempotentNative,
            OutboundPermissionState::Conditional,
            false,
            "The first-party adapter checks message visibility and audience before writing a reaction.",
        )],
    )
}

fn linear_manifest() -> OutboundCapabilityManifest {
    manifest(
        "linear",
        "issue_tracker",
        "TASK mirror mutations must pass the ordinary outbound gate.",
        ["create_issue", "update_issue"]
            .into_iter()
            .map(|kind| {
                verb(
                    kind,
                    kind,
                    json!({"operation_id":"engine digest", "payload":"frozen GraphQL mutation"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Conditional,
                    false,
                    "The host reconciles uncertain delivery; provider-native idempotency is not assumed.",
                )
            })
            .collect(),
    )
}

fn feedback_manifest(channel: &'static str) -> OutboundCapabilityManifest {
    manifest(
        channel,
        "feedback",
        "Approved bundle delivery; exact destination and bytes are consent-bound.",
        vec![
            verb(
                "send",
                "POST",
                json!({"bundle":"approved MessagePack bytes","target":"exact HTTPS endpoint"}),
                OutboundInterruptionClass::Ambient,
                OutboundDeliverySemanticsKind::FireAndForget,
                None,
                OutboundRetryClass::NonIdempotentInterrupt,
                OutboundPermissionState::Conditional,
                false,
                "Requires one approval for one bundle and one destination; never a standing grant.",
            ),
            // OF-420: a content-free ED-08 issue signature the publisher
            // delivery sends on its own; it never carries a bundle or text.
            verb(
                "signature",
                "POST",
                json!({"signature":"oneiron.issue_signature.v1 JSON","target":"exact HTTPS endpoint"}),
                OutboundInterruptionClass::Ambient,
                OutboundDeliverySemanticsKind::FireAndForget,
                None,
                OutboundRetryClass::NonIdempotentInterrupt,
                OutboundPermissionState::Conditional,
                false,
                "Allowed while the owner's \"Help improve Oneiron\" switch and the publisher dial are both on, to the publisher endpoint the owner bound.",
            ),
        ],
    )
}

// OF-380: the failure-signal batch a participating deployment sends its
// publisher. Its standing grant is the participation itself, kept by the
// engine's delivery door; it is never an owner's per-send approval.
fn failure_signals_manifest() -> OutboundCapabilityManifest {
    manifest(
        "failure_signals",
        "telemetry",
        "Content-free tier-1 counts and sealed code-fix records; no world text.",
        vec![verb(
            "send",
            "POST",
            json!({"batch":"failure-signal batch JSON","target":"exact HTTPS publisher endpoint"}),
            OutboundInterruptionClass::Ambient,
            OutboundDeliverySemanticsKind::FireAndForget,
            None,
            OutboundRetryClass::NonIdempotentInterrupt,
            OutboundPermissionState::Conditional,
            false,
            "Allowed while the owner's \"Help improve Oneiron\" switch is on (on by default hosted with opt-out, off by default self-host with opt-in).",
        )],
    )
}
