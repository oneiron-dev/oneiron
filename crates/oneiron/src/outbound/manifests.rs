use serde_json::{Value, json};

use super::capability::{
    OUTBOUND_CAPABILITY_MANIFEST_VERSION, OutboundCapabilityManifest, OutboundCapabilityPermission,
    OutboundDeliverySemantics, OutboundDeliverySemanticsKind, OutboundInterruptionClass,
    OutboundPermissionState, OutboundRetryClass, OutboundVerbContract,
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
                        "reply_token_ref": "payload_ref host-local reply token handle",
                        "messages": [{"type": "text", "text": "string"}],
                        "quota": line_reply_quota()
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
                        "quota": line_push_quota()
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
                        "mode": "reply | push",
                        "messages": [{"type": "text", "text": "string"}],
                        "reply": {
                            "reply_token_ref": "payload_ref host-local reply token handle",
                            "quota": line_reply_quota()
                        },
                        "push": {
                            "to": "line_user_id | line_group_id",
                            "quota": line_push_quota()
                        }
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    false,
                    "Compatibility send requires callers to choose reply or push; push-mode sends debit monthly quota and require plan-tier checks.",
                ),
                verb(
                    "send_media",
                    "reply_message | push_message",
                    json!({
                        "mode": "reply | push",
                        "messages": [{"type": "image|video|audio|file", "originalContentUrl": "https://..."}],
                        "reply": {
                            "reply_token_ref": "payload_ref host-local reply token handle",
                            "quota": line_reply_quota()
                        },
                        "push": {
                            "to": "line_user_id | line_group_id",
                            "quota": line_push_quota()
                        }
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Compatibility media sends require callers to choose reply or push; push-mode sends debit monthly quota and require plan-tier checks.",
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
            "linkedin",
            "professional_network",
            "LinkedIn session content is foreign platform content; normalize inbound text through the LinkedIn connector before claims are proposed.",
            vec![
                verb(
                    "send_dm",
                    "send_message",
                    json!({
                        "linkedin_username": "recipient vanity name or profile key",
                        "profile_urn": "optional fsd_profile URN handle from get_person_profile",
                        "message": "string resolved from content_ref",
                        "confirm_send": "true only after OF-327 grant/gate approval",
                        "verify_after_send": "send_message return is never trusted; re-read get_conversation and content-match before delivered receipt",
                        "engine_side_safety": "per-seat sandbox policy enforces kill-switch, <=15/day default cap, active-session cadence, and no sweeps before connector transport"
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Wraps stickerdaniel/linkedin-mcp-server send_message with verify-after-send; account-risk and principal-session consent remain permission gates.",
                ),
                verb(
                    "connect_request",
                    "connect_with_person",
                    json!({
                        "linkedin_username": "recipient vanity name or profile key",
                        "note": "optional connection note resolved from content_ref",
                        "engine_side_safety": "per-seat sandbox policy revokes this verb when the kill switch is engaged"
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Wraps stickerdaniel/linkedin-mcp-server connect_with_person with optional note; cold outreach and account-risk walls remain permission gates.",
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
