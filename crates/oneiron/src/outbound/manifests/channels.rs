//! The built-in channel manifests, one builder per capability, in the order
//! `build_outbound_capability_manifests` lists them.
//! Entry: `line_manifest`. The shared `manifest`/`verb` constructors stay in `manifests`.

use super::*;

pub(super) fn esign_manifest() -> OutboundCapabilityManifest {
    manifest(
        "esign", "signing", "Native signing request organ.",
        ["send_for_signature", "remind", "void"].into_iter().map(|kind| verb(
            kind, kind, json!({"document": "artifact ref", "recipient_count": "reviewed count"}),
            OutboundInterruptionClass::Interrupt,
            OutboundDeliverySemanticsKind::FireAndForget, None,
            OutboundRetryClass::IdempotentEmulated,
            OutboundPermissionState::Conditional, false,
            "Explicit action grant; durable delivery enqueue is distinct from delivery health.",
        )).collect(),
    )
}

pub(super) fn line_manifest() -> OutboundCapabilityManifest {
    message_manifest(
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
                        "quota": line_push_quota(),
                        "X-Line-Retry-Key": "frozen ledger idempotency key"
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::IdempotentNative,
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
                        "recipient": {"type": "operator", "and": []},
                        "X-Line-Retry-Key": "frozen ledger idempotency key"
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::ProviderReview,
                    true,
                    "LINE narrowcast is a connector-specific capability and can require plan/review constraints.",
                ),
            ],
        ),
        &["send", "reply", "push", "send_media"],
    )
}

pub(super) fn telegram_manifest() -> OutboundCapabilityManifest {
    message_manifest(
        manifest(
            "telegram",
            "chat",
            "Telegram Bot API outbound schema; permissions depend on bot membership and chat policies.",
            vec![
                verb(
                    "send",
                    "sendMessage",
                    json!({"chat_id": "integer|string", "text": "string", "parse_mode": "optional string", "business_connection_id": "owner mode only: the answered business message's connection", "reply_parameters": "optional answered message", "posting": {"default": "named_participant", "post_as_owner_supported": true, "policy_risk": true, "owner_path": "Telegram Business reply-as-you: an answer to a business message, sent on its business_connection_id"}}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::IdempotentEmulated,
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
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Allowed,
                    true,
                    "Media calls require a supported media transport and target chat permission.",
                ),
                verb(
                    "react",
                    "setMessageReaction",
                    json!({"chat_id": "integer|string", "message_id": "integer", "reaction": [{"type": "emoji", "emoji": "string"}], "emoji_vocabulary": "chat_available_reactions"}),
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
        &["send", "send_media"],
    )
}

pub(super) fn slack_manifest() -> OutboundCapabilityManifest {
    message_manifest(
        manifest(
            "slack",
            "workspace_bot",
            "Slack Web API outbound schema; OAuth scopes and workspace policies are distinct from capability.",
            vec![
                verb(
                    "send",
                    "chat.postMessage",
                    json!({"channel": "channel_id", "text": "string", "blocks": "optional block kit array", "thread_ts": "optional string", "username": "persona display name", "icon_url": "optional persona avatar URL", "icon_emoji": "optional persona emoji", "metadata": "optional app-level-token identity metadata", "posting": {"default": "named_participant", "post_as_owner_supported": true, "policy_risk": true, "owner_path": "user-token chat.postMessage with the owner's chat:write user scope from the app's install"}}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires chat:write, chat:write.customize for persona attribution, and channel posting permission; Slack message metadata is app-level-token only.",
                ),
                verb(
                    "react",
                    "reactions.add",
                    json!({"channel": "channel_id", "timestamp": "message_ts", "name": "emoji_name", "emoji_vocabulary": "workspace_unicode_and_custom_names"}),
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
        &["send"],
    )
}

pub(super) fn discord_manifest() -> OutboundCapabilityManifest {
    message_manifest(
        manifest(
            "discord",
            "workspace_bot",
            "Discord Bot API outbound schema; guild/channel permissions control usable capability.",
            vec![
                verb(
                    "send",
                    "create_message",
                    json!({"channel_id": "snowflake", "content": "string", "nonce": "frozen ledger idempotency key", "enforce_nonce": true, "embeds": "optional array", "message_reference": "optional reply"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires Send Messages in the target channel.",
                ),
                verb(
                    "cold_dm",
                    "create_message",
                    json!({"channel_id": "private channel snowflake", "content": "string", "nonce": "frozen ledger idempotency key", "enforce_nonce": true}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::Conditional,
                    true,
                    "Cold or bulk marketing DMs to strangers carry disclosed platform policy risk; hold for a per-channel owner grant. Ordinary owner DMs use send.",
                ),
                verb(
                    "react",
                    "create_reaction",
                    json!({"channel_id": "snowflake", "message_id": "snowflake", "emoji": "unicode|custom", "emoji_vocabulary": "unicode_and_permitted_custom"}),
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
        &["send", "cold_dm"],
    )
}

pub(super) fn apns_manifest() -> OutboundCapabilityManifest {
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
            OutboundRetryClass::IdempotentEmulated,
            OutboundPermissionState::Conditional,
            true,
            "APNs can interrupt users and depends on app entitlement, token validity, and user notification permission.",
        )],
    )
}

pub(super) fn imessage_mfb_manifest() -> OutboundCapabilityManifest {
    message_manifest(
        manifest(
            "imessage_mfb",
            "apple_messages_for_business",
            "Apple Messages for Business schema; capability is distinct from brand approval and conversation state.",
            vec![
                verb(
                    "send",
                    "messages_for_business_send",
                    json!({"conversation_id": "string", "text": "string", "message_uuid": "stable provider-valid UUID derived from frozen ledger idempotency key", "rich_link": "optional object"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::IdempotentNative,
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
        &["send"],
    )
}

pub(super) fn imessage_bridge_manifest() -> OutboundCapabilityManifest {
    message_manifest(
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
                    OutboundRetryClass::IdempotentEmulated,
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
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Conditional,
                    true,
                    "Media sends require explicit file access and host-device consent.",
                ),
                verb(
                    "react",
                    "local_messages_tapback",
                    json!({
                        "chat_id": "string",
                        "message_id": "host-local message handle",
                        "glyph": "tapback glyph",
                        "emoji_vocabulary": crate::reaction::IMESSAGE_TAPBACK_GLYPHS
                    }),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::ReactionTarget,
                    None,
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Conditional,
                    true,
                    "Only a host bridge with tapback support may execute this verb; the target message must be visible to the bridge account.",
                ),
            ],
        ),
        &["send", "send_media"],
    )
}

pub(super) fn linkedin_manifest() -> OutboundCapabilityManifest {
    message_manifest(
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
                        "verify_after_send": "connect_with_person return is never trusted; re-read get_person_profile connection state before delivered receipt",
                        "engine_side_safety": "per-seat sandbox policy enforces kill-switch, connect-request and profile-read caps, cadence, and no sweeps before transport"
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
        &["send_dm"],
    )
}

pub(super) fn email_manifest() -> OutboundCapabilityManifest {
    message_manifest(
        manifest(
            "email",
            "email",
            "SMTP/provider email schema; deliverability and recipient consent are permissions, not raw capability.",
            vec![
                verb(
                    "send",
                    "send_email",
                    json!({"to": ["addr@example.com"], "subject": "string", "body": "text/html|string", "headers": "optional object", "posting": {"default": "named_participant", "post_as_owner_supported": true, "policy_risk": true, "permission": "verified sender plus exact owner space grant"}}),
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
        &["send", "replace"],
    )
}

pub(super) fn calendar_manifest() -> OutboundCapabilityManifest {
    manifest(
        "calendar",
        "calendar",
        "iMIP invitations are first-party calendar objects rendered from our own event state; the ICS bytes never ride the frozen body, only their blob ref does.",
        vec![verb(
            crate::calendar::invite::CALENDAR_INVITE_VERB,
            "send_imip_invitation",
            json!({
                "method": "REQUEST | CANCEL",
                "uid": "event UID, minted once at the first confirm and reused forever",
                "sequence": "iTIP SEQUENCE, strictly increasing on the same UID",
                "ics_blob_ref": "blob artifact ref the connector resolves into the text/calendar part",
                "recipient": "attendee address the invite is addressed to",
                "engine_side_safety": "the chokepoint verifies a prior thread or a confirmed booking grant, requires the primary calendar domain, and commits the SEQUENCE bump with the frozen intent"
            }),
            OutboundInterruptionClass::Interrupt,
            // An update or cancel supersedes the prior revision in the
            // recipient's calendar rather than editing it in place, which
            // is exactly the email `replace` shape.
            OutboundDeliverySemanticsKind::Replaceable,
            None,
            // Replaying the frozen (UID, SEQUENCE, METHOD) is a semantic
            // replacement/no-op in a conforming client. It is replay-safe,
            // unlike queue-emulated sends with no provider guarantee.
            OutboundRetryClass::ReplaceIdempotent,
            OutboundPermissionState::Conditional,
            false,
            "iMIP invites require a prior thread or a confirmed booking standing grant, and must leave from the primary calendar domain — never from sequencer-class infrastructure.",
        )],
    )
}
