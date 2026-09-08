//! Cross-channel provision guards, email/LINE normalizers, and blank/bytes primitives.

use super::inbound_types::{
    ChannelIdentityProviderInbound, EmailProviderInbound, LineOfficialAccountInbound,
};
use crate::channel_identity::{
    ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
};
use crate::channel_identity_lifecycle::ProvisionIntent;
use crate::error::{Error, Result};

/// Stable provider adapter contract version.
pub const CHANNEL_IDENTITY_PROVIDER_ADAPTER_VERSION: &str = "channel_identity.provider_adapter.v1";

/// Stable key for the built-in dev-safe email adapter.
pub const DEV_EMAIL_PROVIDER_KEY: &str = "dev_email";

/// Stable key for the built-in Slack shared-presence adapter.
pub const SLACK_SHARED_PRESENCE_PROVIDER_KEY: &str = "slack_shared_presence";

/// Stable key for the LINE Official Account adapter.
pub const LINE_OFFICIAL_ACCOUNT_PROVIDER_KEY: &str = "line_oa";

/// Stable channel key for email identities.
pub const EMAIL_CHANNEL: &str = "email";

/// Stable channel key for Slack shared-presence identities.
pub const SLACK_CHANNEL: &str = "slack";

/// Stable channel key for LINE Official Account identities.
pub const LINE_CHANNEL: &str = "line";

/// Default deterministic local-part prefix for dev-safe email identities.
pub const DEFAULT_EMAIL_LOCAL_PART_PREFIX: &str = "agent";

/// Default LINE monthly push allowance for the free Messaging API plan.
pub const DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE: u32 = 200;

pub(super) const SIGNATURE_HEX_BYTES: usize = 6;

pub(super) const SIGNATURE_HEX_LEN: usize = SIGNATURE_HEX_BYTES * 2;

pub(super) const MAX_EMAIL_ADDRESS_BYTES: usize = 254;

pub(super) const MAX_EMAIL_LOCAL_PART_BYTES: usize = 64;

pub(super) const MAX_EMAIL_DOMAIN_BYTES: usize = 253;

pub(super) const MAX_EMAIL_PROVIDER_EVENT_ID_BYTES: usize = 128;

pub(super) const MAX_EMAIL_PAYLOAD_REF_BYTES: usize = 512;

pub(super) const MAX_LINE_PROVIDER_EVENT_ID_BYTES: usize = 128;

pub(super) const MAX_LINE_COMPONENT_BYTES: usize = 128;

pub(super) const LINE_USER_ID_BYTES: usize = 33;

pub(super) const MAX_LINE_REPLY_TOKEN_BYTES: usize = 256;

pub(super) const MAX_LINE_PAYLOAD_REF_BYTES: usize = 512;

pub(super) const IDENTITY_HEX_LEN: usize = 32;

pub(super) const LOCAL_PART_SEPARATOR_BYTES: usize = 2;

pub(super) const MAX_LOCAL_PART_PREFIX_BYTES: usize =
    MAX_EMAIL_LOCAL_PART_BYTES - IDENTITY_HEX_LEN - SIGNATURE_HEX_LEN - LOCAL_PART_SEPARATOR_BYTES;

pub(super) const MAX_SLACK_ID_BYTES: usize = 128;

pub(super) const MAX_SLACK_PERSONA_HANDLE_BYTES: usize = 80;

pub(super) const MAX_SLACK_DISPLAY_NAME_BYTES: usize = 80;

pub(super) const MAX_SLACK_URL_BYTES: usize = 512;

pub(super) const MAX_SLACK_TEXT_BYTES: usize = 40_000;

pub(super) const MAX_SLACK_EVENT_ID_BYTES: usize = 128;

pub(super) const MAX_SLACK_PAYLOAD_REF_BYTES: usize = 512;

pub(super) fn validate_provision_intent(
    intent: &ProvisionIntent,
    expected_channel: &str,
    expected_address_or_handle: &str,
    expected_mode: ChannelIdentityFulfillment,
) -> Result<()> {
    if intent.fulfillment_mode != expected_mode {
        return Err(Error::InvalidConfig(
            "provider adapter fulfillment mode does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.channel != expected_channel {
        return Err(Error::InvalidConfig(
            "provider adapter channel does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.address_or_handle != expected_address_or_handle {
        return Err(Error::InvalidConfig(
            "provider adapter address does not match deterministic identity address".to_owned(),
        ));
    }
    if intent.identity.shape != ChannelIdentityShape::DedicatedAddress {
        return Err(Error::InvalidConfig(
            "email provider adapter requires dedicated_address identities".to_owned(),
        ));
    }
    if !matches!(
        intent.identity.binding,
        ChannelIdentityBinding::Actor { .. }
    ) {
        return Err(Error::InvalidConfig(
            "email provider adapter requires agent-scoped identities".to_owned(),
        ));
    }
    intent.identity.validate()
}

pub(super) fn validate_line_provision_intent(
    intent: &ProvisionIntent,
    expected_destination: &str,
) -> Result<()> {
    if intent.fulfillment_mode != ChannelIdentityFulfillment::Manual {
        return Err(Error::InvalidConfig(
            "LINE OA adapter requires manual fulfillment".to_owned(),
        ));
    }
    if intent.identity.channel != LINE_CHANNEL {
        return Err(Error::InvalidConfig(
            "LINE OA adapter channel does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.shape != ChannelIdentityShape::SharedPresence {
        return Err(Error::InvalidConfig(
            "LINE OA adapter requires shared_presence identities".to_owned(),
        ));
    }
    if !matches!(
        intent.identity.binding,
        ChannelIdentityBinding::Actor { .. }
    ) {
        return Err(Error::InvalidConfig(
            "LINE OA adapter requires agent-scoped identities".to_owned(),
        ));
    }
    validate_line_shared_presence_address(
        &intent.identity.address_or_handle,
        expected_destination,
    )?;
    intent.identity.validate()
}

pub(super) fn expect_line_inbound(
    inbound: ChannelIdentityProviderInbound,
) -> Result<LineOfficialAccountInbound> {
    match inbound {
        ChannelIdentityProviderInbound::Line(line) => Ok(line),
        ChannelIdentityProviderInbound::Email(_) | ChannelIdentityProviderInbound::Slack(_) => Err(
            Error::InvalidConfig("LINE OA adapter received non-LINE inbound".to_owned()),
        ),
    }
}

pub(super) fn normalize_domain(domain: &str) -> Result<String> {
    let domain = domain.trim().trim_end_matches('.');
    validate_non_blank(domain, "email adapter domain must be non-empty")?;
    validate_max_bytes(
        domain,
        MAX_EMAIL_DOMAIN_BYTES,
        "email adapter domain exceeds maximum length",
    )?;
    let domain = domain.to_ascii_lowercase();
    if domain.contains('@') || domain.contains('*') || domain.contains("..") {
        return Err(Error::InvalidConfig(
            "email adapter domain must be an exact non-wildcard domain".to_owned(),
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(Error::InvalidConfig(
            "email adapter domain must not start or end with a dot".to_owned(),
        ));
    }
    if !domain
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.'))
    {
        return Err(Error::InvalidConfig(
            "email adapter domain must be ascii hostname characters".to_owned(),
        ));
    }
    for label in domain.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidConfig(
                "email adapter domain contains an invalid label".to_owned(),
            ));
        }
    }
    Ok(domain)
}

pub(super) fn normalize_local_part_prefix(prefix: &str) -> Result<String> {
    let prefix = prefix.trim().to_ascii_lowercase();
    validate_non_blank(&prefix, "email local-part prefix must be non-empty")?;
    if prefix.len() > MAX_LOCAL_PART_PREFIX_BYTES {
        return Err(Error::InvalidConfig(format!(
            "email local-part prefix must be at most {MAX_LOCAL_PART_PREFIX_BYTES} bytes"
        )));
    }
    if prefix.starts_with('-') || prefix.ends_with('-') {
        return Err(Error::InvalidConfig(
            "email local-part prefix must not start or end with hyphen".to_owned(),
        ));
    }
    if !prefix
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err(Error::InvalidConfig(
            "email local-part prefix must be ascii lowercase letters, digits, or hyphen".to_owned(),
        ));
    }
    Ok(prefix)
}

pub(super) fn split_email_address(address: &str) -> Result<(String, String)> {
    let address = address.trim();
    validate_non_blank(address, "email address must be non-empty")?;
    validate_max_bytes(
        address,
        MAX_EMAIL_ADDRESS_BYTES,
        "email address exceeds maximum length",
    )?;
    if address.contains('*') {
        return Err(Error::InvalidConfig(
            "email adapter rejects wildcard or catch-all addresses".to_owned(),
        ));
    }
    let (local_part, domain) = address
        .split_once('@')
        .ok_or_else(|| Error::InvalidConfig("email address must contain @".to_owned()))?;
    if local_part.is_empty() || local_part.contains('@') || domain.contains('@') {
        return Err(Error::InvalidConfig(
            "email address must contain one non-empty local-part and domain".to_owned(),
        ));
    }
    validate_max_bytes(
        local_part,
        MAX_EMAIL_LOCAL_PART_BYTES,
        "email local-part exceeds maximum length",
    )?;
    let domain = normalize_domain(domain)?;
    if !local_part.bytes().all(|byte| {
        matches!(
            byte,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'+'
        )
    }) {
        return Err(Error::InvalidConfig(
            "email local-part contains unsupported characters".to_owned(),
        ));
    }
    Ok((local_part.to_ascii_lowercase(), domain))
}

pub(super) fn validate_email_inbound_metadata(email: &EmailProviderInbound) -> Result<()> {
    validate_non_blank(
        &email.provider_event_id,
        "provider event id must be non-empty",
    )?;
    validate_max_bytes(
        &email.provider_event_id,
        MAX_EMAIL_PROVIDER_EVENT_ID_BYTES,
        "provider event id exceeds maximum length",
    )?;
    if let Some(payload_ref) = &email.payload_ref {
        validate_non_blank(payload_ref, "email payload_ref must be non-empty")?;
        validate_max_bytes(
            payload_ref,
            MAX_EMAIL_PAYLOAD_REF_BYTES,
            "email payload_ref exceeds maximum length",
        )?;
    }
    Ok(())
}

pub(super) fn validate_line_inbound_metadata(line: &LineOfficialAccountInbound) -> Result<()> {
    validate_non_blank(
        &line.provider_event_id,
        "provider event id must be non-empty",
    )?;
    validate_max_bytes(
        &line.provider_event_id,
        MAX_LINE_PROVIDER_EVENT_ID_BYTES,
        "provider event id exceeds maximum length",
    )?;
    if let Some(reply_token) = &line.reply_token {
        validate_non_blank(reply_token, "LINE reply token must be non-empty")?;
        validate_max_bytes(
            reply_token,
            MAX_LINE_REPLY_TOKEN_BYTES,
            "LINE reply token exceeds maximum length",
        )?;
        if line.payload_ref.is_none() {
            return Err(Error::InvalidConfig(
                "LINE reply token requires payload_ref host-local handle".to_owned(),
            ));
        }
    }
    if let Some(payload_ref) = &line.payload_ref {
        validate_non_blank(payload_ref, "LINE payload_ref must be non-empty")?;
        validate_max_bytes(
            payload_ref,
            MAX_LINE_PAYLOAD_REF_BYTES,
            "LINE payload_ref exceeds maximum length",
        )?;
    }
    Ok(())
}

pub(super) fn normalize_line_user_like_id(
    value: &str,
    label: &'static str,
    max: usize,
) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, "LINE id must be non-empty")?;
    validate_line_component_max_bytes(value, max, label)?;
    let bytes = value.as_bytes();
    if bytes.len() != LINE_USER_ID_BYTES
        || bytes.first() != Some(&b'U')
        || !bytes[1..]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Error::InvalidConfig(format!(
            "{label} must match LINE user id shape U[0-9a-f]{{32}}"
        )));
    }
    Ok(value.to_owned())
}

pub(super) fn validate_line_component_max_bytes(
    value: &str,
    max: usize,
    label: &'static str,
) -> Result<()> {
    if value.len() > max {
        return Err(Error::InvalidConfig(format!(
            "{label} exceeds maximum length: {max} bytes"
        )));
    }
    Ok(())
}

pub(super) fn line_shared_presence_address(destination: &str, source_user_id: &str) -> String {
    format!("line:oa:{destination}:user:{source_user_id}")
}

pub(super) fn validate_line_shared_presence_address(
    address: &str,
    expected_destination: &str,
) -> Result<()> {
    validate_non_blank(address, "LINE shared_presence address must be non-empty")?;
    let prefix = format!("line:oa:{expected_destination}:user:");
    let Some(source_user_id) = address.strip_prefix(&prefix) else {
        return Err(Error::InvalidConfig(
            "LINE shared_presence address does not match adapter destination".to_owned(),
        ));
    };
    let source_user_id = normalize_line_user_like_id(
        source_user_id,
        "LINE source user id",
        MAX_LINE_COMPONENT_BYTES,
    )?;
    if address != line_shared_presence_address(expected_destination, &source_user_id) {
        return Err(Error::InvalidConfig(
            "LINE shared_presence address is not normalized".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn normalize_email_address(address: &str, normalized_domain: &str) -> Result<String> {
    let (local_part, domain) = split_email_address(address)?;
    if domain != normalized_domain {
        return Err(Error::InvalidConfig(
            "email normalization domain mismatch".to_owned(),
        ));
    }
    Ok(format!("{local_part}@{domain}"))
}

pub(super) fn validate_non_blank(value: &str, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::InvalidConfig(reason.to_owned()));
    }
    Ok(())
}

pub(super) fn validate_max_bytes(value: &str, max: usize, reason: &'static str) -> Result<()> {
    if value.len() > max {
        return Err(Error::InvalidConfig(format!("{reason}: {max} bytes")));
    }
    Ok(())
}
