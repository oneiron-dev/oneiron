//! Slack key, workspace, and field normalizers shared by the Slack adapter paths.

use super::shared_validate::{
    MAX_SLACK_DISPLAY_NAME_BYTES, MAX_SLACK_ID_BYTES, MAX_SLACK_PAYLOAD_REF_BYTES,
    MAX_SLACK_PERSONA_HANDLE_BYTES, MAX_SLACK_TEXT_BYTES, MAX_SLACK_URL_BYTES, SLACK_CHANNEL,
    validate_max_bytes, validate_non_blank,
};
use crate::channel_identity::{
    ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityShape,
};
use crate::channel_identity_lifecycle::ProvisionIntent;
use crate::error::{Error, Result};

pub(super) fn validate_slack_provision_intent(intent: &ProvisionIntent) -> Result<()> {
    if intent.fulfillment_mode != ChannelIdentityFulfillment::Api {
        return Err(Error::InvalidConfig(
            "slack adapter fulfillment mode does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.channel != SLACK_CHANNEL {
        return Err(Error::InvalidConfig(
            "slack adapter channel does not match ProvisionIntent".to_owned(),
        ));
    }
    if intent.identity.shape != ChannelIdentityShape::SharedPresence {
        return Err(Error::InvalidConfig(
            "slack adapter requires shared_presence identities".to_owned(),
        ));
    }
    if !matches!(
        intent.identity.binding,
        ChannelIdentityBinding::Actor { .. }
    ) {
        return Err(Error::InvalidConfig(
            "slack adapter requires agent-scoped personas".to_owned(),
        ));
    }
    validate_slack_identity_key(&intent.identity.address_or_handle)?;
    intent.identity.validate()
}

pub(super) fn slack_workspace_ref(
    workspace_id: &str,
    enterprise_id: Option<&str>,
) -> Result<String> {
    let workspace_id = normalize_slack_id(workspace_id, "slack workspace id")?;
    match enterprise_id {
        Some(enterprise_id) => {
            let enterprise_id = normalize_slack_id(enterprise_id, "slack enterprise id")?;
            Ok(format!(
                "slack:enterprise:{enterprise_id}:workspace:{workspace_id}"
            ))
        }
        None => Ok(format!("slack:workspace:{workspace_id}")),
    }
}

pub(super) fn slack_identity_key(
    workspace_id: &str,
    enterprise_id: Option<&str>,
    persona_handle: &str,
) -> Result<String> {
    let workspace_ref = slack_workspace_ref(workspace_id, enterprise_id)?;
    let persona_handle = normalize_slack_persona_handle(persona_handle)?;
    Ok(format!("{workspace_ref}:persona:{persona_handle}"))
}

pub(super) fn validate_slack_identity_key(identity_key: &str) -> Result<()> {
    let parts = identity_key.split(':').collect::<Vec<_>>();
    let expected = match parts.as_slice() {
        [
            "slack",
            "workspace",
            workspace_id,
            "persona",
            persona_handle,
        ] => slack_identity_key(workspace_id, None, persona_handle)?,
        [
            "slack",
            "enterprise",
            enterprise_id,
            "workspace",
            workspace_id,
            "persona",
            persona_handle,
        ] => slack_identity_key(workspace_id, Some(enterprise_id), persona_handle)?,
        _ => {
            return Err(Error::InvalidConfig(
                "slack identity key must include workspace and persona".to_owned(),
            ));
        }
    };
    if expected != identity_key {
        return Err(Error::InvalidConfig(
            "slack identity key is not normalized".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn normalize_slack_id(value: &str, field: &'static str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, field)?;
    validate_max_bytes(value, MAX_SLACK_ID_BYTES, "slack id exceeds maximum length")?;
    if !value.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(Error::InvalidConfig(format!(
            "{field} must contain only ascii letters and digits"
        )));
    }
    Ok(value.to_owned())
}

pub(super) fn normalize_slack_persona_handle(value: &str) -> Result<String> {
    let value = value.trim().trim_start_matches('@').to_ascii_lowercase();
    validate_non_blank(&value, "slack persona handle must be non-empty")?;
    validate_max_bytes(
        &value,
        MAX_SLACK_PERSONA_HANDLE_BYTES,
        "slack persona handle exceeds maximum length",
    )?;
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
    {
        return Err(Error::InvalidConfig(
            "slack persona handle must be ascii lowercase letters, digits, hyphen, underscore, or dot".to_owned(),
        ));
    }
    Ok(value)
}

pub(super) fn normalize_slack_display_name(value: &str, reason: &'static str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, reason)?;
    validate_max_bytes(
        value,
        MAX_SLACK_DISPLAY_NAME_BYTES,
        "slack display name exceeds maximum length",
    )?;
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(
            "slack display name must not contain control characters".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

pub(super) fn normalize_slack_url(value: &str, field: &'static str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, field)?;
    validate_max_bytes(
        value,
        MAX_SLACK_URL_BYTES,
        "slack URL exceeds maximum length",
    )?;
    if !value.starts_with("https://") || value.chars().any(char::is_whitespace) {
        return Err(Error::InvalidConfig(format!(
            "{field} must be an https URL without whitespace"
        )));
    }
    Ok(value.to_owned())
}

pub(super) fn normalize_slack_icon_emoji(value: &str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, "slack persona icon_emoji must be non-empty")?;
    validate_max_bytes(
        value,
        MAX_SLACK_DISPLAY_NAME_BYTES,
        "slack persona icon_emoji exceeds maximum length",
    )?;
    if value.len() <= 2
        || !value.starts_with(':')
        || !value.ends_with(':')
        || !value.bytes().all(|byte| byte.is_ascii())
    {
        return Err(Error::InvalidConfig(
            "slack persona icon_emoji must be a Slack emoji shortcode".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

pub(super) fn normalize_slack_text(value: &str) -> Result<String> {
    validate_non_blank(value, "slack outbound text must be non-empty")?;
    validate_max_bytes(
        value,
        MAX_SLACK_TEXT_BYTES,
        "slack outbound text exceeds maximum length",
    )?;
    Ok(value.to_owned())
}

pub(super) fn normalize_slack_ts(value: &str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, "slack thread timestamp must be non-empty")?;
    validate_max_bytes(
        value,
        MAX_SLACK_ID_BYTES,
        "slack thread timestamp exceeds maximum length",
    )?;
    if !value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'.')) {
        return Err(Error::InvalidConfig(
            "slack thread timestamp must contain only digits and dot".to_owned(),
        ));
    }
    Ok(value.to_owned())
}

pub(super) fn normalize_slack_payload_ref(value: &str) -> Result<String> {
    let value = value.trim();
    validate_non_blank(value, "slack payload ref must be non-empty")?;
    validate_max_bytes(
        value,
        MAX_SLACK_PAYLOAD_REF_BYTES,
        "slack payload ref exceeds maximum length",
    )?;
    Ok(value.to_owned())
}
