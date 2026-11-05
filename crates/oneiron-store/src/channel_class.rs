//! Canonical recipient-facing channel classes.

/// Canonical channel-class normalization for the party-channel index.
///
/// Shared by index writers, the contact/comm gate, campaign compliance, and
/// outbound sender/window handling. Provider-specific email rails and the
/// `mail` spelling of inbound mail are one recipient-facing class, not
/// aliases for connector authorization: grants, transport routing and intent
/// ledgers still use each exact connector key.
#[must_use]
pub fn normalize_channel_class(channel: &str) -> String {
    let channel = channel.trim().to_ascii_lowercase();
    if matches!(
        channel.as_str(),
        "mail" | "email_resend" | "email_ses" | "email_postmark"
    ) {
        "email".to_owned()
    } else {
        channel
    }
}
