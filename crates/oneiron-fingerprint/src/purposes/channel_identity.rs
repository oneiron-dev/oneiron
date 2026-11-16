//! Purposes of channel identities (`crates/oneiron/src/channel_identity_lifecycle`,
//! `channel_identity_provider`).

purposes! {
    /// A request ref its host's invocation fixes (`channel_identity_lifecycle::approval`).
    /// Parts: actor, verb, invocation, input digest.
    LIFECYCLE_REQUEST_REF = "oneiron:channel-identity-lifecycle-request-ref:v1";

    /// The one id an identity's mailbox record takes, so a retried provision writes it once
    /// (`channel_identity_provider::native_mail::mailbox`). Parts: identity.
    NATIVE_MAIL_MAILBOX = "oneiron.native_mail.mailbox.v1";

    /// A reputation claim of a native mail identity
    /// (`channel_identity_provider::stalwart::reputation`). Parts: identity, the report's
    /// observation ref, the claim predicate.
    NATIVE_MAIL_REPUTATION = "oneiron.native_mail.reputation.v1";

    /// A workspace write's invocation ref, so one caller's one logical call always names the
    /// same row (`channel_identity_provider::workspace_connector::invocation`). Parts: actor
    /// (hex), attempt, call sequence (u64 little-endian).
    WORKSPACE_WRITE_INVOCATION = "oneiron.workspace_write_invocation.v1";
}

legacy_purposes! {}
