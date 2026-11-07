//! `[mail]`: the host operator's mail settings (fix list row 17645).
//! File-only, like `[line]`. Absent means each setting's default.
//!
//! ```toml
//! [mail.smtp]
//! max_message_octets_unadvertised = 36700160   # the default
//! ```
//!
//! `mail.smtp.max_message_octets_unadvertised` is the most octets one
//! message submitted over SMTP may have when its server's `EHLO` names no
//! `SIZE` limit: an IMAP mailbox's reply with files is refused above it at
//! draft, before the press and at the send. A limit the server names always
//! wins over it. See `docs/ops/mail-reply-size-limits.md`.

use oneiron::mail_pack::{DEFAULT_SMTP_MAX_MESSAGE_OCTETS_UNADVERTISED, MailHostSettings};
use serde::Deserialize;

/// The `[mail]` section.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailConfig {
    /// `[mail.smtp]`: SMTP submission's settings.
    #[serde(default)]
    pub smtp: MailSmtpConfig,
}

/// The `[mail.smtp]` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MailSmtpConfig {
    /// The most octets one message submitted over SMTP may have when its
    /// server's `EHLO` names no `SIZE` limit; 36,700,160 unless set.
    #[serde(default = "default_max_message_octets_unadvertised")]
    pub max_message_octets_unadvertised: u64,
}

impl Default for MailSmtpConfig {
    fn default() -> Self {
        Self {
            max_message_octets_unadvertised: DEFAULT_SMTP_MAX_MESSAGE_OCTETS_UNADVERTISED,
        }
    }
}

const fn default_max_message_octets_unadvertised() -> u64 {
    DEFAULT_SMTP_MAX_MESSAGE_OCTETS_UNADVERTISED
}

impl MailConfig {
    pub(super) fn validate(&self) -> anyhow::Result<()> {
        if self.smtp.max_message_octets_unadvertised == 0 {
            anyhow::bail!("mail.smtp.max_message_octets_unadvertised must be at least 1");
        }
        Ok(())
    }

    /// The settings the engine's mail pack reads on each served vault.
    #[must_use]
    pub const fn host_settings(&self) -> MailHostSettings {
        MailHostSettings {
            smtp_max_message_octets_unadvertised: self.smtp.max_message_octets_unadvertised,
        }
    }
}
