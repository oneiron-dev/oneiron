//! Moved from `crates/oneiron/src/channel_identity/custody.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use std::marker::PhantomData;

pub const MAX_DELEGATED_GRANT_REF_BYTES: usize = 256;

pub const MAX_DELEGATED_GRANT_SCOPES: usize = 8;

/// OAuth scope classes a `delegated_grant` row may carry.
///
/// Two read classes and exactly one write class, `MailSend` (OF-374). There is
/// deliberately no reply, delete, or modify variant: a reply is a send with
/// thread headers, and nothing else a member grant could carry is one the
/// engine acts on. `MailSend` is send CAPABILITY, never send approval: the
/// custody proof requires the host to have registered the provider's own
/// granted-scope evidence for it, and every send still crosses the gate, which
/// holds it for the owner unless a grant covers it (ARCH-0046 "depends on the
/// grant").
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum DelegatedGrantScope {
    /// Read message bodies in the granted mailbox.
    #[serde(rename = "mail.read")]
    MailRead,
    /// Read message headers/metadata only.
    #[serde(rename = "mail.metadata")]
    MailMetadata,
    /// Send mail as the granted mailbox (Gmail `gmail.send`).
    #[serde(rename = "mail.send")]
    MailSend,
}

impl DelegatedGrantScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MailRead => "mail.read",
            Self::MailMetadata => "mail.metadata",
            Self::MailSend => "mail.send",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mail.read" => Some(Self::MailRead),
            "mail.metadata" => Some(Self::MailMetadata),
            "mail.send" => Some(Self::MailSend),
            _ => None,
        }
    }
}

/// The custody handle a `delegated_grant` row carries.
///
/// This is a custody record NAME plus the scopes the grant covers. The
/// OAuth access/refresh token bytes live in the custody record and are reachable
/// only through the SECRET-02 door under an effector binding; they never land on
/// this struct, on the encoded body, or on any claim derived from it.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct DelegatedGrant {
    /// Custody record name (`Vault::resolve_secret_ref` key), never a token.
    pub custody_record_ref: String,
    /// Scopes the grant covers; non-empty, deduplicated.
    pub scopes: Vec<DelegatedGrantScope>,
}

impl DelegatedGrant {
    /// Builds a delegated grant handle from a custody record name and scopes.
    #[must_use]
    pub fn new(custody_record_ref: impl Into<String>, scopes: Vec<DelegatedGrantScope>) -> Self {
        Self {
            custody_record_ref: custody_record_ref.into(),
            scopes,
        }
    }

    /// Whether the scopes this grant covers include OUTBOUND SEND.
    ///
    /// Matched exhaustively on purpose: only [`DelegatedGrantScope::MailSend`]
    /// answers yes, and a new scope class is a compile error here until someone
    /// decides what it answers. That is what keeps a manifest row from turning
    /// a read-only OAuth grant into send authority — the policy row says whether
    /// the ACT class may run, and this says whether the grant we actually hold
    /// carries it. A row can only carry `MailSend` through a custody proof that
    /// found the provider's granted-scope evidence on the binding.
    #[must_use]
    pub fn covers_outbound_send(&self) -> bool {
        self.scopes.iter().any(|scope| match scope {
            DelegatedGrantScope::MailRead | DelegatedGrantScope::MailMetadata => false,
            DelegatedGrantScope::MailSend => true,
        })
    }

    /// Whether the grant covers a READ scope class.
    #[must_use]
    pub fn covers_read(&self) -> bool {
        self.scopes.iter().any(|scope| match scope {
            DelegatedGrantScope::MailRead | DelegatedGrantScope::MailMetadata => true,
            DelegatedGrantScope::MailSend => false,
        })
    }

    /// Validates the grant handle's own bounds.
    ///
    /// # Errors
    ///
    /// [`RecordError::InvalidChannelIdentityBody`](oneiron_base::error::RecordError::InvalidChannelIdentityBody) for a blank or over-long custody
    /// record name, an empty or over-long scope set, or a repeated scope.
    pub fn validate(&self) -> Result<()> {
        let trimmed = self.custody_record_ref.trim();
        if trimmed.is_empty() || self.custody_record_ref.len() > MAX_DELEGATED_GRANT_REF_BYTES {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "delegated_grant_ref must be a non-empty custody record name of at most 256 bytes",
            )));
        }
        if self.scopes.is_empty() || self.scopes.len() > MAX_DELEGATED_GRANT_SCOPES {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "delegated grant must declare 1..=8 scopes",
            )));
        }
        for (index, scope) in self.scopes.iter().enumerate() {
            if self.scopes[..index].contains(scope) {
                return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                    "delegated grant scopes must not repeat",
                )));
            }
        }
        Ok(())
    }
}
