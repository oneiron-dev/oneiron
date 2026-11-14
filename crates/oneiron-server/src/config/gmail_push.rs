//! `[gmail_push]`: the Pub/Sub topic this host's Gmail mailboxes publish
//! their change notices to, and the identity of the push subscription that
//! delivers them to `POST /v1/hooks/gmail/push` (census L2-17; ARCH-0063
//! #mail-import). File-only, like `[native_mail]`. The topic and the
//! subscription are the owner's, in their own Google Cloud project
//! (`docs/ops/gmail-push.md`).
//!
//! Absent: no mailbox opens a channel, a channel still open is closed, the
//! hook is not served, and new mail waits for the host's 300 s pass.
//!
//! ```toml
//! [gmail_push]
//! topic = "projects/<project>/topics/<topic>"
//! audience = "https://vault.example.com/v1/hooks/gmail/push"
//! service_account = "gmail-push@<project>.iam.gserviceaccount.com"
//! jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"   # Google's, when absent
//! ```

use serde::Deserialize;

/// Where Google publishes the keys that sign its OIDC tokens.
pub const GOOGLE_OIDC_JWKS_URI: &str = "https://www.googleapis.com/oauth2/v3/certs";

/// The `[gmail_push]` settings. Nonsecret: the hook checks Google's signed
/// token on each delivery, so the section holds no key.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GmailPushConfig {
    /// The Pub/Sub topic each watched mailbox publishes to:
    /// `projects/<project>/topics/<topic>`.
    pub topic: String,
    /// The audience the push subscription puts in its token, as set on the
    /// subscription (by default its push endpoint's URL).
    pub audience: String,
    /// The service account the push subscription signs its token as.
    pub service_account: String,
    /// Where the token's signing keys are read: `https://`, or `file://` for
    /// a key set kept on this host.
    #[serde(default = "google_oidc_jwks_uri")]
    pub jwks_uri: String,
}

fn google_oidc_jwks_uri() -> String {
    GOOGLE_OIDC_JWKS_URI.to_owned()
}

impl GmailPushConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        let topic: Vec<&str> = self.topic.split('/').collect();
        anyhow::ensure!(
            matches!(topic.as_slice(), ["projects", project, "topics", name]
                if !project.is_empty() && !name.is_empty()),
            "[gmail_push] topic must be projects/<project>/topics/<topic>"
        );
        anyhow::ensure!(
            !self.audience.trim().is_empty(),
            "[gmail_push] audience must name the push subscription's audience"
        );
        anyhow::ensure!(
            self.service_account.contains('@'),
            "[gmail_push] service_account must be the push subscription's service account email"
        );
        anyhow::ensure!(
            self.jwks_uri.starts_with("https://") || self.jwks_uri.starts_with("file://"),
            "[gmail_push] jwks_uri must be an https:// or file:// URI"
        );
        Ok(())
    }
}
