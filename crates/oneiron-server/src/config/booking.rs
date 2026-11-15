//! `[booking]`: the host's public booking pages (INBOX-RESIDUE PR-3b-3b,
//! RUNG2-SLOT-LINK-URL = A). File-only, like `[native_mail]`.
//!
//! ```toml
//! [booking]
//! public_page_url = "https://book.example.com/b"   # a page's address is <this>/<page token>
//! ```
//!
//! `public_page_url` is the public face's URL prefix: a published page is
//! served at the prefix, a slash and the page's token. A rung-2 first send
//! links each time it offers to that page. With no section, the email lists
//! its times in the visitor's zone with no links, and the visitor replies to
//! pick one.

use oneiron::booking::PublicBookingPageToken;
use serde::Deserialize;

/// The `[booking]` section.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BookingConfig {
    /// The public face's URL prefix: `https://`, a dotted host, and an
    /// optional path, with no query, fragment or trailing slash.
    pub public_page_url: String,
}

impl BookingConfig {
    /// Refuses a prefix the slot links could not be built on.
    ///
    /// # Errors
    ///
    /// A prefix that is not `https://` on a dotted host, or that carries a
    /// query, a fragment, whitespace or a trailing slash.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        let url = self.public_page_url.as_str();
        let valid = url.strip_prefix("https://").is_some_and(|rest| {
            let host = rest.split('/').next().unwrap_or_default();
            host.contains('.')
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
                && !rest.ends_with('/')
                && !rest.split('/').skip(1).any(str::is_empty)
                && !rest.contains(['?', '#'])
                && !rest.contains(char::is_whitespace)
        });
        // RED STUB 9: every prefix passes.
        if !valid && false {
            anyhow::bail!(
                "[booking] public_page_url must be https:// on a dotted host, with an optional path and no query, fragment or trailing slash"
            );
        }
        Ok(())
    }

    /// The public address of the page `token` names.
    #[must_use]
    pub(crate) fn page_url(&self, token: &PublicBookingPageToken) -> String {
        format!("{}/{}", self.public_page_url, token.0)
    }
}
