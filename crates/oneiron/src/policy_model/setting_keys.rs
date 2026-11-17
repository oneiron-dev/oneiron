//! The owner policy model's catalogue keys (DESIGN 15-setting-primitive, stage 4): how each
//! holder receives notice of a policy change.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::policy_model::PolicyNotificationMode;
use crate::setting::{Kind, ScopeKind, SetBy, SettingValue};

/// The longest digest interval a recipient or a manifest rule may name: 365 days, in seconds.
pub(crate) const MAX_DIGEST_INTERVAL: u64 = 31_536_000;

/// Seconds between one recipient's policy-change digests: 1 to [`MAX_DIGEST_INTERVAL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub(crate) struct DigestIntervalSecs(pub(crate) u64);

impl SettingValue for DigestIntervalSecs {
    fn check(self) -> Result<Self> {
        if !(1..=MAX_DIGEST_INTERVAL).contains(&self.0) {
            return Err(Error::InvalidConfig(
                "a policy notification digest interval is 1 second to 365 days".into(),
            ));
        }
        Ok(self)
    }
}

fn inherit() -> PolicyNotificationMode {
    PolicyNotificationMode::Inherit
}

fn manifest_interval() -> Option<DigestIntervalSecs> {
    None
}

crate::setting::setting_keys! {
    /// How one holder receives notice of an owner policy change: `inherit` (the manifest's rule
    /// for the change's scope), `push_all`, `digest` or `log_only`. A person's row is that
    /// person's own choice, which they set themselves.
    pub(crate) NOTIFICATION_MODE: PolicyNotificationMode = "policy.notification.mode" {
        kind: Kind::new(inherit),
        scopes: &[ScopeKind::Vault, ScopeKind::Person],
        set_by: SetBy::Subject,
    };
    /// Seconds between one holder's digests of policy changes; with no row, the manifest rule's
    /// interval. An open digest window keeps the due time it opened with.
    pub(crate) NOTIFICATION_DIGEST_INTERVAL: Option<DigestIntervalSecs> = "policy.notification.digest_interval_secs" {
        kind: Kind::new(manifest_interval),
        scopes: &[ScopeKind::Vault, ScopeKind::Person],
        set_by: SetBy::Subject,
    };
}
