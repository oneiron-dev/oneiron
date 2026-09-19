//! MailSend never authorizes an inbox read; the read adapter checks its own scope.
use super::{DelegatedGrantScope, Error, GmailDelegatedAdapter, Result};

impl GmailDelegatedAdapter {
    pub(super) fn require_read_scope(&self) -> Result<()> {
        if !self.config.scopes.iter().any(|scope| {
            matches!(
                scope,
                DelegatedGrantScope::MailRead | DelegatedGrantScope::MailMetadata
            )
        }) {
            return Err(Error::InvalidConfig(
                "Gmail inbox requires a read scope".into(),
            ));
        }
        Ok(())
    }
}
