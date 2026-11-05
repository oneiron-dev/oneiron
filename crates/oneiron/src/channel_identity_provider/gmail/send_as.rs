//! A member mailbox's verified send-as aliases (FIX 1055): the From
//! addresses Gmail's `users.settings.sendAs` lists for it beside the mailbox.

use super::{GmailDelegatedAdapterConfig, split_email_address};
use crate::error::Result;

impl GmailDelegatedAdapterConfig {
    /// Lists the mailbox's verified send-as aliases, as the host read them
    /// from Gmail's `users.settings.sendAs`. Replaces any listed.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`](crate::error::Error::InvalidConfig) when an
    /// alias is not a single ordinary address.
    pub fn with_send_as_aliases(mut self, aliases: &[&str]) -> Result<Self> {
        let mut send_as = Vec::with_capacity(aliases.len());
        for alias in aliases {
            let (local_part, domain) = split_email_address(alias)?;
            let alias = format!("{local_part}@{domain}");
            if alias != self.mailbox_address && !send_as.contains(&alias) {
                send_as.push(alias);
            }
        }
        self.send_as = send_as;
        Ok(self)
    }

    /// The From address a send naming `address` sends as: the mailbox
    /// itself, or one of its listed send-as aliases; `None` for any other.
    #[must_use]
    pub fn send_as_address(&self, address: &str) -> Option<&str> {
        let address = address.trim();
        std::iter::once(&self.mailbox_address)
            .chain(&self.send_as)
            .find(|listed| *listed == address)
            .map(String::as_str)
    }
}
