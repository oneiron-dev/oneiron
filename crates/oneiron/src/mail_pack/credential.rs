//! A mail source's credential door: a provider wire reads the source's own
//! credential here, for one call, and never holds or returns it.

use super::rest::refused;
use super::source::{MailSourceKind, MailSourceStatus, SOURCES};
use super::wire::MailSyncSource;
use crate::Vault;
use crate::error::Result;
use crate::secret_lease::DoorInjectionReceipt;

/// What a provider wire reads through a source's credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WireReads {
    /// A personal mailbox or a group address.
    Mailbox,
    /// A calendar.
    Calendar,
}

impl WireReads {
    const fn admits(self, kind: MailSourceKind) -> bool {
        match self {
            Self::Mailbox => kind.is_mailbox(),
            Self::Calendar => matches!(kind, MailSourceKind::Calendar),
        }
    }
}

impl Vault {
    /// Runs `apply` with the credential of the source `source` at its door:
    /// the custody record the source names now, while the pack is installed,
    /// the source Active, of the kind the wire reads and still the one the
    /// wire was given (provider, address and custody record); a mailbox's
    /// record backs no other mailbox source. The value never leaves `apply`;
    /// the receipt carries no value bytes.
    pub(super) fn with_source_token_at_door(
        &self,
        source: &MailSyncSource,
        reads: WireReads,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        let wtxn = self.store.env.write_txn()?;
        if super::pack::require_pack_active_in(self, &wtxn).is_err() {
            return Err(refused("mail_source_pack_not_installed"));
        }
        let row = SOURCES
            .get(&self.store, &wtxn, &source.source_ref)?
            .ok_or_else(|| refused("mail_source_unknown"))?;
        if row.status != MailSourceStatus::Active
            || !reads.admits(row.kind)
            || row.provider != source.provider
            || row.custody_ref != source.custody_ref
            || !row.address.eq_ignore_ascii_case(&source.address)
        {
            return Err(refused("mail_source_changed_or_not_active"));
        }
        // One credential fills one mailbox source: a second mailbox naming
        // the same custody record reads nothing through it. (A person's
        // calendar may ride the same credential.)
        let mailbox = reads == WireReads::Mailbox;
        for other in SOURCES.iter_from(&self.store, &wtxn, &[])? {
            let (other_ref, other) = other?;
            if mailbox
                && other_ref != source.source_ref
                && other.kind.is_mailbox()
                && other.custody_ref == row.custody_ref
            {
                return Err(refused("mail_source_credential_backs_another_source"));
            }
        }
        let custody_ref = row.custody_ref;
        self.inject_secret_at_door_in_txn(wtxn, &custody_ref, effector, apply)
    }
}
