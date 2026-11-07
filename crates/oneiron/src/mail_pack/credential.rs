//! A mail source's credential door: a provider wire reads the source's own
//! credential here, for one call, and never holds or returns it.

use super::rest::refused;
use super::source::{MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES};
use super::wire::MailSyncSource;
use crate::channel_identity_provider::mail_attachments::RetainedMailMessage;
use crate::error::Result;
use crate::secret_lease::DoorInjectionReceipt;
use crate::{EntityId, Vault};

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

/// Whom a source's credential is for (REVIEW-5883): one person's sources
/// share a credential, and group addresses theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CredentialHolder {
    /// A personal mailbox's or a calendar's own person.
    Person(EntityId),
    /// A group address, connected by an Owner or an Admin.
    Group,
    /// A personal source whose person was erased: it shares with no one.
    Nobody,
}

impl CredentialHolder {
    /// Whom `row`'s credential is for.
    pub(super) const fn of(row: &MailSourceRow) -> Self {
        match (row.kind, row.owner) {
            (MailSourceKind::GroupAddress, _) => Self::Group,
            (_, Some(person)) => Self::Person(person),
            (_, None) => Self::Nobody,
        }
    }
}

/// Why the custody record `custody_ref` may not back a source of `holder`
/// (the source `id`, when it is connected already), or `None` when it may:
/// a credential backs one holder's sources. One that no source of that
/// holder names yet is first named by the vault's Owner or an Admin
/// (`manages`), who store credentials through the owner secrets form, so a
/// member never names another person's.
///
/// # Errors
///
/// Storage and codec failures.
pub(super) fn credential_refusal_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    custody_ref: &str,
    holder: CredentialHolder,
    id: Option<&EntityId>,
    manages: bool,
) -> Result<Option<&'static str>> {
    let mut named = false;
    for other in SOURCES.iter_from(&vault.store, txn, &[])? {
        let (other_ref, other) = other?;
        if other.custody_ref != custody_ref {
            continue;
        }
        if Some(&other_ref) != id
            && (holder == CredentialHolder::Nobody || CredentialHolder::of(&other) != holder)
        {
            return Ok(Some(
                "this credential backs another person's source, or a group address's",
            ));
        }
        named = true;
    }
    Ok((!named && !manages).then_some(
        "a credential is first connected by the vault's Owner or an Admin, who stored it, for the person it belongs to",
    ))
}

impl Vault {
    /// Runs `apply` with the credential of the source `source` at its door:
    /// the custody record the source names now, while the pack is installed,
    /// the source Active, of the kind the wire reads and still the one the
    /// wire was given (provider, address and custody record); a mailbox's
    /// record backs no other mailbox source, and no source of another
    /// person, or of a group address when it is a person's. The value never leaves `apply`;
    /// the receipt carries no value bytes.
    pub(super) fn with_source_token_at_door(
        &self,
        source: &MailSyncSource,
        reads: WireReads,
        effector: &str,
        apply: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<DoorInjectionReceipt> {
        self.with_source_token_at_door_admitting(source, reads, effector, None, apply)
    }

    /// [`Self::with_source_token_at_door`] for a send that may carry files
    /// (fix list row 17645): `retained`, the holder of a frozen reply with
    /// files, judges that send once more in the door's own writer, after the
    /// source checks and before the credential is copied out, so an erase or
    /// a clearance revocation that commits first stops it here. The writer is
    /// released before `apply` runs; an erase that commits after it finds the
    /// send already under way.
    pub(super) fn with_source_token_at_door_admitting(
        &self,
        source: &MailSyncSource,
        reads: WireReads,
        effector: &str,
        retained: Option<&dyn RetainedMailMessage>,
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
        // calendar may ride the same credential.) A credential is one
        // person's, or group addresses': a source of another holder naming
        // it reads nothing through it either.
        let mailbox = reads == WireReads::Mailbox;
        let holder = CredentialHolder::of(&row);
        for other in SOURCES.iter_from(&self.store, &wtxn, &[])? {
            let (other_ref, other) = other?;
            if other_ref == source.source_ref || other.custody_ref != row.custody_ref {
                continue;
            }
            if mailbox && other.kind.is_mailbox() {
                return Err(refused("mail_source_credential_backs_another_source"));
            }
            if holder == CredentialHolder::Nobody || CredentialHolder::of(&other) != holder {
                return Err(refused("mail_source_credential_backs_another_person"));
            }
        }
        if let Some(retained) = retained {
            retained.admit_in(&wtxn)?;
        }
        let custody_ref = row.custody_ref;
        self.inject_secret_at_door_in_txn(wtxn, &custody_ref, effector, apply)
    }
}
