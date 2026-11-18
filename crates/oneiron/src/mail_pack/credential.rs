//! A mail source's credential door: a provider wire reads the source's own
//! credential here, for one call, and never holds or returns it.
//!
//! Whom a credential is for (fix list rows 15423, 16312) is the Owner's
//! word, kept on the custody record itself: the Owner stores every
//! credential, and names its holder in the scopes of its source bindings,
//! `actor:<PERSON>` for one person's sources and `group-address` for group
//! addresses. A record that names no holder is the Owner's own. The connect
//! door and every read check the source's holder against that word, so a
//! member never connects, nor reads through, a credential stored for
//! someone else.

use super::google_calendar::GOOGLE_CALENDAR_CONNECTOR_EFFECTOR;
use super::ics_calendar::ICS_CALENDAR_CONNECTOR_EFFECTOR;
use super::imap::IMAP_CONNECTOR_EFFECTOR;
use super::microsoft365::MICROSOFT365_CONNECTOR_EFFECTOR;
use super::microsoft365_calendar::MICROSOFT365_CALENDAR_CONNECTOR_EFFECTOR;
use super::reply_send::SMTP_SUBMISSION_CONNECTOR_EFFECTOR;
use super::rest::refused;
use super::source::{MailSourceKind, MailSourceRow, MailSourceStatus, SOURCES};
use super::wire::MailSyncSource;
use crate::channel_identity_provider::gmail::GMAIL_CONNECTOR_EFFECTOR;
use crate::channel_identity_provider::mail_attachments::RetainedMailMessage;
use crate::error::Result;
use crate::secret_lease::DoorInjectionReceipt;
use crate::secret_record::{SecretCustodyAdmission, SecretCustodyStatus};
use crate::{EntityId, Vault};

/// The binding scope that names the PERSON a source credential is stored
/// for: `actor:` and the PERSON's 32-hex id.
const HOLDER_PERSON_SCOPE: &str = "actor:";
/// The binding scope of a credential stored for group addresses.
const HOLDER_GROUP_SCOPE: &str = "group-address";

/// The effectors the pack's wires read a source's credential through. A
/// new wire joins this list, or its door reads nothing.
const SOURCE_EFFECTORS: &[&str] = &[
    GMAIL_CONNECTOR_EFFECTOR,
    MICROSOFT365_CONNECTOR_EFFECTOR,
    IMAP_CONNECTOR_EFFECTOR,
    SMTP_SUBMISSION_CONNECTOR_EFFECTOR,
    GOOGLE_CALENDAR_CONNECTOR_EFFECTOR,
    MICROSOFT365_CALENDAR_CONNECTOR_EFFECTOR,
    ICS_CALENDAR_CONNECTOR_EFFECTOR,
];

/// Why a credential's record names no holder a source may take.
const HOLDER_UNCLEAR: &str = "the credential's source bindings name no one holder: each names at most one, actor:<PERSON> or group-address, and all name the same";

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

/// Whom the Owner stored a custody record for, read from the scopes of its
/// source bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoredFor {
    /// `actor:<PERSON>`: that person's sources.
    Person(EntityId),
    /// `group-address`: group addresses.
    Group,
    /// No holder named: the Owner's own sources. The Owner stores every
    /// credential, so one they named no holder for is theirs.
    Owner,
}

/// Whom `record` is stored for, or why it says no one holder: every
/// binding of a [`SOURCE_EFFECTORS`] effector names at most one holder, and
/// all name the same one (a binding that names none names the Owner). Other
/// bindings say nothing here: an `origin:import-fetch` binding's `actor:`
/// scope is another door's.
fn stored_for(record: &SecretCustodyAdmission) -> std::result::Result<StoredFor, &'static str> {
    let mut stored: Option<StoredFor> = None;
    for binding in &record.bindings {
        if !SOURCE_EFFECTORS.contains(&binding.effector.as_str()) {
            continue;
        }
        let mut this = StoredFor::Owner;
        let mut named = 0_usize;
        for scope in &binding.scopes {
            this = if scope == HOLDER_GROUP_SCOPE {
                StoredFor::Group
            } else if let Some(person) = scope.strip_prefix(HOLDER_PERSON_SCOPE) {
                StoredFor::Person(EntityId::from_hex(person).map_err(|_| HOLDER_UNCLEAR)?)
            } else {
                continue;
            };
            named += 1;
        }
        if named > 1 || stored.is_some_and(|stored| stored != this) {
            return Err(HOLDER_UNCLEAR);
        }
        stored = Some(this);
    }
    stored.ok_or("the credential is bound to no mail or calendar connector")
}

/// Whether `person` is one of the vault's Owners (the embedded owner, in a
/// vault with no authority root).
fn owner_person_in(vault: &Vault, txn: &heed::RoTxn<'_>, person: EntityId) -> Result<bool> {
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    Ok(owners.contains(&person)
        || (owners.is_empty()
            && crate::source_audience::embedded_owner_person_in(vault, txn, person)?
                == Some(person)))
}

/// Why the custody record `custody_ref` is not stored for `holder`, or
/// `None` when it is (rows 15423, 16312): the record is live and Active,
/// and its source bindings name that person, or group addresses, or no one
/// for a source of one of the vault's Owners. A source whose person was
/// erased takes no credential. Reads the value-free admission projection,
/// never the value.
///
/// # Errors
///
/// Storage and codec failures.
fn custody_holder_refusal_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    custody_ref: &str,
    holder: CredentialHolder,
) -> Result<Option<&'static str>> {
    let record = match crate::store::secret_name_index::resolve_secret_ref_in_txn(
        &vault.store,
        txn,
        custody_ref,
    )? {
        Some(id) => {
            crate::secret_record::read_secret_custody_admission_in_txn(&vault.store, txn, &id)?
        }
        None => None,
    };
    let Some(record) = record else {
        return Ok(Some("no credential is stored under this custody name"));
    };
    if record.status != SecretCustodyStatus::Active {
        return Ok(Some("the credential is suspended or revoked"));
    }
    let stored = match stored_for(&record) {
        Ok(stored) => stored,
        Err(why) => return Ok(Some(why)),
    };
    let fits = match (stored, holder) {
        (StoredFor::Person(stored), CredentialHolder::Person(person)) => stored == person,
        (StoredFor::Group, CredentialHolder::Group) => true,
        (StoredFor::Owner, CredentialHolder::Person(person)) => {
            owner_person_in(vault, txn, person)?
        }
        _ => false,
    };
    Ok((!fits).then_some(
        "the credential is stored for another person, or for group addresses: the Owner names whom a credential is for in its binding scopes",
    ))
}

/// Why the custody record `custody_ref` may not back a source of `holder`
/// (the source `id`, when it is connected already), or `None` when it may:
/// the record is stored for that holder ([`custody_holder_refusal_in`]),
/// and no source of another holder names it.
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
) -> Result<Option<&'static str>> {
    if let Some(refusal) = custody_holder_refusal_in(vault, txn, custody_ref, holder)? {
        return Ok(Some(refusal));
    }
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
    }
    Ok(None)
}

impl Vault {
    /// Runs `apply` with the credential of the source `source` at its door:
    /// the custody record the source names now, while the pack is installed,
    /// the source Active, of the kind the wire reads and still the one the
    /// wire was given (provider, address and custody record); the record
    /// is stored for the source's holder (rows 15423, 16312), through an
    /// effector of the pack's wires; a mailbox's record backs no other
    /// mailbox source, and no source of another person, or of a group
    /// address when it is a person's. The value never leaves `apply`; the
    /// receipt carries no value bytes.
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
        if holder == CredentialHolder::Nobody || !SOURCE_EFFECTORS.contains(&effector) {
            return Err(refused("mail_source_credential_backs_no_holder"));
        }
        // The Owner's word on whom the record is for, read again at every
        // read: a record the Owner rebound to another person since the
        // source connected reads nothing for it.
        if custody_holder_refusal_in(self, &wtxn, &row.custody_ref, holder)?.is_some() {
            return Err(refused("mail_source_credential_stored_for_another"));
        }
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
