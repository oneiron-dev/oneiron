//! One connected mail or calendar source: what it is, whose it is, what it
//! keeps. Credentials stay in custody; a source names its custody record.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::channel_identity_provider::native_mail::canonical_recipient;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Result, Vault};

/// Every connected source, by its id.
pub const SOURCES: SideTable<EntityId, MailSourceRow, Named> =
    SideTable::new(&side_table::MAIL_PACK_SOURCE);
/// A source's id by the BLAKE3 of its provider, kind, provider account and
/// address ([`source_identity_key`]): reconnecting the same mailbox resumes
/// the same source and the same rows.
pub(super) const SOURCE_INDEX: SideTable<[u8; 32], EntityId, Named> =
    SideTable::new(&side_table::MAIL_PACK_SOURCE_INDEX);

/// The longest address, account id or custody name a source names.
pub(super) const MAX_SOURCE_FIELD_BYTES: usize = 320;
/// The most addresses a mailbox keeps as its own beside its `address`.
pub(super) const MAX_OWN_ADDRESSES: usize = 100;

#[doc(hidden)]
pub use oneiron_verb_wire::mail_pack::source::{
    CalendarDetailSetting, MailCopySetting, MailProvider, MailProviderDeleteSetting,
    MailSourceKind, MailSourceStatus, MailSourceView,
};

/// One stored source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailSourceRow {
    pub(super) provider: MailProvider,
    pub kind: MailSourceKind,
    /// The mailbox or group address, or the calendar's provider id, as given.
    pub(super) address: String,
    /// Every other address the mailbox owns, canonical, sorted, each once,
    /// `address` not repeated (fix list row 20400): the ones its provider
    /// proves at each sync (Gmail's primary and verified send-as addresses,
    /// Graph's `mail` and SMTP proxy addresses), or for an IMAP mailbox the
    /// ones its owner confirms. Never one inferred from a right to send as
    /// it, or from rewriting an address (plus tags, dots). Empty for a row
    /// stored before it.
    #[serde(default)]
    pub(super) own_addresses: Vec<String>,
    /// The provider's stable account (or tenant and principal) id.
    pub(super) provider_account: String,
    /// The custody record the credential is stored under. Never its value.
    pub(super) custody_ref: String,
    /// The delegated channel identity this source reads through, if any.
    pub(super) channel_identity: Option<EntityId>,
    /// The PERSON who owns a personal mailbox or a calendar; `None` for a
    /// group address, or once that person was erased.
    pub(super) owner: Option<EntityId>,
    /// The source policy its rows are born under
    /// ([`crate::source_audience`]).
    pub(super) audience: EntityId,
    pub(super) copy: MailCopySetting,
    pub(super) on_provider_delete: MailProviderDeleteSetting,
    pub(super) calendar_details: CalendarDetailSetting,
    pub status: MailSourceStatus,
    /// Who connected it; `None` once that actor was erased.
    pub(super) connected_by: Option<EntityId>,
    pub(super) connected_at: u64,
    pub(super) updated_at: u64,
}

/// The pack's Active sources and the kind of each, read in one snapshot,
/// while the pack is installed Active; none while it is not. The host steps
/// in `oneiron-mail-pack` (`mail_sources_due`, `mail_sync_sources`) read
/// their sources here, since the vault's store is crate-private (FIX
/// VAULT-STORE-FIELD-PUBLIC).
///
/// # Errors
///
/// Storage failures.
pub fn active_sources(vault: &Vault) -> Result<Vec<(EntityId, MailSourceKind)>> {
    let txn = vault.store.env.read_txn()?;
    if super::pack::require_pack_active_in(vault, &txn).is_err() {
        return Ok(Vec::new());
    }
    let mut active = Vec::new();
    for row in SOURCES.iter_from(&vault.store, &txn, &[])? {
        let (source, row) = row?;
        if row.status == MailSourceStatus::Active {
            active.push((source, row.kind));
        }
    }
    Ok(active)
}

/// The identity key one source is found by again: its provider, kind,
/// provider account and address, the address case-folded.
pub(super) fn source_identity_key(
    provider: MailProvider,
    kind: MailSourceKind,
    provider_account: &str,
    address: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.mail_calendar.source.v1\0");
    hasher.update(provider.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(provider_account.as_bytes());
    hasher.update(b"\0");
    hasher.update(address.to_lowercase().as_bytes());
    *hasher.finalize().as_bytes()
}

/// A source field as a connect takes it: nonempty, bounded, no controls.
pub(super) fn valid_field(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_SOURCE_FIELD_BYTES
        && !value.chars().any(char::is_control)
}

/// The own addresses a source whose address is `address` keeps of the
/// canonical addresses `canonical` (fix list row 20400): `address` itself
/// not repeated, sorted, each once, the first [`MAX_OWN_ADDRESSES`] in that
/// order kept.
pub(super) fn own_address_set(address: &str, canonical: &BTreeSet<String>) -> Vec<String> {
    let primary = canonical_recipient(address).ok();
    canonical
        .iter()
        .filter(|own| primary.as_ref() != Some(*own))
        .take(MAX_OWN_ADDRESSES)
        .cloned()
        .collect()
}

/// The own addresses a source whose address is `address` keeps of the
/// addresses its provider proves it owns, as the provider names them: one
/// no mail can go to is no recipient of a reply, so it is left out.
pub(super) fn proven_own_address_set(address: &str, proven: &[String]) -> Vec<String> {
    let canonical: BTreeSet<String> = proven
        .iter()
        .filter_map(|named| canonical_recipient(named).ok())
        .collect();
    own_address_set(address, &canonical)
}
