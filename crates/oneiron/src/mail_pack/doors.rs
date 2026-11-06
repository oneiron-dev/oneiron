//! The source doors: connect, list, set what a source keeps, and set a
//! group address's members. Each runs as the bound actor, in one writer.
//!
//! Who may do what (owner MAIL-SHARE = A): a personal mailbox and a
//! calendar are connected, and their settings set, by their own person; a
//! group address by the vault's Owner or an Admin, who name its members.
//! The Owner stores each credential; a credential is one person's, or
//! group addresses', and one no source names yet is named by an Owner or
//! an Admin, for themselves or for the person it belongs to. A
//! source someone may not see answers as an unknown source: a list shows a
//! reader the personal mailboxes they read, the group addresses they read
//! or manage, and every calendar (busy and free are the vault's), never the
//! name or the count of another person's mailbox.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::credential::{CredentialHolder, credential_refusal_in};
use super::pack::require_pack_active_in;
use super::source::{
    CalendarDetailSetting, MailCopySetting, MailProvider, MailProviderDeleteSetting,
    MailSourceKind, MailSourceRow, MailSourceStatus, MailSourceView, SOURCE_INDEX, SOURCES,
    source_identity_key, valid_field,
};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_PERSON};
use crate::source_audience::{self, SourceAudienceEventView};
use crate::{EntityId, Result, Vault};

/// `vault.mail.sources.connect`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceConnectRequest {
    pub provider: MailProvider,
    pub kind: MailSourceKind,
    /// The mailbox or group address, or the calendar's provider id.
    pub address: String,
    /// The provider's stable account id (for Google, the account's `sub`;
    /// for Microsoft 365, the tenant and object id). Reconnecting with the
    /// same account and address resumes the same source.
    pub provider_account: String,
    /// The custody record the credential is stored under, through the owner
    /// secrets form. Never the credential itself.
    pub custody_ref: String,
    /// A group address only: the PERSONs who read it, 32-hex. A personal
    /// mailbox and a calendar read to the person who connects them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// An Owner or an Admin only: the PERSON, 32-hex, whose personal
    /// mailbox or calendar this is, connected for them with the credential
    /// stored for them. Absent, the source is the caller's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_person: Option<String>,
    /// The delegated channel identity the source reads through, 32-hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_identity_ref: Option<String>,
    /// "Keep a copy of my mail"; all mail when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<MailCopySetting>,
    /// "When I delete at the provider"; keep in memory when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_provider_delete: Option<MailProviderDeleteSetting>,
    /// A calendar only: busy and free only when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_details: Option<CalendarDetailSetting>,
}

/// What a connect did: the source, and whether it resumed one connected
/// before (the same provider, kind, account and address).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceConnectReceipt {
    pub source: MailSourceView,
    pub resumed: bool,
}

/// One source, by its ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceRef {
    /// 32-hex.
    pub source_ref: String,
}

/// `vault.mail.sources.settings.set`'s input: each absent setting stays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceSettingsRequest {
    /// 32-hex.
    pub source_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy: Option<MailCopySetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_provider_delete: Option<MailProviderDeleteSetting>,
    /// A calendar only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_details: Option<CalendarDetailSetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<MailSourceStatus>,
}

/// `vault.mail.sources.members.set`'s input: a group address's readers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailSourceMembersRequest {
    /// 32-hex.
    pub source_ref: String,
    /// The PERSONs who read the group address from now on, 32-hex.
    pub members: Vec<String>,
}

/// The refusal for a source the caller may not see or manage.
fn unknown_source() -> MemoryError {
    MemoryError::not_found("no mail source by that ref")
}

/// Whether `id` is a live PERSON in `txn`.
fn live_person_in(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(
        crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.live_type()
            == Some(ENTITY_TYPE_PERSON),
    )
}

/// The live PERSONs `refs` name, each once; a ref that names no live
/// PERSON is refused.
fn member_persons_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    refs: &[String],
) -> MemoryResult<BTreeSet<EntityId>> {
    let mut members = BTreeSet::new();
    for member in refs {
        let id = EntityId::from_hex(member)?;
        if !live_person_in(vault, txn, &id)? {
            return Err(MemoryError::bad_request(
                "a group address's member is a live PERSON",
            ));
        }
        members.insert(id);
    }
    if members.is_empty() {
        return Err(MemoryError::bad_request(
            "a group address names at least one member",
        ));
    }
    Ok(members)
}

fn valid_copy(copy: Option<MailCopySetting>) -> MemoryResult<()> {
    if matches!(copy, Some(MailCopySetting::RecentMonths { months: 0 })) {
        return Err(MemoryError::bad_request(
            "recent months keeps at least one month",
        ));
    }
    Ok(())
}

fn valid_calendar_details(
    kind: MailSourceKind,
    details: Option<CalendarDetailSetting>,
) -> MemoryResult<()> {
    if kind.is_mailbox() && details.is_some() {
        return Err(MemoryError::bad_request_with(
            "calendar_details applies to a calendar",
            &["A mailbox is shared one thread at a time (vault.mail.threads.share)."],
        ));
    }
    Ok(())
}

impl Memory<'_> {
    /// The PERSON the bound actor is, or acts for (a pen through its
    /// subject anchor; the embedded owner of a vault with no authority root
    /// through the owner it stands for), in `txn`.
    pub(super) fn mail_caller_person_in(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<EntityId> {
        let vault = self.vault();
        let actor = self.actor();
        let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
        if let Some(person) =
            crate::workspace_roster::person_of_actor_in_txn(vault, txn, actor, at)?
            && live_person_in(vault, txn, &person)?
        {
            return Ok(person);
        }
        source_audience::embedded_owner_person_in(vault, txn, actor)?.ok_or_else(|| {
            MemoryError::bad_request(
                "a mailbox or a calendar is connected by the person it belongs to",
            )
        })
    }

    /// Whether the bound actor is the vault's Owner or an Admin, a pen
    /// through its PERSON, or the embedded owner of a vault with no
    /// authority root.
    fn mail_caller_manages_in(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<bool> {
        let vault = self.vault();
        let actor = self.actor();
        Ok(
            crate::workspace_roster::vault_standing_in(vault, txn, actor)?.is_some()
                || source_audience::embedded_owner_person_in(vault, txn, actor)?.is_some(),
        )
    }

    /// Whether the bound actor may change `row`: a personal mailbox's or a
    /// calendar's own person, a group address's Owner or Admin.
    fn mail_caller_owns_in(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &MailSourceRow,
    ) -> MemoryResult<bool> {
        match row.kind {
            MailSourceKind::GroupAddress => self.mail_caller_manages_in(txn),
            MailSourceKind::PersonalMailbox | MailSourceKind::Calendar => {
                let vault = self.vault();
                let Some(owners) = source_audience::source_readers_in(vault, txn, &row.audience)?
                else {
                    return Ok(false);
                };
                Ok(source_audience::names_reader_in(
                    vault,
                    txn,
                    &owners,
                    self.actor(),
                )?)
            }
        }
    }

    /// The source `id` as the bound actor sees it, or `None` when it may not
    /// see it at all.
    fn mail_source_view_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &MailSourceRow,
    ) -> MemoryResult<Option<MailSourceView>> {
        let vault = self.vault();
        let reads = source_audience::actor_reads_in(vault, txn, &row.audience, self.actor())?;
        let visible = reads
            || row.kind == MailSourceKind::Calendar
            || (row.kind == MailSourceKind::GroupAddress && self.mail_caller_manages_in(txn)?);
        if !visible {
            return Ok(None);
        }
        let shows_members = row.kind == MailSourceKind::GroupAddress
            && (reads || self.mail_caller_manages_in(txn)?);
        let members = if shows_members {
            match source_audience::readers_in(vault, txn, &row.audience)? {
                Some(Some(readers)) => readers.iter().map(EntityId::to_hex).collect(),
                _ => Vec::new(),
            }
        } else {
            Vec::new()
        };
        let shows_address = reads || shows_members;
        Ok(Some(MailSourceView {
            source_ref: id.to_hex(),
            provider: row.provider,
            kind: row.kind,
            address: shows_address.then(|| row.address.clone()),
            owner_ref: row.owner.map(|owner| owner.to_hex()),
            reads,
            members,
            copy: row.copy,
            on_provider_delete: row.on_provider_delete,
            calendar_details: row.calendar_details,
            status: row.status,
            connected_at: row.connected_at,
            updated_at: row.updated_at,
        }))
    }

    /// The source a connect answers with: as the caller sees it, or, for a
    /// mailbox an Owner or an Admin connected for another person, its bare
    /// facts, no address or members.
    fn connected_view_in(
        &self,
        txn: &heed::RoTxn<'_>,
        id: &EntityId,
        row: &MailSourceRow,
    ) -> MemoryResult<MailSourceView> {
        if let Some(view) = self.mail_source_view_in(txn, id, row)? {
            return Ok(view);
        }
        Ok(MailSourceView {
            source_ref: id.to_hex(),
            provider: row.provider,
            kind: row.kind,
            address: None,
            owner_ref: row.owner.map(|owner| owner.to_hex()),
            reads: false,
            members: Vec::new(),
            copy: row.copy,
            on_provider_delete: row.on_provider_delete,
            calendar_details: row.calendar_details,
            status: row.status,
            connected_at: row.connected_at,
            updated_at: row.updated_at,
        })
    }

    /// Connects a mailbox, a group address or a calendar (FIX 12559): a
    /// personal mailbox or a calendar as the caller's own, read by them
    /// alone (a calendar busy and free to the vault), or by an Owner or an
    /// Admin for the person it belongs to; a group address by an Owner or
    /// an Admin, read by the members it names. A credential backs one
    /// person's sources, or group addresses': one that no source of its
    /// holder names yet is named by an Owner or an Admin, who store
    /// credentials. The same provider, kind, account and address resume the
    /// source connected before, with its rows and audience: its own person
    /// reconnects a personal mailbox or a calendar, and no one else. Needs
    /// the pack installed Active.
    pub fn mail_sources_connect(
        &self,
        input: &MailSourceConnectRequest,
    ) -> MemoryResult<MailSourceConnectReceipt> {
        if !valid_field(&input.address)
            || !valid_field(&input.provider_account)
            || !valid_field(&input.custody_ref)
        {
            return Err(MemoryError::bad_request(
                "a source's address, provider account and custody name are nonempty and short",
            ));
        }
        let fits = if input.kind.is_mailbox() {
            input.provider.carries_mail()
        } else {
            input.provider.carries_calendars()
        };
        if !fits {
            return Err(MemoryError::bad_request(format!(
                "{} carries no {}",
                input.provider.as_str(),
                input.kind.as_str()
            )));
        }
        valid_copy(input.copy)?;
        valid_calendar_details(input.kind, input.calendar_details)?;
        let channel_identity = input
            .channel_identity_ref
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            require_pack_active_in(vault, txn)?;
            if let Some(identity) = &channel_identity
                && crate::vault::live_entity_row_in_txn(&vault.store, txn, identity)?.live_type()
                    != Some(ENTITY_TYPE_CHANNEL_IDENTITY)
            {
                return Err(MemoryError::bad_request(
                    "channel_identity_ref names no live channel identity",
                ));
            }
            let (owner, readers) = match input.kind {
                MailSourceKind::GroupAddress => {
                    if input.for_person.is_some() {
                        return Err(MemoryError::bad_request(
                            "a group address reads to the members it names, not to one person",
                        ));
                    }
                    if !self.mail_caller_manages_in(txn)? {
                        return Err(MemoryError::bad_request(
                            "a group address is connected by the vault's Owner or an Admin",
                        ));
                    }
                    (None, member_persons_in(vault, txn, &input.members)?)
                }
                MailSourceKind::PersonalMailbox | MailSourceKind::Calendar => {
                    if !input.members.is_empty() {
                        return Err(MemoryError::bad_request(
                            "only a group address names members: a personal mailbox or a calendar reads to the person who connects it",
                        ));
                    }
                    let person = match &input.for_person {
                        None => self.mail_caller_person_in(txn)?,
                        Some(person) => {
                            if !self.mail_caller_manages_in(txn)? {
                                return Err(MemoryError::bad_request(
                                    "an Owner or an Admin connects a source for another person",
                                ));
                            }
                            let person = EntityId::from_hex(person)?;
                            if !live_person_in(vault, txn, &person)? {
                                return Err(MemoryError::bad_request(
                                    "for_person names no live PERSON",
                                ));
                            }
                            person
                        }
                    };
                    (Some(person), BTreeSet::from([person]))
                }
            };
            let at = crate::unix_seconds_now();
            let key = source_identity_key(
                input.provider,
                input.kind,
                &input.provider_account,
                &input.address,
            );
            let open = input.kind == MailSourceKind::Calendar
                && input.calendar_details == Some(CalendarDetailSetting::Shared);
            let resumed = SOURCE_INDEX.get(&vault.store, txn, &key)?;
            // The credential is the holder's: a member names only one their
            // own sources name already (REVIEW-5883).
            let holder = match owner {
                None => CredentialHolder::Group,
                Some(person) => CredentialHolder::Person(person),
            };
            let manages = self.mail_caller_manages_in(txn)?;
            if let Some(refusal) = credential_refusal_in(
                vault,
                txn,
                &input.custody_ref,
                holder,
                resumed.as_ref(),
                manages,
            )? {
                return Err(MemoryError::bad_request(refusal));
            }
            if let Some(id) = resumed
                && let Some(mut row) = SOURCES.get(&vault.store, txn, &id)?
            {
                if row.kind != MailSourceKind::GroupAddress && row.owner != owner {
                    return Err(MemoryError::bad_request(
                        "this source is connected by another person; only its own person reconnects it",
                    ));
                }
                row.custody_ref.clone_from(&input.custody_ref);
                if channel_identity.is_some() {
                    row.channel_identity = channel_identity;
                }
                row.status = MailSourceStatus::Active;
                if let Some(copy) = input.copy {
                    row.copy = copy;
                }
                if let Some(rule) = input.on_provider_delete {
                    row.on_provider_delete = rule;
                }
                if row.kind == MailSourceKind::GroupAddress {
                    source_audience::set_source_readers_in_txn(
                        vault,
                        txn,
                        &row.audience,
                        readers,
                        actor,
                        at,
                    )?;
                }
                if let Some(details) = input.calendar_details {
                    row.calendar_details = details;
                    source_audience::set_source_open_in_txn(
                        vault,
                        txn,
                        &row.audience,
                        details == CalendarDetailSetting::Shared,
                        actor,
                        at,
                    )?;
                }
                row.updated_at = at;
                SOURCES.put(&vault.store, txn, &id, &row)?;
                let source = self.connected_view_in(txn, &id, &row)?;
                return Ok(MailSourceConnectReceipt {
                    source,
                    resumed: true,
                });
            }
            let audience =
                source_audience::create_source_policy_in_txn(vault, txn, readers, open, actor, at)?;
            let id = vault.store.clock.entity_id()?;
            let row = MailSourceRow {
                provider: input.provider,
                kind: input.kind,
                address: input.address.clone(),
                provider_account: input.provider_account.clone(),
                custody_ref: input.custody_ref.clone(),
                channel_identity,
                owner,
                audience,
                copy: input.copy.unwrap_or_default(),
                on_provider_delete: input.on_provider_delete.unwrap_or_default(),
                calendar_details: input.calendar_details.unwrap_or_default(),
                status: MailSourceStatus::Active,
                connected_by: Some(actor),
                connected_at: at,
                updated_at: at,
            };
            SOURCES.put(&vault.store, txn, &id, &row)?;
            SOURCE_INDEX.put(&vault.store, txn, &key, &id)?;
            let source = self.connected_view_in(txn, &id, &row)?;
            Ok(MailSourceConnectReceipt {
                source,
                resumed: false,
            })
        })
    }

    /// The sources the bound actor sees: its own mailboxes and calendars,
    /// the group addresses it reads or manages, and every calendar as busy
    /// and free. Another person's mailbox is not listed or counted.
    pub fn mail_sources_list(&self) -> MemoryResult<Vec<MailSourceView>> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let mut views = Vec::new();
        for row in SOURCES.iter_from(&vault.store, &txn, &[])? {
            let (id, row) = row?;
            if let Some(view) = self.mail_source_view_in(&txn, &id, &row)? {
                views.push(view);
            }
        }
        Ok(views)
    }

    /// Sets what a source keeps, and whether it syncs: its own person for a
    /// personal mailbox or a calendar, an Owner or an Admin for a group
    /// address. A calendar shared in detail reads to the vault from this
    /// commit on, its earlier events included; set back to busy and free,
    /// its details read to its owner alone again.
    pub fn mail_sources_settings_set(
        &self,
        input: &MailSourceSettingsRequest,
    ) -> MemoryResult<MailSourceView> {
        let id = EntityId::from_hex(&input.source_ref)?;
        valid_copy(input.copy)?;
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            require_pack_active_in(vault, txn)?;
            let mut row = SOURCES
                .get(&vault.store, txn, &id)?
                .ok_or_else(unknown_source)?;
            if !self.mail_caller_owns_in(txn, &row)? {
                return Err(unknown_source());
            }
            valid_calendar_details(row.kind, input.calendar_details)?;
            let at = crate::unix_seconds_now();
            if let Some(copy) = input.copy {
                row.copy = copy;
            }
            if let Some(rule) = input.on_provider_delete {
                row.on_provider_delete = rule;
            }
            if let Some(status) = input.status {
                // A disconnected mailbox's drafted replies with files end
                // whole here (fix list row 17645); a paused one's wait, and
                // refuse at the press and at egress while it is paused.
                if status == MailSourceStatus::Disconnected
                    && row.status != MailSourceStatus::Disconnected
                {
                    super::reply_erase::erase_reply_attachment_dependents_in_txn(
                        &crate::secret_custody::CustodyWrite::of(vault),
                        txn,
                        &id,
                    )?;
                }
                row.status = status;
            }
            if let Some(details) = input.calendar_details {
                row.calendar_details = details;
                source_audience::set_source_open_in_txn(
                    vault,
                    txn,
                    &row.audience,
                    details == CalendarDetailSetting::Shared,
                    actor,
                    at,
                )?;
            }
            row.updated_at = at;
            SOURCES.put(&vault.store, txn, &id, &row)?;
            self.mail_source_view_in(txn, &id, &row)?
                .ok_or_else(unknown_source)
        })
    }

    /// Sets a group address's members, by the vault's Owner or an Admin: a
    /// member removed reads none of the group's rows from this commit on,
    /// the earlier ones included; one added reads them all.
    pub fn mail_sources_members_set(
        &self,
        input: &MailSourceMembersRequest,
    ) -> MemoryResult<MailSourceView> {
        let id = EntityId::from_hex(&input.source_ref)?;
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            require_pack_active_in(vault, txn)?;
            let mut row = SOURCES
                .get(&vault.store, txn, &id)?
                .ok_or_else(unknown_source)?;
            if row.kind != MailSourceKind::GroupAddress || !self.mail_caller_manages_in(txn)? {
                return Err(unknown_source());
            }
            let members = member_persons_in(vault, txn, &input.members)?;
            let at = crate::unix_seconds_now();
            source_audience::set_source_readers_in_txn(
                vault,
                txn,
                &row.audience,
                members,
                actor,
                at,
            )?;
            row.updated_at = at;
            SOURCES.put(&vault.store, txn, &id, &row)?;
            self.mail_source_view_in(txn, &id, &row)?
                .ok_or_else(unknown_source)
        })
    }

    /// Every change to a source's readers, oldest first: its receipts. Its
    /// readers see them, and an Owner or an Admin a group address's.
    pub fn mail_sources_audience_events(
        &self,
        input: &MailSourceRef,
    ) -> MemoryResult<Vec<SourceAudienceEventView>> {
        let id = EntityId::from_hex(&input.source_ref)?;
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let row = SOURCES
            .get(&vault.store, &txn, &id)?
            .ok_or_else(unknown_source)?;
        let reads = source_audience::actor_reads_in(vault, &txn, &row.audience, self.actor())?;
        let manages =
            row.kind == MailSourceKind::GroupAddress && self.mail_caller_manages_in(&txn)?;
        if !reads && !manages {
            return Err(unknown_source());
        }
        Ok(source_audience::events_in(vault, &txn, &row.audience)?)
    }
}

/// An actor's erase takes its id out of every source (FIX 3520): a personal
/// mailbox or a calendar it owned keeps no owner, so no one changes it, and
/// its rows read to no one. Its drafted replies with files end whole in the
/// same writer (fix list row 17645).
pub(crate) fn erase_source_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    let sources = SOURCES.scan(&vault.store, wtxn)?;
    for (id, mut row) in sources {
        let mut changed = false;
        if row.owner == Some(*actor) {
            super::reply_erase::erase_reply_attachment_dependents_in_txn(
                &crate::secret_custody::CustodyWrite::of(vault),
                wtxn,
                &id,
            )?;
            row.owner = None;
            changed = true;
        }
        if row.connected_by == Some(*actor) {
            row.connected_by = None;
            changed = true;
        }
        if changed {
            SOURCES.put(&vault.store, wtxn, &id, &row)?;
        }
    }
    Ok(())
}
