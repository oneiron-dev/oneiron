//! Other members' personal mailboxes in an Owner's whole-vault export (fix
//! list row 15416; owner rulings EXPORT-MAILBOXES, 2026-11-07 01:43 and
//! 01:45; ARCH-0043 RD-28): who owns the shared vault decides.
//!
//! - An **org-owned** vault (the Team and Org presets) carries every other
//!   member's personal mailbox, and the facts learned from it, in its
//!   Owner's export. The copy's audit row counts those mailboxes for every
//!   co-Owner, and each mailbox's person is told in their inbox; both are
//!   written in one write before the copy leaves.
//! - A **person-owned** vault (Family, Community, or a shared vault with no
//!   preset) leaves another member's mailbox out, and the export names each
//!   mailbox it left out to the Owner who exported. While an Owner or an
//!   Admin has "Owners can export members' mail" on, it carries them as an
//!   org-owned vault does; each change of that setting is kept in the
//!   compliance log.
//! - A **personal** vault (no shared-vault creation, or the Personal preset)
//!   has no members' mailboxes: nothing changes.
//!
//! The exporter's own mailbox always goes, and so does a group address. An
//! export never waits: a mailbox whose person cannot be told before the copy
//! leaves is left out of it, and named.
//!
//! Which rows are a mailbox's is the source audiences' answer: a row goes
//! when its own binding's source and the sources of everything its words
//! came from go ([`crate::source_audience::ExportJudge`]), read once per
//! export pass from the vault's sources.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::compliance::{manages_in, record_export_member_mail_change_in_txn};
use super::doors::live_person_in;
use super::source::{MailSourceKind, SOURCES};
use crate::federation::SharedVaultPreset;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::side_table::{self, Named, SideTable};
use crate::source_audience::{ExportAudience, ExportJudge, ExportMet};
use crate::{EntityId, Result, Vault};

/// "Owners can export members' mail"; absent reads off.
const SETTING: SideTable<(), OwnersExportMemberMailRow, Named> =
    SideTable::new(&side_table::MAIL_PACK_OWNERS_EXPORT_MEMBER_MAIL);

/// The producer of a mailbox person's notice that an Owner's export carried
/// their mailbox.
const MEMBER_MAILBOX_EXPORT_PRODUCER: &str = "mail_pack.member_mailbox_export";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwnersExportMemberMailRow {
    enabled: bool,
    set_by: Option<EntityId>,
    set_at: u64,
}

/// Who owns a shared vault (ARCH-0043 RD-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedVaultOwner {
    /// A team's or an org's vault.
    Org,
    /// A household's, friends' or community's vault.
    Person,
}

/// Who owns the vault in `txn`, by its shared-vault creation's preset:
/// `None` for a personal vault, one with no creation row or the Personal
/// preset. A shared vault with no preset is person-owned.
fn shared_vault_owner_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Option<SharedVaultOwner>> {
    Ok(vault
        .shared_vault_creation_in_txn(txn)?
        .and_then(|creation| match creation.preset {
            Some(SharedVaultPreset::Personal) => None,
            Some(SharedVaultPreset::Team | SharedVaultPreset::Org) => Some(SharedVaultOwner::Org),
            Some(SharedVaultPreset::Family | SharedVaultPreset::Community) | None => {
                Some(SharedVaultOwner::Person)
            }
        }))
}

/// Whether "Owners can export members' mail" is on in `txn`; absent reads
/// off.
fn owners_export_member_mail_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(SETTING
        .get(&vault.store, txn, &())?
        .is_some_and(|row| row.enabled))
}

/// Where an Owner's request for one member's mailbox stands for an export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberMailRequest {
    /// No Owner asked for it.
    NotRequested,
}

/// Whether an export carries one other member's personal mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemberMailboxDecision {
    Include,
    LeaveOut,
}

/// The one rule (EXPORT-MAILBOXES, 01:43 and 01:45): an org-owned vault's
/// export carries another member's mailbox; a person-owned vault's carries
/// it while "Owners can export members' mail" (`setting`) is on, and leaves
/// it out otherwise. A request never answered, or declined, leaves it out
/// of the export too (rule X).
const fn member_mailbox_decision(
    owner: SharedVaultOwner,
    setting: bool,
    request: MemberMailRequest,
) -> MemberMailboxDecision {
    match (owner, setting, request) {
        (SharedVaultOwner::Org, _, _) | (SharedVaultOwner::Person, true, _) => {
            MemberMailboxDecision::Include
        }
        (SharedVaultOwner::Person, false, MemberMailRequest::NotRequested) => {
            MemberMailboxDecision::LeaveOut
        }
    }
}

/// Why an Owner's whole-vault export left a mailbox out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MailboxLeftOutReason {
    /// Another member's personal mailbox, in a vault a person owns, while
    /// "Owners can export members' mail" is off.
    MemberMailbox,
    /// Another member's personal mailbox whose person could not be told
    /// before the copy left.
    PersonNotTold,
    /// Rows a source landed whose source this vault cannot name.
    SourceUnidentified,
}

/// One mailbox an Owner's whole-vault export left out, named to the Owner
/// who exported: never a word of its mail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct MailboxExportNotice {
    /// The source, 32-hex; absent for rows whose source this vault cannot
    /// name.
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ref: Option<String>,
    /// The mailbox's address.
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    reason: MailboxLeftOutReason,
}

/// What an export does with one other member's personal mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// It goes, once `person` is told.
    Carried {
        person: EntityId,
    },
    LeftOut(MailboxLeftOutReason),
}

/// One other member's personal mailbox, as an export pass found it.
struct MemberMailbox {
    source: EntityId,
    address: String,
    placement: Placement,
}

/// One export pass's reading of the vault's members' mailboxes: who owns
/// the vault, the setting, and each source, read once in the pass's own
/// snapshot.
pub(crate) struct MemberMailboxPlan {
    exporter: EntityId,
    audience: ExportAudience,
    /// Each other member's personal mailbox, by the source policy its rows
    /// were born under.
    members: BTreeMap<EntityId, MemberMailbox>,
}

/// Whether the personal mailbox `owner` owns is `exporter`'s own: its
/// PERSON names the exporter as a read names its reader (a pen through its
/// PERSON anchor, the embedded owner through the owner it stands for). A
/// mailbox whose person was erased is no one's.
fn own_mailbox_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: Option<EntityId>,
    exporter: EntityId,
) -> Result<bool> {
    match owner {
        Some(owner) => {
            crate::source_audience::names_reader_in(vault, txn, &BTreeSet::from([owner]), exporter)
        }
        None => Ok(false),
    }
}

impl MemberMailboxPlan {
    /// The plan of `exporter`'s export of the vault in `txn`, each source
    /// read once: `None` in a personal vault. With `untold`, the people of
    /// the members' mailboxes this export would carry could not be told, and
    /// it carries none of them.
    ///
    /// # Errors
    ///
    /// Storage and codec failures.
    pub(crate) fn read_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        exporter: EntityId,
        untold: bool,
    ) -> Result<Option<Self>> {
        let Some(owner) = shared_vault_owner_in(vault, txn)? else {
            return Ok(None);
        };
        let setting = owners_export_member_mail_in(vault, txn)?;
        let mut sources = BTreeMap::new();
        let mut members = BTreeMap::new();
        for row in SOURCES.iter_from(&vault.store, txn, &[])? {
            let (source, row) = row?;
            if row.kind != MailSourceKind::PersonalMailbox
                || own_mailbox_in(vault, txn, row.owner, exporter)?
            {
                sources.insert(row.audience, true);
                continue;
            }
            let person = match row.owner {
                Some(person) => live_person_in(vault, txn, &person)?.then_some(person),
                None => None,
            };
            let placement = match (
                member_mailbox_decision(owner, setting, MemberMailRequest::NotRequested),
                person,
            ) {
                (MemberMailboxDecision::LeaveOut, _) => {
                    Placement::LeftOut(MailboxLeftOutReason::MemberMailbox)
                }
                (MemberMailboxDecision::Include, Some(person)) if !untold => {
                    Placement::Carried { person }
                }
                (MemberMailboxDecision::Include, _) => {
                    Placement::LeftOut(MailboxLeftOutReason::PersonNotTold)
                }
            };
            sources.insert(row.audience, matches!(placement, Placement::Carried { .. }));
            members.insert(
                row.audience,
                MemberMailbox {
                    source,
                    address: row.address,
                    placement,
                },
            );
        }
        Ok(Some(Self {
            exporter,
            audience: ExportAudience { exporter, sources },
            members,
        }))
    }

    /// The pass's judge of the rows it reads in `dbs` and `txn`.
    ///
    /// # Errors
    ///
    /// Storage failures.
    pub(crate) fn judge<'a, 's, 't>(
        &'a self,
        vault: &'a Vault,
        dbs: &'a crate::store::StoreRead<'s>,
        txn: &'a heed::RoTxn<'t>,
    ) -> Result<ExportJudge<'a, 's, 't>> {
        ExportJudge::new(vault, dbs, txn, &self.audience)
    }

    /// What the pass left out and carried, from what its judge `met`: one
    /// notice for each member's mailbox it left out whose rows the pass met,
    /// one for the rows of a source this vault cannot name, and the
    /// members' mailboxes it carries, each to be told before the copy leaves
    /// (`None` when it carries none).
    pub(crate) fn outcome(
        self,
        met: &ExportMet,
    ) -> (Vec<MailboxExportNotice>, Option<CarriedMemberMailboxes>) {
        let mut notices = Vec::new();
        let mut carried = Vec::new();
        for (audience, member) in self.members {
            if !met.sources.contains(&audience) {
                continue;
            }
            match member.placement {
                Placement::Carried { person } => carried.push(CarriedMailbox {
                    source: member.source,
                    audience,
                    person,
                }),
                Placement::LeftOut(reason) => notices.push(MailboxExportNotice {
                    source_ref: Some(member.source.to_hex()),
                    address: Some(member.address),
                    reason,
                }),
            }
        }
        if met.unidentified {
            notices.push(MailboxExportNotice {
                source_ref: None,
                address: None,
                reason: MailboxLeftOutReason::SourceUnidentified,
            });
        }
        let carried = (!carried.is_empty()).then_some(CarriedMemberMailboxes {
            exporter: self.exporter,
            mailboxes: carried,
        });
        (notices, carried)
    }
}

/// One other member's personal mailbox an export's copy carries.
struct CarriedMailbox {
    source: EntityId,
    /// The source policy its rows were born under.
    audience: EntityId,
    /// The PERSON told of the copy.
    person: EntityId,
}

/// The other members' personal mailboxes an export's copy carries, each
/// person to be told before a byte of it leaves.
pub(crate) struct CarriedMemberMailboxes {
    exporter: EntityId,
    mailboxes: Vec<CarriedMailbox>,
}

impl CarriedMemberMailboxes {
    /// The person whose copy it is.
    pub(crate) const fn exporter(&self) -> EntityId {
        self.exporter
    }
}

/// Tells each person of `carried` that the copy `export` carries their
/// mailbox, in the export audit's own write `txn`, at `at`: one inbox
/// NOTIFICATION each, for that person alone, naming the source, the exporter
/// and the export, never a word of the mail. The vault's rule and each
/// source are read again in `txn` first: a mailbox the rule no longer
/// carries, a source changed since the copy read it, or a person gone fails
/// the write, as any notice that is not written does. Answers how many
/// mailboxes were told.
///
/// # Errors
///
/// The mailbox no longer goes with the copy; storage failures.
pub(crate) fn tell_member_mailboxes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    carried: &CarriedMemberMailboxes,
    export: EntityId,
    at: u64,
) -> Result<u64> {
    let owner = shared_vault_owner_in(vault, txn)?;
    let setting = owners_export_member_mail_in(vault, txn)?;
    for mailbox in &carried.mailboxes {
        let carries = owner.is_some_and(|owner| {
            member_mailbox_decision(owner, setting, MemberMailRequest::NotRequested)
                == MemberMailboxDecision::Include
        });
        let stands = SOURCES
            .get(&vault.store, txn, &mailbox.source)?
            .is_some_and(|row| {
                row.kind == MailSourceKind::PersonalMailbox
                    && row.audience == mailbox.audience
                    && row.owner == Some(mailbox.person)
            });
        if !carries || !stands || !live_person_in(vault, txn, &mailbox.person)? {
            return Err(crate::Error::InvalidConfig(
                "a member's mailbox the export read no longer goes with it".into(),
            ));
        }
        vault.record_notification_in_txn(
            txn,
            &NotificationEvent {
                kind: NotificationKind::Finding,
                source: NotificationSource {
                    producer: MEMBER_MAILBOX_EXPORT_PRODUCER.to_owned(),
                    event: format!(
                        "{}:{}:{}",
                        export.to_hex(),
                        mailbox.source.to_hex(),
                        mailbox.person.to_hex()
                    ),
                    result: Some(export.to_hex()),
                    ..NotificationSource::default()
                },
                subject_refs: vec![mailbox.source, carried.exporter],
                recipient: Some(mailbox.person),
                created_at: at,
                origin_conversation: None,
            },
        )?;
    }
    Ok(carried.mailboxes.len() as u64)
}

/// `vault.mail.export_member_mail.set`'s input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailExportMemberMailSetRequest {
    pub enabled: bool,
}

/// "Owners can export members' mail", as the vault holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailExportMemberMailSettingView {
    pub enabled: bool,
    /// Who last changed it, 32-hex; absent if it was never set, or once that
    /// actor was erased.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_by_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_at: Option<u64>,
}

impl Memory<'_> {
    /// Turns "Owners can export members' mail" on or off (fix list row
    /// 15416), by the vault's Owner or an Admin: on, a person-owned shared
    /// vault's whole-vault export carries members' personal mailboxes as an
    /// org-owned vault's does, each mailbox's person told. Each change is
    /// kept in the compliance log; a request that changes nothing records
    /// nothing.
    pub fn mail_export_member_mail_set(
        &self,
        input: &MailExportMemberMailSetRequest,
    ) -> MemoryResult<MailExportMemberMailSettingView> {
        let actor = self.actor();
        self.with_verified_actor_write_txn(|txn| {
            let vault = self.vault();
            super::pack::require_pack_active_in(vault, txn)?;
            if !manages_in(vault, txn, actor)? {
                return Err(MemoryError::bad_request(
                    "\"Owners can export members' mail\" is set by the vault's Owner or an Admin",
                ));
            }
            if owners_export_member_mail_in(vault, txn)? != input.enabled {
                let at = crate::unix_seconds_now();
                SETTING.put(
                    &vault.store,
                    txn,
                    &(),
                    &OwnersExportMemberMailRow {
                        enabled: input.enabled,
                        set_by: Some(actor),
                        set_at: at,
                    },
                )?;
                record_export_member_mail_change_in_txn(vault, txn, input.enabled, actor, at)?;
            }
            let row = SETTING.get(&vault.store, txn, &())?;
            Ok(MailExportMemberMailSettingView {
                enabled: row.as_ref().is_some_and(|row| row.enabled),
                set_by_ref: row
                    .as_ref()
                    .and_then(|row| row.set_by)
                    .map(|id| id.to_hex()),
                set_at: row.map(|row| row.set_at),
            })
        })
    }
}

/// An actor's erase takes its id out of "Owners can export members' mail"
/// (FIX 3520), beside the compliance setting's and log's.
pub(super) fn erase_export_member_mail_setter_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if let Some(mut row) = SETTING.get(&vault.store, wtxn, &())?
        && row.set_by == Some(*actor)
    {
        row.set_by = None;
        SETTING.put(&vault.store, wtxn, &(), &row)?;
    }
    Ok(())
}
