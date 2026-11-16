//! The catalogue keys the weave digest declares (DESIGN 15-setting-primitive, stage 4; Engine
//! RULING SETTING-KEYED-A-K2B-WEAVE-SPLIT = A): one reader's digest rhythm, its sections and where
//! its clock starts. The owner's own digest is one key, a person's or an agent's another. The
//! due state the timer moves (the next due second and a hold) stays in `WEAVE_DIGEST_SCHEDULE`:
//! each key's hook keeps that row in step with the value, in the write that changes it.

use serde::{Deserialize, Serialize};

use super::super::WeaveSectionSpec;
use super::super::weave_report::validate_weave_schedule_recipe;
use super::super::weave_serve::WeaveSectionInput;
use super::wire::{WireDue, WireSectionSpec, due_row_in_txn, put_due_in_txn};
use super::{SCHEDULE_PREFIX, WeaveDigestCadence, WeaveDigestReader};
use crate::error::{Error, Result};
use crate::setting::{
    EncodedValue, Kind, ScopeKind, Setter, SettingChange, SettingMode, SettingScope, SettingSource,
    SettingValue,
};
use crate::store::Store;
use crate::{EdgeKind, Vault};

/// One reader's digest as the owner chose it: its rhythm, its sections in the order the digest
/// lays them out, and the first due second.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct WeaveDigestScheduleSetup {
    pub(crate) cadence: WeaveDigestCadence,
    /// The digest's sections, in its order; at least one.
    pub(crate) recipe: Vec<WeaveSectionInput>,
    /// The first due Unix second: where the digest's clock starts. A change of it starts the
    /// clock again there; any other change keeps the clock where it is.
    pub(crate) starts_at: u64,
}

impl SettingValue for WeaveDigestScheduleSetup {
    fn check(self) -> Result<Self> {
        if self.recipe.is_empty() {
            return Err(Error::InvalidConfig(
                "a digest schedule names at least one section".into(),
            ));
        }
        wire_recipe(&self)?;
        Ok(self)
    }
}

impl WeaveDigestScheduleSetup {
    /// The setup a schedule row's choice holds: its cadence, recipe and clock start.
    pub(super) fn of(
        cadence: WeaveDigestCadence,
        recipe: &[WireSectionSpec],
        starts_at: u64,
    ) -> Result<Self> {
        Ok(Self {
            cadence,
            recipe: recipe
                .iter()
                .map(|section| {
                    Ok(WeaveSectionInput {
                        kind: section.kind,
                        predicates: section.predicates.clone(),
                        edge_kinds: section
                            .edge_kinds
                            .iter()
                            .map(|kind| {
                                EdgeKind::try_from_u8(*kind)
                                    .map(|kind| kind.name().to_owned())
                                    .ok_or_else(super::invalid)
                            })
                            .collect::<Result<Vec<_>>>()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            starts_at,
        })
    }
}

/// `setup`'s recipe as a schedule row holds it, each edge kind by its byte.
///
/// # Errors
///
/// `InvalidConfig` for an edge kind no graph has.
pub(super) fn wire_recipe(setup: &WeaveDigestScheduleSetup) -> Result<Vec<WireSectionSpec>> {
    setup
        .recipe
        .iter()
        .map(|section| {
            Ok(WireSectionSpec {
                kind: section.kind,
                predicates: section.predicates.clone(),
                edge_kinds: section
                    .edge_kinds
                    .iter()
                    .map(|name| {
                        EdgeKind::from_name(name)
                            .map(|kind| kind as u8)
                            .ok_or_else(|| {
                                Error::InvalidConfig(format!("`{name}` is not a weave edge kind"))
                            })
                    })
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect()
}

/// `setup`'s recipe as the weave report reads it.
fn section_specs(setup: &WeaveDigestScheduleSetup) -> Result<Vec<WeaveSectionSpec>> {
    wire_recipe(setup)?
        .into_iter()
        .map(|section| {
            Ok(WeaveSectionSpec {
                kind: section.kind,
                predicates: section.predicates,
                edge_kinds: section
                    .edge_kinds
                    .into_iter()
                    .map(|kind| EdgeKind::try_from_u8(kind).ok_or_else(super::invalid))
                    .collect::<Result<Vec<_>>>()?,
            })
        })
        .collect()
}

/// The weave report policy's role for a scheduled reader.
const fn policy_role(reader: WeaveDigestReader) -> &'static str {
    match reader {
        WeaveDigestReader::Owner(_) => "owner",
        WeaveDigestReader::Person(_) => "person",
        WeaveDigestReader::Agent(_) => "agent",
        WeaveDigestReader::Admin(_) => crate::gate::weave_policy::ADMIN_ROLE,
    }
}

fn no_schedule() -> Option<WeaveDigestScheduleSetup> {
    None
}

/// Every applied change of either key moves the deadline timer: it re-reads committed rows.
fn schedule_committed(vault: &Vault) {
    vault.store.notify_proactivity_changes();
}

fn owner_schedule_changed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    schedule_changed_in_txn(vault, txn, change, Holder::Owner)
}

fn reader_schedule_changed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    schedule_changed_in_txn(vault, txn, change, Holder::Reader)
}

crate::setting::setting_keys! {
    /// One owner's own digest (OF-499, FIX 5495): its rhythm (`daily` or `weekly`), its sections
    /// in the order it lays them out, and its first due second. Its row sits at that owner's
    /// person scope; only he sets it. The Coach changes its rhythm or its section order under
    /// his Grant, or proposes the change for him to accept, and he undoes it in one tap. His own
    /// change supersedes a waiting proposal and retires what he told the Coach. Null: no digest.
    pub(crate) OWNER_SCHEDULE: Option<WeaveDigestScheduleSetup> = "weave.digest.owner_schedule" {
        kind: Kind::new(no_schedule).strictest(no_schedule),
        scopes: &[ScopeKind::Person],
        on_change: Some(owner_schedule_changed_in_txn),
        after_commit: Some(schedule_committed),
    };
    /// A person's or an agent's digest (OF-499): its rhythm, its sections in its order, and its
    /// first due second, set by the owner. Its row sits at that reader's own scope, never the
    /// vault's: no reader falls back to another's digest. Each section must be one the weave
    /// report policy lets that reader read. Null: no digest.
    pub(crate) READER_SCHEDULE: Option<WeaveDigestScheduleSetup> = "weave.digest.reader_schedule" {
        kind: Kind::new(no_schedule).strictest(no_schedule),
        scopes: &[ScopeKind::Person, ScopeKind::Agent],
        on_change: Some(reader_schedule_changed_in_txn),
        after_commit: Some(schedule_committed),
    };
}

/// Which of the two keys a change is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holder {
    Owner,
    Reader,
}

/// The reader a row of the `holder` key at `scope` schedules; `None` at any other scope.
fn reader_at(holder: Holder, scope: &SettingScope) -> Option<WeaveDigestReader> {
    match (holder, scope) {
        (Holder::Owner, SettingScope::Person(id)) => Some(WeaveDigestReader::Owner(*id)),
        (Holder::Reader, SettingScope::Person(id)) => Some(WeaveDigestReader::Person(*id)),
        (Holder::Reader, SettingScope::Agent(id)) => Some(WeaveDigestReader::Agent(*id)),
        _ => None,
    }
}

/// The scope a `reader`'s row sits at, with its key; `None` for an Admin, which has no schedule
/// (OF-499 A3).
fn row_of(
    reader: WeaveDigestReader,
) -> Option<(
    &'static crate::setting::Setting<Option<WeaveDigestScheduleSetup>>,
    SettingScope,
)> {
    match reader {
        WeaveDigestReader::Owner(id) => Some((&OWNER_SCHEDULE, SettingScope::Person(id))),
        WeaveDigestReader::Person(id) => Some((&READER_SCHEDULE, SettingScope::Person(id))),
        WeaveDigestReader::Agent(id) => Some((&READER_SCHEDULE, SettingScope::Agent(id))),
        WeaveDigestReader::Admin(_) => None,
    }
}

/// A change's stored value, decoded; `None` for no row, a null value, or one that does not decode.
fn decoded(value: Option<&EncodedValue>) -> Option<WeaveDigestScheduleSetup> {
    value
        .and_then(EncodedValue::decode::<Option<WeaveDigestScheduleSetup>>)
        .flatten()
}

/// `reader`'s setup in force, with its row's revision; `None` when it has none. Only the value
/// row at the reader's own scope counts: a vault row or a pin (each refused by the hook, so one
/// arrived by sync or a restore) and a row that does not decode schedule nothing.
pub(super) fn schedule_setup_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    reader: WeaveDigestReader,
) -> Result<Option<(WeaveDigestScheduleSetup, u64)>> {
    let Some((key, scope)) = row_of(reader) else {
        return Ok(None);
    };
    let resolved = key.read_in_dbs_txn(store, txn, std::slice::from_ref(&scope), None)?;
    Ok(match (resolved.value, resolved.source) {
        (Some(setup), SettingSource::Row(at)) if at == scope => Some((setup, resolved.revision)),
        _ => None,
    })
}

/// The one hook of both keys, in the write that changes a row. It refuses a pin, a row at any
/// scope but its reader's, an owner row for a person who is no live owner, and an owner's set of
/// another owner's row; it runs the weave report policy's recipe check for the reader. Then it
/// keeps the reader's due row in step: a clear deletes it (the reader's newest period settles
/// on the lens's axes, as a stop always did); a new schedule, or a new clock start, due at
/// `starts_at`; any other change keeps the due second, and the hold unless the engine made it
/// (the Coach's flow keeps a hold, as it always did). The owner's own change to his row
/// supersedes the Coach's waiting proposal and retires his feedback.
fn schedule_changed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
    holder: Holder,
) -> Result<()> {
    if change.mode == SettingMode::Pin {
        return Err(Error::InvalidConfig(
            "a digest schedule is a value row, never a pin".into(),
        ));
    }
    let Some(reader) = reader_at(holder, &change.scope) else {
        return Err(Error::InvalidConfig(match holder {
            Holder::Owner => format!(
                "`{}` sits at its owner's person scope, never the vault's",
                change.key
            ),
            Holder::Reader => format!(
                "`{}` sits at its reader's person or agent scope, never the vault's: no \
                 reader falls back to another's digest",
                change.key
            ),
        }));
    };
    if let WeaveDigestReader::Owner(id) = reader {
        if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &id)? {
            return Err(Error::InvalidConfig(
                "an owner digest schedule is a live owner's own".into(),
            ));
        }
        if change.setter == Setter::Owner && change.by != Some(id) {
            return Err(Error::InvalidConfig(
                "an owner sets his own digest schedule, never another owner's".into(),
            ));
        }
    }
    let prior = decoded(change.prior.as_ref());
    let value = decoded(change.value.as_ref());
    let key = reader.key(SCHEDULE_PREFIX);
    match &value {
        Some(setup) => {
            let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
            validate_weave_schedule_recipe(
                &policy,
                policy_role(reader),
                reader.id(),
                &section_specs(setup)?,
            )?;
            let kept = match prior.as_ref() {
                Some(prior) if prior.starts_at == setup.starts_at => {
                    due_row_in_txn(&vault.store, txn, &key)?
                }
                _ => None,
            };
            let due = match kept {
                Some(due) if matches!(change.setter, Setter::Engine { .. }) => due,
                Some(due) => WireDue {
                    next_due_at: due.next_due_at,
                    held_until: None,
                    held_because: None,
                },
                None => WireDue {
                    next_due_at: setup.starts_at,
                    held_until: None,
                    held_because: None,
                },
            };
            put_due_in_txn(&vault.store, txn, &key, &due)?;
        }
        None => {
            vault.store.vault_meta.delete(txn, &key)?;
            if prior.is_some() {
                vault.settle_stopped_weave_digest_in_txn(txn, reader, change.at);
            }
        }
    }
    if let WeaveDigestReader::Owner(id) = reader
        && change.setter == Setter::Owner
    {
        vault.owner_edited_weave_digest_in_txn(txn, id, change.at)?;
    }
    Ok(())
}
