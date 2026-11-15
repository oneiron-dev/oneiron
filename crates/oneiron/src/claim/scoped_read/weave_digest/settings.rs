//! The owner's own digest settings record (FIX 5495): the one writer the
//! Coach's flow changes his Owner schedule through (his
//! `weave.digest.owner_schedule` setting, whose row revision is the guard a
//! stale accept or undo is refused by), what he told the Coach, and his own
//! behaviour with his digests (when a period's due notice reached him and
//! when he first opened it).
//! Nothing here holds digest text, and nothing reads another reader's
//! behaviour. A failure in the behaviour notes is logged and skipped: it
//! never fails or delays the owner's read or the timer's notice.

use super::setting_keys::{OWNER_SCHEDULE, WeaveDigestScheduleSetup};
use super::{
    SCHEDULE_PREFIX, WeaveDigestCadence, WeaveDigestReader, WeaveSectionKind, WireSchedule,
    invalid, schedule_bytes_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::setting::{
    EngineSetting, SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope,
};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};
use serde::{Deserialize, Serialize};

/// The due rows of the readers' schedules, listed here for the Owner ones.
/// Key: the reader kind byte, then the reader.
pub(super) const SCHEDULES: SideTable<([u8; 1], EntityId), Vec<u8>, Raw> =
    SideTable::new(&side_table::WEAVE_DIGEST_SCHEDULE);
/// The kind byte of an Owner reader's schedule key.
pub(super) const OWNER_TAG: [u8; 1] = *b"o";
/// Each owner's settings row. Key: the owner.
pub(super) const SETTINGS: SideTable<EntityId, SettingsRow, Named> =
    SideTable::new(&side_table::WEAVE_DIGEST_SETTINGS);
/// The owner's own behaviour with each period. Key: the owner, then the
/// period's `scheduled_for`.
const BEHAVIOUR: SideTable<(EntityId, u64), PeriodRow, Named> =
    SideTable::new(&side_table::WEAVE_DIGEST_BEHAVIOUR);
/// The Coach's changes to each owner's settings. Key: the owner, then the
/// change.
pub(super) const CHANGES: SideTable<(EntityId, EntityId), WeaveDigestSettingChange, Named> =
    SideTable::new(&side_table::WEAVE_DIGEST_SETTING_CHANGE);

/// How long a period's behaviour row is kept, from its `scheduled_for`
/// (CALLS: FIX 5495 retention). A write prunes older rows of that owner.
const WEAVE_DIGEST_BEHAVIOUR_KEEP_SECS: u64 = 90 * 86_400;

/// An Owner schedule's settings as the Coach may change them: its rhythm and
/// the order its sections lead in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestSettings {
    pub cadence: WeaveDigestCadence,
    /// The schedule's section kinds, in the order its digest lays them out.
    pub sections: Vec<WeaveSectionKind>,
}

#[doc(hidden)]
pub use oneiron_verb_wire::claim::scoped_read::weave_digest::settings::{
    WeaveDigestSettingAnswer, WeaveDigestSettingChangeStatus, WeaveDigestSettingUndo,
};

/// One Coach change to the owner's digest rhythm or section order, from his
/// own behaviour only (FIX 5495). Applied and accepted changes keep a
/// one-tap undo while the settings stay as the change left them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestSettingChange {
    /// The change, as 32 hex.
    pub change_ref: String,
    pub status: WeaveDigestSettingChangeStatus,
    /// The settings it was proposed against.
    pub before: WeaveDigestSettings,
    /// The settings it sets.
    pub after: WeaveDigestSettings,
    /// Why the Coach proposed it, from the owner's own behaviour.
    pub reason: String,
    /// The Coach that proposed it, as 32 hex.
    pub coach_ref: String,
    /// The Grant naming digest settings it applied under, as 32 hex; absent
    /// for a proposal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
    /// The settings generation it was proposed against: the revision of the
    /// owner's `weave.digest.owner_schedule` row, which every change to it
    /// moves on.
    pub base_generation: u64,
    /// The generation its apply or accept wrote; its undo needs it current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_generation: Option<u64>,
    /// The generation its undo wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_generation: Option<u64>,
    /// When the Coach made it, in Unix seconds.
    pub created_at: u64,
    /// When it reached its status, in Unix seconds; absent while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<u64>,
    /// For a proposal, why a Grant of the Coach's that named these settings
    /// was passed over: `pact_standing_lapsed` when, on a shared vault, its
    /// pact membership alone had lapsed (FIX 7548). Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_omitted: Option<String>,
}

/// What the owner tells the Coach about his own digest. His next own edit of
/// the schedule retires it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WeaveDigestFeedback {
    /// The rhythm he wants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_cadence: Option<WeaveDigestCadence>,
    /// The section he wants first; it must already be one of the schedule's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead_section: Option<WeaveSectionKind>,
    /// Keep the settings as they are: the Coach proposes nothing.
    #[serde(default)]
    pub keep_current: bool,
}

/// One owner's settings row: the Coach's state and his own input to it. His
/// settings themselves are his `weave.digest.owner_schedule` row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettingsRow {
    /// When the Coach last evaluated this owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) last_evaluated_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) feedback: Option<StoredFeedback>,
}

/// The owner's feedback, with when and under which generation (his owner
/// schedule row's revision) he gave it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredFeedback {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) preferred_cadence: Option<WeaveDigestCadence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) lead_section: Option<WeaveSectionKind>,
    #[serde(default)]
    pub(super) keep_current: bool,
    pub(super) given_at: u64,
    pub(super) generation: u64,
}

/// The owner's own behaviour with one period: no digest text.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PeriodRow {
    pub(super) cadence: WeaveDigestCadence,
    /// When the period's due notice first reached him.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) noticed_at: Option<u64>,
    /// The period's due notice, as 32 hex: its read marks show a dismissal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) notice_ref: Option<String>,
    /// When he first opened the period.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) opened_at: Option<u64>,
}

/// The owner's Owner schedule: his setting in force joined with his due row.
pub(super) fn owner_wire_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> Result<Option<WireSchedule>> {
    schedule_bytes_in_txn(
        store,
        txn,
        &WeaveDigestReader::Owner(owner).key(SCHEDULE_PREFIX),
    )?
    .map(|bytes| serde_json::from_slice::<WireSchedule>(&bytes).map_err(|_| invalid()))
    .transpose()
}

/// The owner's changes, in key order. A row that does not decode is left out:
/// it neither answers nor undoes.
pub(super) fn owner_changes_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> Result<Vec<(EntityId, WeaveDigestSettingChange)>> {
    let mut changes = Vec::new();
    for row in CHANGES.iter_raw_from(store, txn, owner.as_bytes())? {
        let (key, bytes) = row?;
        let Some(id) = key
            .get(16..)
            .and_then(|id| <[u8; 16]>::try_from(id).ok())
            .and_then(|id| EntityId::from_bytes(id).ok())
        else {
            continue;
        };
        if let Ok(change) = CHANGES.decode_value(&bytes) {
            changes.push((id, change));
        }
    }
    Ok(changes)
}

/// The owner's period rows, oldest first. A row that does not decode is
/// left out.
pub(super) fn owner_periods_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> Result<Vec<(u64, PeriodRow)>> {
    let mut periods = Vec::new();
    for row in BEHAVIOUR.iter_raw_from(store, txn, owner.as_bytes())? {
        let (key, bytes) = row?;
        let Some(at) = key
            .get(16..)
            .and_then(|at| <[u8; 8]>::try_from(at).ok())
            .map(u64::from_be_bytes)
        else {
            continue;
        };
        if let Ok(period) = BEHAVIOUR.decode_value(&bytes) {
            periods.push((at, period));
        }
    }
    Ok(periods)
}

/// A deleted reader takes its settings, behaviour and change rows with it.
pub(super) fn erase_owner_weave_digest_settings_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    SETTINGS.delete(store, txn, owner)?;
    BEHAVIOUR.delete_from(store, txn, owner.as_bytes())?;
    CHANGES.delete_from(store, txn, owner.as_bytes())?;
    Ok(())
}

/// The owner's settings row as the Coach and his own answers read it: an
/// absent row reads as new, and a row that no longer decodes is rebuilt new
/// (FIX 5633). The caller's next put writes the rebuilt row; what the
/// damaged row held (his feedback, the Coach's last evaluation) is gone with
/// it. The stale guard is his setting row's revision, which no damage here
/// moves.
pub(super) fn settings_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
) -> Result<SettingsRow> {
    if !SETTINGS.contains(store, txn, &owner)? {
        return Ok(SettingsRow::default());
    }
    if let Some(row) = SETTINGS.get_lenient(store, txn, &owner)? {
        return Ok(row);
    }
    tracing::warn!(owner = %owner.to_hex(), "an owner's digest settings row did not decode; it is rebuilt");
    Ok(SettingsRow::default())
}

impl Vault {
    /// The one writer of the Coach's flow (FIX 5495): a Coach change under
    /// the owner's Grant, an accepted proposal and an undo each write the
    /// owner's `weave.digest.owner_schedule` row as the engine (Engine RULING
    /// SETTING-KEYED-A-K2B-WEAVE-SPLIT = A), with `why` naming the change, in
    /// the caller's write. Its due time and holds stay as they are. Returns
    /// the row's new revision: the generation the change wrote.
    pub(super) fn put_owner_weave_digest_setup_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        wire: &WireSchedule,
        why: String,
    ) -> Result<u64> {
        let setup = WeaveDigestScheduleSetup::of(wire.cadence, &wire.recipe, wire.starts_at)?;
        let request = SetSetting {
            key: OWNER_SCHEDULE.spec.name.to_owned(),
            item: None,
            scope: SettingScope::Person(owner),
            mode: SettingMode::Value,
            value: Some(serde_json::to_value(Some(setup)).map_err(|_| invalid())?),
            expected_revision: Some(wire.revision),
            why: Some(why),
            check_in_ref: None,
        };
        match self.set_setting_in_txn(txn, SettingCaller::Engine(EngineSetting::own()), &request)? {
            SetSettingOutcome::Applied { revision, .. } => Ok(revision),
            SetSettingOutcome::Pending { .. } => Err(Error::InvariantViolation(
                "the engine's digest settings change waits on no check-in",
            )),
        }
    }

    /// The owner's own change to his Owner schedule, in its hook's write: it
    /// wins over a pending Coach change, which it supersedes, and it retires
    /// his feedback.
    pub(super) fn owner_edited_weave_digest_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        now: u64,
    ) -> Result<()> {
        let mut row = settings_row_in_txn(&self.store, txn, owner)?;
        row.feedback = None;
        for (id, mut change) in owner_changes_in_txn(&self.store, txn, owner)? {
            if change.status == WeaveDigestSettingChangeStatus::Pending {
                change.status = WeaveDigestSettingChangeStatus::Superseded;
                change.settled_at = Some(now);
                CHANGES.put(&self.store, txn, &(owner, id), &change)?;
                // Its ask no longer waits for him (FIX 5631).
                self.settle_weave_setting_ask_in_txn(txn, owner, &change)?;
            }
        }
        SETTINGS.put(&self.store, txn, &owner, &row)?;
        Ok(())
    }

    /// The owner's own exposure to one period: its due notice reached him.
    /// Recorded once per period; the timer reuses the notice on each visit.
    /// Evidence for the Coach, never a gate on the notice.
    pub(super) fn note_owner_weave_digest_notice(
        &self,
        owner: EntityId,
        scheduled_for: u64,
        cadence: WeaveDigestCadence,
        notice: EntityId,
        now: u64,
    ) {
        let noted = self.with_write_txn_grouped(|txn| {
            let mut row = match BEHAVIOUR.get(&self.store, txn, &(owner, scheduled_for))? {
                Some(row) if row.noticed_at.is_some() => return Ok(()),
                Some(row) => row,
                None => PeriodRow {
                    cadence,
                    noticed_at: None,
                    notice_ref: None,
                    opened_at: None,
                },
            };
            row.noticed_at = Some(now);
            row.notice_ref = Some(notice.to_hex());
            self.put_owner_period_in_txn(txn, owner, scheduled_for, &row, now)
        });
        if let Err(error) = noted {
            tracing::warn!(?error, "the owner's digest notice was not noted");
        }
    }

    /// The owner's own first open of the period his digest read returned,
    /// under his live proof. `latest`: he asked for his newest period, which
    /// may have rendered just now with no notice; an older period he names
    /// counts only once its notice reached him. Person and agent reads never
    /// come here. Evidence for the Coach, never a gate on the read.
    pub(crate) fn note_owner_weave_digest_open(
        &self,
        owner: &AuthenticatedOwner,
        reader: WeaveDigestReader,
        scheduled_for: u64,
        latest: bool,
    ) {
        let WeaveDigestReader::Owner(id) = reader else {
            return;
        };
        if let Err(error) = self.record_owner_weave_digest_open(owner, id, scheduled_for, latest) {
            tracing::warn!(?error, "the owner's digest open was not noted");
        }
    }

    fn record_owner_weave_digest_open(
        &self,
        owner: &AuthenticatedOwner,
        id: EntityId,
        scheduled_for: u64,
        latest: bool,
    ) -> Result<()> {
        // A period already opened, or one he names that never reached him,
        // costs no write.
        {
            let txn = self.store.env.read_txn()?;
            match BEHAVIOUR.get(&self.store, &txn, &(id, scheduled_for))? {
                Some(row) if row.opened_at.is_some() => return Ok(()),
                None if !latest => return Ok(()),
                _ => {}
            }
        }
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            if owner.revalidate_in_txn(self, txn)? != id {
                return Ok(());
            }
            let mut row = match BEHAVIOUR.get(&self.store, txn, &(id, scheduled_for))? {
                Some(row) if row.opened_at.is_some() => return Ok(()),
                Some(row) => row,
                None if !latest => return Ok(()),
                None => {
                    let Some(wire) = owner_wire_in_txn(&self.store, txn, id)? else {
                        return Ok(());
                    };
                    PeriodRow {
                        cadence: wire.cadence,
                        noticed_at: None,
                        notice_ref: None,
                        opened_at: None,
                    }
                }
            };
            row.opened_at = Some(now);
            self.put_owner_period_in_txn(txn, id, scheduled_for, &row, now)
        })
    }

    /// Writes one period row and prunes the owner's rows older than
    /// [`WEAVE_DIGEST_BEHAVIOUR_KEEP_SECS`].
    fn put_owner_period_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        scheduled_for: u64,
        row: &PeriodRow,
        now: u64,
    ) -> Result<()> {
        BEHAVIOUR.put(&self.store, txn, &(owner, scheduled_for), row)?;
        let stale: Vec<u64> = owner_periods_in_txn(&self.store, txn, owner)?
            .into_iter()
            .map(|(at, _)| at)
            .filter(|at| at.saturating_add(WEAVE_DIGEST_BEHAVIOUR_KEEP_SECS) < now)
            .collect();
        for at in stale {
            BEHAVIOUR.delete(&self.store, txn, &(owner, at))?;
        }
        Ok(())
    }
}
