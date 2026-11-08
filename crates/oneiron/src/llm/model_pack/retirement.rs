//! Retirement notices and the retirement-day move (FIX 5368, MODEL PACKS =
//! A: "Notices go out 60, 30 and 7 days before; then the model
//! auto-migrates to its successor", on Eiri DEC-0004 #deprecation's
//! schedule).
//!
//! The pass is a sweep of the engine's housekeeping pass
//! (`HousekeepingSweep::ModelPackRetirement`, FIX 20193), so every host that
//! runs the pass runs it the same way: a serving host on its tick, with the
//! access its offers hold, on its vault and each shared environment it keeps
//! open, and `oneiron maintain` on a stopped vault, with the access the
//! router `serve` would build from its `[models]` config and the vault's
//! mesh discovery rows holds (FIX 22059, 22189). The vault keeps models,
//! prices and scores, never an offer. A host that stops a vault is told the
//! first day to come on which a pass owes work, a notice mark with no notice
//! recorded or a retirement day's move
//! ([`Vault::model_pack_retirement_wake_at`]), and runs it again then. The
//! vault's clock names the day. A pass first moves a pin whose
//! pack retired to the successor ([`migrated_model_pack_preference`]) and
//! records the active pack's retirement-day move as a change that keeps the
//! pack before it, so the change's notice offers the revert (FIX 5369).
//! Then, at each of
//! [`MODEL_PACK_RETIREMENT_NOTICE_DAYS`](crate::settings::model_pack::MODEL_PACK_RETIREMENT_NOTICE_DAYS),
//! it tells each owner once of the active pack's retirement, and of each
//! retiring model a role resolves to on the host's access, while the pack
//! binds roles: an owner's manifest that outranks it leaves no notice. A
//! retired model's roles move to its successor in the resolver itself
//! ([`super::resolve_model_pack_role`]). The notices sent are recorded by
//! subject, retirement day and mark, so a restart or a second pass never
//! sends one twice. A pass that finds several marks passed since the last
//! notice (the vault stopped through a mark day, or no serving host ran on
//! it) sends the newest alone and records each mark it passed as handled,
//! so no later pass sends an older one (FIX 22119).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    ACTIVE, AccessSnapshot, MODEL_PACK_COMPACTION_KEY, ModelPackChangeCause, ModelPackReceipt,
    PREFERENCE, SECONDS_PER_DAY, manifest_outranks_model_pack, model_pack_role_key,
    resolve_model_pack_role,
};
use crate::Vault;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::llm::ModelId;
use crate::llm::manifest::{MODEL_ROLES, read_manifest};
use crate::settings::ModelStackDeprecation;
use crate::settings::model_pack::{
    MODEL_PACK_RETIREMENT_NOTICE_DAYS, ModelPack, ModelPackModelRetirement, ModelPackPreference,
    migrated_model_pack_preference, retirement_notice_mark, select_model_pack,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::InstalledModelPack;

/// Each retirement notice sent. Key: u64be(retirement day) + u64be(mark, in
/// days before it) + the subject (`pack:<pack id>` or `model:<model id>`).
const NOTICES: SideTable<(u64, u64, String), RetirementNoticeSent, Named> =
    SideTable::new(&side_table::LLM_MODEL_PACK_RETIREMENT_NOTICE);

/// Producer of the owner's notice of a coming pack or model retirement.
pub const MODEL_PACK_RETIREMENT_NOTIFICATION_PRODUCER: &str = "llm.model_pack.retirement";

/// One retirement notice mark handled: its notice sent to the vault's
/// owners, or, for a mark a pass found passed beside a newer one, the newer
/// mark's notice sent in its place (FIX 22119).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementNoticeSent {
    /// Unix seconds.
    sent_at: u64,
}

/// What one retirement pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ModelPackRetirementReport {
    /// Retirement notices sent, one per subject and mark, each to every
    /// owner.
    pub(crate) notices: u32,
    /// Whether the pass moved a pin or recorded the active pack's
    /// retirement-day move.
    pub(crate) migrated: bool,
}

/// One notice a pass owes.
struct DueNotice {
    key: (u64, u64, String),
    /// The record keys of the earlier marks the schedule passed with no
    /// notice recorded: handled by this notice and recorded with it (FIX
    /// 22119).
    passed: Vec<(u64, u64, String)>,
    /// The pack or model id the notice is about.
    subject: String,
    detail: String,
}

/// What a pass owes, read in one snapshot.
#[derive(Default)]
struct RetirementWork {
    /// Where a pin whose pack retired moves.
    preference: Option<ModelPackPreference>,
    /// The pack the last change recorded has retired: the move off it is a
    /// change of its own.
    active_retired: bool,
    notices: Vec<DueNotice>,
}

impl RetirementWork {
    fn is_empty(&self) -> bool {
        self.preference.is_none() && !self.active_retired && self.notices.is_empty()
    }
}

/// What a pass reads besides its notice records, read once in one snapshot,
/// so a wake time reads the work of each day to come without reading the
/// store again (FIX 22059).
#[derive(Default)]
struct RetirementInputs {
    packs: Vec<InstalledModelPack>,
    /// The owner's preference as stored.
    stored: ModelPackPreference,
    /// The pack the vault's last change recorded.
    recorded: Option<ModelPackReceipt>,
    /// Whether the pack the vault follows binds roles: no owner's manifest
    /// outranks it ([`manifest_outranks_model_pack`]).
    binds: bool,
}

/// Which models a day's model notices are about.
#[derive(Clone, Copy)]
enum NoticedModels<'a> {
    /// Those the followed pack's roles resolve to on the access the host's
    /// offers hold: a pass.
    Resolved(&'a AccessSnapshot),
    /// Those a role of the followed pack resolves to on some access
    /// ([`models_named`]): a stopped vault's wake time, which no offers
    /// inform (FIX 22059).
    Named,
}

fn pack_of(installed: &InstalledModelPack) -> &ModelPack {
    &installed.pack
}

/// `day` as a calendar date (UTC).
fn epoch_day_text(day: u32) -> String {
    i64::try_from(u64::from(day) * SECONDS_PER_DAY)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map_or_else(
            || format!("epoch day {day}"),
            |date| date.format("%Y-%m-%d").to_string(),
        )
}

/// When a retirement comes, in the notice's words.
fn countdown_text(left: u32, retires_epoch_day: u32) -> String {
    let unit = if left == 1 { "day" } else { "days" };
    format!(
        "retires in {left} {unit}, on {}",
        epoch_day_text(retires_epoch_day)
    )
}

/// The active pack's retirement notice: when it retires, the pack the vault
/// follows from that day, as selection will read it then, and the
/// successor the pack names.
fn pack_notice_text(
    packs: &[InstalledModelPack],
    following: &ModelPackPreference,
    pack: &ModelPack,
    left: u32,
    retires_epoch_day: u32,
) -> String {
    let mut text = format!(
        "Model pack {} {} (season {}) {}.",
        pack.id,
        pack.version,
        pack.season,
        countdown_text(left, retires_epoch_day)
    );
    let then = migrated_model_pack_preference(packs, pack_of, following, retires_epoch_day);
    let next = select_model_pack(
        packs,
        pack_of,
        then.as_ref().unwrap_or(following),
        retires_epoch_day,
    );
    match next {
        Some(next) => text.push_str(&format!(
            " The vault then moves to model pack {} {} (season {}).",
            next.pack.id, next.pack.version, next.pack.season
        )),
        None => text.push_str(" No installed model pack is served then."),
    }
    match &pack.successor {
        Some(successor) if next.is_some_and(|next| next.pack.id == *successor) => {}
        Some(successor)
            if packs
                .iter()
                .any(|installed| installed.pack.id == *successor) =>
        {
            text.push_str(&format!(" It names {successor} as its successor."));
        }
        Some(successor) => text.push_str(&format!(
            " It names {successor} as its successor, which is not installed."
        )),
        None => text.push_str(" It names no successor."),
    }
    text
}

/// A retiring model's notice: the roles of `pack` that use it, when it
/// retires, and where those roles go then.
fn model_notice_text(
    pack: &ModelPack,
    retiring: &ModelPackModelRetirement,
    roles: &[String],
    left: u32,
) -> String {
    let mut text = format!(
        "Model {}, which model pack {} uses for {}, {}.",
        retiring.model,
        pack.id,
        roles.join(", "),
        countdown_text(left, retiring.retirement.retires_epoch_day)
    );
    match &retiring.successor {
        Some(successor) => text.push_str(&format!(
            " Those roles then move to {successor} where their access carries it, else to their next variant in the pack."
        )),
        None => text.push_str(" Those roles then move to their next variant in the pack."),
    }
    text
}

impl Vault {
    /// One retirement pass (FIX 5368), the housekeeping pass's
    /// `ModelPackRetirement` sweep and its only caller (FIX 20193): `access`
    /// is what the host's offers hold, against which the active pack's roles
    /// resolve, and none on a host with no model offers. It moves a pin whose
    /// pack retired to its successor, records the active pack's
    /// retirement-day move as a change (with its notice and revert, FIX
    /// 5369), and sends each retirement notice due today once, to every
    /// owner. A pass with nothing due reads one snapshot and writes nothing.
    ///
    /// # Errors
    /// Storage errors. The sweep is retried whole on a later pass.
    pub(crate) fn run_model_pack_retirement(
        &self,
        access: &AccessSnapshot,
    ) -> Result<ModelPackRetirementReport> {
        let today = self.model_pack_today();
        let models = NoticedModels::Resolved(access);
        {
            let txn = self.store.env.read_txn()?;
            let inputs = self.model_pack_retirement_inputs_in_txn(&txn)?;
            if self
                .model_pack_retirement_work_in_txn(&txn, &inputs, models, today)?
                .is_empty()
            {
                return Ok(ModelPackRetirementReport::default());
            }
        }
        self.with_write_txn_grouped(|txn| {
            let inputs = self.model_pack_retirement_inputs_in_txn(txn)?;
            let work = self.model_pack_retirement_work_in_txn(txn, &inputs, models, today)?;
            let before = self.model_pack_in_effect_in_txn(txn)?;
            if let Some(preference) = &work.preference {
                PREFERENCE.put(&self.store, txn, &(), preference)?;
            }
            let migrated = work.preference.is_some() || work.active_retired;
            if migrated {
                self.note_active_model_pack_in_txn(txn, before, ModelPackChangeCause::Retirement)?;
            }
            let sent_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let owners = crate::policy_model::owners_in_txn(self, txn)?;
            for notice in &work.notices {
                for key in std::iter::once(&notice.key).chain(&notice.passed) {
                    NOTICES.put(&self.store, txn, key, &RetirementNoticeSent { sent_at })?;
                }
                let (retires, mark, subject) = &notice.key;
                for owner in &owners {
                    self.record_notification_in_txn(
                        txn,
                        &NotificationEvent {
                            kind: NotificationKind::Finding,
                            source: NotificationSource {
                                producer: MODEL_PACK_RETIREMENT_NOTIFICATION_PRODUCER.to_owned(),
                                event: format!("{subject}:{retires}:{mark}:{}", owner.to_hex()),
                                result: Some(notice.subject.clone()),
                                detail: Some(notice.detail.clone()),
                                ..NotificationSource::default()
                            },
                            subject_refs: Vec::new(),
                            recipient: Some(*owner),
                            created_at: sent_at,
                            origin_conversation: None,
                        },
                    )?;
                }
            }
            Ok(ModelPackRetirementReport {
                notices: u32::try_from(work.notices.len()).unwrap_or(u32::MAX),
                migrated,
            })
        })
    }

    /// What a retirement pass reads in `txn` besides its notice records: the
    /// installed packs (each receipt probed for its kind and status, FIX
    /// 22119), the stored preference, the pack the last change recorded and
    /// whether the owner's manifest outranks the pack. With no pack
    /// installed, nothing more is read.
    fn model_pack_retirement_inputs_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<RetirementInputs> {
        let packs = self.installed_model_packs_in_txn(txn)?;
        if packs.is_empty() {
            return Ok(RetirementInputs::default());
        }
        Ok(RetirementInputs {
            stored: PREFERENCE.get(&self.store, txn, &())?.unwrap_or_default(),
            recorded: ACTIVE
                .get(&self.store, txn, &())?
                .and_then(|change| change.active),
            binds: !manifest_outranks_model_pack(read_manifest(&self.store, txn)?.as_ref()),
            packs,
        })
    }

    /// What a retirement pass owes on `today` given `inputs`, its notice
    /// records read in `txn`, its model notices about `models`. An engine
    /// call (CALLS, FIX 5368, 20193): the retirement-day move of a pin or of
    /// the recorded pack runs whether or not an owner's manifest outranks the
    /// pack, as it concerns the owner's setting. The notices follow the roles
    /// the pack binds, by the test the role pick reads
    /// ([`manifest_outranks_model_pack`]): a manifest that outranks the pack
    /// leaves no notice, of the pack or of a model, as the pack picks nothing.
    /// Each subject owes one notice at most, at today's mark, the newest it
    /// passed; the earlier marks it passed unrecorded go with it (FIX 22119).
    fn model_pack_retirement_work_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        inputs: &RetirementInputs,
        models: NoticedModels<'_>,
        today: u32,
    ) -> Result<RetirementWork> {
        let packs = inputs.packs.as_slice();
        if packs.is_empty() {
            return Ok(RetirementWork::default());
        }
        let stored = &inputs.stored;
        let preference = migrated_model_pack_preference(packs, pack_of, stored, today);
        let active_retired = inputs.recorded.as_ref().is_some_and(|recorded| {
            packs
                .iter()
                .any(|installed| recorded.names(installed) && !installed.pack.is_served_on(today))
        });
        let following = preference.as_ref().unwrap_or(stored);
        let mut notices = Vec::new();
        // A pack an owner's manifest outranks binds no role: no notice talks
        // of a pack that picks nothing, or of a model no role of it uses.
        if inputs.binds
            && let Some(active) = select_model_pack(packs, pack_of, following, today)
        {
            let pack = &active.pack;
            if let Some(retirement) = pack.retirement
                && let Some(mark) = retirement_notice_mark(retirement, today)
            {
                let subject_key = format!("pack:{}", pack.id);
                let key = notice_key(retirement.retires_epoch_day, mark, &subject_key);
                if NOTICES.get(&self.store, txn, &key)?.is_none() {
                    notices.push(DueNotice {
                        key,
                        passed: self.unrecorded_passed_marks_in_txn(
                            txn,
                            retirement,
                            mark,
                            &subject_key,
                        )?,
                        subject: pack.id.to_string(),
                        detail: pack_notice_text(
                            packs,
                            following,
                            pack,
                            retirement.retires_epoch_day - today,
                            retirement.retires_epoch_day,
                        ),
                    });
                }
            }
            let used = match models {
                NoticedModels::Resolved(access) => models_in_use(pack, access, today),
                NoticedModels::Named => models_named(pack, today),
            };
            for (model, roles) in used {
                let Some(retiring) = pack.model_retirement(&model) else {
                    continue;
                };
                let retirement = retiring.retirement;
                let Some(mark) = retirement_notice_mark(retirement, today) else {
                    continue;
                };
                let subject_key = format!("model:{model}");
                let key = notice_key(retirement.retires_epoch_day, mark, &subject_key);
                if NOTICES.get(&self.store, txn, &key)?.is_none() {
                    notices.push(DueNotice {
                        key,
                        passed: self.unrecorded_passed_marks_in_txn(
                            txn,
                            retirement,
                            mark,
                            &subject_key,
                        )?,
                        subject: model.to_string(),
                        detail: model_notice_text(
                            pack,
                            retiring,
                            &roles,
                            retirement.retires_epoch_day - today,
                        ),
                    });
                }
            }
        }
        Ok(RetirementWork {
            preference,
            active_retired,
            notices,
        })
    }

    /// The record keys of the marks before `mark` that `retirement` passed
    /// by today with no notice recorded for `subject` (FIX 22119): a vault
    /// stopped through a mark day, or a day no serving host ran, passes a
    /// mark unsent. The pass sends `mark`'s notice, the newest, alone, and
    /// records these with it as handled, so no later pass sends one.
    fn unrecorded_passed_marks_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        retirement: ModelStackDeprecation,
        mark: u32,
        subject: &str,
    ) -> Result<Vec<(u64, u64, String)>> {
        let mut passed = Vec::new();
        for earlier in MODEL_PACK_RETIREMENT_NOTICE_DAYS
            .into_iter()
            .filter(|earlier| *earlier > mark)
        {
            let key = notice_key(retirement.retires_epoch_day, earlier, subject);
            if NOTICES.get(&self.store, txn, &key)?.is_none() {
                passed.push(key);
            }
        }
        Ok(passed)
    }

    /// When a stopped vault must next run a retirement pass (FIX 22059), in
    /// Unix seconds: `0` while a pass with no access owes work today (a
    /// move, or the pack's notice), else the start of the first day to come
    /// on which a pass owes work, or `None` when no day does. Each day to
    /// come is read as the pass will read it
    /// ([`Self::model_pack_retirement_work_in_txn`]), over the store as it
    /// is now, since a stopped vault's store does not change before that
    /// pass: a pin or the recorded pack to move on, or a notice mark of the
    /// followed pack or of a retiring model with no notice recorded at it.
    /// Only the days on which that work can change are read, in order
    /// ([`schedule_days`], over every installed pack). On a day to come, a
    /// model's notice counts for each retiring model a role of the followed
    /// pack resolves to on some access ([`NoticedModels::Named`]), as a
    /// stopped vault holds no offers. A model's mark today is left to the
    /// serving host's own pass, which ran each minute it served, and a day
    /// may wake the vault for a model no role of its host uses; that pass
    /// sends nothing. The installed packs are read once.
    pub(crate) fn model_pack_retirement_wake_at(&self) -> Result<Option<u64>> {
        let today = self.model_pack_today();
        let txn = self.store.env.read_txn()?;
        let inputs = self.model_pack_retirement_inputs_in_txn(&txn)?;
        let none = AccessSnapshot::new();
        if !self
            .model_pack_retirement_work_in_txn(
                &txn,
                &inputs,
                NoticedModels::Resolved(&none),
                today,
            )?
            .is_empty()
        {
            return Ok(Some(0));
        }
        for day in schedule_days(&inputs.packs, today) {
            if !self
                .model_pack_retirement_work_in_txn(&txn, &inputs, NoticedModels::Named, day)?
                .is_empty()
            {
                return Ok(Some(u64::from(day) * SECONDS_PER_DAY));
            }
        }
        Ok(None)
    }
}

/// Each day after `today`, in order, on which what a retirement pass owes
/// can change (FIX 22059): the notice start, each notice mark and the
/// retirement day of every retirement an installed pack names, its own and
/// its models'. Between two of them a pass owes what it owed on the first:
/// each pack is served or not, each schedule is at its mark
/// ([`retirement_notice_mark`]) and each variant runs as its model
/// ([`ModelPack::variant_on`]) all along.
fn schedule_days(packs: &[InstalledModelPack], today: u32) -> BTreeSet<u32> {
    packs
        .iter()
        .flat_map(|installed| {
            let pack = &installed.pack;
            pack.retirement.into_iter().chain(
                pack.retiring_models
                    .iter()
                    .map(|retiring| retiring.retirement),
            )
        })
        .flat_map(|retirement| {
            let retires = retirement.retires_epoch_day;
            MODEL_PACK_RETIREMENT_NOTICE_DAYS
                .into_iter()
                .map(move |mark| retires.saturating_sub(mark))
                .chain([retirement.notice_starts_epoch_day, retires])
        })
        .filter(|day| *day > today)
        .collect()
}

/// The record key of the notice at `mark` days before `retires_epoch_day`
/// about `subject`.
fn notice_key(retires_epoch_day: u32, mark: u32, subject: &str) -> (u64, u64, String) {
    (
        u64::from(retires_epoch_day),
        u64::from(mark),
        subject.to_owned(),
    )
}

/// The keys that read a pack's pick: the engine's own roles and the
/// compaction model (FIX 20042).
fn read_keys() -> impl Iterator<Item = String> {
    MODEL_ROLES
        .into_iter()
        .map(model_pack_role_key)
        .chain([MODEL_PACK_COMPACTION_KEY.to_owned()])
}

/// Each model `pack`'s roles resolve to on `access` today, with the role
/// keys that resolve to it: only the keys that read a pack's pick
/// ([`read_keys`]).
fn models_in_use(
    pack: &ModelPack,
    access: &AccessSnapshot,
    today: u32,
) -> BTreeMap<ModelId, Vec<String>> {
    let mut used: BTreeMap<ModelId, Vec<String>> = BTreeMap::new();
    for key in read_keys() {
        if let Some(variant) = resolve_model_pack_role(pack, &key, access, today) {
            used.entry(variant.model).or_default().push(key);
        }
    }
    used
}

/// Each model a key of `pack` that reads its pick ([`read_keys`]) resolves
/// to today on some access, with the keys that may resolve to it: the model
/// each of its variants runs as today ([`ModelPack::variant_on`]), whatever
/// access the host holds.
fn models_named(pack: &ModelPack, today: u32) -> BTreeMap<ModelId, Vec<String>> {
    let mut named: BTreeMap<ModelId, Vec<String>> = BTreeMap::new();
    for key in read_keys() {
        for variant in pack.variants(&key) {
            if let Some(variant) = pack.variant_on(variant, today) {
                let keys = named.entry(variant.model).or_default();
                if !keys.contains(&key) {
                    keys.push(key.clone());
                }
            }
        }
    }
    named
}
