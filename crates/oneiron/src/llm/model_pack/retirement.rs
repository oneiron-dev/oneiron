//! Retirement notices and the retirement-day move (FIX 5368, MODEL PACKS =
//! A: "Notices go out 60, 30 and 7 days before; then the model
//! auto-migrates to its successor", on Eiri DEC-0004 #deprecation's
//! schedule).
//!
//! A host runs [`Vault::run_model_pack_retirement`] on its housekeeping
//! tick, with the access its offers hold, and the vault's clock names the
//! day. A pass first moves a pin whose pack retired to the successor
//! ([`migrated_model_pack_preference`]) and records the active pack's
//! retirement-day move as a change that keeps the pack before it, so the
//! change's notice offers the revert (FIX 5369). Then, at each of
//! [`MODEL_PACK_RETIREMENT_NOTICE_DAYS`](crate::settings::model_pack::MODEL_PACK_RETIREMENT_NOTICE_DAYS),
//! it tells each owner once of the active pack's retirement, and of each
//! retiring model a role resolves to on the host's access. A retired
//! model's roles move to its successor in the resolver itself
//! ([`super::resolve_model_pack_role`]). The notices sent are recorded by
//! subject, retirement day and mark, so a restart or a second pass never
//! sends one twice.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{
    ACTIVE, AccessSnapshot, ModelPackChangeCause, PREFERENCE, SECONDS_PER_DAY,
    manifest_outranks_model_pack, model_pack_role_key, resolve_model_pack_role,
};
use crate::Vault;
use crate::error::Result;
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::llm::ModelId;
use crate::llm::manifest::{MODEL_ROLES, read_manifest};
use crate::settings::model_pack::{
    ModelPack, ModelPackModelRetirement, ModelPackPreference, migrated_model_pack_preference,
    retirement_notice_mark, select_model_pack,
};
use crate::side_table::{self, Named, SideTable};
use crate::skill_hub::pack_catalog::InstalledModelPack;

/// Each retirement notice sent. Key: u64be(retirement day) + u64be(mark, in
/// days before it) + the subject (`pack:<pack id>` or `model:<model id>`).
const NOTICES: SideTable<(u64, u64, String), RetirementNoticeSent, Named> =
    SideTable::new(&side_table::LLM_MODEL_PACK_RETIREMENT_NOTICE);

/// Producer of the owner's notice of a coming pack or model retirement.
pub const MODEL_PACK_RETIREMENT_NOTIFICATION_PRODUCER: &str = "llm.model_pack.retirement";

/// One retirement notice sent to the vault's owners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementNoticeSent {
    /// Unix seconds.
    sent_at: u64,
}

/// What one retirement pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModelPackRetirementReport {
    /// Retirement notices sent, one per subject and mark, each to every
    /// owner.
    pub notices: u32,
    /// Whether the pass moved a pin or recorded the active pack's
    /// retirement-day move.
    pub migrated: bool,
}

/// One notice a pass owes.
struct DueNotice {
    key: (u64, u64, String),
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
    /// One retirement pass (FIX 5368), for a host's housekeeping tick:
    /// `access` is what the host's offers hold, against which the active
    /// pack's roles resolve. It moves a pin whose pack retired to its
    /// successor, records the active pack's retirement-day move as a change
    /// (with its notice and revert, FIX 5369), and sends each retirement
    /// notice due today once, to every owner. A pass with nothing due reads
    /// one snapshot and writes nothing.
    ///
    /// # Errors
    /// Storage errors. The pass is retried whole on the next tick.
    pub fn run_model_pack_retirement(
        &self,
        access: &AccessSnapshot,
    ) -> Result<ModelPackRetirementReport> {
        let today = self.model_pack_today();
        {
            let txn = self.store.env.read_txn()?;
            if self
                .model_pack_retirement_work_in_txn(&txn, access, today)?
                .is_empty()
            {
                return Ok(ModelPackRetirementReport::default());
            }
        }
        self.with_write_txn_grouped(|txn| {
            let work = self.model_pack_retirement_work_in_txn(txn, access, today)?;
            if let Some(preference) = &work.preference {
                PREFERENCE.put(&self.store, txn, &(), preference)?;
            }
            let migrated = work.preference.is_some() || work.active_retired;
            if migrated {
                self.note_active_model_pack_in_txn(txn, ModelPackChangeCause::Retirement)?;
            }
            let sent_at = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let owners = crate::policy_model::owners_in_txn(self, txn)?;
            for notice in &work.notices {
                NOTICES.put(
                    &self.store,
                    txn,
                    &notice.key,
                    &RetirementNoticeSent { sent_at },
                )?;
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

    /// What a retirement pass owes on `today`, read in `txn`. An engine call
    /// (CALLS, FIX 5368): the active pack's own notices and its move go out
    /// whether or not an owner's manifest outranks the pack, as they concern
    /// the owner's setting; model notices follow the roles the pack binds,
    /// so a manifest that outranks it leaves none.
    fn model_pack_retirement_work_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        access: &AccessSnapshot,
        today: u32,
    ) -> Result<RetirementWork> {
        let packs = self.installed_model_packs_in_txn(txn)?;
        if packs.is_empty() {
            return Ok(RetirementWork::default());
        }
        let stored = PREFERENCE.get(&self.store, txn, &())?.unwrap_or_default();
        let preference = migrated_model_pack_preference(&packs, pack_of, &stored, today);
        let active_retired = ACTIVE
            .get(&self.store, txn, &())?
            .and_then(|change| change.active)
            .is_some_and(|recorded| {
                packs.iter().any(|installed| {
                    recorded.names(installed) && !installed.pack.is_served_on(today)
                })
            });
        let following = preference.as_ref().unwrap_or(&stored);
        let mut notices = Vec::new();
        if let Some(active) = select_model_pack(&packs, pack_of, following, today) {
            let pack = &active.pack;
            if let Some(retirement) = pack.retirement
                && let Some(mark) = retirement_notice_mark(retirement, today)
            {
                let key = notice_key(
                    retirement.retires_epoch_day,
                    mark,
                    &format!("pack:{}", pack.id),
                );
                if NOTICES.get(&self.store, txn, &key)?.is_none() {
                    notices.push(DueNotice {
                        key,
                        subject: pack.id.to_string(),
                        detail: pack_notice_text(
                            &packs,
                            following,
                            pack,
                            retirement.retires_epoch_day - today,
                            retirement.retires_epoch_day,
                        ),
                    });
                }
            }
            // A pack an owner's manifest outranks binds no role, so no model
            // of it is in use.
            if !manifest_outranks_model_pack(read_manifest(&self.store, txn)?.as_ref()) {
                for (model, roles) in models_in_use(pack, access, today) {
                    let Some(retiring) = pack.model_retirement(&model) else {
                        continue;
                    };
                    let retirement = retiring.retirement;
                    let Some(mark) = retirement_notice_mark(retirement, today) else {
                        continue;
                    };
                    let key = notice_key(
                        retirement.retires_epoch_day,
                        mark,
                        &format!("model:{model}"),
                    );
                    if NOTICES.get(&self.store, txn, &key)?.is_none() {
                        notices.push(DueNotice {
                            key,
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
        }
        Ok(RetirementWork {
            preference,
            active_retired,
            notices,
        })
    }
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

/// Each model `pack`'s roles resolve to on `access` today, with the role
/// keys that resolve to it: only the engine's own roles, as only those read
/// a pack's pick.
fn models_in_use(
    pack: &ModelPack,
    access: &AccessSnapshot,
    today: u32,
) -> BTreeMap<ModelId, Vec<String>> {
    let mut used: BTreeMap<ModelId, Vec<String>> = BTreeMap::new();
    for role in MODEL_ROLES {
        let key = model_pack_role_key(role);
        if let Some(variant) = resolve_model_pack_role(pack, &key, access, today) {
            used.entry(variant.model).or_default().push(key);
        }
    }
    used
}
