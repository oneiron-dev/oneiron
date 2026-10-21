//! The Coach's changes to an owner's digest settings (FIX 5495; DEC-0005
//! policy residence). The Coach proposes from the owner's own behaviour; it
//! applies a change directly only under the owner's Grant that names digest
//! settings, and every applied or accepted change reaches him as a notice
//! whose one tap is its undo, his own act. His own edit always wins: it
//! supersedes a pending change, and an accept or undo after it is refused.
//! The Coach only ever moves an Owner schedule's rhythm or section order;
//! it never clears or stops one, and never touches its due time, holds,
//! another reader's schedule, urgency or notification policy.

use super::coach::{CoachInput, CoachStep, PeriodRecord, weave_digest_coach_step};
use super::settings::{
    CHANGES, OWNER_TAG, SCHEDULES, SETTINGS, SettingsEdit, SettingsRow, StoredFeedback,
    WeaveDigestFeedback, WeaveDigestSettingChange, WeaveDigestSettingChangeStatus as Status,
    WeaveDigestSettings, owner_changes_in_txn, owner_periods_in_txn, owner_wire_in_txn,
    settings_row_in_txn,
};
use super::{WEAVE_DIGEST_NOTIFICATION_PRODUCER, WireSchedule, invalid};
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::inbox::{NotificationEvent, NotificationKind, NotificationSource};
use crate::{EntityId, Vault};

// The Coach's model drafts the step on a host Coach (FIX 5609).
mod draft;

/// The producer of the owner's notices about a Coach change to his digest
/// settings: an ask for a proposal, a settings-changed notice for an
/// applied or accepted change. `source.result` names the change.
pub const WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER: &str = "weave.digest.settings";
/// The Coach evaluates each owner at most once in this many seconds (CALLS:
/// FIX 5495 evaluation).
const WEAVE_DIGEST_COACH_EVERY_SECS: u64 = 86_400;
const CHANGE_ID_DOMAIN: &[u8] = b"oneiron:weave-digest-setting-change:v1";

const STALE_ACCEPT: &str = "your digest settings changed since; nothing applied";
const STALE_UNDO: &str = "your digest settings changed since; nothing undone";
const SETTLED: &str = "this digest settings change was already settled";
const NOT_UNDOABLE: &str = "only an applied or accepted digest settings change has an undo";
const NO_SCHEDULE: &str = "you have no digest schedule to tell the Coach about";
const LEAD_NOT_IN_RECIPE: &str = "the lead section must already be one of your digest's sections";

/// The settings a schedule row holds.
fn settings_of(wire: &WireSchedule) -> WeaveDigestSettings {
    WeaveDigestSettings {
        cadence: wire.cadence,
        sections: wire.recipe.iter().map(|section| section.kind).collect(),
    }
}

/// The step a change takes: its rhythm when that moved, else its lead.
fn step_of(change: &WeaveDigestSettingChange) -> Option<CoachStep> {
    if change.after.cadence != change.before.cadence {
        Some(CoachStep::Cadence(change.after.cadence))
    } else {
        change.after.sections.first().copied().map(CoachStep::Lead)
    }
}

/// Takes `step` on a schedule row, keeping its due time, holds and every
/// section's predicates and edge kinds. `false`: the step names no section
/// the row holds.
fn take_step(wire: &mut WireSchedule, step: CoachStep) -> bool {
    match step {
        CoachStep::Cadence(cadence) => wire.cadence = cadence,
        CoachStep::Lead(kind) => {
            let Some(at) = wire.recipe.iter().position(|section| section.kind == kind) else {
                return false;
            };
            let section = wire.recipe.remove(at);
            wire.recipe.insert(0, section);
        }
    }
    true
}

/// Restores `before`'s rhythm and section order on a schedule row, keeping
/// its due time, holds and sections.
fn restore(wire: &mut WireSchedule, before: &WeaveDigestSettings) -> Result<()> {
    let mut rest: Vec<_> = wire.recipe.drain(..).map(Some).collect();
    let mut ordered = Vec::with_capacity(rest.len());
    for kind in &before.sections {
        let section = rest
            .iter_mut()
            .find(|slot| matches!(slot, Some(section) if section.kind == *kind))
            .and_then(Option::take)
            .ok_or_else(invalid)?;
        ordered.push(section);
    }
    if rest.iter().any(Option::is_some) {
        return Err(invalid());
    }
    wire.cadence = before.cadence;
    wire.recipe = ordered;
    Ok(())
}

/// A change the owner declined, or undid, under `generation`.
fn refused_under(change: &WeaveDigestSettingChange, generation: u64) -> bool {
    match change.status {
        Status::Declined => change.base_generation == generation,
        Status::Undone => change.undone_generation == Some(generation),
        _ => false,
    }
}

fn change_id(owner: EntityId, base: u64, step: CoachStep, now: u64) -> Result<EntityId> {
    let base = base.to_be_bytes();
    let now = now.to_be_bytes();
    let step = format!("{step:?}");
    crate::codebase::entity_id_from_hash_material(
        CHANGE_ID_DOMAIN,
        &[
            owner.as_bytes().as_slice(),
            base.as_slice(),
            now.as_slice(),
            step.as_bytes(),
        ],
    )
}

fn evaluation_due(last_evaluated_at: Option<u64>, now: u64) -> bool {
    last_evaluated_at.is_none_or(|at| now >= at.saturating_add(WEAVE_DIGEST_COACH_EVERY_SECS))
}

/// Retires the part of the owner's feedback `change` answered, once it
/// settled applied, accepted or declined (FIX 5632): the rhythm it set, or
/// the section it led with, when he asked for it before the change was
/// made. Feedback that then asks for nothing is retired whole; the rest
/// stays for the Coach's next proposal. `true` when anything was retired.
fn retire_answered_feedback(row: &mut SettingsRow, change: &WeaveDigestSettingChange) -> bool {
    let Some(feedback) = row.feedback.as_mut() else {
        return false;
    };
    if feedback.given_at > change.created_at {
        return false;
    }
    match step_of(change) {
        Some(CoachStep::Cadence(cadence)) if feedback.preferred_cadence == Some(cadence) => {
            feedback.preferred_cadence = None;
        }
        Some(CoachStep::Lead(kind)) if feedback.lead_section == Some(kind) => {
            feedback.lead_section = None;
        }
        _ => return false,
    }
    if feedback.preferred_cadence.is_none()
        && feedback.lead_section.is_none()
        && !feedback.keep_current
    {
        row.feedback = None;
    }
    true
}

/// The owner's notice about `change`: an ask while it is pending, else a
/// settings-changed notice whose one tap is its undo. Its id derives from
/// its producer and event, so the same event finds the same row.
fn setting_change_event(
    owner: EntityId,
    change: &WeaveDigestSettingChange,
    kind: NotificationKind,
    now: u64,
) -> NotificationEvent {
    let what = if kind == NotificationKind::Ask {
        "proposed"
    } else {
        "changed"
    };
    NotificationEvent {
        kind,
        source: NotificationSource {
            producer: WEAVE_DIGEST_SETTINGS_NOTIFICATION_PRODUCER.to_owned(),
            event: format!("{}:{what}", change.change_ref),
            result: Some(change.change_ref.clone()),
            detail: Some(change.reason.clone()),
            ..NotificationSource::default()
        },
        subject_refs: Vec::new(),
        recipient: Some(owner),
        created_at: now,
        origin_conversation: None,
    }
}

impl Vault {
    /// The Coach's pass over every Owner schedule, from the digest timer on
    /// the home node after it served (FIX 5495). Each owner is evaluated in
    /// its own short write, at most once per
    /// [`WEAVE_DIGEST_COACH_EVERY_SECS`]. A failure is logged and skipped:
    /// it never fails the timer's own work. While a host Coach serves this
    /// vault, its model drafts each step (FIX 5609): the timer only queues
    /// its job, and the rule here never also runs. Serving means ready, not
    /// spawned (FIX 6165): before its first round served, after a round
    /// erred, or once its readiness lapsed because no round served within
    /// its liveness span (FIX 7211; a hung round runs on, uncancelled), the
    /// rule here evaluates as with no host.
    pub(super) fn coach_weave_digest_settings(&self, now: u64) {
        if self.coach_weave_digest_host_ready() {
            self.queue_coach_weave_digest_settings(now);
            return;
        }
        let owners = match self.owner_schedule_ids() {
            Ok(owners) => owners,
            Err(error) => {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "the Coach's digest settings pass was skipped"
                );
                return;
            }
        };
        for owner in owners {
            match self.coach_owner_weave_digest(owner, now) {
                // The deadline timer re-reads committed rows on this signal.
                Ok(true) => self.store.notify_proactivity_changes(),
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    error_kind = ?error.kind(),
                    owner = %owner.to_hex(),
                    "the Coach skipped an owner's digest settings"
                ),
            }
        }
    }

    /// Every owner with an Owner schedule.
    fn owner_schedule_ids(&self) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let mut owners = Vec::new();
        for row in SCHEDULES.iter_raw_from(&self.store, &txn, &OWNER_TAG)? {
            let (key, _) = row?;
            if let Some(owner) = key
                .get(1..)
                .and_then(|id| <[u8; 16]>::try_from(id).ok())
                .and_then(|id| EntityId::from_bytes(id).ok())
            {
                owners.push(owner);
            }
        }
        Ok(owners)
    }

    /// One owner's evaluation by the closed-form rule, filed through
    /// [`Self::file_coach_step_in_txn`]. `true`: a change applied.
    fn coach_owner_weave_digest(&self, owner: EntityId, now: u64) -> Result<bool> {
        {
            let txn = self.store.env.read_txn()?;
            let settings = settings_row_in_txn(&self.store, &txn, owner)?;
            if !evaluation_due(settings.last_evaluated_at, now) {
                return Ok(false);
            }
        }
        self.with_write_txn_grouped(|txn| {
            // A row that no longer decodes is rebuilt here (FIX 5633).
            let mut settings = settings_row_in_txn(&self.store, txn, owner)?;
            if !evaluation_due(settings.last_evaluated_at, now) {
                return Ok(false);
            }
            settings.last_evaluated_at = Some(now);
            SETTINGS.put(&self.store, txn, &owner, &settings)?;
            let Some(wire) = owner_wire_in_txn(&self.store, txn, owner)? else {
                return Ok(false);
            };
            let changes = owner_changes_in_txn(&self.store, txn, owner)?;
            // At most one proposal waits for him at a time.
            if changes
                .iter()
                .any(|(_, change)| change.status == Status::Pending)
            {
                return Ok(false);
            }
            let refused: Vec<CoachStep> = changes
                .iter()
                .filter(|(_, change)| refused_under(change, settings.generation))
                .filter_map(|(_, change)| step_of(change))
                .collect();
            let periods = self.owner_period_records_in_txn(txn, owner)?;
            let before = settings_of(&wire);
            let Some(drafted) = weave_digest_coach_step(&CoachInput {
                now,
                cadence: wire.cadence,
                sections: &before.sections,
                feedback: settings.feedback.as_ref(),
                periods: &periods,
                refused: &refused,
            }) else {
                return Ok(false);
            };
            self.file_coach_step_in_txn(txn, owner, settings.generation, wire, drafted, now)
        })
    }

    /// Files the Coach's step and its reason on the owner's schedule row
    /// `wire`, read in this write at settings `generation`, whether the rule
    /// or the Coach's model chose it. With a live Grant of the Coach that
    /// names this owner's digest settings, the step applies, attributed to
    /// the Coach and the Grant, with the owner's notice and its undo in the
    /// same commit; with no such Grant, or any error reading it, it lands as
    /// a proposal, which names a Grant passed over on its lapsed pact
    /// membership alone (FIX 7548). `true`: a change applied.
    fn file_coach_step_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        generation: u64,
        wire: WireSchedule,
        (step, reason): (CoachStep, String),
        now: u64,
    ) -> Result<bool> {
        let before = settings_of(&wire);
        let mut after_wire = wire;
        if !take_step(&mut after_wire, step) {
            return Ok(false);
        }
        let coach = self.coach_authority_in_txn(txn)?.entity_ref();
        // Any error reading the Grant means a proposal, never an apply.
        let grant = self
            .coach_weave_digest_settings_grant_in_txn(txn, coach, owner)
            .unwrap_or_else(|error| {
                tracing::warn!(
                    error_kind = ?error.kind(),
                    "the Coach's digest settings Grant was not read"
                );
                Err(crate::authority::NoStanding::NotStanding)
            });
        let id = change_id(owner, generation, step, now)?;
        let mut change = WeaveDigestSettingChange {
            change_ref: id.to_hex(),
            status: Status::Pending,
            before,
            after: settings_of(&after_wire),
            reason,
            coach_ref: coach.to_hex(),
            grant_ref: None,
            base_generation: generation,
            after_generation: None,
            undone_generation: None,
            created_at: now,
            settled_at: None,
            grant_omitted: None,
        };
        let grant = match grant {
            Ok(grant) => grant,
            Err(no_standing) => {
                change.grant_omitted =
                    crate::authority::grant_omission(no_standing).map(str::to_owned);
                CHANGES.put(&self.store, txn, &(owner, id), &change)?;
                self.notify_setting_change_in_txn(txn, owner, &change, NotificationKind::Ask, now)?;
                return Ok(false);
            }
        };
        let bytes = serde_json::to_vec(&after_wire).map_err(|_| invalid())?;
        let after = self.put_owner_weave_digest_schedule_in_txn(
            txn,
            owner,
            &bytes,
            SettingsEdit::Change,
            now,
        )?;
        change.status = Status::Applied;
        change.grant_ref = Some(grant.to_hex());
        change.after_generation = Some(after);
        change.settled_at = Some(now);
        CHANGES.put(&self.store, txn, &(owner, id), &change)?;
        self.retire_answered_feedback_in_txn(txn, owner, &change)?;
        self.notify_setting_change_in_txn(
            txn,
            owner,
            &change,
            NotificationKind::WeaveDigestSettingsChanged,
            now,
        )?;
        Ok(true)
    }

    /// The owner's own period records, each unopened period's dismissal read
    /// off its due notice: his acknowledgement on the notice the timer sent
    /// him for that period.
    fn owner_period_records_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: EntityId,
    ) -> Result<Vec<PeriodRecord>> {
        let mut records = Vec::new();
        for (scheduled_for, row) in owner_periods_in_txn(&self.store, txn, owner)? {
            let dismissed = match (&row.notice_ref, row.opened_at) {
                (Some(notice), None) => {
                    self.notice_dismissed_in_txn(txn, owner, scheduled_for, notice)?
                }
                _ => false,
            };
            records.push(PeriodRecord {
                scheduled_for,
                cadence: row.cadence,
                opened_at: row.opened_at,
                dismissed,
            });
        }
        Ok(records)
    }

    /// Whether the owner acknowledged the due notice `notice` of his period
    /// `scheduled_for`: a live weave digest notice for him, of that period,
    /// that carries his key among its acknowledgements.
    fn notice_dismissed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: EntityId,
        scheduled_for: u64,
        notice: &str,
    ) -> Result<bool> {
        let Ok(id) = EntityId::from_hex(notice) else {
            return Ok(false);
        };
        let crate::vault::LiveEntityRow::Live { entity_type, body } =
            crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?
        else {
            return Ok(false);
        };
        if entity_type != crate::registry::ENTITY_TYPE_NOTIFICATION {
            return Ok(false);
        }
        let Ok(body) = crate::inbox::decode_notification_body(&body) else {
            return Ok(false);
        };
        let key = owner.to_hex();
        let period = scheduled_for.to_string();
        if body.source.producer != WEAVE_DIGEST_NOTIFICATION_PRODUCER
            || body.recipient.as_deref() != Some(key.as_str())
            || body.source.result.as_deref() != Some(period.as_str())
        {
            return Ok(false);
        }
        Ok(self
            .owner_ack_keys_in_txn(txn, owner)?
            .iter()
            .any(|key| body.acked_by.get(key) == Some(&true)))
    }

    /// The actor keys the owner acknowledges his own notices under (FIX
    /// 5630): his own key, and on a personal vault, of which the embedded
    /// owner is the one owner, the host's own-device lane he reads through.
    fn owner_ack_keys_in_txn(&self, txn: &heed::RoTxn<'_>, owner: EntityId) -> Result<Vec<String>> {
        let mut keys = vec![owner.to_hex()];
        let embedded = crate::vault::embedded_owner_actor_id()?;
        if embedded != owner && crate::policy_model::owners_in_txn(self, txn)? == [embedded] {
            keys.push(embedded.to_hex());
        }
        Ok(keys)
    }

    /// Settles the owner's ask about `change` once it left pending (FIX
    /// 5631): seen and acked for him, it stays in his inbox as answered,
    /// never as one still waiting on him. An ask already acked, or deleted,
    /// stays as it is.
    pub(super) fn settle_weave_setting_ask_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        change: &WeaveDigestSettingChange,
    ) -> Result<()> {
        // Its own event finds its row untouched, as a replay does.
        let ask = self.record_notification_in_txn(
            txn,
            &setting_change_event(owner, change, NotificationKind::Ask, change.created_at),
        )?;
        let crate::vault::LiveEntityRow::Live { entity_type, body } =
            crate::vault::live_entity_row_in_txn(&self.store, &*txn, &ask)?
        else {
            return Ok(());
        };
        if entity_type != crate::registry::ENTITY_TYPE_NOTIFICATION {
            return Ok(());
        }
        let mut body = crate::inbox::decode_notification_body(&body)?;
        let key = owner.to_hex();
        if body.acked_by.get(&key) == Some(&true) {
            return Ok(());
        }
        body.seen_by.insert(key.clone(), true);
        body.acked_by.insert(key, true);
        self.put_notification_in_txn(txn, &ask, &body)?;
        Ok(())
    }

    /// [`retire_answered_feedback`] on the owner's settings row, in the
    /// settling write.
    fn retire_answered_feedback_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        change: &WeaveDigestSettingChange,
    ) -> Result<()> {
        let mut row = settings_row_in_txn(&self.store, txn, owner)?;
        if retire_answered_feedback(&mut row, change) {
            SETTINGS.put(&self.store, txn, &owner, &row)?;
        }
        Ok(())
    }

    /// The owner's notice about `change`: an ask while it is pending, else a
    /// settings-changed notice whose one tap is its undo.
    fn notify_setting_change_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        change: &WeaveDigestSettingChange,
        kind: NotificationKind,
        now: u64,
    ) -> Result<()> {
        self.record_notification_in_txn(txn, &setting_change_event(owner, change, kind, now))
            .map(drop)
    }

    /// The owner's own digest settings changes, newest first (FIX 5495).
    pub fn weave_digest_setting_changes(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<Vec<WeaveDigestSettingChange>> {
        let txn = self.store.env.read_txn()?;
        let actor = owner.revalidate_in_txn(self, &txn)?;
        let mut changes: Vec<_> = owner_changes_in_txn(&self.store, &txn, actor)?
            .into_iter()
            .map(|(_, change)| change)
            .collect();
        changes.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| b.change_ref.cmp(&a.change_ref))
        });
        Ok(changes)
    }

    /// The owner's answer to his own proposed change `change`. An accept is
    /// his own act: it applies through the same writer as his own schedule
    /// edit, only while the settings are still the generation it was
    /// proposed against, and gets its notice and one-tap undo. A stale
    /// accept marks the change superseded and applies nothing.
    ///
    /// # Errors
    /// [`Error::EntityNotFound`] for no such change of his;
    /// [`Error::InvalidConfig`] for one already settled, or a stale accept.
    pub fn answer_weave_digest_setting_change(
        &self,
        owner: &AuthenticatedOwner,
        change: EntityId,
        accept: bool,
    ) -> Result<WeaveDigestSettingChange> {
        let now = self.store.clock.now_recorded_at();
        let (answered, applied): (std::result::Result<WeaveDigestSettingChange, &str>, bool) = self
            .with_write_txn_grouped(|txn| {
                let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
                let key = (actor, change);
                let mut stored = CHANGES
                    .get(&self.store, txn, &key)?
                    .ok_or(Error::EntityNotFound)?;
                if stored.status != Status::Pending {
                    return Err(Error::InvalidConfig(SETTLED.to_owned()));
                }
                if !accept {
                    stored.status = Status::Declined;
                    stored.settled_at = Some(now);
                    CHANGES.put(&self.store, txn, &key, &stored)?;
                    self.settle_weave_setting_ask_in_txn(txn, actor, &stored)?;
                    self.retire_answered_feedback_in_txn(txn, actor, &stored)?;
                    return Ok((Ok(stored), false));
                }
                let generation = settings_row_in_txn(&self.store, txn, actor)?.generation;
                let current = owner_wire_in_txn(&self.store, txn, actor)?.filter(|wire| {
                    generation == stored.base_generation && settings_of(wire) == stored.before
                });
                let step = step_of(&stored);
                let (Some(mut wire), Some(step)) = (current, step) else {
                    stored.status = Status::Superseded;
                    stored.settled_at = Some(now);
                    CHANGES.put(&self.store, txn, &key, &stored)?;
                    self.settle_weave_setting_ask_in_txn(txn, actor, &stored)?;
                    return Ok((Err(STALE_ACCEPT), false));
                };
                if !take_step(&mut wire, step) {
                    return Err(invalid());
                }
                let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
                let after = self.put_owner_weave_digest_schedule_in_txn(
                    txn,
                    actor,
                    &bytes,
                    SettingsEdit::Change,
                    now,
                )?;
                stored.status = Status::Accepted;
                stored.after_generation = Some(after);
                stored.settled_at = Some(now);
                CHANGES.put(&self.store, txn, &key, &stored)?;
                self.settle_weave_setting_ask_in_txn(txn, actor, &stored)?;
                self.retire_answered_feedback_in_txn(txn, actor, &stored)?;
                self.notify_setting_change_in_txn(
                    txn,
                    actor,
                    &stored,
                    NotificationKind::WeaveDigestSettingsChanged,
                    now,
                )?;
                Ok((Ok(stored), true))
            })?;
        if applied {
            self.store.notify_proactivity_changes();
        }
        answered.map_err(|refusal| Error::InvalidConfig(refusal.to_owned()))
    }

    /// The owner's one-tap undo of an applied or accepted change `change`,
    /// his own act: the rhythm and section order before it come back, with
    /// the schedule's due time and holds as they are now, only while the
    /// settings are still the generation the change wrote. A retry answers
    /// what the first tap did. No clock ends it (CALLS: FIX 5495 undo).
    ///
    /// # Errors
    /// [`Error::EntityNotFound`] for no such change of his;
    /// [`Error::InvalidConfig`] for a change with no undo, or settings that
    /// changed since it.
    pub fn undo_weave_digest_setting_change(
        &self,
        owner: &AuthenticatedOwner,
        change: EntityId,
    ) -> Result<WeaveDigestSettingChange> {
        let now = self.store.clock.now_recorded_at();
        let (undone, applied) = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let key = (actor, change);
            let mut stored = CHANGES
                .get(&self.store, txn, &key)?
                .ok_or(Error::EntityNotFound)?;
            match stored.status {
                Status::Undone => return Ok((stored, false)),
                Status::Applied | Status::Accepted => {}
                Status::Pending | Status::Declined | Status::Superseded => {
                    return Err(Error::InvalidConfig(NOT_UNDOABLE.to_owned()));
                }
            }
            let generation = settings_row_in_txn(&self.store, txn, actor)?.generation;
            let Some(mut wire) = owner_wire_in_txn(&self.store, txn, actor)?.filter(|wire| {
                stored.after_generation == Some(generation) && settings_of(wire) == stored.after
            }) else {
                return Err(Error::InvalidConfig(STALE_UNDO.to_owned()));
            };
            restore(&mut wire, &stored.before)?;
            let bytes = serde_json::to_vec(&wire).map_err(|_| invalid())?;
            let after = self.put_owner_weave_digest_schedule_in_txn(
                txn,
                actor,
                &bytes,
                SettingsEdit::Change,
                now,
            )?;
            stored.status = Status::Undone;
            stored.undone_generation = Some(after);
            stored.settled_at = Some(now);
            CHANGES.put(&self.store, txn, &key, &stored)?;
            Ok((stored, true))
        })?;
        if applied {
            self.store.notify_proactivity_changes();
        }
        Ok(undone)
    }

    /// What the owner tells the Coach about his own digest: the rhythm he
    /// wants, the section he wants first (already one of his schedule's),
    /// or to keep it as it is. His next own schedule edit retires it.
    ///
    /// # Errors
    /// [`Error::InvalidConfig`] when he has no digest schedule, or names a
    /// lead section it does not hold.
    pub fn set_weave_digest_feedback(
        &self,
        owner: &AuthenticatedOwner,
        feedback: &WeaveDigestFeedback,
    ) -> Result<WeaveDigestFeedback> {
        let now = self.store.clock.now_recorded_at();
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            let wire = owner_wire_in_txn(&self.store, txn, actor)?
                .ok_or_else(|| Error::InvalidConfig(NO_SCHEDULE.to_owned()))?;
            if let Some(kind) = feedback.lead_section
                && !wire.recipe.iter().any(|section| section.kind == kind)
            {
                return Err(Error::InvalidConfig(LEAD_NOT_IN_RECIPE.to_owned()));
            }
            let mut settings = settings_row_in_txn(&self.store, txn, actor)?;
            settings.feedback = Some(StoredFeedback {
                preferred_cadence: feedback.preferred_cadence,
                lead_section: feedback.lead_section,
                keep_current: feedback.keep_current,
                given_at: now,
                generation: settings.generation,
            });
            SETTINGS.put(&self.store, txn, &actor, &settings)?;
            Ok(feedback.clone())
        })
    }
}
