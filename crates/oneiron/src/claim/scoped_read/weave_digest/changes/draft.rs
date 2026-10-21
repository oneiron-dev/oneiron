//! The Coach's model drafts each owner's digest settings step (FIX 5609;
//! ARCH-0026, DEC-0005 policy residence). What to propose is policy, so a
//! host Coach runs the `weave-digest-settings` hub skill on the owner's own
//! record. The substrate stays the rule path's: his own signals, the Grant
//! check, apply or propose, the notice, the change row and its
//! generation-checked undo. One owner's evaluation reads a snapshot, asks the
//! model with no transaction open, then files only while nothing the filing
//! depends on moved. A drafter that is unavailable leaves the step to the
//! closed-form rule, on a fresh read.

use std::sync::atomic::Ordering;

use super::super::coach::{
    CoachDraft, CoachInput, CoachStep, WeaveDigestSettingsDrafter, coach_brief_sources,
    weave_digest_coach_brief, weave_digest_coach_draft,
};
use super::super::settings::{
    SETTINGS, StoredFeedback, WeaveDigestSettingChangeStatus as Status, WeaveDigestSettings,
    owner_changes_in_txn, owner_wire_in_txn, settings_row_in_txn,
};
use super::{evaluation_due, refused_under, settings_of, step_of};
use crate::dreamer_runner::maintenance::coach::{
    COACH_HOST_QUEUE_KIND, COACH_WEAVE_DIGEST_SETTINGS_FACET,
};
use crate::dreamer_runner::{DreamerAdmittedAttempt, DreamerAttemptPayload, DreamerRunnerStore};
use crate::error::Result;
use crate::{EntityId, Vault};

/// The hub skill the Coach's model drafts with (ARCH-0053): loaded by name
/// from what a skill hub provided, never embedded in the engine.
const WEAVE_DIGEST_SETTINGS_SKILL_NAME: &str = "weave-digest-settings";

/// What one owner's filing must find unchanged since his draft was read.
struct Basis {
    generation: u64,
    last_evaluated_at: Option<u64>,
    feedback: Option<StoredFeedback>,
    /// His settings; `None` with no schedule.
    before: Option<WeaveDigestSettings>,
    /// A proposal waits for him.
    pending: bool,
    /// The steps he declined or undid under `generation`.
    refused: Vec<CoachStep>,
}

impl Basis {
    /// Nothing the filing depends on moved: his settings and their
    /// generation, what he told the Coach and when, a waiting proposal, what
    /// he refused, and the last evaluation.
    fn holds(&self, current: &Self) -> bool {
        let told = |basis: &Self| {
            basis.feedback.as_ref().map(|feedback| {
                (
                    feedback.preferred_cadence,
                    feedback.lead_section,
                    feedback.keep_current,
                    feedback.given_at,
                    feedback.generation,
                )
            })
        };
        self.generation == current.generation
            && self.last_evaluated_at == current.last_evaluated_at
            && told(self) == told(current)
            && self.before == current.before
            && self.pending == current.pending
            && self.refused == current.refused
    }
}

impl Vault {
    /// Marks this open vault as served by a host Coach whose model drafts its
    /// digest settings steps (FIX 5609): from then on the digest timer queues
    /// the Coach's job instead of running the closed-form rule. In memory
    /// only: a reopened vault starts unmarked.
    pub fn register_coach_weave_digest_host(&self) {
        self.coach_weave_digest_host.store(true, Ordering::Release);
    }

    /// A host Coach drafts this vault's digest settings steps.
    pub(super) fn coach_weave_digest_host_registered(&self) -> bool {
        self.coach_weave_digest_host.load(Ordering::Acquire)
    }

    /// The timer's part while a host Coach serves this vault: the Coach's
    /// job, queued under its facet's fixed key while any owner's evaluation
    /// is due, so an unleased job absorbs the next pass's. Queueing marks no
    /// owner evaluated. A failure is logged and skipped.
    pub(super) fn queue_coach_weave_digest_settings(&self, now: u64) {
        if let Err(error) = self.try_queue_coach_weave_digest_settings(now) {
            tracing::warn!(?error, "the Coach's digest settings job was not queued");
        }
    }

    fn try_queue_coach_weave_digest_settings(&self, now: u64) -> Result<()> {
        let owners = self.owner_schedule_ids()?;
        let due = {
            let txn = self.store.env.read_txn()?;
            let mut due = false;
            for owner in owners {
                let settings = settings_row_in_txn(&self.store, &txn, owner)?;
                if evaluation_due(settings.last_evaluated_at, now) {
                    due = true;
                    break;
                }
            }
            due
        };
        if !due {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            DreamerRunnerStore::new(self)
                .enqueue_kind_in_txn(
                    txn,
                    COACH_HOST_QUEUE_KIND,
                    DreamerAttemptPayload {
                        attempt_type: COACH_WEAVE_DIGEST_SETTINGS_FACET.into(),
                        input: rmpv::Value::Nil,
                        parent_attempt: None,
                    },
                    Some(COACH_WEAVE_DIGEST_SETTINGS_FACET.into()),
                    None,
                    now,
                )
                .map(drop)
        })
    }

    /// The `weave-digest-settings` skill a skill hub provided this vault
    /// (FIX 5609): a live, active, approved shared skill of that name that
    /// keeps an active hub provenance, the first in id order. `None`: no hub
    /// row provides it, and the Coach's model drafts nothing.
    ///
    /// # Errors
    /// Storage errors.
    pub fn weave_digest_settings_skill(&self) -> Result<Option<EntityId>> {
        let named = {
            let txn = self.store.env.read_txn()?;
            let mut named = Vec::new();
            for id in crate::ports::EntityStoreRead::port_entity_ids_by_type(
                &self.store,
                &txn,
                crate::registry::ENTITY_TYPE_SKILL,
                None,
            )? {
                let id = id?;
                if !crate::vault::live_entity_row_in_txn(&self.store, &txn, &id)?.is_live() {
                    continue;
                }
                // A row that does not read is no skill to load.
                let Ok(Some(record)) = self.get_skill_record_in_txn(&txn, &id) else {
                    continue;
                };
                if record.skill_id == WEAVE_DIGEST_SETTINGS_SKILL_NAME
                    && crate::skill::skill_loadable(&record)
                    && matches!(crate::skill::resident_of(&record), Ok(None))
                {
                    named.push(id);
                }
            }
            named
        };
        for id in named {
            if self.skill_hub_provenance_count(&id)? > 0 {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// The Coach's digest settings pass under a leased
    /// `coach.weave_digest_settings` attempt (FIX 5609), on the home node
    /// only, as the timer's is. Each owner whose evaluation is due gets the
    /// step `drafter` drafts, which the engine checks and files as it files
    /// the rule's. An owner's failure is logged and skipped.
    ///
    /// # Errors
    /// An attempt that is not this facet's Coach attempt, or storage errors
    /// before any owner is read.
    pub fn run_coach_weave_digest_settings(
        &self,
        attempt: &DreamerAdmittedAttempt,
        drafter: &dyn WeaveDigestSettingsDrafter,
        now: u64,
    ) -> Result<()> {
        self.require_coach_attempt(attempt, COACH_WEAVE_DIGEST_SETTINGS_FACET)?;
        let store = DreamerRunnerStore::new(self);
        let local = store
            .local_home_node_candidate(false, false, false)?
            .node_id;
        if store
            .home_node_designation()?
            .is_none_or(|home| home.node_id != local)
        {
            return Ok(());
        }
        for owner in self.owner_schedule_ids()? {
            match self.draft_owner_weave_digest(owner, drafter, now) {
                // The deadline timer re-reads committed rows on this signal.
                Ok(true) => self.store.notify_proactivity_changes(),
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    ?error,
                    owner = %owner.to_hex(),
                    "the Coach skipped an owner's digest settings"
                ),
            }
        }
        Ok(())
    }

    /// One owner's evaluation on the Coach's model, at most once per
    /// evaluation window. An unavailable drafter hands him to the rule; a
    /// valid `{"step": null}` or a refused draft evaluates him with nothing
    /// written. `true`: a change applied.
    fn draft_owner_weave_digest(
        &self,
        owner: EntityId,
        drafter: &dyn WeaveDigestSettingsDrafter,
        now: u64,
    ) -> Result<bool> {
        let (basis, periods) = {
            let txn = self.store.env.read_txn()?;
            let basis = self.coach_basis_in_txn(&txn, owner)?;
            if !evaluation_due(basis.last_evaluated_at, now) {
                return Ok(false);
            }
            let periods = if basis.before.is_some() && !basis.pending {
                self.owner_period_records_in_txn(&txn, owner)?
            } else {
                Vec::new()
            };
            (basis, periods)
        };
        // No schedule, or a proposal waiting for him: he is evaluated with
        // nothing asked, as the rule has it.
        let mut step = None;
        if let Some(before) = basis.before.as_ref().filter(|_| !basis.pending) {
            let input = CoachInput {
                now,
                cadence: before.cadence,
                sections: &before.sections,
                feedback: basis.feedback.as_ref(),
                periods: &periods,
                refused: &basis.refused,
            };
            // No transaction is open across the model's call.
            let brief = weave_digest_coach_brief(&input)?;
            let sources = coach_brief_sources(&input);
            let Some(answer) = drafter.draft_sourced(owner, basis.generation, &brief, sources)?
            else {
                // Unavailable: the closed-form rule decides, on a fresh read.
                return self.coach_owner_weave_digest(owner, now);
            };
            match weave_digest_coach_draft(&input, &answer) {
                CoachDraft::Step(chosen, reason) => step = Some((chosen, reason)),
                CoachDraft::Nothing => {}
                CoachDraft::Refused => tracing::debug!(
                    owner = %owner.to_hex(),
                    "the Coach's digest settings draft was refused"
                ),
            }
        }
        self.with_write_txn_grouped(|txn| {
            // Anything he did since the read, or another evaluation, drops
            // the draft: the next pass evaluates him from what he has then.
            if !basis.holds(&self.coach_basis_in_txn(txn, owner)?) {
                return Ok(false);
            }
            let mut settings = settings_row_in_txn(&self.store, txn, owner)?;
            settings.last_evaluated_at = Some(now);
            SETTINGS.put(&self.store, txn, &owner, &settings)?;
            let Some(drafted) = step else {
                return Ok(false);
            };
            let Some(wire) = owner_wire_in_txn(&self.store, txn, owner)? else {
                return Ok(false);
            };
            self.file_coach_step_in_txn(txn, owner, settings.generation, wire, drafted, now)
        })
    }

    /// What one owner's filing checks again, read in `txn`.
    fn coach_basis_in_txn(&self, txn: &heed::RoTxn<'_>, owner: EntityId) -> Result<Basis> {
        let settings = settings_row_in_txn(&self.store, txn, owner)?;
        let before = owner_wire_in_txn(&self.store, txn, owner)?
            .as_ref()
            .map(settings_of);
        let changes = owner_changes_in_txn(&self.store, txn, owner)?;
        Ok(Basis {
            generation: settings.generation,
            last_evaluated_at: settings.last_evaluated_at,
            before,
            pending: changes
                .iter()
                .any(|(_, change)| change.status == Status::Pending),
            refused: changes
                .iter()
                .filter(|(_, change)| refused_under(change, settings.generation))
                .filter_map(|(_, change)| step_of(change))
                .collect(),
            feedback: settings.feedback,
        })
    }
}
