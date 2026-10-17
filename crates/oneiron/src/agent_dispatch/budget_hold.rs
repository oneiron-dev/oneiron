//! The graceful stop (ARCH-0079 #budget, OF-541): a run near the end of
//! its lease gets the wrap-up warning, then stops with its partial results
//! saved in a state it resumes from, and the owner gets a notice. A
//! suspension is a hold, not a kill.
//!
//! The scoped spend signal drives it. At the wrap-up boundary every running
//! attempt of the run gets the queue's budget warning (finish the step, hand
//! over what exists). At the cap, the worker holding an attempt parks it
//! through the queue's lease-fenced hold door with its checkpoint; the
//! attempt is `Paused`, never `Cancelled`, and no TASK terminal report is
//! written. The durable [`PartialResultHold`] gathers the run's saved
//! results and checkpoints, the notice and whether it was delivered, and
//! whether the run can resume. Resume is the ordinary queue intervention on
//! the same rows.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{
    AttemptId, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptResumePoint,
    AttemptState, HoldAttemptForBudget, InterveneAttempt, LandingWarningOutcome,
    WarnAttemptBudgetPressure,
};
use crate::error::Result;
use crate::side_table::{self, LegacyJson, SideTable};

use super::AgentDispatcher;
use super::planner::TeamPlan;
use super::spend_record::{SpendRead, SpendScopeId, SpendSignal};
use super::widen_record::invalid;

/// Where a run's budget hold stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetHoldState {
    /// The wrap-up warning went out; nothing is parked yet.
    Warned,
    /// At least one attempt is parked at the cap.
    Held,
    /// The owner resumed the run.
    Resumed,
}

/// One attempt the hold parked, with the checkpoint it resumes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldAttempt {
    pub attempt: AttemptId,
    pub resume_point: AttemptResumePoint,
}

/// The owner's notice of a held run, and whether the host delivered it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetHoldNotice {
    pub text: String,
    /// Unix seconds the host delivered it; `None` while it is still owed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<u64>,
}

/// A run's saved partial state (ARCH-0079 #budget): who was warned, which
/// attempts are parked and where each resumes, the results the run already
/// saved, the plan it ran, the owner's notice and whether the run can
/// resume. The hold is what a resume reads; the attempts themselves sit in
/// the queue's paused state, never killed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartialResultHold {
    /// The spawn (root) attempt this hold belongs to.
    pub root_attempt: AttemptId,
    pub state: BudgetHoldState,
    /// Attempts the wrap-up warning reached.
    #[serde(default)]
    pub warned: Vec<AttemptId>,
    #[serde(default)]
    pub held: Vec<HeldAttempt>,
    /// Saved result handles the run produced before the hold.
    #[serde(default)]
    pub partial_result_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<TeamPlan>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warned_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<BudgetHoldNotice>,
    /// Whether the run's spend scope has spend left now, as last read.
    #[serde(default)]
    pub resume_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_by: Option<String>,
}

/// The lease a worker holds on the attempt it parks: what its claim
/// returned, and the checkpoint the same work resumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetHoldLease {
    pub attempt: AttemptId,
    pub lease_owner: String,
    pub attempt_count: u32,
    pub resume_point: AttemptResumePoint,
}

/// Holds keyed by root attempt id.
const PLAN_HOLD: SideTable<AttemptId, PartialResultHold, LegacyJson> =
    SideTable::new(&side_table::AGENT_DISPATCH_PLAN_HOLD);

impl PartialResultHold {
    fn new(root_attempt: AttemptId, reason: &str) -> Self {
        Self {
            root_attempt,
            state: BudgetHoldState::Warned,
            warned: Vec::new(),
            held: Vec::new(),
            partial_result_refs: Vec::new(),
            plan: None,
            reason: reason.to_owned(),
            warned_at: None,
            held_at: None,
            notice: None,
            resume_ready: false,
            resumed_at: None,
            resumed_by: None,
        }
    }

    fn notice_text(&self) -> String {
        format!(
            "run held at its spend cap with {} saved result(s) and {} parked agent(s); resume it once the budget allows",
            self.partial_result_refs.len(),
            self.held.len()
        )
    }
}

impl AgentDispatcher<'_> {
    /// Acts on one scoped spend signal for the run rooted at `root`: at the
    /// wrap-up boundary or the cap, every running attempt of the run except
    /// `own` (the caller's) gets the budget warning. Parking is the lease
    /// holder's act ([`Self::hold_for_budget`]). `None` with no signal.
    ///
    /// # Errors
    ///
    /// As [`Self::warn_for_budget`].
    pub fn budget_signal(
        &self,
        root: AttemptId,
        read: &SpendRead,
        own: Option<AttemptId>,
        reason: &str,
        now: u64,
    ) -> Result<Option<PartialResultHold>> {
        match read.signal {
            Some(SpendSignal::WrapUp { .. } | SpendSignal::AtCap { .. }) => {
                self.warn_for_budget(root, own, reason, now).map(Some)
            }
            None => Ok(None),
        }
    }

    /// The wrap-up warning (the queue's `budget.land.95` rung): every
    /// running attempt in the run gets one budget-pressure landing request,
    /// idempotent per outstanding ask, and the hold records who was warned.
    /// Nothing is cancelled.
    ///
    /// # Errors
    ///
    /// A blank reason, a missing root, or storage errors.
    pub fn warn_for_budget(
        &self,
        root: AttemptId,
        own: Option<AttemptId>,
        reason: &str,
        now: u64,
    ) -> Result<PartialResultHold> {
        if reason.trim().is_empty() {
            return Err(invalid("a budget hold names its reason"));
        }
        let queue = AttemptQueue::new(self.vault);
        let mut warned = Vec::new();
        for attempt in self.run_attempts(root)? {
            if Some(attempt.id) == own || attempt.state != AttemptState::Leased {
                continue;
            }
            match queue.warn_budget_pressure(WarnAttemptBudgetPressure {
                id: attempt.id,
                now,
            })? {
                LandingWarningOutcome::LandingRequested(_)
                | LandingWarningOutcome::AlreadyRequested(_) => warned.push(attempt.id),
                _ => {}
            }
        }
        let mut wtxn = self.vault.store.env.write_txn()?;
        let mut hold = PLAN_HOLD
            .get(&self.vault.store, &wtxn, &root)?
            .unwrap_or_else(|| PartialResultHold::new(root, reason));
        for id in warned {
            if !hold.warned.contains(&id) {
                hold.warned.push(id);
            }
        }
        hold.warned_at.get_or_insert(now);
        PLAN_HOLD.put(&self.vault.store, &mut wtxn, &root, &hold)?;
        wtxn.commit()?;
        Ok(hold)
    }

    /// Parks the caller's own attempt at the spend cap: the queue's
    /// lease-fenced hold moves it to `Paused` with its checkpoint, and the
    /// run's hold gathers its saved results and owes the owner a notice, in
    /// one transaction. Never `Cancelled`, never a TASK terminal report.
    ///
    /// # Errors
    ///
    /// A stale lease, an attempt that is not running, or storage errors.
    pub fn hold_for_budget(
        &self,
        root: AttemptId,
        lease: BudgetHoldLease,
        plan: Option<TeamPlan>,
        reason: &str,
        now: u64,
    ) -> Result<PartialResultHold> {
        if reason.trim().is_empty() {
            return Err(invalid("a budget hold names its reason"));
        }
        let saved: Vec<String> = self
            .run_attempts(root)?
            .into_iter()
            .filter(|attempt| attempt.state == AttemptState::Completed)
            .filter_map(|attempt| attempt.result_ref.map(|result| result.as_str().to_owned()))
            .collect();
        let ready = self.scope_has_spend(root)?;
        let queue = AttemptQueue::new(self.vault);
        let mut wtxn = self.vault.store.env.write_txn()?;
        queue.hold_for_budget_in_txn(
            &mut wtxn,
            HoldAttemptForBudget {
                id: lease.attempt,
                lease_owner: lease.lease_owner,
                attempt_count: lease.attempt_count,
                resume_point: lease.resume_point.clone(),
                now,
            },
        )?;
        let mut hold = PLAN_HOLD
            .get(&self.vault.store, &wtxn, &root)?
            .unwrap_or_else(|| PartialResultHold::new(root, reason));
        hold.state = BudgetHoldState::Held;
        hold.held.retain(|held| held.attempt != lease.attempt);
        hold.held.push(HeldAttempt {
            attempt: lease.attempt,
            resume_point: lease.resume_point,
        });
        for result in saved {
            if !hold.partial_result_refs.contains(&result) {
                hold.partial_result_refs.push(result);
            }
        }
        if plan.is_some() {
            hold.plan = plan;
        }
        hold.held_at = Some(now);
        hold.resume_ready = ready;
        hold.resumed_at = None;
        hold.resumed_by = None;
        hold.notice = Some(BudgetHoldNotice {
            text: hold.notice_text(),
            delivered_at: None,
        });
        PLAN_HOLD.put(&self.vault.store, &mut wtxn, &root, &hold)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(hold)
    }

    /// Records that the host delivered the hold's notice to the owner.
    ///
    /// # Errors
    ///
    /// A run with no hold or no notice owed; storage errors.
    pub fn acknowledge_budget_notice(
        &self,
        root: AttemptId,
        now: u64,
    ) -> Result<PartialResultHold> {
        self.update_hold(root, |hold| {
            let notice = hold
                .notice
                .as_mut()
                .ok_or_else(|| invalid("budget hold owes no notice"))?;
            notice.delivered_at.get_or_insert(now);
            Ok(())
        })
    }

    /// Re-reads whether the held run's scope has spend left and records it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn refresh_budget_hold(&self, root: AttemptId) -> Result<Option<PartialResultHold>> {
        if self.plan_hold(root)?.is_none() {
            return Ok(None);
        }
        let ready = self.scope_has_spend(root)?;
        self.update_hold(root, |hold| {
            hold.resume_ready = ready;
            Ok(())
        })
        .map(Some)
    }

    /// Resumes a held run: the ordinary `Resume` intervention, as `actor`,
    /// on every attempt the hold still parks, so the same logical work is
    /// queued again and its next lease reads its checkpoint. A row someone
    /// else paused or settled since is left as it is.
    ///
    /// # Errors
    ///
    /// A blank or reserved actor, a run with no hold, or storage errors.
    pub fn resume_budget_hold(
        &self,
        root: AttemptId,
        actor: &str,
        now: u64,
    ) -> Result<PartialResultHold> {
        if actor.trim().is_empty() {
            return Err(invalid("a resume names its actor"));
        }
        let hold = self
            .plan_hold(root)?
            .ok_or_else(|| invalid("run has no budget hold"))?;
        let ready = self.scope_has_spend(root)?;
        let queue = AttemptQueue::new(self.vault);
        let mut wtxn = self.vault.store.env.write_txn()?;
        for held in &hold.held {
            let still_held = queue
                .get_in_write_txn(&wtxn, held.attempt)?
                .is_some_and(|record| record.budget_hold());
            if still_held {
                queue.intervene_in_txn(
                    &mut wtxn,
                    InterveneAttempt {
                        id: held.attempt,
                        kind: AttemptInterventionKind::Resume,
                        actor: actor.to_owned(),
                        note: Some("resume from the budget hold".to_owned()),
                        now,
                    },
                )?;
            }
        }
        let mut hold = hold;
        hold.state = BudgetHoldState::Resumed;
        hold.resume_ready = ready;
        hold.resumed_at = Some(now);
        hold.resumed_by = Some(actor.to_owned());
        PLAN_HOLD.put(&self.vault.store, &mut wtxn, &root, &hold)?;
        wtxn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(hold)
    }

    /// The saved hold for a run, if one was warned or held.
    pub fn plan_hold(&self, root_attempt: AttemptId) -> Result<Option<PartialResultHold>> {
        let rtxn = self.vault.store.env.read_txn()?;
        PLAN_HOLD.get(&self.vault.store, &rtxn, &root_attempt)
    }

    /// Clear a hold once its run has resumed (or its owner gave it up).
    /// Clearing is bookkeeping only: it touches no attempt.
    pub fn clear_plan_hold(&self, root_attempt: AttemptId) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        PLAN_HOLD.delete(&self.vault.store, &mut wtxn, &root_attempt)?;
        wtxn.commit()?;
        Ok(())
    }

    fn update_hold(
        &self,
        root: AttemptId,
        change: impl FnOnce(&mut PartialResultHold) -> Result<()>,
    ) -> Result<PartialResultHold> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        let mut hold = PLAN_HOLD
            .get(&self.vault.store, &wtxn, &root)?
            .ok_or_else(|| invalid("run has no budget hold"))?;
        change(&mut hold)?;
        PLAN_HOLD.put(&self.vault.store, &mut wtxn, &root, &hold)?;
        wtxn.commit()?;
        Ok(hold)
    }

    /// The run's attempts: every row sharing the root's run id, else the
    /// root alone.
    fn run_attempts(&self, root: AttemptId) -> Result<Vec<AttemptRecord>> {
        let queue = AttemptQueue::new(self.vault);
        let record = queue
            .get(root)?
            .ok_or_else(|| invalid("budget hold root attempt is missing"))?;
        match record.run_id.as_deref() {
            Some(run) => queue.list_run(run),
            None => Ok(vec![record]),
        }
    }

    /// Whether the root's spend scope has spend left now; an unmetered run
    /// always does.
    fn scope_has_spend(&self, root: AttemptId) -> Result<bool> {
        let scope = SpendScopeId::for_attempt(&root);
        if self.read_spend_scope(&scope)?.is_none() {
            return Ok(true);
        }
        Ok(self.available_units(&scope)? > 0)
    }
}
