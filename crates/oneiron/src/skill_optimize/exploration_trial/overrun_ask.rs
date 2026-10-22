//! Overrun asks: the board's yes or no on one run past the goal's exploration slice.
//! Entry functions: `queue_trial_ask`, `answer_in_txn`, `climb_stale_ask`.
//! The trial, its state and its tables remain defined in `super`.

use super::*;

/// The trial state an answer to an overrun ask leaves: a yes covers
/// one run of up to `charge` past the slice; anything else declines.
/// None for a yes whose answerer was erased: that authority ended with
/// the erase, so the answer stays and the overrun is asked again (FIX 3520).
fn answered(charge: u64, answer: &AskAnswer) -> Option<TrialState> {
    match answer.answer {
        DecisionAnswer::Noul(true) => answer.by.id().map(|_| TrialState::Approved { charge }),
        _ => Some(TrialState::Closed(ExplorationTrialClose::OverrunDeclined)),
    }
}

/// Applies the answer to the trial's queued overrun ask, once one is
/// given. `true` when the state moved.
pub(super) fn take_answer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    trial: &mut ExplorationTrial,
) -> Result<bool> {
    let TrialState::AskPending(PendingOverrun {
        seq: Some(seq),
        charge,
        ..
    }) = trial.state
    else {
        return Ok(false);
    };
    let Some(state) = vault
        .decision_ask_in_txn(txn, seq)?
        .and_then(|ask| ask.answer)
        .and_then(|answer| answered(charge, &answer))
    else {
        return Ok(false);
    };
    trial.state = state;
    Ok(true)
}

/// The board's answer to a pending overrun ask, applied while the trial
/// still waits on that ask. A yes whose answerer was erased leaves the
/// overrun pending with no ask, to be asked again from its chain's start.
pub(super) fn answer_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    proposal: &EntityId,
    seq: u64,
    answer: &AskAnswer,
) -> Result<TrialState> {
    let Some(mut trial) = TRIALS.get(&vault.store, txn, proposal)? else {
        return Err(Error::EntityNotFound);
    };
    if let TrialState::AskPending(pending) = &mut trial.state
        && pending.seq == Some(seq)
    {
        match answered(pending.charge, answer) {
            Some(state) => trial.state = state,
            None => {
                pending.seq = None;
                pending.climbed_at = None;
            }
        }
        TRIALS.put(&vault.store, txn, proposal, &trial)?;
    }
    Ok(trial.state)
}

/// The versioned yes/no question about one overrun's exact charge.
fn overrun_request(
    proposal: &EntityId,
    record: &SkillRecord,
    trial: &ExplorationTrial,
    pending: &PendingOverrun,
) -> HumanDecisionRequest {
    let unit = trial.unit.as_str();
    let over = pending.charge.saturating_sub(pending.remaining);
    HumanDecisionRequest {
        question: DecisionQuestion {
            id: trial.question,
            version: pending.version,
            text: format!(
                "Run the trial of {}@{} (proposal {}) on one more live run, estimated at {} {unit}? \
                 Its project goal's exploration slice is {} {unit}, {} {unit} charged, {} {unit} \
                 left: this run passes it by {over} {unit}.",
                record.skill_id,
                record.version,
                proposal.to_hex(),
                pending.charge,
                pending.slice,
                pending.charged,
                pending.remaining,
            ),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        principal: trial.project,
        evidence: vec![*proposal, trial.target, trial.goal_claim],
        reason: HumanAskReason::ExplorationBudget,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: OVERRUN_QUEUE.to_owned(),
            version: OVERRUN_QUEUE_VERSION.to_owned(),
        },
        // The project's board decides its goal's exploration overrun. With no
        // live holder there, the ask goes up the chain (the parents' boards,
        // then the owners) to the first role that has one.
        correlation: None,
        to: AskTo {
            role: AskRole::Board {
                project: trial.project,
            },
            ceiling: RoleRank::Owner,
            act: AskAct::Judgment,
        },
    }
}

/// Queues the board ask of `proposal`'s pending overrun and keeps its
/// arrival number on the trial. Outside any write transaction: the queue
/// opens its own. An ask already queued, or no pending overrun: nothing.
/// # Errors
/// An unreadable row, an invalid question, or storage errors.
pub(crate) fn queue_trial_ask(vault: &Vault, proposal: &EntityId) -> Result<()> {
    let trial = {
        let txn = vault.store.env.read_txn()?;
        TRIALS.get(&vault.store, &txn, proposal)?
    };
    let Some(trial) = trial else {
        return Ok(());
    };
    let TrialState::AskPending(pending) = &trial.state else {
        return Ok(());
    };
    if pending.seq.is_some() {
        return Ok(());
    }
    let record = vault
        .get_skill_record(proposal)?
        .ok_or(Error::EntityNotFound)?;
    let seq = vault.queue_decision_ask(&overrun_request(proposal, &record, &trial, pending))?;
    vault.with_write_txn_grouped(|txn| {
        let Some(mut now) = TRIALS.get(&vault.store, txn, proposal)? else {
            return Ok(());
        };
        let unqueued = matches!(
            &now.state,
            TrialState::AskPending(held) if held.version == pending.version && held.seq.is_none()
        );
        if unqueued {
            if let TrialState::AskPending(held) = &mut now.state {
                held.seq = Some(seq);
            }
            TRIALS.put(&vault.store, txn, proposal, &now)?;
        }
        Ok(())
    })
}

/// Climbs `proposal`'s unanswered overrun ask `seq` one role up its chain
/// once [`EXPLORATION_ASK_CLIMB_HOURS`] have passed `since`, and restarts
/// that clock. An ask at its chain's top keeps its clock, and lapses once
/// [`EXPLORATION_ASK_LAPSE_HOURS`] have passed it too: the trial closes as
/// declined, and the ask is withdrawn from its role's queue in the same
/// write, so a later answer is refused. `true` when it lapsed.
pub(super) fn climb_stale_ask(
    vault: &Vault,
    proposal: &EntityId,
    seq: u64,
    since: u64,
    at: u64,
) -> Result<bool> {
    let waited = at.saturating_sub(since) as f64;
    let hours = crate::learning_setting::setting_value(vault, &EXPLORATION_ASK_CLIMB_HOURS)?;
    if waited < hours * 3600.0 {
        return Ok(false);
    }
    let climbed = vault.climb_decision_ask(seq)?.is_some();
    let lapsed = !climbed
        && waited
            >= crate::learning_setting::setting_value(vault, &EXPLORATION_ASK_LAPSE_HOURS)?
                * 3600.0;
    if !climbed && !lapsed {
        return Ok(false);
    }
    let withdrew = vault.with_write_txn_grouped(|txn| {
        let Some(mut now) = TRIALS.get(&vault.store, txn, proposal)? else {
            return Ok(false);
        };
        let held = matches!(&now.state, TrialState::AskPending(held) if held.seq == Some(seq));
        if !held {
            return Ok(false);
        }
        if lapsed {
            now.state = TrialState::Closed(ExplorationTrialClose::OverrunLapsed);
            vault.withdraw_decision_ask_in_txn(txn, seq)?;
        } else if let TrialState::AskPending(held) = &mut now.state {
            held.climbed_at = Some(at);
        }
        TRIALS.put(&vault.store, txn, proposal, &now)?;
        Ok(lapsed)
    })?;
    // A lapsed ask's waiters wake once its withdrawal committed (FIX 4706).
    if withdrew {
        vault.signal_decision_answer(seq);
    }
    Ok(withdrew)
}
