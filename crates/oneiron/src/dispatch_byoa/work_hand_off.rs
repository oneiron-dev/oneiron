//! A spent seat's work handed to the next seat (OF-137): "the router mints
//! the next attempt on the next seat; the task never moves, only the
//! attempt" (ARCH-0068 RC5).
//!
//! A bound work's CLI seat reads its task through a reference to the work's
//! original request record ([`RunnerTaskSource`]), re-read at each hand-off
//! and never copied (FIX 7449). Where that record is erased or unreadable,
//! or none was kept, the CLI seat is passed over and named and the work
//! goes on to the next seat. A seat the quota view shows spent and not yet
//! back is passed over and named too (FIX 7453), and so is a CLI seat whose
//! argv cannot carry the task (FIX 7505).
//!
//! The same search serves an explicit resume of a work a spend parked
//! (`work_resume`, FIX 7450): it starts where the caller says, the spent
//! seat included, where the automatic hand-off starts past it.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::checkout::CheckoutId;
use crate::entity_id::bytes_to_hex_lower;

use super::connector::{ByoaAttemptPayload, ByoaConnectorSpec, ByoaDispatchOutcome};
use super::dispatcher::{ByoEndpointBackendFactory, ByoaDispatcher, ByoaEnqueue};
use super::error::{ByoaResult, ERR_EXECUTION_CHECKOUT, invalid};
use super::exhaust::{ByoaEgressPort, ByoaTerminalReceipt, decode_byoa_record};
use super::provider::ProviderAdapterRegistry;
use super::repo_binding::{ByoaRepoBinding, claim_successor_in_txn, successor_checkout};
use super::seat::{
    RUNNER_SEAT_DEDUPE_PREFIX, RunnerSeat, RunnerSeatPolicy, SeatPassedOver, SeatRoute, SeatSpent,
    SkippedRunnerSeat, runner_task,
};
use super::seat_candidate::runner_seat_candidate;
use super::seat_quota::seat_quotas_in_txn;
use super::staged_input::{
    StagedInputPin, carry_staged_input, staged_input_readable_in_txn, staged_job_pointer,
};
use super::work_binding::{
    RunnerTaskSource, RunnerWorkBinding, SpentCapture, note_next_hop_in_txn,
};

/// What a spent attempt hands its next seat: the task a CLI seat runs, read
/// from its record, the checkout a successor starts from, the custody it
/// claims from, the staged job, and the binding the successor carries on.
pub(super) struct HandOff {
    task: Option<String>,
    base: CheckoutId,
    repo: Option<ByoaRepoBinding>,
    staged: Option<StagedInputPin>,
    work: Option<RunnerWorkBinding>,
}

impl HandOff {
    /// `None` when `spent` carries neither a binding nor a CLI runner task:
    /// an unbound endpoint or MCP seat's work parks, as before. A bound
    /// work's task is `None` when its original request record is erased or
    /// unreadable, or none was kept: its CLI seats are passed over. So it is
    /// when the spent attempt is that record and an erase left it no task
    /// (FIX 7502): the work goes on to its next seat, never parked for it.
    pub(super) fn of(
        vault: &Vault,
        rtxn: &heed::RoTxn<'_>,
        spent: &AttemptRecord,
        payload: ByoaAttemptPayload,
    ) -> ByoaResult<Option<Self>> {
        let ByoaAttemptPayload {
            connector,
            repo_binding,
            work,
            ..
        } = payload;
        if let ByoaConnectorSpec::CliSandbox(ran) = connector {
            // A CLI runner attempt carries its task (the argv after `--`),
            // unless an erase took it.
            let own = runner_task(&ran).map(str::to_owned);
            let Some(work) = work else {
                // Unbound work's task lives in the spent argv alone.
                let Some(own) = own else {
                    return Ok(None);
                };
                return Ok(Some(Self {
                    task: Some(own),
                    base: ran.checkout_id,
                    repo: repo_binding,
                    staged: ran.staged_input,
                    work: None,
                }));
            };
            // A bound work's first CLI attempt is its original request
            // record, named once; a later one re-reads the original.
            let here = RunnerTaskSource::CliAttempt(*spent.id.as_bytes());
            let work = RunnerWorkBinding {
                task_source: work.task_source.or(Some(here)),
                ..work
            };
            let task = if work.task_source == Some(here) {
                own
            } else {
                original_task(vault, rtxn, &work)?
            };
            let repo = repo_binding.or_else(|| work.repo_binding.clone());
            return Ok(Some(Self {
                task,
                base: ran.checkout_id,
                repo,
                staged: ran.staged_input,
                work: Some(work),
            }));
        }
        let Some(work) = work else {
            return Ok(None);
        };
        Ok(Some(Self {
            task: original_task(vault, rtxn, &work)?,
            base: CheckoutId::from_bytes(work.checkout)
                .map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))?,
            repo: work.repo_binding.clone(),
            staged: work.staged_input.clone(),
            work: Some(work),
        }))
    }
}

/// A bound work's task, re-read from its original request record: the first
/// CLI attempt's argv, or a pointer to its staged job. `None` when that
/// record is erased or unreadable, or none was kept.
fn original_task(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    work: &RunnerWorkBinding,
) -> ByoaResult<Option<String>> {
    match work.task_source {
        Some(RunnerTaskSource::CliAttempt(source)) => cli_task(vault, rtxn, source),
        Some(RunnerTaskSource::StagedJob) => match &work.staged_input {
            Some(pin) if staged_input_readable_in_txn(vault, rtxn, pin)? => {
                Ok(Some(staged_job_pointer(pin)))
            }
            _ => Ok(None),
        },
        None => Ok(None),
    }
}

/// The task the CLI attempt `source` was handed, re-read from its argv.
/// `None` when that row is gone, does not decode, or names no task.
fn cli_task(vault: &Vault, rtxn: &heed::RoTxn<'_>, source: [u8; 16]) -> ByoaResult<Option<String>> {
    let Ok(id) = AttemptId::from_bytes(&source) else {
        return Ok(None);
    };
    let Some(record) = AttemptQueue::new(vault).get_in_txn(rtxn, id)? else {
        return Ok(None);
    };
    let Ok(ByoaAttemptPayload {
        connector: ByoaConnectorSpec::CliSandbox(spec),
        ..
    }) = decode_byoa_record(&record)
    else {
        return Ok(None);
    };
    Ok(runner_task(&spec).map(str::to_owned))
}

fn park(receipt: ByoaTerminalReceipt, spent: SeatSpent, now: u64) -> SeatRoute {
    SeatRoute::Park {
        until: spent.back_at(now),
        receipt,
        spent,
    }
}

fn passed_over(index: usize, seat: &RunnerSeat, reason: SeatPassedOver) -> SkippedRunnerSeat {
    SkippedRunnerSeat {
        seat: index,
        runner: seat.runner.clone(),
        reason,
    }
}

/// Where a search for a spent work's successor starts in the owner's order,
/// whether it tries that seat alone (an explicit seat, spent or not, whose
/// connector keeps its own refusal), and the vault's time.
#[derive(Debug, Clone, Copy)]
pub(super) struct SeatSearch {
    pub(super) from: usize,
    pub(super) only: bool,
    pub(super) now: u64,
}

/// What a successor search found: the seat that took the work and its
/// dispatch, else whether a spent seat was passed over and when the first
/// one is back; and each seat passed over, with why, in the owner's order.
pub(super) struct Successor {
    pub(super) took: Option<(usize, ByoaDispatchOutcome)>,
    pub(super) skipped: Vec<SkippedRunnerSeat>,
    pub(super) spent_seen: bool,
    pub(super) back_at: Option<u64>,
}

impl<B, E> ByoaDispatcher<'_, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// The NextSeat route of a spent attempt (OF-137): the next seat in the
    /// owner's order this runtime may run takes the work as a child of the
    /// spent attempt, whatever shape either seat has. A CLI seat's task is
    /// re-read from the bound work's original request record (its first
    /// CLI attempt's argv, else a pointer to its staged job), or from an
    /// unbound CLI attempt's own argv, never copied. Passed over and named
    /// in the receipt's `skipped_seats`: a seat the quota view shows spent
    /// and not yet back, a CLI seat when that record is erased or
    /// unreadable or none was kept, and a seat a hosted-only bound keeps off
    /// this runtime. The work parks when no seat is left, and when the
    /// spent attempt is unbound and carries no CLI runner task (an endpoint
    /// or MCP seat's).
    pub(super) fn next_seat_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        capture: SpentCapture,
    ) -> ByoaResult<SeatRoute> {
        let SpentCapture {
            mut receipt,
            spent,
            seat,
            now,
        } = capture;
        let vault = self.vault();
        let payload = decode_byoa_record(&receipt.attempt)?;
        let Some(hand) = HandOff::of(vault, wtxn, &receipt.attempt, payload)? else {
            return Ok(park(receipt, spent, now));
        };
        let search = SeatSearch {
            from: seat + 1,
            only: false,
            now,
        };
        let found =
            self.successor_in_txn(wtxn, registry, policy, &receipt.attempt, &hand, search)?;
        receipt.skipped_seats.extend(found.skipped);
        Ok(match found.took {
            Some((seat, outcome)) => SeatRoute::NextSeat {
                receipt,
                spent,
                seat,
                outcome,
            },
            None => park(receipt, spent, now),
        })
    }

    /// The successor search of a spent attempt's work (OF-137): from
    /// `search.from` in the owner's order, the first seat this runtime may
    /// run takes the work as a child of `spent`, on a fresh checkout claimed
    /// from the work's custody, under a dedupe key of the spent attempt and
    /// the seat, so a replay finds the child it dispatched. Passed over and
    /// named: a seat the quota view shows spent and not yet back, a CLI seat
    /// whose argv cannot carry the task (FIX 7505) or that has no readable
    /// task, and a seat a hosted-only bound keeps off this runtime. An
    /// explicit seat (`search.only`) is tried whatever its quota, and its
    /// connector keeps its refusal.
    ///
    /// # Errors
    /// An unknown runner, a custody claim or a dispatch the store refuses.
    pub(super) fn successor_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        spent: &AttemptRecord,
        hand: &HandOff,
        search: SeatSearch,
    ) -> ByoaResult<Successor> {
        let vault = self.vault();
        let SeatSearch { from, only, now } = search;
        let quotas = if only {
            Vec::new()
        } else {
            seat_quotas_in_txn(vault, wtxn, policy, now)?
        };
        let parent = *spent.id.as_bytes();
        let tried = if only { 1 } else { policy.seats.len() };
        let mut found = Successor {
            took: None,
            skipped: Vec::new(),
            spent_seen: false,
            back_at: None,
        };
        for (index, next) in policy.seats.iter().enumerate().skip(from).take(tried) {
            if let Some(quota) = quotas.get(index).filter(|quota| !quota.available) {
                found.spent_seen = true;
                found.back_at = match (found.back_at, quota.back_at) {
                    (Some(first), Some(back)) => Some(first.min(back)),
                    (first, back) => first.or(back),
                };
                let reason = SeatPassedOver::Spent {
                    back_at: quota.back_at,
                };
                found.skipped.push(passed_over(index, next, reason));
                continue;
            }
            let checkout = successor_checkout(spent.id, hand.base, hand.repo.as_ref(), index)?;
            let task = hand.task.clone().unwrap_or_default();
            let connector = if only {
                next.connector(registry, task, checkout)?
            } else if let Some(connector) = runner_seat_candidate(next, registry, task, checkout)? {
                connector
            } else {
                let reason = SeatPassedOver::CliArgvShape;
                found.skipped.push(passed_over(index, next, reason));
                continue;
            };
            if hand.task.is_none() && matches!(connector, ByoaConnectorSpec::CliSandbox(_)) {
                let reason = SeatPassedOver::TaskUnreadable;
                found.skipped.push(passed_over(index, next, reason));
                continue;
            }
            let connector = carry_staged_input(connector, hand.staged.as_ref());
            let context = registry.resolve(&next.runner)?.placement_context();
            if let Some(bound) = self.seat_bound(next.logs_in(), &connector, context)? {
                let reason = SeatPassedOver::Hosted(bound);
                found.skipped.push(passed_over(index, next, reason));
                continue;
            }
            claim_successor_in_txn(vault, wtxn, hand.repo.as_ref(), checkout, now)?;
            let outcome = self.enqueue_in_txn(
                wtxn,
                ByoaEnqueue {
                    user_login: next.logs_in(),
                    connector,
                    task_ref: spent.task_ref.clone(),
                    parent_attempt: Some(parent),
                    run_id: spent.run_id.clone(),
                    dedupe_key: Some(format!(
                        "{RUNNER_SEAT_DEDUPE_PREFIX}{}:{index}",
                        bytes_to_hex_lower(&parent)
                    )),
                    now,
                    official_seat: context,
                    work: hand.work.clone(),
                },
            )?;
            if let Some(work) = &hand.work {
                let attempt = outcome.status().attempt.id;
                note_next_hop_in_txn(vault, wtxn, work, spent.id, attempt, index, now)?;
            }
            found.took = Some((index, outcome));
            return Ok(found);
        }
        Ok(found)
    }
}
