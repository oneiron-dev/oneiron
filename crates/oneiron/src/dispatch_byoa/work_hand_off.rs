//! A spent seat's work handed to the next seat (OF-137): "the router mints
//! the next attempt on the next seat; the task never moves, only the
//! attempt" (ARCH-0068 RC5).
//!
//! A bound work's CLI seat reads its task through a reference to the work's
//! original request record ([`RunnerTaskSource`]), re-read at each hand-off
//! and never copied (FIX 7449). Where that record is erased or unreadable,
//! or none was kept, the CLI seat is passed over and named and the work
//! goes on to the next seat. A seat the quota view shows spent and not yet
//! back is passed over and named too (FIX 7453).

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::checkout::CheckoutId;
use crate::entity_id::bytes_to_hex_lower;

use super::connector::{ByoaAttemptPayload, ByoaConnectorSpec};
use super::dispatcher::{ByoEndpointBackendFactory, ByoaDispatcher, ByoaEnqueue};
use super::error::{ByoaResult, ERR_EXECUTION_CHECKOUT, invalid};
use super::exhaust::{ByoaEgressPort, ByoaTerminalReceipt, decode_byoa_record};
use super::provider::ProviderAdapterRegistry;
use super::repo_binding::{ByoaRepoBinding, claim_successor_in_txn, successor_checkout};
use super::seat::{
    RUNNER_SEAT_DEDUPE_PREFIX, RunnerSeat, RunnerSeatPolicy, SeatPassedOver, SeatRoute, SeatSpent,
    SkippedRunnerSeat, runner_task,
};
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
struct HandOff {
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
    fn of(
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
        let quotas = seat_quotas_in_txn(vault, wtxn, policy, now)?;
        let parent = *receipt.attempt.id.as_bytes();
        for (index, next) in policy.seats.iter().enumerate().skip(seat + 1) {
            if let Some(quota) = quotas.get(index).filter(|quota| !quota.available) {
                let reason = SeatPassedOver::Spent {
                    back_at: quota.back_at,
                };
                receipt.skipped_seats.push(passed_over(index, next, reason));
                continue;
            }
            let checkout =
                successor_checkout(receipt.attempt.id, hand.base, hand.repo.as_ref(), index)?;
            let task = hand.task.clone().unwrap_or_default();
            let connector = next.connector(registry, task, checkout)?;
            if hand.task.is_none() && matches!(connector, ByoaConnectorSpec::CliSandbox(_)) {
                let reason = SeatPassedOver::TaskUnreadable;
                receipt.skipped_seats.push(passed_over(index, next, reason));
                continue;
            }
            let connector = carry_staged_input(connector, hand.staged.as_ref());
            let context = registry.resolve(&next.runner)?.placement_context();
            if let Some(bound) = self.seat_bound(next.logs_in(), &connector, context)? {
                let reason = SeatPassedOver::Hosted(bound);
                receipt.skipped_seats.push(passed_over(index, next, reason));
                continue;
            }
            claim_successor_in_txn(vault, wtxn, hand.repo.as_ref(), checkout, now)?;
            let outcome = self.enqueue_in_txn(
                wtxn,
                ByoaEnqueue {
                    user_login: next.logs_in(),
                    connector,
                    task_ref: receipt.attempt.task_ref.clone(),
                    parent_attempt: Some(parent),
                    run_id: receipt.attempt.run_id.clone(),
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
                note_next_hop_in_txn(vault, wtxn, work, attempt, index, now)?;
            }
            return Ok(SeatRoute::NextSeat {
                receipt,
                spent,
                seat: index,
                outcome,
            });
        }
        Ok(park(receipt, spent, now))
    }
}
