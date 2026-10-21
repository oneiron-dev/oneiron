//! A Dreamer's runner work, bound once and handed seat to seat (OF-137):
//! "the router mints the next attempt on the next seat; the task never
//! moves, only the attempt" (ARCH-0068 RC5).
//!
//! [`ByoaDispatcher::bind_runner_work_in_txn`] dispatches one step of a
//! Dreamer attempt to a runner seat in the caller's writer, under an id
//! derived from that attempt and the step's key, so a parked and resumed
//! parent finds the same work again. Every attempt of the work carries a
//! [`RunnerWorkBinding`] of references only: the binding, the CLI attempt
//! whose argv holds the task, the staged job, the checkout and its custody.
//! No task text is copied. A CLI seat's task stays in its own argv, and a
//! next seat re-reads it there, so a spent seat of any connector shape hands
//! the work on from its durable row alone.
//!
//! The binding's hops (which attempt carries the work on which seat, and
//! the spend that stopped it there) are versions of the binding's own
//! record ([`super::record`]). [`runner_work_outcome`] reads its head.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, AttemptState,
};
use crate::checkout::CheckoutId;
use crate::codebase::entity_id_from_hash_material;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::Error;
use crate::llm::LlmUsage;

use super::connector::{BYOA_ATTEMPT_KIND, ByoaAttemptPayload, ByoaConnectorSpec};
use super::dispatcher::{ByoEndpointBackendFactory, ByoaDispatcher, ByoaEnqueue};
use super::error::{ByoaResult, ERR_EXECUTION_CHECKOUT, invalid};
use super::exhaust::{
    ByoaEgressPort, ByoaTerminalDisposition, ByoaTerminalReceipt, decode_byoa_exhaust,
    decode_byoa_record, parse_byoa_result_ref,
};
use super::provider::ProviderAdapterRegistry;
use super::record::{append_record_in_txn, head_record};
use super::repo_binding::{
    ByoaRepoBinding, claim_successor_in_txn, repo_stale_lease_reason, successor_checkout,
};
use super::seat::{
    RUNNER_SEAT_DEDUPE_PREFIX, RunnerSeatPolicy, SeatRoute, SeatSpent, SkippedRunnerSeat,
    runner_task,
};
use super::seat_quota::seat_quotas_in_txn;
use super::staged_input::{StagedInputPin, carry_staged_input};

/// Domain a binding id is derived under.
const RUNNER_WORK_BINDING_DOMAIN: &[u8] = b"oneiron:byoa-runner-work-binding:v1";

/// Domain a terminal outcome's step hash is derived under.
const RUNNER_WORK_TERMINAL_DOMAIN: &str = "oneiron.byoa.runner-work-terminal.v1";

/// Media type of a binding's hop record.
const RUNNER_WORK_HOPS_MEDIA_TYPE: &str = "application/vnd.oneiron.byoa-runner-work-hops+msgpack";

/// Dedupe prefix of a bound work's first attempt.
const RUNNER_WORK_DEDUPE_PREFIX: &str = "byoa.work:";

/// The durable id of one bound runner work, derived from the Dreamer attempt
/// that bound it and the step's key: the parent derives it again after a
/// park, and its hop record lives under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunnerWorkBindingId(EntityId);

impl RunnerWorkBindingId {
    /// The binding `parent` makes for its step `step_key`.
    ///
    /// # Errors
    /// Returns [`super::ByoaError::Store`] when no id can be derived.
    pub fn of(parent: AttemptId, step_key: &str) -> ByoaResult<Self> {
        Ok(Self(entity_id_from_hash_material(
            RUNNER_WORK_BINDING_DOMAIN,
            &[parent.as_bytes(), step_key.as_bytes()],
        )?))
    }

    /// The binding a work's attempt names ([`RunnerWorkBinding::binding`]).
    ///
    /// # Errors
    /// Returns [`super::ByoaError::Store`] for bytes no id has.
    pub fn from_bytes(bytes: [u8; 16]) -> ByoaResult<Self> {
        Ok(Self(EntityId::from_bytes(bytes)?))
    }

    /// The id's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// The id in lower-case hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

/// What every attempt of a bound runner work carries, references only: the
/// work's task stays where it already lives (a CLI seat's argv, a staged
/// job), and no login or key is ever one of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerWorkBinding {
    /// The binding's id ([`RunnerWorkBindingId`]).
    pub binding: [u8; 16],
    /// The CLI runner attempt whose argv holds the work's task, its home:
    /// the last CLI seat the work ran on before this attempt. `None` while
    /// it ran on none before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_source: Option<[u8; 16]>,
    /// The checkout the work names. A CLI successor of a bound checkout
    /// derives its own from the custody below.
    pub checkout: [u8; 16],
    /// The work's staged job, when it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staged_input: Option<StagedInputPin>,
    /// The first checkout custody a CLI seat of the work pinned (FIX 6867),
    /// which a successor of any shape claims a fresh checkout from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_binding: Option<ByoaRepoBinding>,
}

/// Which seat a bound work starts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerSeatChoice {
    /// The seat at this index, as the caller picked it, spent or not.
    Seat(usize),
    /// The first seat from this index in the owner's order that this runtime
    /// may run and whose quota is not spent ([`super::runner_seat_quotas`]).
    NextSeat {
        /// The first index tried.
        from: usize,
    },
}

/// One step of a Dreamer attempt to bind to a runner seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRunnerWork {
    /// The Dreamer attempt the work is a step of.
    pub parent_attempt_id: AttemptId,
    /// The step's key within that attempt (its run/step key).
    pub step_key: String,
    /// The task a CLI seat is handed after its `--`. Kept only in that
    /// seat's argv; an endpoint or MCP seat's connector drops it.
    pub task: String,
    /// The job the task points at, already stored as a staged input.
    pub staged_input: Option<StagedInputPin>,
    /// The checkout a CLI seat runs against.
    pub checkout_id: CheckoutId,
    /// The TASK the work realizes.
    pub task_ref: Option<EntityId>,
    /// The run every attempt of the work joins.
    pub run_id: Option<String>,
    /// The seat the work starts on.
    pub choice: RunnerSeatChoice,
    /// The vault's time, in seconds.
    pub now: u64,
}

/// Where binding a work left it. A work no seat can take is a value, never
/// an error; whether it falls back to the Dreamer's own model roles stays
/// the caller's choice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunnerWorkBound {
    /// The work is bound and its attempt on `seat` dispatched. `existing`
    /// when an earlier bind of the same parent and step already did, and
    /// then `seat` and `attempt` are where the work stands now.
    Bound {
        binding: RunnerWorkBindingId,
        seat: usize,
        attempt: AttemptId,
        existing: bool,
    },
    /// No seat this runtime may run is left: each one tried is named with
    /// its hosted-only bound.
    NoSeat { skipped: Vec<SkippedRunnerSeat> },
    /// Every seat this runtime may run is spent. `back_at` is the first time
    /// one is back; none waits for the owner.
    Exhausted {
        back_at: Option<u64>,
        skipped: Vec<SkippedRunnerSeat>,
    },
}

/// How a bound work's last attempt ended without completing, without any
/// provider or runner text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunnerWorkErrorKind {
    /// Its seat was spent and the route kept the work there (the owner's
    /// Stop or InternalModels, or a NextSeat with no seat left).
    SeatSpent,
    /// Its checkout went stale while it ran (`repo_stale_lease`).
    StaleCheckout,
    /// The runner failed.
    RunnerFailed,
    /// The runner stopped carrying the work.
    RunnerStopped,
    /// The attempt was cancelled.
    Cancelled,
}

/// A bound work's last attempt, ended.
#[derive(Debug, Clone, PartialEq)]
pub struct RunnerWorkTerminal {
    /// The attempt that ended.
    pub attempt: AttemptId,
    /// The seat it ran on.
    pub seat: usize,
    /// How it ended.
    pub status: ByoaTerminalDisposition,
    /// Why it did not complete; `None` when it did.
    pub error: Option<RunnerWorkErrorKind>,
    /// The spent refusal that kept the work on its seat.
    pub spent: Option<SeatSpent>,
    /// When that seat is back; `None` while it waits for the owner.
    pub back_at: Option<u64>,
    /// The provider usage a completed endpoint run's transcript names.
    /// `None` for a CLI or MCP run, which reports none here.
    pub usage: Option<LlmUsage>,
    /// The attempt's captured exhaust (`blob-artifact:<id>@<version>`).
    pub exhaust_ref: Option<AttemptResultRef>,
    /// This end's identity, the same on every read: a settlement that keys
    /// on it charges the work once however often it is read.
    pub step_hash: [u8; 32],
}

/// Where a bound work stands.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum RunnerWorkOutcome {
    /// Its attempt on `seat` has not ended.
    Pending { attempt: AttemptId, seat: usize },
    /// Its last attempt ended.
    Terminal(Box<RunnerWorkTerminal>),
    /// Nothing holds the work: never bound here, or erased or pruned.
    Gone,
}

/// One hop of a bound work: the attempt carrying it, on which seat, and the
/// spend that kept it there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RunnerWorkHop {
    attempt: [u8; 16],
    seat: u64,
    spent: Option<SeatSpent>,
    observed_at: u64,
}

/// The part of an endpoint run's transcript that names its usage.
#[derive(Deserialize)]
struct TranscriptUsage {
    usage: LlmUsage,
}

/// What a spent attempt hands its next seat: the task's text read from its
/// home, the checkout a successor starts from, the custody it claims from,
/// the staged job, and the binding the successor carries on.
struct HandOff {
    task: Option<String>,
    base: CheckoutId,
    repo: Option<ByoaRepoBinding>,
    staged: Option<StagedInputPin>,
    work: Option<RunnerWorkBinding>,
}

/// A spent attempt's capture as the route hands it to the next seat.
pub(super) struct SpentCapture {
    /// The capture.
    pub(super) receipt: ByoaTerminalReceipt,
    /// The spend read from it.
    pub(super) spent: SeatSpent,
    /// The seat it ran on.
    pub(super) seat: usize,
    /// The capture's time.
    pub(super) now: u64,
}

impl HandOff {
    /// `None` when `spent` carries neither a binding nor a CLI runner task:
    /// an unbound endpoint or MCP seat's work parks, as before.
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
            // Only a CLI runner attempt carries its task (the argv after
            // `--`); it is the task's home for every later seat.
            let Some(task) = runner_task(&ran).map(str::to_owned) else {
                return Ok(None);
            };
            let work = work.map(|work| RunnerWorkBinding {
                task_source: Some(*spent.id.as_bytes()),
                ..work
            });
            let repo = repo_binding.or_else(|| work.as_ref()?.repo_binding.clone());
            return Ok(Some(Self {
                task: Some(task),
                base: ran.checkout_id,
                repo,
                staged: ran.staged_input,
                work,
            }));
        }
        let Some(work) = work else {
            return Ok(None);
        };
        let task = match work.task_source {
            Some(source) => source_task(vault, rtxn, source)?,
            None => None,
        };
        Ok(Some(Self {
            task,
            base: CheckoutId::from_bytes(work.checkout)
                .map_err(|_| invalid(ERR_EXECUTION_CHECKOUT))?,
            repo: work.repo_binding.clone(),
            staged: work.staged_input.clone(),
            work: Some(work),
        }))
    }
}

/// The task the CLI attempt `source` was handed, re-read from its argv.
/// `None` when that row is gone or names no task.
fn source_task(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    source: [u8; 16],
) -> ByoaResult<Option<String>> {
    let Some(record) =
        AttemptQueue::new(vault).get_in_txn(rtxn, AttemptId::from_bytes(&source)?)?
    else {
        return Ok(None);
    };
    let ByoaConnectorSpec::CliSandbox(spec) = decode_byoa_record(&record)?.connector else {
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

fn seat_index(seat: u64) -> usize {
    usize::try_from(seat).unwrap_or(usize::MAX)
}

fn head_hop(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    binding: RunnerWorkBindingId,
) -> ByoaResult<Option<RunnerWorkHop>> {
    head_record(vault, rtxn, &binding.0)
}

/// Appends `hop` to `binding`'s record. A replay names the hop the head
/// already holds and appends nothing.
fn append_hop_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    binding: RunnerWorkBindingId,
    hop: &RunnerWorkHop,
) -> ByoaResult<()> {
    if head_hop(vault, wtxn, binding)?.is_some_and(|head| {
        head.attempt == hop.attempt && head.spent.is_some() == hop.spent.is_some()
    }) {
        return Ok(());
    }
    append_record_in_txn(
        vault,
        wtxn,
        &binding.0,
        format!("{BYOA_ATTEMPT_KIND}/work/{}", binding.to_hex()),
        RUNNER_WORK_HOPS_MEDIA_TYPE,
        hop,
        hop.observed_at,
    )
}

/// Notes, for a bound work that a spend kept on its seat, the spend on its
/// record; unbound work records nothing.
///
/// # Errors
/// A payload that does not decode; a store failure.
pub(super) fn note_spent_hop_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    receipt: &ByoaTerminalReceipt,
    seat: usize,
    spent: &SeatSpent,
) -> ByoaResult<()> {
    let Some(work) = decode_byoa_record(&receipt.attempt)?.work else {
        return Ok(());
    };
    append_hop_in_txn(
        vault,
        wtxn,
        RunnerWorkBindingId::from_bytes(work.binding)?,
        &RunnerWorkHop {
            attempt: *receipt.attempt.id.as_bytes(),
            seat: seat as u64,
            spent: Some(spent.clone()),
            observed_at: receipt.attempt.updated_at,
        },
    )
}

impl<B, E> ByoaDispatcher<'_, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// Binds one step of a Dreamer attempt to a runner seat and dispatches
    /// it there, in the caller's writer `wtxn` (OF-137). The first attempt
    /// is a child of the Dreamer attempt; the binding and its first hop are
    /// written in the same writer, so a park and resume of the parent finds
    /// them again, and a second bind of the same parent and step returns
    /// where the work stands without dispatching again. With
    /// [`RunnerSeatChoice::NextSeat`] a seat a hosted-only bound keeps off
    /// this runtime is passed over and named, and a spent seat is passed
    /// over until it is back.
    ///
    /// # Errors
    ///
    /// Refuses an invalid policy or seat index, an unknown runner, and every
    /// refusal a dispatch has.
    pub fn bind_runner_work_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        request: BindRunnerWork,
    ) -> ByoaResult<RunnerWorkBound> {
        policy.validate(registry)?;
        let (start, only) = match request.choice {
            RunnerSeatChoice::Seat(seat) => (seat, true),
            RunnerSeatChoice::NextSeat { from } => (from, false),
        };
        policy.seat(start)?;
        let vault = self.vault();
        let binding = RunnerWorkBindingId::of(request.parent_attempt_id, &request.step_key)?;
        if let Some(head) = head_hop(vault, wtxn, binding)? {
            return Ok(RunnerWorkBound::Bound {
                binding,
                seat: seat_index(head.seat),
                attempt: AttemptId::from_bytes(&head.attempt)?,
                existing: true,
            });
        }
        let quotas = if only {
            Vec::new()
        } else {
            seat_quotas_in_txn(vault, wtxn, policy, request.now)?
        };
        let mut skipped = Vec::new();
        let mut spent_seen = false;
        let mut back_at: Option<u64> = None;
        let tried = if only { 1 } else { policy.seats.len() };
        for (index, seat) in policy.seats.iter().enumerate().skip(start).take(tried) {
            if let Some(quota) = quotas.get(index).filter(|quota| !quota.available) {
                spent_seen = true;
                back_at = match (back_at, quota.back_at) {
                    (Some(first), Some(next)) => Some(first.min(next)),
                    (first, next) => first.or(next),
                };
                continue;
            }
            let connector = seat.connector(registry, request.task.clone(), request.checkout_id)?;
            let connector = carry_staged_input(connector, request.staged_input.as_ref());
            let context = registry.resolve(&seat.runner)?.placement_context();
            if let Some(bound) = self.seat_bound(seat.logs_in(), &connector, context)? {
                skipped.push(SkippedRunnerSeat {
                    seat: index,
                    runner: seat.runner.clone(),
                    bound,
                });
                continue;
            }
            let outcome = self.enqueue_in_txn(
                wtxn,
                ByoaEnqueue {
                    user_login: seat.logs_in(),
                    connector,
                    task_ref: request.task_ref.map(|task_ref| task_ref.to_hex()),
                    parent_attempt: Some(*request.parent_attempt_id.as_bytes()),
                    run_id: request.run_id,
                    dedupe_key: Some(format!("{RUNNER_WORK_DEDUPE_PREFIX}{}", binding.to_hex())),
                    now: request.now,
                    official_seat: context,
                    work: Some(RunnerWorkBinding {
                        binding: *binding.as_bytes(),
                        task_source: None,
                        checkout: *request.checkout_id.as_bytes(),
                        staged_input: request.staged_input,
                        repo_binding: None,
                    }),
                },
            )?;
            let attempt = outcome.status().attempt.id;
            append_hop_in_txn(
                vault,
                wtxn,
                binding,
                &RunnerWorkHop {
                    attempt: *attempt.as_bytes(),
                    seat: index as u64,
                    spent: None,
                    observed_at: request.now,
                },
            )?;
            return Ok(RunnerWorkBound::Bound {
                binding,
                seat: index,
                attempt,
                existing: false,
            });
        }
        Ok(if spent_seen {
            RunnerWorkBound::Exhausted { back_at, skipped }
        } else {
            RunnerWorkBound::NoSeat { skipped }
        })
    }

    /// The NextSeat route of a spent attempt (OF-137): the next seat in the
    /// owner's order this runtime may run takes the work as a child of the
    /// spent attempt, whatever shape either seat has. Its task is re-read
    /// from its home (the spent CLI attempt's argv, else the CLI attempt
    /// the bound work names), never copied. The work parks when no seat is
    /// left, when the spent attempt is unbound and carries no CLI runner
    /// task (an endpoint or MCP seat's), and when the next seat is a CLI
    /// runner but no CLI seat behind the work holds its task. A seat a
    /// hosted-only bound keeps off this runtime is passed over and named in
    /// the receipt's `skipped_seats`.
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
        let parent = *receipt.attempt.id.as_bytes();
        for (index, next) in policy.seats.iter().enumerate().skip(seat + 1) {
            let checkout =
                successor_checkout(receipt.attempt.id, hand.base, hand.repo.as_ref(), index)?;
            let task = hand.task.clone().unwrap_or_default();
            let connector = next.connector(registry, task, checkout)?;
            if hand.task.is_none() && matches!(connector, ByoaConnectorSpec::CliSandbox(_)) {
                return Ok(park(receipt, spent, now));
            }
            let connector = carry_staged_input(connector, hand.staged.as_ref());
            let context = registry.resolve(&next.runner)?.placement_context();
            if let Some(bound) = self.seat_bound(next.logs_in(), &connector, context)? {
                receipt.skipped_seats.push(SkippedRunnerSeat {
                    seat: index,
                    runner: next.runner.clone(),
                    bound,
                });
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
                append_hop_in_txn(
                    vault,
                    wtxn,
                    RunnerWorkBindingId::from_bytes(work.binding)?,
                    &RunnerWorkHop {
                        attempt: *outcome.status().attempt.id.as_bytes(),
                        seat: index as u64,
                        spent: None,
                        observed_at: now,
                    },
                )?;
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

/// Where the bound work `binding` stands (OF-137): its attempt still
/// running, its last attempt's end, or gone. A read: it settles nothing, and
/// every read of one end carries the same `step_hash`.
///
/// # Errors
/// A record or payload that does not decode; a completed endpoint run's
/// capture that does not resolve; a store failure.
pub fn runner_work_outcome(
    vault: &Vault,
    binding: RunnerWorkBindingId,
) -> ByoaResult<RunnerWorkOutcome> {
    let (mut terminal, endpoint) = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some(head) = head_hop(vault, &rtxn, binding)? else {
            return Ok(RunnerWorkOutcome::Gone);
        };
        let attempt = AttemptId::from_bytes(&head.attempt)?;
        let Some(record) = AttemptQueue::new(vault).get_in_txn(&rtxn, attempt)? else {
            return Ok(RunnerWorkOutcome::Gone);
        };
        let seat = seat_index(head.seat);
        let Some(status) = terminal_status(record.state) else {
            return Ok(RunnerWorkOutcome::Pending { attempt, seat });
        };
        let endpoint = matches!(
            decode_byoa_record(&record)?.connector,
            ByoaConnectorSpec::Endpoint(_)
        );
        let error = match status {
            _ if head.spent.is_some() => Some(RunnerWorkErrorKind::SeatSpent),
            ByoaTerminalDisposition::Completed => None,
            ByoaTerminalDisposition::Failed => Some(RunnerWorkErrorKind::RunnerFailed),
            ByoaTerminalDisposition::Abandoned
                if record.last_error.as_deref() == Some(repo_stale_lease_reason()) =>
            {
                Some(RunnerWorkErrorKind::StaleCheckout)
            }
            ByoaTerminalDisposition::Abandoned => Some(RunnerWorkErrorKind::RunnerStopped),
            ByoaTerminalDisposition::Cancelled => Some(RunnerWorkErrorKind::Cancelled),
        };
        let back_at = head
            .spent
            .as_ref()
            .and_then(|spent| spent.back_at(head.observed_at));
        let terminal = RunnerWorkTerminal {
            attempt,
            seat,
            status,
            error,
            spent: head.spent,
            back_at,
            usage: None,
            step_hash: step_hash(binding, attempt, record.result_ref.as_ref()),
            exhaust_ref: record.result_ref,
        };
        (terminal, endpoint)
    };
    if endpoint && terminal.status == ByoaTerminalDisposition::Completed {
        terminal.usage = transcript_usage(vault, terminal.exhaust_ref.as_ref())?;
    }
    Ok(RunnerWorkOutcome::Terminal(Box::new(terminal)))
}

const fn terminal_status(state: AttemptState) -> Option<ByoaTerminalDisposition> {
    match state {
        AttemptState::Completed => Some(ByoaTerminalDisposition::Completed),
        AttemptState::Failed => Some(ByoaTerminalDisposition::Failed),
        AttemptState::Cancelled => Some(ByoaTerminalDisposition::Cancelled),
        AttemptState::Abandoned => Some(ByoaTerminalDisposition::Abandoned),
        _ => None,
    }
}

fn step_hash(
    binding: RunnerWorkBindingId,
    attempt: AttemptId,
    exhaust: Option<&AttemptResultRef>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(RUNNER_WORK_TERMINAL_DOMAIN);
    hasher.update(binding.as_bytes());
    hasher.update(attempt.as_bytes());
    if let Some(exhaust) = exhaust {
        hasher.update(exhaust.as_str().as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// The usage a completed endpoint run's transcript names, read from its
/// capture. `None` when its transcript names none.
fn transcript_usage(
    vault: &Vault,
    exhaust: Option<&AttemptResultRef>,
) -> ByoaResult<Option<LlmUsage>> {
    let Some(exhaust) = exhaust else {
        return Ok(None);
    };
    let (artifact_id, version) = parse_byoa_result_ref(exhaust)?;
    let (_, _, captured) = decode_byoa_exhaust(vault, &artifact_id, version)?;
    Ok(captured.transcript.and_then(|transcript| {
        serde_json::from_reader::<_, TranscriptUsage>(transcript.reader())
            .ok()
            .map(|read| read.usage)
    }))
}
