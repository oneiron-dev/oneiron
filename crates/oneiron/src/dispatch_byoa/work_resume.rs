//! An explicit resume of a bound runner work a spend parked (FIX 7450): the
//! owner's Stop, InternalModels, or a NextSeat route with no seat left keeps
//! a spent work on its seat, and only this act hands it on again.
//!
//! The work never moves, only the attempt (ARCH-0068 RC5): a resume mints a
//! successor of the spent attempt on the seat it picks, the spent seat
//! included, as the automatic hand-off does past it (`work_hand_off`). The
//! successor claims a fresh checkout of the work's repo, TASK and holder;
//! the spent attempt keeps its own checkout epoch, its capture and its
//! place as the successor's parent. A resume acts only while the work
//! still stands at the spent attempt its caller saw, so a work that moved
//! on, is running or ended without a spend is answered as it stands, and a
//! replay of the old spent capture never takes it back (`moved_on_in_txn`).
//!
//! There is no served resume door: the trusted dispatcher calls it under its
//! own authority, and the owner through [`ByoaDispatcher::resume_runner_work_as_owner`].

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::consent::AuthenticatedOwner;

use super::connector::{ByoaDispatchOutcome, ByoaDispatchStatus};
use super::dispatcher::{ByoEndpointBackendFactory, ByoaDispatcher};
use super::error::ByoaResult;
use super::exhaust::{ByoaEgressPort, ByoaTerminalReceipt, decode_byoa_record};
use super::provider::ProviderAdapterRegistry;
use super::seat::{RunnerSeatPolicy, SeatRoute, SeatSpent, SkippedRunnerSeat};
use super::work_binding::{RunnerSeatChoice, RunnerWorkBindingId, head_hop, seat_index};
use super::work_hand_off::{HandOff, SeatSearch};

/// A bound work a spend parked, to resume on a seat (FIX 7450).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeRunnerWork {
    /// The bound work.
    pub binding: RunnerWorkBindingId,
    /// The spent attempt the caller saw at the work's head: the resume acts
    /// only while the work still stands there.
    pub expected_attempt: AttemptId,
    /// The seat to resume on. `None` searches the owner's order from the
    /// spent seat, that seat included; `NextSeat { from }` searches from
    /// `from`; `Seat(i)` takes seat `i`, spent or not.
    pub choice: Option<RunnerSeatChoice>,
    /// The vault's time, in seconds.
    pub now: u64,
}

/// Where resuming a bound work left it. Each arm is where the work stands,
/// never a refusal; every arm but `Resumed` wrote nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunnerWorkResume {
    /// A successor on `seat` carries the work now, a child of the spent
    /// attempt on a fresh checkout. `existing` when that seat's successor
    /// of the spent attempt was already dispatched. Each seat the search
    /// passed over first is named.
    Resumed {
        seat: usize,
        attempt: AttemptId,
        existing: bool,
        skipped: Vec<SkippedRunnerSeat>,
    },
    /// The work stands at `attempt` on `seat`: it moved past the attempt
    /// named, or that attempt has not ended.
    Current { seat: usize, attempt: AttemptId },
    /// The attempt named ended without a spend (completed, failed,
    /// cancelled or stopped): there is nothing to resume.
    Unchanged { seat: usize, attempt: AttemptId },
    /// No seat this runtime may run took the work; each one tried is named
    /// with why.
    NoSeat { skipped: Vec<SkippedRunnerSeat> },
    /// Every seat tried is spent or passed over, a spent one among them.
    /// `back_at` is the first time one is back; none waits for the owner.
    Exhausted {
        back_at: Option<u64>,
        skipped: Vec<SkippedRunnerSeat>,
    },
    /// Nothing holds the work: never bound here, or erased or pruned.
    Gone,
}

impl<B, E> ByoaDispatcher<'_, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// Resumes a bound work a spend parked, in the caller's writer `wtxn`
    /// (FIX 7450). While the work's head is `request.expected_attempt`,
    /// ended with its spend, the work goes to a successor of that attempt:
    /// the first seat from `request.choice` in the owner's order that this
    /// runtime may run, the spent seat included, passing over and naming a
    /// spent seat, a CLI seat that cannot carry the task, and a seat a
    /// hosted-only bound keeps off this runtime; or the explicit seat, spent
    /// or not. The successor keeps the work's binding, repo, TASK, holder,
    /// staged job and run, and claims a fresh checkout; the spent attempt
    /// keeps its own. Its dedupe key is the spent attempt and the seat, so a
    /// retry finds the same successor. A work that moved on, is running, or
    /// ended without a spend is answered as it stands, with no write.
    ///
    /// # Errors
    ///
    /// Refuses an invalid policy, an explicit seat index past the policy's
    /// order, an unknown runner, an explicit seat's connector refusal, and
    /// every refusal a dispatch and a checkout claim have, without durable
    /// writes.
    pub fn resume_runner_work_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        request: ResumeRunnerWork,
    ) -> ByoaResult<RunnerWorkResume> {
        policy.validate(registry)?;
        let vault = self.vault();
        let Some(head) = head_hop(vault, wtxn, request.binding)? else {
            return Ok(RunnerWorkResume::Gone);
        };
        let attempt = AttemptId::from_bytes(&head.attempt)?;
        let seat = seat_index(head.seat);
        if attempt != request.expected_attempt {
            return Ok(RunnerWorkResume::Current { seat, attempt });
        }
        let Some(spent) = AttemptQueue::new(vault).get_in_write_txn(wtxn, attempt)? else {
            return Ok(RunnerWorkResume::Gone);
        };
        if !spent.state.is_terminal() {
            return Ok(RunnerWorkResume::Current { seat, attempt });
        }
        if head.spent.is_none() {
            return Ok(RunnerWorkResume::Unchanged { seat, attempt });
        }
        let (from, only) = match request.choice {
            None => (seat, false),
            Some(RunnerSeatChoice::NextSeat { from }) => (from, false),
            Some(RunnerSeatChoice::Seat(index)) => (index, true),
        };
        if request.choice.is_some() {
            policy.seat(from)?;
        }
        let payload = decode_byoa_record(&spent)?;
        let Some(hand) = HandOff::of(vault, wtxn, &spent, payload)? else {
            return Ok(RunnerWorkResume::Unchanged { seat, attempt });
        };
        let search = SeatSearch {
            from,
            only,
            now: request.now,
        };
        let found = self.successor_in_txn(wtxn, registry, policy, &spent, &hand, search)?;
        Ok(match found.took {
            Some((seat, outcome)) => RunnerWorkResume::Resumed {
                seat,
                attempt: outcome.status().attempt.id,
                existing: matches!(outcome, ByoaDispatchOutcome::Existing(_)),
                skipped: found.skipped,
            },
            None if found.spent_seen => RunnerWorkResume::Exhausted {
                back_at: found.back_at,
                skipped: found.skipped,
            },
            None => RunnerWorkResume::NoSeat {
                skipped: found.skipped,
            },
        })
    }

    /// [`Self::resume_runner_work_in_txn`] as the vault owner's own act, in
    /// its own writer: the owner's proof is rechecked in that writer before
    /// the work is read.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, and every refusal
    /// [`Self::resume_runner_work_in_txn`] has, without durable writes.
    pub fn resume_runner_work_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        registry: &ProviderAdapterRegistry,
        policy: &RunnerSeatPolicy,
        request: ResumeRunnerWork,
    ) -> ByoaResult<RunnerWorkResume> {
        let vault = self.vault();
        vault.try_with_write_txn_grouped(|wtxn| -> ByoaResult<RunnerWorkResume> {
            owner.revalidate_in_txn(vault, wtxn)?;
            self.resume_runner_work_in_txn(wtxn, registry, policy, request)
        })
    }
}

/// The route a spent capture `receipt` takes when it is replayed after its
/// bound work moved past it (a later hop, or a resume, FIX 7450): the
/// work's head as a next seat that already exists, with no write. `None`
/// for a capture that read no spend, unbound work, a work that still
/// stands at this attempt, and one whose head is gone.
///
/// # Errors
/// A payload, record or binding id that does not decode; a store failure.
pub(super) fn moved_on_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    receipt: &ByoaTerminalReceipt,
    spent: Option<&SeatSpent>,
) -> ByoaResult<Option<SeatRoute>> {
    let Some(spent) = spent else {
        return Ok(None);
    };
    let Some(work) = decode_byoa_record(&receipt.attempt)?.work else {
        return Ok(None);
    };
    let binding = RunnerWorkBindingId::from_bytes(work.binding)?;
    let Some(head) = head_hop(vault, rtxn, binding)? else {
        return Ok(None);
    };
    if head.attempt == *receipt.attempt.id.as_bytes() {
        return Ok(None);
    }
    let id = AttemptId::from_bytes(&head.attempt)?;
    let Some(attempt) = AttemptQueue::new(vault).get_in_txn(rtxn, id)? else {
        return Ok(None);
    };
    let connector_kind = decode_byoa_record(&attempt)?.connector.kind();
    Ok(Some(SeatRoute::NextSeat {
        receipt: receipt.clone(),
        spent: spent.clone(),
        seat: seat_index(head.seat),
        outcome: ByoaDispatchOutcome::Existing(ByoaDispatchStatus {
            attempt,
            connector_kind,
        }),
    }))
}
