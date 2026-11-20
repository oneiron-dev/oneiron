//! The runner seats a continue searches, in the policy's order with the
//! owner's first (census L10-17).

use super::super::work_binding::{BindRunnerWork, RunnerSeatSearch};
use super::super::{
    ByoaConnectorSpec, ByoaDispatcher, ByoaResult, ProviderAdapterRegistry, RunnerSeat,
    RunnerSeatPolicy, SeatPassedOver, SkippedRunnerSeat, SkippedRunnerSeatView,
};
use super::hand_over::{ContinueEgress, ContinueEndpoints};

/// The wire views of the seats a search passed over, in the policy's order.
pub(super) fn skipped_views(skipped: &[SkippedRunnerSeat]) -> Vec<SkippedRunnerSeatView> {
    skipped
        .iter()
        .map(|skip| SkippedRunnerSeatView {
            seat: skip.seat,
            runner: skip.runner.clone(),
            reason: skip.reason.to_string(),
        })
        .collect()
}

/// The seats of the owner's policy that name the runner a continue asks
/// for. A continue searches only these, so a seat passed over as spent or
/// as one this runtime may not run never hands the work to another
/// vendor's runner; each seat keeps its quota and placement checks.
#[derive(Clone)]
pub(super) struct RunnerSeats {
    /// Those seats as a policy of their own, in the owner's order, under
    /// the owner's spend rule.
    policy: RunnerSeatPolicy,
    /// Each seat's index in the owner's policy.
    indices: Vec<usize>,
}

impl RunnerSeats {
    /// The seats of `policy` that name `runner`; `None` when no seat does.
    pub(super) fn of(policy: &RunnerSeatPolicy, runner: &str) -> Option<Self> {
        let (indices, seats): (Vec<usize>, Vec<RunnerSeat>) = policy
            .seats
            .iter()
            .enumerate()
            .filter(|(_, seat)| seat.runner == runner)
            .map(|(index, seat)| (index, seat.clone()))
            .unzip();
        if seats.is_empty() {
            return None;
        }
        Some(Self {
            policy: RunnerSeatPolicy {
                seats,
                on_spent: policy.on_spent,
            },
            indices,
        })
    }

    /// The seat search over these seats from the first, read in `txn`, its
    /// seat indices put back in the owner's order. A seat whose connector
    /// is not a CLI one is passed over and named, and the search runs again
    /// over the seats left, so every other seat keeps the reason the search
    /// gives it: the hand-over job rides only a CLI connector, and a host
    /// claims only CLI work, so no runner would ever read work bound there.
    ///
    /// # Errors
    ///
    /// Every refusal the search has.
    pub(super) fn search_in_txn(
        &self,
        dispatcher: &ByoaDispatcher<'_, ContinueEndpoints, ContinueEgress>,
        txn: &heed::RoTxn<'_>,
        registry: &ProviderAdapterRegistry,
        work: &BindRunnerWork,
    ) -> ByoaResult<RunnerSeatSearch> {
        let mut seats = self.clone();
        let mut non_cli = Vec::new();
        loop {
            if seats.policy.seats.is_empty() {
                return Ok(RunnerSeatSearch::NoSeat { skipped: non_cli });
            }
            match dispatcher.search_runner_seat_in_txn(txn, registry, &seats.policy, work)? {
                RunnerSeatSearch::Found {
                    seat, connector, ..
                } if !matches!(*connector, ByoaConnectorSpec::CliSandbox(_)) => {
                    non_cli.push(SkippedRunnerSeat {
                        seat: seats.owner_index(seat),
                        runner: seats.policy.seats[seat].runner.clone(),
                        reason: SeatPassedOver::NonCliConnector,
                    });
                    seats = seats.without(seat);
                }
                RunnerSeatSearch::Found {
                    seat,
                    connector,
                    context,
                    task_source,
                } => {
                    return Ok(RunnerSeatSearch::Found {
                        seat: seats.owner_index(seat),
                        connector,
                        context,
                        task_source,
                    });
                }
                RunnerSeatSearch::NoSeat { skipped } => {
                    return Ok(RunnerSeatSearch::NoSeat {
                        skipped: owner_ordered(seats.owner_skipped(skipped), non_cli),
                    });
                }
                RunnerSeatSearch::Exhausted { back_at, skipped } => {
                    return Ok(RunnerSeatSearch::Exhausted {
                        back_at,
                        skipped: owner_ordered(seats.owner_skipped(skipped), non_cli),
                    });
                }
            }
        }
    }

    /// These seats without seat `index` of them.
    fn without(&self, index: usize) -> Self {
        let mut seats = self.clone();
        seats.policy.seats.remove(index);
        seats.indices.remove(index);
        seats
    }

    /// Seat `index` of these seats as its index in the owner's policy. A
    /// search over these seats answers only their own indices.
    fn owner_index(&self, index: usize) -> usize {
        self.indices[index]
    }

    /// `skipped` with each seat named by its index in the owner's policy.
    fn owner_skipped(&self, skipped: Vec<SkippedRunnerSeat>) -> Vec<SkippedRunnerSeat> {
        skipped
            .into_iter()
            .map(|skip| SkippedRunnerSeat {
                seat: self.owner_index(skip.seat),
                ..skip
            })
            .collect()
    }
}

/// The seats one search passed over and the non-CLI seats passed over
/// before it, as one list in the owner's order.
fn owner_ordered(
    mut skipped: Vec<SkippedRunnerSeat>,
    non_cli: Vec<SkippedRunnerSeat>,
) -> Vec<SkippedRunnerSeat> {
    skipped.extend(non_cli);
    skipped.sort_by_key(|skip| skip.seat);
    skipped
}
