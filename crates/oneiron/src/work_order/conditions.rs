//! Row Q5's conditions on an open order, looked at before any machine is fitted (pass 34, 1.1):
//! the order its `after` names, then its named running caps and its group's cap. Each holds the
//! order with an order-level blocker that clears by waiting; an `after` whose order ended
//! without success gives the order up.
use crate::error::Result;
use crate::{EntityId, Vault};

use super::blocker::{BlockedOn, Blocker};
use super::caps::RunningCaps;
use super::pass::{OrderFit, PassReport};
use super::record::{GiveUpWhy, OrderState, WORK_ORDERS, WorkOrder};
use super::upstream::UpstreamHold;

impl Vault {
    /// The fit row Q5's conditions give `order` in `txn`, given the live attempts `running`
    /// counts: the order waits on its `after` while that order is not at an end and gives up
    /// when it ended without success; it waits on each cap that is full. `None` when nothing
    /// holds it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn order_conditions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        order: &WorkOrder,
        running: &RunningCaps,
    ) -> Result<Option<OrderFit>> {
        match self.upstream_hold_in_txn(txn, order)? {
            Some(UpstreamHold::Ended(upstream)) => {
                return Ok(Some(OrderFit::UpstreamEnded(upstream)));
            }
            Some(UpstreamHold::Waiting(upstream)) => {
                return Ok(Some(OrderFit::Blocked(vec![BlockedOn {
                    machine: None,
                    blocker: Blocker::After {
                        order: upstream.to_hex(),
                    },
                }])));
            }
            None => {}
        }
        let capped = self.cap_blockers_in_txn(txn, order, running)?;
        Ok((!capped.is_empty()).then(|| {
            OrderFit::Blocked(
                capped
                    .into_iter()
                    .map(|blocker| BlockedOn {
                        machine: None,
                        blocker,
                    })
                    .collect(),
            )
        }))
    }

    /// Q5's conditions again in the attempt's own write `txn` (pass 34, 1.1: fit is checked
    /// again where the attempt is written), so a cap the owner lowered or an attempt another
    /// caller made after the pass read its rows still holds the order: the order its `after`
    /// names has ended well, and no cap it counts against is full, with the live attempts
    /// counted over every order `txn` reads. The first blocker that holds it, else `None`.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn attempt_conditions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        order: &WorkOrder,
    ) -> Result<Option<Blocker>> {
        if let Some(UpstreamHold::Waiting(upstream) | UpstreamHold::Ended(upstream)) =
            self.upstream_hold_in_txn(txn, order)?
        {
            return Ok(Some(Blocker::After {
                order: upstream.to_hex(),
            }));
        }
        if order.limits.caps.is_empty() && order.group.is_none() {
            return Ok(None);
        }
        let orders = WORK_ORDERS.scan(&self.store, txn)?;
        let running = RunningCaps::of(orders.iter().map(|(_, row)| row));
        Ok(self
            .cap_blockers_in_txn(txn, order, &running)?
            .into_iter()
            .next())
    }

    /// Gives `order` up: the order its `after` names, `upstream`, ended without the end it
    /// waited for.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn give_up_on_upstream(
        &self,
        order: &WorkOrder,
        upstream: EntityId,
        now_ms: u64,
        report: &mut PassReport,
    ) -> Result<()> {
        if self.update_work_order(order, now_ms, |order| {
            order.state = OrderState::GivenUp {
                why: GiveUpWhy::Upstream { order: upstream },
            };
        })? {
            report.closed.push(order.id);
        }
        Ok(())
    }
}
