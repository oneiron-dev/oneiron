//! The stored work orders: every order, one order, and the revision-checked write that every
//! change of an order's state and attempts goes through.
use crate::work_order::record::{WORK_ORDERS, WorkOrder};
use crate::{EntityId, Vault};

impl Vault {
    /// Every work order of this vault.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn work_orders(&self) -> crate::Result<Vec<WorkOrder>> {
        self.work_orders_in_txn(&self.store.env.read_txn()?)
    }

    /// [`Self::work_orders`] in the caller's read transaction, for a read that joins the orders
    /// to other rows of one snapshot (`vault.jobs.history`).
    pub(crate) fn work_orders_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> crate::Result<Vec<WorkOrder>> {
        WORK_ORDERS
            .iter_from(&self.store, txn, &[])?
            .map(|row| row.map(|(_, order)| order))
            .collect()
    }

    /// One work order.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn work_order(&self, id: &EntityId) -> crate::Result<Option<WorkOrder>> {
        WORK_ORDERS.get(&self.store, &self.store.env.read_txn()?, id)
    }

    /// Writes `order` if its stored row is still at `order.revision`, bumping it, and settles
    /// in the same write each `vault.jobs.orders.wait` the write reaches. Every change of an
    /// order's state and attempts comes through here. Returns false, writing nothing, when
    /// another write came first.
    pub(in crate::work_order) fn put_work_order_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        order: &mut WorkOrder,
        now_ms: u64,
    ) -> crate::Result<bool> {
        let stored = WORK_ORDERS.get(&self.store, txn, &order.id)?;
        if stored.as_ref().map(|row| row.revision) != Some(order.revision) {
            return Ok(false);
        }
        order.revision += 1;
        order.updated_at_ms = now_ms;
        WORK_ORDERS.put(&self.store, txn, &order.id, order)?;
        self.settle_order_waits_in_txn(txn, stored.as_ref(), order, now_ms)?;
        Ok(true)
    }

    /// Applies `change` to the order as read and writes it if nobody wrote it since; false
    /// when another write came first.
    pub(in crate::work_order) fn update_work_order(
        &self,
        order: &WorkOrder,
        now_ms: u64,
        change: impl FnOnce(&mut WorkOrder),
    ) -> crate::Result<bool> {
        let mut next = order.clone();
        change(&mut next);
        self.with_write_txn_grouped(|txn| self.put_work_order_in_txn(txn, &mut next, now_ms))
    }
}
