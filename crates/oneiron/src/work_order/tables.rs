//! The side table `work_order` keeps: its row declares it, and the crate's build script places
//! it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One work order (pass 34, 1.1; EM-18 = A): durable intent above the built job, which
    /// holds no device and no money while it waits, its typed reasons, and its attempts. Key:
    /// id16 (order). Written by the issuer's engine only.
    WORK_ORDER: VaultMeta b"work_order:v1:" Named
        // Restore class: An order is live: a restore never dispatches again an order the live
        // vault cancelled or finished, or forgets an attempt a machine may run.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::work_order::erase_order_actor_in_txn;
}
