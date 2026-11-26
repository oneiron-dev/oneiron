//! The side tables `work_order` keeps: each row declares one, and the crate's build script places
//! each in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One work order (pass 34, 1.1; EM-18 = A): durable intent above the built job, which
    /// holds no device and no money while it waits, its typed reasons, and its attempts. Key:
    /// id16 (order). Written by the issuer's engine only.
    WORK_ORDER: VaultMeta b"work_order:v1:" Named
        // Restore class: An order is live: a restore never dispatches again an order the live
        // vault cancelled or finished, or forgets an attempt a machine may run.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::work_order::erase_order_actor_in_txn;
    /// One array group of work orders (pass 34, 1.1; row Q5): the cap on its members that hold
    /// a live attempt at once, and who made it. Key: id16 (group). Written by the issuer's
    /// engine in the create write of the group's first member; never changed after.
    WORK_ORDER_GROUP: VaultMeta b"work_order_group:v1:" Named
        // Restore class: A group is live with its member orders: a restore keeps the cap the
        // live vault's members ran under.
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::work_order::group::erase_group_actor_in_txn;
}
