//! The side tables `human_task` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Follow-up reminder/escalation cursor state for one human task. Key: id16.
    HUMAN_TASK_FOLLOWUP: VaultMeta b"human_task.followup.v1\0" Raw;
    /// The TASK whose follow-up cursor the due sweep read last: the next wake pass resumes after
    /// it. Key: ().
    HUMAN_TASK_FOLLOWUP_SWEEP: VaultMeta b"human_task.followup_sweep.v1" Raw;
    /// Idempotency marker recording which signal/surface-event a wait's response already produced.
    /// Key: id16.
    HUMAN_TASK_WAIT_SIGNAL: VaultMeta b"human_task.wait.signal.v1\0" Raw;
    /// Active binding from a human task to the trap claim awaiting its response. Key: id16.
    HUMAN_TASK_WAIT_BINDING: VaultMeta b"human_task.wait.v1\0" Raw;
}
